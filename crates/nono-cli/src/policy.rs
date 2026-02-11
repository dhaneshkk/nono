//! Group-based policy resolver
//!
//! Parses `policy.json` and resolves named groups into `CapabilitySet` entries
//! and platform-specific rules. This replaces the flat `security-lists.toml` approach
//! with composable, platform-aware groups.

use crate::profile;
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NonoError, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::debug;

// ============================================================================
// JSON schema types
// ============================================================================

/// Root policy file structure
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    #[allow(dead_code)]
    pub meta: PolicyMeta,
    /// Default groups applied to all sandbox invocations
    #[serde(default)]
    pub base_groups: Vec<String>,
    pub groups: HashMap<String, Group>,
    /// Built-in profile definitions
    #[serde(default)]
    pub profiles: HashMap<String, ProfileDef>,
}

/// Policy metadata
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyMeta {
    #[allow(dead_code)]
    pub version: u64,
    #[allow(dead_code)]
    pub schema_version: String,
}

/// A named group of rules
#[derive(Debug, Clone, Deserialize)]
pub struct Group {
    #[allow(dead_code)]
    pub description: String,
    /// If set, this group only applies on the specified platform
    #[serde(default)]
    pub platform: Option<String>,
    /// Allow operations
    #[serde(default)]
    pub allow: Option<AllowOps>,
    /// Deny operations
    #[serde(default)]
    pub deny: Option<DenyOps>,
    /// macOS symlink path pairs (symlink -> real target)
    #[serde(default)]
    pub symlink_pairs: Option<HashMap<String, String>>,
}

/// Allow operations nested under `allow`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AllowOps {
    /// Paths granted read access
    #[serde(default)]
    pub read: Vec<String>,
    /// Paths granted write-only access
    #[serde(default)]
    pub write: Vec<String>,
    /// Paths granted read+write access
    #[serde(default)]
    pub readwrite: Vec<String>,
}

/// Deny operations nested under `deny`
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DenyOps {
    /// Paths denied all content access (read+write; metadata still allowed)
    #[serde(default)]
    pub access: Vec<String>,
    /// Block file deletion globally
    #[serde(default)]
    pub unlink: bool,
    /// Override unlink denial for user-writable paths
    #[serde(default)]
    pub unlink_override_for_user_writable: bool,
    /// Commands to block
    #[serde(default)]
    pub commands: Vec<String>,
}

/// Profile definition as stored in policy.json
///
/// Separate from `profile::Profile` because in JSON `trust_groups` lives at the
/// profile level and `security.groups` means "additional groups on top of base",
/// not the complete merged list.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileDef {
    #[serde(default)]
    pub meta: profile::ProfileMeta,
    #[serde(default)]
    pub security: profile::SecurityConfig,
    /// Base groups to exclude for this profile
    #[serde(default)]
    pub trust_groups: Vec<String>,
    #[serde(default)]
    pub filesystem: profile::FilesystemConfig,
    #[serde(default)]
    pub network: profile::NetworkConfig,
    #[serde(default)]
    pub secrets: profile::SecretsConfig,
    #[serde(default)]
    pub workdir: profile::WorkdirConfig,
    #[serde(default)]
    pub hooks: profile::HooksConfig,
    #[serde(default)]
    pub interactive: bool,
}

impl ProfileDef {
    /// Convert to a full Profile with merged group list.
    ///
    /// Computes: `(base_groups - trust_groups) + security.groups`
    pub fn to_profile(&self, base_groups: &[String]) -> profile::Profile {
        let mut groups: Vec<String> = base_groups
            .iter()
            .filter(|g| !self.trust_groups.contains(g))
            .cloned()
            .collect();
        groups.extend(self.security.groups.clone());

        profile::Profile {
            meta: self.meta.clone(),
            security: profile::SecurityConfig {
                groups,
                trust_groups: self.trust_groups.clone(),
            },
            filesystem: self.filesystem.clone(),
            network: self.network.clone(),
            secrets: self.secrets.clone(),
            workdir: self.workdir.clone(),
            hooks: self.hooks.clone(),
            interactive: self.interactive,
        }
    }
}

// ============================================================================
// Platform detection
// ============================================================================

/// Current platform identifier
fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

/// Check if a group applies to the current platform
fn group_matches_platform(group: &Group) -> bool {
    match &group.platform {
        Some(platform) => platform == current_platform(),
        None => true, // No platform restriction = applies everywhere
    }
}

// ============================================================================
// Path expansion
// ============================================================================

/// Expand `~` to $HOME and `$TMPDIR` to the environment variable value.
///
/// Returns an error if HOME or TMPDIR are set to non-absolute paths.
fn expand_path(path_str: &str) -> Result<PathBuf> {
    use crate::config;

    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        let home = config::validated_home()?;
        format!("{}/{}", home, rest)
    } else if path_str == "~" {
        config::validated_home()?
    } else if path_str == "$TMPDIR" {
        config::validated_tmpdir()?
    } else if let Some(rest) = path_str.strip_prefix("$TMPDIR/") {
        let tmpdir = config::validated_tmpdir()?;
        format!("{}/{}", tmpdir, rest)
    } else {
        path_str.to_string()
    };

    Ok(PathBuf::from(expanded))
}

/// Escape a path for Seatbelt profile strings.
///
/// Paths are placed inside double-quoted S-expression strings where `\` and `"`
/// are the significant characters. All control characters (0x00-0x1F, 0x7F, and
/// Unicode control chars) are stripped since they cannot appear in valid filesystem
/// paths and could disrupt Seatbelt's S-expression parser.
fn escape_seatbelt_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            c if c.is_control() => {}
            _ => result.push(c),
        }
    }
    result
}

// ============================================================================
// Group resolution
// ============================================================================

/// Load policy from JSON string
pub fn load_policy(json: &str) -> Result<Policy> {
    serde_json::from_str(json)
        .map_err(|e| NonoError::ConfigParse(format!("Failed to parse policy.json: {}", e)))
}

/// Result of resolving policy groups
pub struct ResolvedGroups {
    /// Names of groups that were resolved (platform-matching only)
    pub names: Vec<String>,
    /// Whether unlink overrides should be applied after all paths are finalized.
    /// This is deferred because the caller may add more writable paths (e.g., from
    /// the profile's [filesystem] section or CLI flags) after group resolution.
    pub needs_unlink_overrides: bool,
}

/// Resolve a list of group names into capability set entries and platform rules.
///
/// For each group:
/// - `allow.read` paths become `FsCapability` with `AccessMode::Read`
/// - `allow.write` paths become `FsCapability` with `AccessMode::Write`
/// - `allow.readwrite` paths become `FsCapability` with `AccessMode::ReadWrite`
/// - `deny.access` paths become platform rules (deny read data + deny write)
/// - `deny.unlink` becomes a platform rule
/// - `deny.commands` are added to the blocked commands list
/// - `symlink_pairs` become platform rules for non-canonical paths
///
/// Groups with a `platform` field that doesn't match the current OS are skipped.
/// Non-existent allow paths are skipped with a warning.
/// Non-existent deny paths still generate rules (defensive).
///
/// **Important**: If `resolved.needs_unlink_overrides` is true, the caller MUST call
/// `apply_unlink_overrides(caps)` after all writable paths have been added to the
/// capability set (including profile [filesystem] and CLI overrides).
pub fn resolve_groups(
    policy: &Policy,
    group_names: &[String],
    caps: &mut CapabilitySet,
) -> Result<ResolvedGroups> {
    let mut resolved_groups = Vec::new();
    let mut needs_unlink_overrides = false;

    for name in group_names {
        let group = policy
            .groups
            .get(name.as_str())
            .ok_or_else(|| NonoError::ConfigParse(format!("Unknown policy group: '{}'", name)))?;

        if !group_matches_platform(group) {
            debug!(
                "Skipping group '{}' (platform {:?} != {})",
                name,
                group.platform,
                current_platform()
            );
            continue;
        }

        if resolve_single_group(name, group, caps)? {
            needs_unlink_overrides = true;
        }
        resolved_groups.push(name.clone());
    }

    Ok(ResolvedGroups {
        names: resolved_groups,
        needs_unlink_overrides,
    })
}

/// Resolve a single group into capability set entries.
/// Returns true if unlink overrides were requested (to be deferred).
fn resolve_single_group(group_name: &str, group: &Group, caps: &mut CapabilitySet) -> Result<bool> {
    let source = CapabilitySource::Group(group_name.to_string());
    let mut needs_unlink_overrides = false;

    // Process allow operations
    if let Some(allow) = &group.allow {
        for path_str in &allow.read {
            add_fs_capability(path_str, AccessMode::Read, &source, caps)?;
        }
        for path_str in &allow.write {
            add_fs_capability(path_str, AccessMode::Write, &source, caps)?;
        }
        for path_str in &allow.readwrite {
            add_fs_capability(path_str, AccessMode::ReadWrite, &source, caps)?;
        }
    }

    // Process deny operations
    if let Some(deny) = &group.deny {
        for path_str in &deny.access {
            add_deny_access_rules(path_str, caps)?;
        }

        if deny.unlink {
            caps.add_platform_rule("(deny file-write-unlink)")?;
        }

        if deny.unlink_override_for_user_writable {
            // Deferred: caller must call apply_unlink_overrides() after all writable
            // paths are finalized (profile [filesystem] + CLI overrides).
            needs_unlink_overrides = true;
        }

        for cmd in &deny.commands {
            caps.add_blocked_command(cmd.clone());
        }
    }

    // Process symlink pairs (macOS-specific path handling)
    if let Some(pairs) = &group.symlink_pairs {
        for symlink in pairs.keys() {
            let expanded = expand_path(symlink)?;
            let escaped = escape_seatbelt_path(&expanded.to_string_lossy());
            caps.add_platform_rule(format!("(allow file-read* (subpath \"{}\"))", escaped))?;
        }
    }

    Ok(needs_unlink_overrides)
}

/// Add a filesystem capability from a group path, handling expansion and existence checks
fn add_fs_capability(
    path_str: &str,
    mode: AccessMode,
    source: &CapabilitySource,
    caps: &mut CapabilitySet,
) -> Result<()> {
    let path = expand_path(path_str)?;

    if !path.exists() {
        debug!(
            "Group path '{}' (expanded to '{}') does not exist, skipping",
            path_str,
            path.display()
        );
        return Ok(());
    }

    if path.is_dir() {
        match FsCapability::new_dir(&path, mode) {
            Ok(mut cap) => {
                cap.source = source.clone();
                caps.add_fs(cap);
            }
            Err(e) => {
                debug!("Could not add group directory {}: {}", path_str, e);
            }
        }
    } else if path.is_file() {
        match FsCapability::new_file(&path, mode) {
            Ok(mut cap) => {
                cap.source = source.clone();
                caps.add_fs(cap);
            }
            Err(e) => {
                debug!("Could not add group file {}: {}", path_str, e);
            }
        }
    } else {
        debug!(
            "Group path '{}' is neither file nor directory, skipping",
            path_str
        );
    }

    Ok(())
}

/// Add deny.access rules as platform-specific Seatbelt rules.
///
/// Generates:
/// - `(allow file-read-metadata ...)` — programs can stat/check existence
/// - `(deny file-read-data ...)` — deny reading content
/// - `(deny file-write* ...)` — deny writing
///
/// Uses `subpath` for directories, `literal` for files.
/// For non-existent paths, defaults to `subpath` (defensive).
fn add_deny_access_rules(path_str: &str, caps: &mut CapabilitySet) -> Result<()> {
    let path = expand_path(path_str)?;
    let escaped = escape_seatbelt_path(&path.to_string_lossy());

    // Determine filter type: literal for files, subpath for directories
    let filter = if path.exists() && path.is_file() {
        format!("literal \"{}\"", escaped)
    } else {
        // Default to subpath for dirs and non-existent paths (defensive)
        format!("subpath \"{}\"", escaped)
    };

    caps.add_platform_rule(format!("(allow file-read-metadata ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-read-data ({}))", filter))?;
    caps.add_platform_rule(format!("(deny file-write* ({}))", filter))?;

    Ok(())
}

/// Apply unlink override rules for all writable paths in the capability set.
///
/// This allows file deletion in paths that have Write or ReadWrite access,
/// counteracting a global `(deny file-write-unlink)` rule.
///
/// **Must be called after all paths are finalized** (groups + profile + CLI overrides).
pub fn apply_unlink_overrides(caps: &mut CapabilitySet) {
    // Collect writable paths from existing capabilities
    let writable_paths: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| matches!(cap.access, AccessMode::Write | AccessMode::ReadWrite))
        .filter(|cap| !cap.is_file)
        .map(|cap| cap.resolved.clone())
        .collect();

    for path in writable_paths {
        let escaped = escape_seatbelt_path(&path.to_string_lossy());
        // These rules are well-formed S-expressions for user-granted writable paths,
        // so validation should not fail. Log and skip on error to avoid breaking the sandbox.
        if let Err(e) = caps.add_platform_rule(format!(
            "(allow file-write-unlink (subpath \"{}\"))",
            escaped
        )) {
            tracing::warn!("Skipping unlink override rule: {}", e);
        }
    }
}

/// Get the list of all group names defined in the policy
#[allow(dead_code)]
pub fn list_groups(policy: &Policy) -> Vec<&str> {
    let mut names: Vec<&str> = policy.groups.keys().map(|s| s.as_str()).collect();
    names.sort();
    names
}

/// Get group description by name
#[allow(dead_code)]
pub fn group_description<'a>(policy: &'a Policy, name: &str) -> Option<&'a str> {
    policy.groups.get(name).map(|g| g.description.as_str())
}

// ============================================================================
// Query helpers: extract flat lists from policy groups
// ============================================================================

/// Get all sensitive (deny.access) paths from platform-matching policy groups.
///
/// Returns a list of `(expanded_path, group_description)` tuples suitable for
/// display in `nono why`. Paths are expanded (~ -> $HOME, $TMPDIR -> value).
pub fn get_sensitive_paths(policy: &Policy) -> Result<Vec<(String, String)>> {
    let mut result = Vec::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(deny) = &group.deny {
            for path_str in &deny.access {
                let expanded = expand_path(path_str)?;
                result.push((
                    expanded.to_string_lossy().into_owned(),
                    group.description.clone(),
                ));
            }
        }
    }

    Ok(result)
}

/// Get all dangerous (deny.commands) from platform-matching policy groups.
///
/// Returns a flat set of command names that should be blocked.
pub fn get_dangerous_commands(policy: &Policy) -> HashSet<String> {
    let mut result = HashSet::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(deny) = &group.deny {
            for cmd in &deny.commands {
                result.insert(cmd.clone());
            }
        }
    }

    result
}

/// Get all system read paths from allow.read groups for the current platform.
///
/// Collects `allow.read` entries from all platform-matching groups. Paths are
/// returned unexpanded (with `~` and `$TMPDIR` intact) for caller to expand.
/// Used by learn mode (Linux only).
#[allow(dead_code)]
pub fn get_system_read_paths(policy: &Policy) -> Vec<String> {
    let mut result = Vec::new();

    for group in policy.groups.values() {
        if !group_matches_platform(group) {
            continue;
        }
        if let Some(allow) = &group.allow {
            result.extend(allow.read.iter().cloned());
        }
    }

    result
}

/// Common deny + system groups shared by all sandbox invocations.
///
/// Reads from the embedded policy.json `base_groups` array. This is the base
/// set of groups that both `from_args()` (non-profile CLI) and built-in
/// profiles use. Profiles extend this with additional groups.
pub fn base_groups() -> Vec<String> {
    // The embedded policy must be valid at build time; a corrupted binary is fatal.
    let policy = load_embedded_policy().expect("embedded policy.json must be valid");
    policy.base_groups
}

/// Get a built-in profile from embedded policy.json.
///
/// Returns `None` if the profile name is not defined in policy.json.
pub fn get_policy_profile(name: &str) -> Result<Option<profile::Profile>> {
    let policy = load_embedded_policy()?;
    Ok(policy
        .profiles
        .get(name)
        .map(|def| def.to_profile(&policy.base_groups)))
}

/// List all built-in profile names from embedded policy.json.
pub fn list_policy_profiles() -> Result<Vec<String>> {
    let policy = load_embedded_policy()?;
    let mut names: Vec<String> = policy.profiles.keys().cloned().collect();
    names.sort();
    Ok(names)
}

/// Load the embedded policy and return the parsed Policy struct.
///
/// Convenience wrapper that loads from the compile-time embedded JSON.
pub fn load_embedded_policy() -> Result<Policy> {
    let json = crate::config::embedded::embedded_policy_json();
    load_policy(json)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy_json() -> &'static str {
        r#"{
            "meta": { "version": 2, "schema_version": "2.0" },
            "groups": {
                "test_read": {
                    "description": "Test read group",
                    "allow": { "read": ["/tmp"] }
                },
                "test_deny": {
                    "description": "Test deny group",
                    "deny": { "access": ["/nonexistent/test/path"] }
                },
                "test_commands": {
                    "description": "Test command blocking",
                    "deny": { "commands": ["rm", "dd"] }
                },
                "test_macos_only": {
                    "description": "macOS-only group",
                    "platform": "macos",
                    "allow": { "read": ["/tmp"] }
                },
                "test_linux_only": {
                    "description": "Linux-only group",
                    "platform": "linux",
                    "allow": { "read": ["/tmp"] }
                },
                "test_unlink": {
                    "description": "Unlink protection",
                    "deny": { "unlink": true }
                },
                "test_symlinks": {
                    "description": "Symlink test",
                    "symlink_pairs": { "/etc": "/private/etc" }
                }
            }
        }"#
    }

    #[test]
    fn test_load_policy() {
        let policy = load_policy(sample_policy_json());
        assert!(policy.is_ok());
        let policy = policy.expect("parse failed");
        assert_eq!(policy.meta.version, 2);
        assert_eq!(policy.groups.len(), 7);
    }

    #[test]
    fn test_load_embedded_policy() {
        let json = crate::config::embedded::embedded_policy_json();
        let policy = load_policy(json);
        assert!(policy.is_ok(), "Failed to parse embedded policy.json");
        let policy = policy.expect("parse failed");
        assert!(policy.meta.version >= 2);
        assert!(!policy.groups.is_empty());
    }

    #[test]
    fn test_resolve_read_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_read".to_string()], &mut caps);
        assert!(resolved.is_ok());
        // /tmp should exist on all platforms
        assert!(caps.has_fs());
    }

    #[test]
    fn test_resolve_deny_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_deny".to_string()], &mut caps);
        assert!(resolved.is_ok());
        // Should have platform rules for deny
        assert!(!caps.platform_rules().is_empty());

        let rules = caps.platform_rules().join("\n");
        assert!(rules.contains("deny file-read-data"));
        assert!(rules.contains("deny file-write*"));
        assert!(rules.contains("allow file-read-metadata"));
    }

    #[test]
    fn test_resolve_command_group() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_commands".to_string()], &mut caps);
        assert!(resolved.is_ok());
        assert!(caps.blocked_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"dd".to_string()));
    }

    #[test]
    fn test_platform_filtering() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();

        // Resolve both platform groups - only the matching one should be active
        let resolved = resolve_groups(
            &policy,
            &["test_macos_only".to_string(), "test_linux_only".to_string()],
            &mut caps,
        )
        .expect("resolve failed");

        // Exactly one should have been resolved
        assert_eq!(resolved.names.len(), 1);

        if cfg!(target_os = "macos") {
            assert_eq!(resolved.names[0], "test_macos_only");
        } else {
            assert_eq!(resolved.names[0], "test_linux_only");
        }
    }

    #[test]
    fn test_unknown_group_error() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let result = resolve_groups(&policy, &["nonexistent_group".to_string()], &mut caps);
        assert!(result.is_err());
    }

    #[test]
    fn test_unlink_protection() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_unlink".to_string()], &mut caps);
        assert!(resolved.is_ok());
        assert!(caps
            .platform_rules()
            .iter()
            .any(|r| r.contains("deny file-write-unlink")));
    }

    #[test]
    fn test_symlink_pairs() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let mut caps = CapabilitySet::new();
        let resolved = resolve_groups(&policy, &["test_symlinks".to_string()], &mut caps);
        assert!(resolved.is_ok());
        assert!(caps.platform_rules().iter().any(|r| r.contains("/etc")));
    }

    #[test]
    fn test_expand_path_tilde() {
        let path = expand_path("~/.ssh").expect("HOME must be valid");
        assert!(path.to_string_lossy().contains(".ssh"));
        assert!(!path.to_string_lossy().starts_with("~"));
    }

    #[test]
    fn test_expand_path_tmpdir() {
        let path = expand_path("$TMPDIR").expect("TMPDIR must be valid");
        assert!(!path.to_string_lossy().starts_with("$"));
    }

    #[test]
    fn test_expand_path_absolute() {
        let path = expand_path("/usr/bin").expect("absolute path needs no env");
        assert_eq!(path, PathBuf::from("/usr/bin"));
    }

    #[test]
    fn test_list_groups() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        let names = list_groups(&policy);
        assert!(names.contains(&"test_read"));
        assert!(names.contains(&"test_deny"));
    }

    #[test]
    fn test_group_description() {
        let policy = load_policy(sample_policy_json()).expect("parse failed");
        assert_eq!(
            group_description(&policy, "test_read"),
            Some("Test read group")
        );
        assert_eq!(group_description(&policy, "nonexistent"), None);
    }

    #[test]
    fn test_deny_access_generates_all_three_rules() {
        let mut caps = CapabilitySet::new();
        add_deny_access_rules("/nonexistent/test/deny", &mut caps)
            .expect("expand_path should succeed for absolute paths");

        let rules = caps.platform_rules();
        assert_eq!(rules.len(), 3);
        assert!(rules[0].contains("allow file-read-metadata"));
        assert!(rules[1].contains("deny file-read-data"));
        assert!(rules[2].contains("deny file-write*"));
    }

    #[test]
    fn test_escape_seatbelt_path() {
        assert_eq!(escape_seatbelt_path("/simple/path"), "/simple/path");
        assert_eq!(
            escape_seatbelt_path("/path with\\slash"),
            "/path with\\\\slash"
        );
        assert_eq!(escape_seatbelt_path("/path\"quoted"), "/path\\\"quoted");
        assert_eq!(
            escape_seatbelt_path("/path\nwith\nnewlines"),
            "/pathwithnewlines"
        );
        assert_eq!(
            escape_seatbelt_path("/path\rwith\rreturns"),
            "/pathwithreturns"
        );
        assert_eq!(escape_seatbelt_path("/path\0with\0nulls"), "/pathwithnulls");
        // All control characters must be stripped
        assert_eq!(escape_seatbelt_path("/path\twith\ttabs"), "/pathwithtabs");
        assert_eq!(
            escape_seatbelt_path("/path\x0bwith\x0cfeeds"),
            "/pathwithfeeds"
        );
        assert_eq!(
            escape_seatbelt_path("/path\x1bwith\x1bescape"),
            "/pathwithescape"
        );
        assert_eq!(escape_seatbelt_path("/path\x7fwith\x7fdel"), "/pathwithdel");
    }

    #[test]
    fn test_escape_seatbelt_path_injection_via_newline() {
        let malicious = "/tmp/evil\n(allow file-read* (subpath \"/\"))";
        let escaped = escape_seatbelt_path(malicious);
        assert!(
            !escaped.contains('\n'),
            "escaped path must not contain newlines"
        );
    }

    #[test]
    fn test_escape_seatbelt_path_injection_via_quote() {
        let malicious = "/tmp/evil\")(allow file-read* (subpath \"/\"))(\"";
        let escaped = escape_seatbelt_path(malicious);
        let chars: Vec<char> = escaped.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            if c == '"' {
                assert!(
                    i > 0 && chars[i - 1] == '\\',
                    "unescaped quote at position {}",
                    i
                );
            }
        }
    }
}
