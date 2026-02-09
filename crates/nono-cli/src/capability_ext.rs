//! CLI-specific extensions for CapabilitySet
//!
//! This module provides methods to construct a CapabilitySet from CLI arguments
//! or profiles. These are CLI-specific and not part of the core library.

use crate::cli::SandboxArgs;
use crate::config;
use crate::policy;
use crate::profile::{expand_vars, Profile};
use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, Result};
use std::path::Path;
use tracing::{debug, warn};

/// Extension trait for CapabilitySet to add CLI-specific construction methods
pub trait CapabilitySetExt {
    /// Create a capability set from CLI sandbox arguments
    fn from_args(args: &SandboxArgs) -> Result<CapabilitySet>;

    /// Create a capability set from a profile with CLI overrides
    fn from_profile(profile: &Profile, workdir: &Path, args: &SandboxArgs)
        -> Result<CapabilitySet>;
}

impl CapabilitySetExt for CapabilitySet {
    fn from_args(args: &SandboxArgs) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();

        // Directory permissions
        for path in &args.allow {
            if path.exists() {
                let cap = FsCapability::new_dir(path, AccessMode::ReadWrite)?;
                caps.add_fs(cap);
            } else {
                warn!("Skipping non-existent path: {}", path.display());
            }
        }

        for path in &args.read {
            if path.exists() {
                let cap = FsCapability::new_dir(path, AccessMode::Read)?;
                caps.add_fs(cap);
            } else {
                warn!("Skipping non-existent path: {}", path.display());
            }
        }

        for path in &args.write {
            if path.exists() {
                let cap = FsCapability::new_dir(path, AccessMode::Write)?;
                caps.add_fs(cap);
            } else {
                warn!("Skipping non-existent path: {}", path.display());
            }
        }

        // Single file permissions
        for path in &args.allow_file {
            if path.exists() {
                let cap = FsCapability::new_file(path, AccessMode::ReadWrite)?;
                caps.add_fs(cap);
            } else {
                warn!("Skipping non-existent file: {}", path.display());
            }
        }

        for path in &args.read_file {
            if path.exists() {
                let cap = FsCapability::new_file(path, AccessMode::Read)?;
                caps.add_fs(cap);
            } else {
                warn!("Skipping non-existent file: {}", path.display());
            }
        }

        for path in &args.write_file {
            if path.exists() {
                let cap = FsCapability::new_file(path, AccessMode::Write)?;
                caps.add_fs(cap);
            } else {
                warn!("Skipping non-existent file: {}", path.display());
            }
        }

        // Network blocking
        if args.net_block {
            caps.set_network_blocked(true);
        }

        // Command allow/block lists
        for cmd in &args.allow_command {
            caps.add_allowed_command(cmd.clone());
        }

        for cmd in &args.block_command {
            caps.add_blocked_command(cmd.clone());
        }

        // Add system read paths from config (required for executables to run)
        add_system_read_paths(&mut caps);

        Ok(caps)
    }

    fn from_profile(
        profile: &Profile,
        workdir: &Path,
        args: &SandboxArgs,
    ) -> Result<CapabilitySet> {
        let mut caps = CapabilitySet::new();
        let has_groups = !profile.security.groups.is_empty();

        // Resolve policy groups if the profile references them
        let mut needs_unlink_overrides = false;
        if has_groups {
            let policy_json = config::embedded::embedded_policy_json();
            let loaded_policy = policy::load_policy(policy_json)?;

            let resolved =
                policy::resolve_groups(&loaded_policy, &profile.security.groups, &mut caps)?;
            needs_unlink_overrides = resolved.needs_unlink_overrides;
            debug!("Resolved {} policy groups", resolved.names.len());
        }

        // Process profile filesystem config (profile-specific paths on top of groups)
        let fs = &profile.filesystem;

        // Directories with read+write access
        for path_template in &fs.allow {
            let path = expand_vars(path_template, workdir);
            if path.exists() {
                let cap = FsCapability::new_dir(&path, AccessMode::ReadWrite)?;
                caps.add_fs(cap);
            } else {
                warn!(
                    "Profile path '{}' (expanded to '{}') does not exist, skipping",
                    path_template,
                    path.display()
                );
            }
        }

        // Directories with read-only access
        for path_template in &fs.read {
            let path = expand_vars(path_template, workdir);
            if path.exists() {
                let cap = FsCapability::new_dir(&path, AccessMode::Read)?;
                caps.add_fs(cap);
            } else {
                warn!(
                    "Profile path '{}' (expanded to '{}') does not exist, skipping",
                    path_template,
                    path.display()
                );
            }
        }

        // Directories with write-only access
        for path_template in &fs.write {
            let path = expand_vars(path_template, workdir);
            if path.exists() {
                let cap = FsCapability::new_dir(&path, AccessMode::Write)?;
                caps.add_fs(cap);
            } else {
                warn!(
                    "Profile path '{}' (expanded to '{}') does not exist, skipping",
                    path_template,
                    path.display()
                );
            }
        }

        // Single files with read+write access
        for path_template in &fs.allow_file {
            let path = expand_vars(path_template, workdir);
            if path.exists() {
                let cap = FsCapability::new_file(&path, AccessMode::ReadWrite)?;
                caps.add_fs(cap);
            } else {
                warn!(
                    "Profile file '{}' (expanded to '{}') does not exist, skipping",
                    path_template,
                    path.display()
                );
            }
        }

        // Single files with read-only access
        for path_template in &fs.read_file {
            let path = expand_vars(path_template, workdir);
            if path.exists() {
                let cap = FsCapability::new_file(&path, AccessMode::Read)?;
                caps.add_fs(cap);
            } else {
                warn!(
                    "Profile file '{}' (expanded to '{}') does not exist, skipping",
                    path_template,
                    path.display()
                );
            }
        }

        // Single files with write-only access
        for path_template in &fs.write_file {
            let path = expand_vars(path_template, workdir);
            if path.exists() {
                let cap = FsCapability::new_file(&path, AccessMode::Write)?;
                caps.add_fs(cap);
            } else {
                warn!(
                    "Profile file '{}' (expanded to '{}') does not exist, skipping",
                    path_template,
                    path.display()
                );
            }
        }

        // Network blocking from profile
        if profile.network.block {
            caps.set_network_blocked(true);
        }

        // Apply CLI overrides (CLI args take precedence)
        add_cli_overrides(&mut caps, args)?;

        // Only add legacy system paths if NO groups were specified.
        // Groups handle system paths via system_read_macos, system_write_macos, etc.
        if !has_groups {
            add_system_read_paths(&mut caps);
        }

        // Apply deferred unlink overrides now that ALL writable paths are in place
        // (groups + profile [filesystem] + CLI overrides + CWD).
        if needs_unlink_overrides {
            policy::apply_unlink_overrides(&mut caps);
        }

        // Deduplicate capabilities
        caps.deduplicate();

        Ok(caps)
    }
}

/// Apply CLI argument overrides on top of existing capabilities
fn add_cli_overrides(caps: &mut CapabilitySet, args: &SandboxArgs) -> Result<()> {
    // Additional directories from CLI
    for path in &args.allow {
        if path.exists() && !caps.path_covered(path) {
            let cap = FsCapability::new_dir(path, AccessMode::ReadWrite)?;
            caps.add_fs(cap);
        }
    }

    for path in &args.read {
        if path.exists() && !caps.path_covered(path) {
            let cap = FsCapability::new_dir(path, AccessMode::Read)?;
            caps.add_fs(cap);
        }
    }

    for path in &args.write {
        if path.exists() && !caps.path_covered(path) {
            let cap = FsCapability::new_dir(path, AccessMode::Write)?;
            caps.add_fs(cap);
        }
    }

    // Additional files from CLI
    for path in &args.allow_file {
        if path.exists() {
            let cap = FsCapability::new_file(path, AccessMode::ReadWrite)?;
            caps.add_fs(cap);
        }
    }

    for path in &args.read_file {
        if path.exists() {
            let cap = FsCapability::new_file(path, AccessMode::Read)?;
            caps.add_fs(cap);
        }
    }

    for path in &args.write_file {
        if path.exists() {
            let cap = FsCapability::new_file(path, AccessMode::Write)?;
            caps.add_fs(cap);
        }
    }

    // CLI network blocking overrides profile
    if args.net_block {
        caps.set_network_blocked(true);
    }

    // Command allow/block from CLI
    for cmd in &args.allow_command {
        caps.add_allowed_command(cmd.clone());
    }

    for cmd in &args.block_command {
        caps.add_blocked_command(cmd.clone());
    }

    Ok(())
}

/// Expand `~` prefix to the user's home directory.
fn expand_tilde(path_str: &str) -> std::path::PathBuf {
    if let Some(rest) = path_str.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    } else if path_str == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(home);
        }
    }
    std::path::PathBuf::from(path_str)
}

/// Add system read paths from security config
///
/// These are paths required for executables to run (e.g., /usr, /bin, /lib).
/// On macOS, also adds writable system paths (e.g., /tmp, /private/var/folders)
/// needed for programs to create temp files.
/// The library is a pure sandbox primitive - all policy lives in CLI.
fn add_system_read_paths(caps: &mut CapabilitySet) {
    let system_paths = config::get_system_read_paths();

    for path_str in system_paths {
        let path = expand_tilde(&path_str);
        if path.exists() && !caps.path_covered(&path) {
            match FsCapability::new_dir(&path, AccessMode::Read) {
                Ok(mut cap) => {
                    cap.source = CapabilitySource::System;
                    caps.add_fs(cap);
                }
                Err(e) => {
                    // Non-fatal: some system paths may not be directories
                    tracing::debug!("Could not add system path {}: {}", path_str, e);
                }
            }
        }
    }

    // Add macOS writable system paths (e.g., /tmp, /dev, /private/var/folders)
    // These need write access for programs to create temp files, write to /dev/null, etc.
    // NOTE: Do NOT use path_covered() here - a parent path having Read access
    // does not mean we can skip adding Write access for a child path.
    #[cfg(target_os = "macos")]
    {
        let writable_paths = config::get_system_writable_paths();
        for path_str in writable_paths {
            let path = expand_tilde(&path_str);
            if path.exists() {
                match FsCapability::new_dir(&path, AccessMode::ReadWrite) {
                    Ok(mut cap) => {
                        cap.source = CapabilitySource::System;
                        caps.add_fs(cap);
                    }
                    Err(e) => {
                        tracing::debug!("Could not add writable system path {}: {}", path_str, e);
                    }
                }
            }
        }

        // Add $TMPDIR explicitly (dynamic path, usually under /private/var/folders)
        if let Ok(tmpdir) = std::env::var("TMPDIR") {
            let path = std::path::PathBuf::from(&tmpdir);
            if path.exists() {
                match FsCapability::new_dir(&path, AccessMode::ReadWrite) {
                    Ok(mut cap) => {
                        cap.source = CapabilitySource::System;
                        caps.add_fs(cap);
                    }
                    Err(e) => {
                        tracing::debug!("Could not add TMPDIR {}: {}", tmpdir, e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_from_args_basic() {
        let dir = tempdir().expect("Failed to create temp dir");

        let args = SandboxArgs {
            allow: vec![dir.path().to_path_buf()],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.has_fs());
        assert!(!caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_network_blocked() {
        let args = SandboxArgs {
            allow: vec![],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: true,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_from_args_with_commands() {
        let args = SandboxArgs {
            allow: vec![],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec!["rm".to_string()],
            block_command: vec!["custom".to_string()],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps = CapabilitySet::from_args(&args).expect("Failed to build caps");
        assert!(caps.allowed_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"custom".to_string()));
    }

    #[test]
    fn test_from_profile_with_groups() {
        let profile = crate::profile::load_profile("claude-code", false)
            .expect("Failed to load claude-code profile");

        let workdir = tempdir().expect("Failed to create temp dir");
        let args = SandboxArgs {
            allow: vec![],
            read: vec![],
            write: vec![],
            allow_file: vec![],
            read_file: vec![],
            write_file: vec![],
            net_block: false,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: None,
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        let caps =
            CapabilitySet::from_profile(&profile, workdir.path(), &args).expect("Failed to build");

        // Groups should have populated filesystem capabilities
        assert!(caps.has_fs());

        // Deny groups should have generated platform rules
        assert!(!caps.platform_rules().is_empty());

        // Deny rules should include credential protection
        let rules = caps.platform_rules().join("\n");
        assert!(rules.contains("deny file-read-data"));
        assert!(rules.contains("deny file-write*"));

        // Unlink protection should be present
        assert!(rules.contains("deny file-write-unlink"));

        // Unlink overrides must exist for writable paths (including ~/.claude from
        // the profile [filesystem] section, which is added AFTER group resolution).
        // This verifies the deferred unlink override fix.
        assert!(
            rules.contains("allow file-write-unlink"),
            "Expected unlink overrides for writable paths, got:\n{}",
            rules
        );

        // Dangerous commands should be blocked
        assert!(caps.blocked_commands().contains(&"rm".to_string()));
        assert!(caps.blocked_commands().contains(&"dd".to_string()));
    }
}
