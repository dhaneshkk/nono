//! macOS sandbox implementation using Seatbelt
//!
//! This is a pure sandboxing primitive - it applies ONLY the capabilities provided.
//! The caller is responsible for:
//! - Adding system paths (e.g., /usr, /lib, /System/Library) if executables need to run
//! - Implementing any security policy (sensitive path blocking, etc.)

use crate::capability::{AccessMode, CapabilitySet};
use crate::error::{NonoError, Result};
use crate::sandbox::SupportInfo;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use tracing::{debug, info};

// FFI bindings to macOS sandbox API
// These are private APIs but have been stable for years
// Reference: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Check if Seatbelt sandboxing is supported
pub fn is_supported() -> bool {
    // Seatbelt is available on all modern macOS versions
    true
}

/// Get information about sandbox support
pub fn support_info() -> SupportInfo {
    SupportInfo {
        is_supported: true,
        platform: "macos",
        details: "macOS Seatbelt sandbox available".to_string(),
    }
}

/// Collect parent directories that need metadata access for path resolution.
///
/// Programs need to lstat() each path component when resolving paths.
/// For example, to access /Users/luke/.claude, Node.js needs to lstat:
/// - /Users
/// - /Users/luke
///
/// This function returns those parent directories so we can allow metadata
/// (but not data) access to them.
fn collect_parent_dirs(caps: &CapabilitySet) -> std::collections::HashSet<String> {
    let mut parents = std::collections::HashSet::new();

    for cap in caps.fs_capabilities() {
        // Collect parents for both resolved and original paths.
        // On macOS, /tmp is a symlink to /private/tmp. If the user passes
        // --allow /tmp, we need metadata access to / for the symlink itself.
        // The original path's parents handle this.
        let paths_to_walk: Vec<&std::path::Path> = if cap.original != cap.resolved {
            vec![cap.resolved.as_path(), cap.original.as_path()]
        } else {
            vec![cap.resolved.as_path()]
        };

        for path in paths_to_walk {
            let mut current = path.parent();
            while let Some(parent) = current {
                let parent_str = parent.to_string_lossy().to_string();

                // Stop at root
                if parent_str == "/" || parent_str.is_empty() {
                    break;
                }

                // If already present, ancestors were processed too - early exit
                if !parents.insert(parent_str) {
                    break;
                }
                current = parent.parent();
            }
        }
    }

    parents
}

/// Build Seatbelt path filters for a capability.
///
/// On macOS, symlinks like `/tmp` -> `/private/tmp` mean the user's original
/// path may differ from the canonicalized resolved path. Seatbelt operates on
/// literal paths, not resolved symlinks, so we must emit rules for both.
/// Returns one or two `(subpath "...")` or `(literal "...")` strings.
fn path_filters_for_cap(cap: &crate::capability::FsCapability) -> Result<Vec<String>> {
    let mut filters = Vec::with_capacity(2);

    let resolved_str = cap.resolved.to_str().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "path contains non-UTF-8 bytes: {}",
            cap.resolved.display()
        ))
    })?;
    let escaped_resolved = escape_path(resolved_str);
    let kind = if cap.is_file { "literal" } else { "subpath" };
    filters.push(format!("{} \"{}\"", kind, escaped_resolved));

    // If the original path differs (e.g. /tmp vs /private/tmp), emit a rule
    // for the original too so Seatbelt allows traversing the symlink.
    if cap.original != cap.resolved {
        if let Some(original_str) = cap.original.to_str() {
            let escaped_original = escape_path(original_str);
            filters.push(format!("{} \"{}\"", kind, escaped_original));
        }
    }

    Ok(filters)
}

/// Escape a path for use in Seatbelt profile strings.
///
/// Paths are placed inside double-quoted S-expression strings where `\` and `"`
/// are the significant characters. All control characters (0x00-0x1F, 0x7F, and
/// Unicode control chars) are stripped since they cannot appear in valid filesystem
/// paths and could disrupt Seatbelt's S-expression parser.
fn escape_path(path: &str) -> String {
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

/// Generate a Seatbelt profile from capabilities
///
/// This is a pure primitive - it generates rules ONLY for paths in the CapabilitySet.
/// The caller must include all necessary paths (system paths, temp dirs, etc.).
///
/// Returns an error if any path contains non-UTF-8 bytes (which would produce
/// incorrect Seatbelt rules via lossy conversion).
fn generate_profile(caps: &CapabilitySet) -> Result<String> {
    let mut profile = String::new();

    // Profile version
    profile.push_str("(version 1)\n");

    // Start with deny default
    profile.push_str("(deny default)\n");

    // Allow specific process operations needed for execution
    profile.push_str("(allow process-exec*)\n");
    profile.push_str("(allow process-fork)\n");

    // Process info: allow self-inspection, deny inspecting others
    profile.push_str("(allow process-info* (target self))\n");
    profile.push_str("(deny process-info* (target others))\n");

    // Allow specific system operations
    profile.push_str("(allow sysctl-read)\n");

    // Mach IPC: allow only service resolution and identity, deny privileged ops
    profile.push_str("(allow mach-lookup)\n");
    profile.push_str("(allow mach-per-user-lookup)\n");
    profile.push_str("(allow mach-task-name)\n");
    profile.push_str("(deny mach-priv*)\n");

    // IPC: allow only POSIX shared memory operations
    profile.push_str("(allow ipc-posix-shm-read-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-data)\n");
    profile.push_str("(allow ipc-posix-shm-write-create)\n");

    profile.push_str("(allow signal)\n");
    profile.push_str("(allow system-socket)\n");
    profile.push_str("(allow system-fsctl)\n");
    profile.push_str("(allow system-info)\n");

    // Allow reading the root directory entry itself (required for exec path resolution)
    profile.push_str("(allow file-read* (literal \"/\"))\n");

    // Allow metadata access to parent directories of granted paths (for path resolution)
    let parent_dirs = collect_parent_dirs(caps);
    for parent in &parent_dirs {
        let escaped = escape_path(parent);
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            escaped
        ));
    }

    // Allow mapping executables into memory, restricted to readable paths.
    // This prevents loading arbitrary shared libraries via DYLD_INSERT_LIBRARIES
    // from paths outside the sandbox's read set.
    for cap in caps.fs_capabilities() {
        if matches!(cap.access, AccessMode::Read | AccessMode::ReadWrite) {
            for filter in path_filters_for_cap(cap)? {
                profile.push_str(&format!("(allow file-map-executable ({}))\n", filter));
            }
        }
    }

    // Allow file ioctl restricted to TTY/PTY devices and granted paths
    profile.push_str("(allow file-ioctl (literal \"/dev/tty\"))\n");
    profile.push_str("(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\"))\n");
    profile.push_str("(allow file-ioctl (regex #\"^/dev/pty[a-z][0-9a-f]+$\"))\n");
    // Also allow ioctl on explicitly granted paths (for interactive programs)
    for cap in caps.fs_capabilities() {
        for filter in path_filters_for_cap(cap)? {
            profile.push_str(&format!("(allow file-ioctl ({}))\n", filter));
        }
    }

    // Allow pseudo-terminal operations
    profile.push_str("(allow pseudo-tty)\n");

    // Add read rules for all capabilities with Read or ReadWrite access.
    // Emits rules for both original and resolved paths when they differ
    // (e.g. /tmp vs /private/tmp) so Seatbelt allows traversing symlinks.
    for cap in caps.fs_capabilities() {
        match cap.access {
            AccessMode::Read | AccessMode::ReadWrite => {
                for filter in path_filters_for_cap(cap)? {
                    profile.push_str(&format!("(allow file-read* ({}))\n", filter));
                }
            }
            AccessMode::Write => {
                // Write-only doesn't need read access
            }
        }
    }

    // SECURITY: Platform deny rules are placed BETWEEN read and write rules.
    // This matches the research CLI pattern where sensitive path denials come
    // after read allows but before write allows. In Seatbelt, more specific rules
    // always win regardless of order; for equal specificity, last-match wins.
    // Placing deny rules here ensures they override read allows when equally specific,
    // while write allows below can still override deny-unlink for user-granted paths.
    for rule in caps.platform_rules() {
        profile.push_str(rule);
        profile.push('\n');
    }

    // Add write rules for all capabilities with Write or ReadWrite access.
    // These come AFTER platform deny rules so user-granted write paths can
    // override global denials like (deny file-write-unlink).
    // Emits rules for both original and resolved paths when they differ.
    for cap in caps.fs_capabilities() {
        match cap.access {
            AccessMode::Write | AccessMode::ReadWrite => {
                for filter in path_filters_for_cap(cap)? {
                    profile.push_str(&format!("(allow file-write* ({}))\n", filter));
                }
            }
            AccessMode::Read => {
                // Read-only doesn't need write access
            }
        }
    }

    // Network rules
    if caps.is_network_blocked() {
        profile.push_str("(deny network*)\n");
    } else {
        profile.push_str("(allow network-outbound)\n");
        profile.push_str("(allow network-inbound)\n");
        profile.push_str("(allow network-bind)\n");
    }

    Ok(profile)
}

/// Apply Seatbelt sandbox with the given capabilities
///
/// This is a pure primitive - it applies ONLY the capabilities provided.
/// The caller is responsible for including all necessary paths.
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    let profile = generate_profile(caps)?;

    debug!("Generated Seatbelt profile:\n{}", profile);

    let profile_cstr = CString::new(profile)
        .map_err(|e| NonoError::SandboxInit(format!("Invalid profile string: {}", e)))?;

    let mut error_buf: *mut c_char = ptr::null_mut();

    // SAFETY: sandbox_init is a stable macOS API. We pass:
    // - A valid null-terminated C string for the profile
    // - 0 for raw profile mode (not a named profile)
    // - A pointer to receive any error message
    let result = unsafe {
        sandbox_init(
            profile_cstr.as_ptr(),
            0, // Raw profile mode
            &mut error_buf,
        )
    };

    if result != 0 {
        let error_msg = if !error_buf.is_null() {
            // SAFETY: sandbox_init sets error_buf to a valid C string on error
            let msg = unsafe {
                std::ffi::CStr::from_ptr(error_buf)
                    .to_string_lossy()
                    .into_owned()
            };
            // SAFETY: sandbox_free_error expects a pointer from sandbox_init
            unsafe { sandbox_free_error(error_buf) };
            msg
        } else {
            format!("sandbox_init returned error code {}", result)
        };

        return Err(NonoError::SandboxInit(error_msg));
    }

    info!("Seatbelt sandbox applied successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};
    use std::path::PathBuf;

    #[test]
    fn test_generate_profile_empty() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        // Network is allowed by default
        assert!(profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_generate_profile_with_dir() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(allow file-read* (subpath \"/test\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/test\"))"));
        assert!(profile.contains("(allow file-map-executable (subpath \"/test\"))"));
    }

    #[test]
    fn test_generate_profile_with_file() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test.txt"),
            resolved: PathBuf::from("/test.txt"),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("file-write*"));
        assert!(profile.contains("literal \"/test.txt\""));
        // Write-only paths must NOT get file-map-executable
        assert!(!profile.contains("file-map-executable"));
    }

    #[test]
    fn test_generate_profile_no_global_file_map_executable() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps).unwrap();

        // Must not contain a global (unrestricted) file-map-executable
        assert!(!profile.contains("(allow file-map-executable)\n"));
    }

    #[test]
    fn test_generate_profile_network_blocked() {
        let caps = CapabilitySet::new().block_network();

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(!profile.contains("(allow network-outbound)"));
    }

    #[test]
    fn test_support_info() {
        let info = support_info();
        assert!(info.is_supported);
        assert_eq!(info.platform, "macos");
    }

    #[test]
    fn test_collect_parent_dirs() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/Users/test/.claude"),
            resolved: PathBuf::from("/Users/test/.claude"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let parents = collect_parent_dirs(&caps);

        assert!(parents.contains("/Users"));
        assert!(parents.contains("/Users/test"));
        assert!(!parents.contains("/"));
    }

    #[test]
    fn test_escape_path() {
        assert_eq!(escape_path("/simple/path"), "/simple/path");
        assert_eq!(escape_path("/path with\\slash"), "/path with\\\\slash");
        assert_eq!(escape_path("/path\"quoted"), "/path\\\"quoted");
        assert_eq!(escape_path("/path\nwith\nnewlines"), "/pathwithnewlines");
        assert_eq!(escape_path("/path\rwith\rreturns"), "/pathwithreturns");
        assert_eq!(escape_path("/path\0with\0nulls"), "/pathwithnulls");
        // All control characters must be stripped
        assert_eq!(escape_path("/path\twith\ttabs"), "/pathwithtabs");
        assert_eq!(escape_path("/path\x0bwith\x0cfeeds"), "/pathwithfeeds");
        assert_eq!(escape_path("/path\x1bwith\x1bescape"), "/pathwithescape");
        assert_eq!(escape_path("/path\x7fwith\x7fdel"), "/pathwithdel");
    }

    #[test]
    fn test_generate_profile_with_platform_rules() {
        let mut caps = CapabilitySet::new();
        caps.add_platform_rule("(deny file-read-data (subpath \"/private/var/db\"))")
            .unwrap();
        caps.add_platform_rule("(deny file-write-unlink)").unwrap();

        let profile = generate_profile(&caps).unwrap();

        assert!(profile.contains("(deny file-read-data (subpath \"/private/var/db\"))"));
        assert!(profile.contains("(deny file-write-unlink)"));
        // Platform deny rules should appear before network rules
        let platform_pos = profile
            .find("(deny file-write-unlink)")
            .expect("platform rule not found");
        let network_pos = profile
            .find("(allow network-outbound)")
            .expect("network rule not found");
        assert!(
            platform_pos < network_pos,
            "platform rules must appear before network rules"
        );
    }

    #[test]
    fn test_generate_profile_platform_rules_between_reads_and_writes() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_platform_rule("(deny file-write-unlink)").unwrap();

        let profile = generate_profile(&caps).unwrap();

        let read_pos = profile
            .find("(allow file-read* (subpath \"/test\"))")
            .expect("read rule not found");
        let deny_pos = profile
            .find("(deny file-write-unlink)")
            .expect("deny rule not found");
        let write_pos = profile
            .find("(allow file-write* (subpath \"/test\"))")
            .expect("write rule not found");

        // Order: read rules -> platform deny rules -> write rules
        assert!(
            read_pos < deny_pos,
            "read rules must come before platform deny rules"
        );
        assert!(
            deny_pos < write_pos,
            "platform deny rules must come before write rules"
        );
    }

    #[test]
    fn test_generate_profile_platform_rules_empty() {
        let caps = CapabilitySet::new();
        let profile = generate_profile(&caps).unwrap();

        // Should still generate a valid profile without platform rules
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_escape_path_injection_via_newline() {
        // An attacker embeds a newline to break out of the quoted string and inject
        // a new S-expression: "/tmp/evil\n(allow file-read* (subpath \"/\"))"
        // Without newline stripping, this would become a standalone rule line.
        let malicious = "/tmp/evil\n(allow file-read* (subpath \"/\"))";
        let escaped = escape_path(malicious);
        assert!(
            !escaped.contains('\n'),
            "escaped path must not contain newlines"
        );
        // With newlines stripped, the S-expression text stays inside the quoted string
        // where parentheses are harmless literal characters.
    }

    #[test]
    fn test_escape_path_injection_via_quote() {
        // An attacker embeds a double-quote to terminate the string early and inject
        // a new rule: /tmp/evil")(allow file-read* (subpath "/"))("
        let malicious = "/tmp/evil\")(allow file-read* (subpath \"/\"))(\"";
        let escaped = escape_path(malicious);
        // Every " in the escaped output must be preceded by \ so Seatbelt
        // treats it as a literal quote inside the string, not a terminator.
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

    #[test]
    fn test_generate_profile_malicious_path_no_injection() {
        let mut caps = CapabilitySet::new();
        // A path with embedded newline + Seatbelt injection attempt
        caps.add_fs(FsCapability {
            original: PathBuf::from("/tmp/evil"),
            resolved: PathBuf::from("/tmp/evil\n(allow file-read* (subpath \"/\"))"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });

        let profile = generate_profile(&caps).unwrap();

        // The profile must NOT contain the injected rule as a standalone line
        for line in profile.lines() {
            if line.contains("(allow file-read*") {
                // Legitimate read rules contain subpath or literal for the path
                assert!(
                    !line.contains("(subpath \"/\")"),
                    "injected root-read rule must not appear: {}",
                    line
                );
            }
        }
    }

    #[test]
    fn test_capability_source_tagging() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr"),
            resolved: PathBuf::from("/usr"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("system_read_macos".to_string()),
        });

        // Group-sourced capabilities should generate the same profile rules
        let profile = generate_profile(&caps).unwrap();
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
    }
}
