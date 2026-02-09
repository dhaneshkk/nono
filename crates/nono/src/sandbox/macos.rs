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
        let path = cap.resolved.as_path();
        let mut current = path.parent();

        // Walk up the directory tree, collecting each parent
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

    parents
}

/// Escape a path for use in Seatbelt profile strings.
///
/// Paths are placed inside double-quoted S-expression strings where `\` and `"`
/// are the significant characters. Control characters are stripped since they
/// cannot appear in valid filesystem paths and could disrupt profile parsing.
fn escape_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' | '\r' | '\0' => {}
            _ => result.push(c),
        }
    }
    result
}

/// Generate a Seatbelt profile from capabilities
///
/// This is a pure primitive - it generates rules ONLY for paths in the CapabilitySet.
/// The caller must include all necessary paths (system paths, temp dirs, etc.).
fn generate_profile(caps: &CapabilitySet) -> String {
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
    profile.push_str("(allow mach*)\n");
    profile.push_str("(allow ipc*)\n");
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
            let escaped_path = escape_path(&cap.resolved.display().to_string());
            let path_filter = if cap.is_file {
                format!("literal \"{}\"", escaped_path)
            } else {
                format!("subpath \"{}\"", escaped_path)
            };
            profile.push_str(&format!("(allow file-map-executable ({}))\n", path_filter));
        }
    }

    // Allow file ioctl for TTY
    profile.push_str("(allow file-ioctl)\n");

    // Allow pseudo-terminal operations
    profile.push_str("(allow pseudo-tty)\n");

    // Add read rules for all capabilities with Read or ReadWrite access
    for cap in caps.fs_capabilities() {
        let escaped_path = escape_path(&cap.resolved.display().to_string());

        let path_filter = if cap.is_file {
            format!("literal \"{}\"", escaped_path)
        } else {
            format!("subpath \"{}\"", escaped_path)
        };

        match cap.access {
            AccessMode::Read | AccessMode::ReadWrite => {
                profile.push_str(&format!("(allow file-read* ({}))\n", path_filter));
            }
            AccessMode::Write => {
                // Write-only doesn't need read access
            }
        }
    }

    // Add write rules for all capabilities with Write or ReadWrite access
    for cap in caps.fs_capabilities() {
        let escaped_path = escape_path(&cap.resolved.display().to_string());

        let path_filter = if cap.is_file {
            format!("literal \"{}\"", escaped_path)
        } else {
            format!("subpath \"{}\"", escaped_path)
        };

        match cap.access {
            AccessMode::Write | AccessMode::ReadWrite => {
                profile.push_str(&format!("(allow file-write* ({}))\n", path_filter));
            }
            AccessMode::Read => {
                // Read-only doesn't need write access
            }
        }
    }

    // Platform-specific rules injected verbatim by the caller (e.g., deny rules from groups)
    for rule in caps.platform_rules() {
        profile.push_str(rule);
        profile.push('\n');
    }

    // Network rules
    if caps.is_network_blocked() {
        profile.push_str("(deny network*)\n");
    } else {
        profile.push_str("(allow network-outbound)\n");
        profile.push_str("(allow network-inbound)\n");
        profile.push_str("(allow network-bind)\n");
    }

    profile
}

/// Apply Seatbelt sandbox with the given capabilities
///
/// This is a pure primitive - it applies ONLY the capabilities provided.
/// The caller is responsible for including all necessary paths.
pub fn apply(caps: &CapabilitySet) -> Result<()> {
    let profile = generate_profile(caps);

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
        let profile = generate_profile(&caps);

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

        let profile = generate_profile(&caps);

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

        let profile = generate_profile(&caps);

        assert!(profile.contains("file-write*"));
        assert!(profile.contains("literal \"/test.txt\""));
        // Write-only paths must NOT get file-map-executable
        assert!(!profile.contains("file-map-executable"));
    }

    #[test]
    fn test_generate_profile_no_global_file_map_executable() {
        let caps = CapabilitySet::default();
        let profile = generate_profile(&caps);

        // Must not contain a global (unrestricted) file-map-executable
        assert!(!profile.contains("(allow file-map-executable)\n"));
    }

    #[test]
    fn test_generate_profile_network_blocked() {
        let caps = CapabilitySet::new().block_network();

        let profile = generate_profile(&caps);

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
    }

    #[test]
    fn test_generate_profile_with_platform_rules() {
        let mut caps = CapabilitySet::new();
        caps.add_platform_rule("(deny file-read-data (subpath \"/private/var/db\"))");
        caps.add_platform_rule("(deny file-write-unlink)");

        let profile = generate_profile(&caps);

        assert!(profile.contains("(deny file-read-data (subpath \"/private/var/db\"))"));
        assert!(profile.contains("(deny file-write-unlink)"));
        // Platform rules should appear before network rules
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
    fn test_generate_profile_platform_rules_empty() {
        let caps = CapabilitySet::new();
        let profile = generate_profile(&caps);

        // Should still generate a valid profile without platform rules
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
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
        let profile = generate_profile(&caps);
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
    }
}
