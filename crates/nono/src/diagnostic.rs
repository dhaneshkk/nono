//! Diagnostic output formatter for sandbox policy.
//!
//! This module provides human and agent-readable diagnostic output
//! when sandboxed commands fail. The output helps identify whether
//! the failure was due to sandbox restrictions.
//!
//! # Design Principles
//!
//! - **Unmistakable prefix**: All lines start with `[nono]` so agents
//!   immediately recognize the source
//! - **May vs was**: Phrased as "may be due to" not "was caused by"
//!   because the non-zero exit could be unrelated to the sandbox
//! - **Actionable**: Provides specific flags to grant additional access
//! - **Mode-aware**: Different guidance for supervised vs standard mode
//! - **Library code**: No process management, no CLI assumptions

use crate::capability::{AccessMode, CapabilitySet, CapabilitySource};
use std::path::PathBuf;

/// Why a path access was denied during a supervised session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Path is permanently blocked by security policy (never_grant)
    PolicyBlocked,
    /// User declined the interactive approval prompt
    UserDenied,
    /// Request was rate limited (too many requests)
    RateLimited,
    /// Approval backend returned an error
    BackendError,
}

/// Record of a denied access attempt during a supervised session.
#[derive(Debug, Clone)]
pub struct DenialRecord {
    /// The path that was denied
    pub path: PathBuf,
    /// Access mode requested
    pub access: AccessMode,
    /// Why it was denied
    pub reason: DenialReason,
}

/// Execution mode for diagnostic context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticMode {
    /// Standard mode: suggest --allow flags for re-run
    Standard,
    /// Supervised mode: interactive expansion available, show denials
    Supervised,
}

/// Formats diagnostic information about sandbox policy.
///
/// This is library code that can be used by any parent process
/// that wants to explain sandbox denials to users or AI agents.
pub struct DiagnosticFormatter<'a> {
    caps: &'a CapabilitySet,
    mode: DiagnosticMode,
    denials: &'a [DenialRecord],
}

impl<'a> DiagnosticFormatter<'a> {
    /// Create a new formatter for the given capability set.
    #[must_use]
    pub fn new(caps: &'a CapabilitySet) -> Self {
        Self {
            caps,
            mode: DiagnosticMode::Standard,
            denials: &[],
        }
    }

    /// Set the diagnostic mode (standard or supervised).
    #[must_use]
    pub fn with_mode(mut self, mode: DiagnosticMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add denial records from a supervised session.
    #[must_use]
    pub fn with_denials(mut self, denials: &'a [DenialRecord]) -> Self {
        self.denials = denials;
        self
    }

    /// Format the diagnostic footer for a failed command.
    ///
    /// Returns a multi-line string with `[nono]` prefix on each line.
    /// The output is designed to be printed to stderr.
    #[must_use]
    pub fn format_footer(&self, exit_code: i32) -> String {
        match self.mode {
            DiagnosticMode::Standard => self.format_standard_footer(exit_code),
            DiagnosticMode::Supervised => self.format_supervised_footer(exit_code),
        }
    }

    /// Standard mode footer: concise policy summary with --allow suggestions.
    fn format_standard_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "[nono] Command exited with code {}. This may be due to sandbox restrictions.",
            exit_code
        ));
        lines.push("[nono]".to_string());

        // Concise policy summary: show user paths, summarize system/group paths
        lines.push("[nono] Sandbox policy:".to_string());
        self.format_allowed_paths_concise(&mut lines);
        self.format_network_status(&mut lines);

        // Help section
        lines.push("[nono]".to_string());
        lines.push("[nono] To grant additional access, re-run with:".to_string());
        lines.push("[nono]   --allow <path>     read+write access to directory".to_string());
        lines.push("[nono]   --read <path>      read-only access to directory".to_string());
        lines.push("[nono]   --write <path>     write-only access to directory".to_string());

        if self.caps.is_network_blocked() {
            lines.push(
                "[nono]   --allow-net        network access (remove --net-block)".to_string(),
            );
        }

        lines.join("\n")
    }

    /// Supervised mode footer: show denials and mode-specific guidance.
    fn format_supervised_footer(&self, exit_code: i32) -> String {
        let mut lines = Vec::new();

        lines.push(format!(
            "[nono] Command exited with code {}. This may be due to sandbox restrictions.",
            exit_code
        ));
        lines.push("[nono]".to_string());

        if self.denials.is_empty() {
            // No denials recorded -- failure might be unrelated
            lines.push("[nono] No access requests were denied during this session.".to_string());
            lines.push("[nono] The failure may be unrelated to sandbox restrictions.".to_string());
        } else {
            // Show denied paths grouped by reason
            let policy_blocked: Vec<_> = self
                .denials
                .iter()
                .filter(|d| d.reason == DenialReason::PolicyBlocked)
                .collect();
            let user_denied: Vec<_> = self
                .denials
                .iter()
                .filter(|d| d.reason == DenialReason::UserDenied)
                .collect();
            let other_denied: Vec<_> = self
                .denials
                .iter()
                .filter(|d| {
                    d.reason != DenialReason::PolicyBlocked && d.reason != DenialReason::UserDenied
                })
                .collect();

            lines.push("[nono] Denied paths during this session:".to_string());

            // Deduplicate paths within each category (same path may be attempted
            // multiple times)
            if !policy_blocked.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for d in &policy_blocked {
                    if seen.insert(&d.path) {
                        lines.push(format!(
                            "[nono]   {} ({}) - permanently restricted by security policy",
                            d.path.display(),
                            access_str(d.access),
                        ));
                    }
                }
            }
            if !user_denied.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for d in &user_denied {
                    if seen.insert(&d.path) {
                        lines.push(format!(
                            "[nono]   {} ({}) - access declined by user",
                            d.path.display(),
                            access_str(d.access),
                        ));
                    }
                }
            }
            if !other_denied.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for d in &other_denied {
                    if seen.insert(&d.path) {
                        lines.push(format!(
                            "[nono]   {} ({}) - denied",
                            d.path.display(),
                            access_str(d.access),
                        ));
                    }
                }
            }
        }

        // Supervised-mode guidance
        lines.push("[nono]".to_string());
        let has_policy_blocked = self
            .denials
            .iter()
            .any(|d| d.reason == DenialReason::PolicyBlocked);
        let has_user_denied = self
            .denials
            .iter()
            .any(|d| d.reason == DenialReason::UserDenied);

        if has_policy_blocked && !has_user_denied {
            lines.push(
                "[nono] Some paths are permanently restricted and cannot be granted.".to_string(),
            );
        } else if has_user_denied && !has_policy_blocked {
            lines.push(
                "[nono] Re-run the command and approve the access prompt to grant access."
                    .to_string(),
            );
        } else if has_policy_blocked && has_user_denied {
            lines.push(
                "[nono] Some paths are permanently restricted. Others can be granted by approving the prompt."
                    .to_string(),
            );
        }

        lines.join("\n")
    }

    /// Format allowed paths concisely: show user/profile paths explicitly,
    /// summarize group/system paths with a count.
    fn format_allowed_paths_concise(&self, lines: &mut Vec<String>) {
        let caps = self.caps.fs_capabilities();
        if caps.is_empty() {
            lines.push("[nono]   Allowed paths: (none)".to_string());
            return;
        }

        let mut user_paths = Vec::new();
        let mut group_count: usize = 0;

        for cap in caps {
            match &cap.source {
                CapabilitySource::User | CapabilitySource::Profile => {
                    let kind = if cap.is_file { "file" } else { "dir" };
                    user_paths.push(format!(
                        "[nono]     {} ({}, {})",
                        cap.resolved.display(),
                        access_str(cap.access),
                        kind,
                    ));
                }
                CapabilitySource::Group(_) | CapabilitySource::System => {
                    group_count += 1;
                }
            }
        }

        if user_paths.is_empty() && group_count == 0 {
            lines.push("[nono]   Allowed paths: (none)".to_string());
        } else {
            lines.push("[nono]   Allowed paths:".to_string());
            for p in &user_paths {
                lines.push(p.clone());
            }
            if group_count > 0 {
                lines.push(format!(
                    "[nono]     + {} system/profile path(s)",
                    group_count
                ));
            }
        }
    }

    /// Format the network status.
    fn format_network_status(&self, lines: &mut Vec<String>) {
        if self.caps.is_network_blocked() {
            lines.push("[nono]   Network: blocked".to_string());
        } else {
            lines.push("[nono]   Network: allowed".to_string());
        }
    }

    /// Format a concise single-line summary of the policy.
    ///
    /// Useful for logging or brief status messages.
    #[must_use]
    pub fn format_summary(&self) -> String {
        let path_count = self.caps.fs_capabilities().len();
        let network_status = if self.caps.is_network_blocked() {
            "blocked"
        } else {
            "allowed"
        };

        format!(
            "[nono] Policy: {} path(s), network {}",
            path_count, network_status
        )
    }
}

fn access_str(access: AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read",
        AccessMode::Write => "write",
        AccessMode::ReadWrite => "read+write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};

    fn make_test_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps
    }

    fn make_mixed_caps() -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/home/user/project"),
            resolved: PathBuf::from("/home/user/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/bin"),
            resolved: PathBuf::from("/usr/bin"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("base_read".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/usr/lib"),
            resolved: PathBuf::from("/usr/lib"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("base_read".to_string()),
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/tmp"),
            resolved: PathBuf::from("/tmp"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::System,
        });
        caps
    }

    // --- Standard mode tests ---

    #[test]
    fn test_standard_footer_contains_exit_code() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("exited with code 1"));
    }

    #[test]
    fn test_standard_footer_uses_may_not_was() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("may be due to"));
        assert!(!output.contains("was caused by"));
    }

    #[test]
    fn test_standard_footer_has_nono_prefix() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        for line in output.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("[nono]"), "Line missing prefix: {}", line);
            }
        }
    }

    #[test]
    fn test_standard_footer_shows_user_paths() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("/test/project"));
        assert!(output.contains("read+write"));
    }

    #[test]
    fn test_standard_footer_summarizes_group_paths() {
        let caps = make_mixed_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        // User path shown explicitly
        assert!(output.contains("/home/user/project"));
        // Group/system paths summarized, not listed individually
        assert!(output.contains("3 system/profile path(s)"));
        assert!(!output.contains("/usr/bin"));
        assert!(!output.contains("/usr/lib"));
    }

    #[test]
    fn test_standard_footer_shows_network_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: blocked"));
    }

    #[test]
    fn test_standard_footer_shows_network_allowed() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("Network: allowed"));
    }

    #[test]
    fn test_standard_footer_shows_help() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow <path>"));
        assert!(output.contains("--read <path>"));
        assert!(output.contains("--write <path>"));
    }

    #[test]
    fn test_standard_footer_shows_network_help_when_blocked() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("--allow-net"));
    }

    #[test]
    fn test_standard_footer_no_network_help_when_allowed() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/project"),
            resolved: PathBuf::from("/test/project"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(!output.contains("--allow-net"));
    }

    #[test]
    fn test_standard_footer_empty_caps() {
        let caps = CapabilitySet::new();
        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("(none)"));
    }

    #[test]
    fn test_standard_footer_file_vs_dir() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/file.txt"),
            resolved: PathBuf::from("/test/file.txt"),
            access: AccessMode::Read,
            is_file: true,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test/dir"),
            resolved: PathBuf::from("/test/dir"),
            access: AccessMode::Write,
            is_file: false,
            source: CapabilitySource::User,
        });

        let formatter = DiagnosticFormatter::new(&caps);
        let output = formatter.format_footer(1);

        assert!(output.contains("file.txt (read, file)"));
        assert!(output.contains("dir (write, dir)"));
    }

    #[test]
    fn test_format_summary() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps);
        let summary = formatter.format_summary();

        assert!(summary.contains("1 path(s)"));
        assert!(summary.contains("network blocked"));
    }

    // --- Supervised mode tests ---

    #[test]
    fn test_supervised_no_denials() {
        let caps = make_test_caps();
        let formatter = DiagnosticFormatter::new(&caps).with_mode(DiagnosticMode::Supervised);
        let output = formatter.format_footer(1);

        assert!(output.contains("No access requests were denied"));
        assert!(output.contains("may be unrelated"));
        // Should NOT suggest --allow re-run
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_policy_blocked_denial() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/etc/shadow"));
        assert!(output.contains("permanently restricted"));
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_user_denied() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/home/user/secret.txt"),
            access: AccessMode::Read,
            reason: DenialReason::UserDenied,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/home/user/secret.txt"));
        assert!(output.contains("declined by user"));
        assert!(output.contains("Re-run the command and approve"));
        assert!(!output.contains("--allow <path>"));
    }

    #[test]
    fn test_supervised_mixed_denials() {
        let caps = make_test_caps();
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
            DenialRecord {
                path: PathBuf::from("/home/user/data.txt"),
                access: AccessMode::Read,
                reason: DenialReason::UserDenied,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/etc/shadow"));
        assert!(output.contains("/home/user/data.txt"));
        assert!(output.contains("permanently restricted"));
        assert!(output.contains("approving the prompt"));
    }

    #[test]
    fn test_supervised_deduplicates_paths() {
        let caps = make_test_caps();
        let denials = vec![
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
            DenialRecord {
                path: PathBuf::from("/etc/shadow"),
                access: AccessMode::Read,
                reason: DenialReason::PolicyBlocked,
            },
        ];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        // Should only appear once
        let count = output.matches("/etc/shadow").count();
        assert_eq!(count, 1, "Path should be deduplicated");
    }

    #[test]
    fn test_supervised_has_nono_prefix() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/etc/shadow"),
            access: AccessMode::Read,
            reason: DenialReason::PolicyBlocked,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        for line in output.lines() {
            if !line.is_empty() {
                assert!(line.starts_with("[nono]"), "Line missing prefix: {}", line);
            }
        }
    }

    #[test]
    fn test_supervised_rate_limited_denial() {
        let caps = make_test_caps();
        let denials = vec![DenialRecord {
            path: PathBuf::from("/tmp/flood"),
            access: AccessMode::Read,
            reason: DenialReason::RateLimited,
        }];
        let formatter = DiagnosticFormatter::new(&caps)
            .with_mode(DiagnosticMode::Supervised)
            .with_denials(&denials);
        let output = formatter.format_footer(1);

        assert!(output.contains("/tmp/flood"));
        assert!(output.contains("denied"));
    }
}
