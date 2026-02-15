//! Terminal-based interactive approval backend for supervisor IPC
//!
//! Prompts the user at the terminal when the sandboxed child requests
//! additional filesystem access. This is the default approval backend
//! for `nono run --supervised`.

use nono::{AccessMode, ApprovalBackend, ApprovalDecision, CapabilityRequest, NonoError, Result};
use std::io::{BufRead, IsTerminal, Write};

/// Interactive terminal approval backend.
///
/// Prints capability expansion requests to stderr and reads the user's
/// response from `/dev/tty` (not stdin, which belongs to the sandboxed child).
///
/// Returns `Denied` automatically if no terminal is available.
pub struct TerminalApproval;

impl ApprovalBackend for TerminalApproval {
    fn request_capability(&self, request: &CapabilityRequest) -> Result<ApprovalDecision> {
        let stderr = std::io::stderr();
        if !stderr.is_terminal() {
            return Ok(ApprovalDecision::Denied {
                reason: "No terminal available for interactive approval".to_string(),
            });
        }

        // Display the request
        eprintln!();
        eprintln!("[nono] The sandboxed process is requesting additional access:");
        eprintln!("[nono]   Path:   {}", request.path.display());
        eprintln!("[nono]   Access: {}", format_access_mode(&request.access));
        if let Some(ref reason) = request.reason {
            eprintln!("[nono]   Reason: {}", reason);
        }
        eprintln!("[nono]");
        eprint!("[nono] Grant access? [y/N] ");
        let _ = std::io::stderr().flush();

        // Read from /dev/tty, not stdin (which belongs to the sandboxed child)
        let tty = std::fs::File::open("/dev/tty").map_err(|e| {
            NonoError::SandboxInit(format!("Failed to open /dev/tty for approval prompt: {e}"))
        })?;
        let mut reader = std::io::BufReader::new(tty);
        let mut input = String::new();
        reader.read_line(&mut input).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to read approval response: {e}"))
        })?;

        let input = input.trim().to_lowercase();
        if input == "y" || input == "yes" {
            eprintln!("[nono] Access granted.");
            Ok(ApprovalDecision::Granted)
        } else {
            eprintln!("[nono] Access denied.");
            Ok(ApprovalDecision::Denied {
                reason: "User denied the request".to_string(),
            })
        }
    }

    fn backend_name(&self) -> &str {
        "terminal"
    }
}

/// Format an access mode for human-readable display.
fn format_access_mode(access: &AccessMode) -> &'static str {
    match access {
        AccessMode::Read => "read-only",
        AccessMode::Write => "write-only",
        AccessMode::ReadWrite => "read+write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_approval_backend_name() {
        let backend = TerminalApproval;
        assert_eq!(backend.backend_name(), "terminal");
    }

    #[test]
    fn test_format_access_mode() {
        assert_eq!(format_access_mode(&AccessMode::Read), "read-only");
        assert_eq!(format_access_mode(&AccessMode::Write), "write-only");
        assert_eq!(format_access_mode(&AccessMode::ReadWrite), "read+write");
    }
}
