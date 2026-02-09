//! CLI output styling for nono

use colored::Colorize;
use nono::{AccessMode, CapabilitySet, CapabilitySource, NonoError, Result};
use rand::seq::SliceRandom;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

/// Hedgehog puns for the banner
const QUOTES: &[&str] = &[
    "Trust in the hog",
    "Curled up and secure",
    "The opposite of yolo",
    "Prickly about permissions",
    "No hoggin' resources",
    "All your base are belong to us",
    "Rolling with restrictions",
];

/// Print the nono banner with hedgehog mascot
pub fn print_banner(silent: bool) {
    if silent {
        return;
    }

    let quote = QUOTES
        .choose(&mut rand::thread_rng())
        .unwrap_or(&"The opposite of yolo");

    let version = env!("CARGO_PKG_VERSION");

    // Hedgehog in brown/tan - 2 lines, compact
    let hog_line1 = " \u{2584}\u{2588}\u{2584}".truecolor(139, 90, 43); //  ▄█▄ (leading space to center)
    let hog_line2 = "\u{2580}\u{2584}^\u{2584}\u{2580}".truecolor(139, 90, 43); // ▀▄^▄▀

    // Title in orange
    let title = "  nono".truecolor(204, 102, 0).bold();
    let ver = format!("v{}", version).white();

    eprintln!();
    eprintln!(" {} {} {}", hog_line1, title, ver);
    eprintln!(" {}  - {}", hog_line2, quote.truecolor(150, 150, 150));
    eprintln!();
}

/// Print the capability summary with colors
///
/// When `verbose` is 0, only user-specified capabilities are shown (CLI flags
/// and profile filesystem entries). System paths and group-resolved paths are
/// hidden to reduce noise. Use `-v` to show all capabilities.
pub fn print_capabilities(caps: &CapabilitySet, verbose: u8, silent: bool) {
    if silent {
        return;
    }

    eprintln!("{}", "Capabilities:".white().bold());

    // Filesystem capabilities
    let fs_caps = caps.fs_capabilities();
    if !fs_caps.is_empty() {
        let (user_caps, other_count) = if verbose > 0 {
            // Show everything with source labels
            (fs_caps.to_vec(), 0)
        } else {
            // Only show user-specified capabilities
            let user: Vec<_> = fs_caps
                .iter()
                .filter(|c| matches!(c.source, CapabilitySource::User))
                .cloned()
                .collect();
            let hidden = fs_caps.len() - user.len();
            (user, hidden)
        };

        eprintln!("  {}", "Filesystem:".white());
        for cap in &user_caps {
            let kind = if cap.is_file { "file" } else { "dir" };
            let access_str = cap.access.to_string();
            let access_colored = match cap.access {
                AccessMode::Read => access_str.green(),
                AccessMode::Write => access_str.yellow(),
                AccessMode::ReadWrite => access_str.truecolor(204, 102, 0), // orange
            };

            if verbose > 0 {
                let source_str = format!("{}", cap.source);
                eprintln!(
                    "    {} [{}] ({}) [{}]",
                    cap.resolved.display().to_string().white(),
                    access_colored,
                    kind.truecolor(150, 150, 150),
                    source_str.truecolor(100, 100, 100),
                );
            } else {
                eprintln!(
                    "    {} [{}] ({})",
                    cap.resolved.display().to_string().white(),
                    access_colored,
                    kind.truecolor(150, 150, 150)
                );
            }
        }

        if other_count > 0 {
            eprintln!(
                "    {}",
                format!("+ {} system/group paths (use -v to show)", other_count)
                    .truecolor(100, 100, 100)
            );
        }
    }

    // Network status
    eprintln!("  {}", "Network:".white());
    if caps.is_network_blocked() {
        eprintln!("    outbound: {}", "blocked".red());
    } else {
        eprintln!("    outbound: {}", "allowed".green());
    }

    eprintln!();
}

/// Print status message for applying sandbox
pub fn print_applying_sandbox(silent: bool) {
    if silent {
        return;
    }
    eprintln!(
        "{}",
        "Applying Kernel sandbox protections.".truecolor(150, 150, 150)
    );
}

/// Print success message when sandbox is active
pub fn print_sandbox_active(silent: bool) {
    if silent {
        return;
    }
    eprintln!(
        "{}",
        "Sandbox active. Restrictions are now in effect.".green()
    );
    eprintln!();
}

/// Print dry run message
pub fn print_dry_run(program: &OsStr, cmd_args: &[OsString], silent: bool) {
    if silent {
        return;
    }
    let mut command = Vec::with_capacity(1 + cmd_args.len());
    command.push(program.to_string_lossy().into_owned());
    command.extend(
        cmd_args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned()),
    );

    eprintln!(
        "{}",
        "Dry run mode - sandbox would be applied with above capabilities".yellow()
    );
    eprintln!("Command: {:?}", command);
}

/// Prompt the user to confirm sharing the current working directory.
///
/// Returns `Ok(true)` if user confirms, `Ok(false)` if user declines.
/// Returns `Ok(false)` with a hint if stdin is not a TTY.
pub fn prompt_cwd_sharing(cwd: &Path, access: &AccessMode) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        eprintln!(
            "{}",
            "Skipping CWD prompt (non-interactive). Use --allow-cwd to include working directory."
                .truecolor(150, 150, 150),
        );
        return Ok(false);
    }

    let access_str = access.to_string();
    let access_colored = match access {
        AccessMode::Read => access_str.green(),
        AccessMode::Write => access_str.yellow(),
        AccessMode::ReadWrite => access_str.truecolor(204, 102, 0),
    };

    eprintln!(
        "Current directory '{}' will be shared with {} access.",
        cwd.display().to_string().white().bold(),
        access_colored,
    );
    eprintln!(
        "{}",
        "tip: use --allow-cwd to skip this prompt".truecolor(150, 150, 150),
    );
    eprint!("  {} ", "Proceed? [y/N]:".white());
    std::io::stderr().flush().ok();

    let mut input = String::new();
    stdin.lock().read_line(&mut input).map_err(NonoError::Io)?;

    let answer = input.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}
