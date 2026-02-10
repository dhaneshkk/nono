//! nono CLI - Capability-based sandbox for AI agents
//!
//! This is the CLI binary that uses the nono library for OS-level sandboxing.

mod capability_ext;
mod cli;
mod config;
mod exec_strategy;
mod hooks;
mod learn;
mod output;
mod policy;
mod profile;
mod query_ext;
mod sandbox_state;
mod setup;

use capability_ext::CapabilitySetExt;
use clap::Parser;
use cli::{Cli, Commands, LearnArgs, SandboxArgs, SetupArgs, ShellArgs, WhyArgs, WhyOp};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result, Sandbox};
use profile::WorkdirAccess;
use std::ffi::OsString;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    if let Err(e) = run() {
        error!("{}", e);
        eprintln!("nono: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Learn(args) => run_learn(*args, cli.silent),
        Commands::Run(args) => {
            output::print_banner(cli.silent);
            run_sandbox(args.sandbox, args.command, cli.silent)
        }
        Commands::Shell(args) => {
            output::print_banner(cli.silent);
            run_shell(*args, cli.silent)
        }
        Commands::Why(args) => run_why(*args),
        Commands::Setup(args) => run_setup(args),
    }
}

/// Set up nono on this system
fn run_setup(args: SetupArgs) -> Result<()> {
    let runner = setup::SetupRunner::new(&args);
    runner.run()
}

/// Learn mode: trace file accesses to discover required paths
fn run_learn(args: LearnArgs, silent: bool) -> Result<()> {
    // Warn user that the command runs unrestricted
    if !silent {
        eprintln!(
            "{}",
            "WARNING: nono learn runs the command WITHOUT any sandbox restrictions.".yellow()
        );
        eprintln!(
            "{}",
            "The command will have full access to your system to discover required paths.".yellow()
        );
        eprintln!();
        eprint!("Continue? [y/N] ");

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| NonoError::LearnError(format!("Failed to read input: {}", e)))?;

        let input = input.trim().to_lowercase();
        if input != "y" && input != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
        eprintln!();
    }

    eprintln!("nono learn - Tracing file accesses...\n");

    let result = learn::run_learn(&args)?;

    if args.toml {
        println!("{}", result.to_toml());
    } else {
        println!("{}", result.to_summary());
    }

    if result.has_paths() {
        eprintln!(
            "\nTo use these paths, add them to your profile or use --read/--write/--allow flags."
        );
    }

    Ok(())
}

/// Check why a path or network operation would be allowed or denied
fn run_why(args: WhyArgs) -> Result<()> {
    use query_ext::{print_result, query_network, query_path, QueryResult};
    use sandbox_state::load_sandbox_state;

    // Build capability set from args or load from sandbox state
    let caps = if args.self_query {
        // Inside sandbox - load from state file
        match load_sandbox_state() {
            Some(state) => state.to_caps(),
            None => {
                let result = QueryResult::NotSandboxed {
                    message: "Not running inside a nono sandbox".to_string(),
                };
                if args.json {
                    let json = serde_json::to_string_pretty(&result).map_err(|e| {
                        NonoError::ConfigParse(format!("JSON serialization failed: {}", e))
                    })?;
                    println!("{}", json);
                } else {
                    print_result(&result);
                }
                return Ok(());
            }
        }
    } else if let Some(ref profile_name) = args.profile {
        // Load from profile
        let prof = profile::load_profile(profile_name, args.trust_unsigned)?;
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        // Create a minimal SandboxArgs to pass to from_profile
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            net_block: args.net_block,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: args.workdir.clone(),
            trust_unsigned: args.trust_unsigned,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        CapabilitySet::from_profile(&prof, &workdir, &sandbox_args)?
    } else {
        // Build from CLI args
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            net_block: args.net_block,
            allow_command: vec![],
            block_command: vec![],
            secrets: None,
            profile: None,
            allow_cwd: false,
            workdir: args.workdir.clone(),
            trust_unsigned: false,
            config: None,
            verbose: 0,
            dry_run: false,
        };

        CapabilitySet::from_args(&sandbox_args)?
    };

    // Execute the query
    let result = if let Some(ref path) = args.path {
        let op = match args.op {
            Some(WhyOp::Read) => AccessMode::Read,
            Some(WhyOp::Write) => AccessMode::Write,
            Some(WhyOp::ReadWrite) => AccessMode::ReadWrite,
            None => AccessMode::Read, // Default to read
        };
        query_path(path, op, &caps)?
    } else if let Some(ref host) = args.host {
        query_network(host, args.port, &caps)
    } else {
        return Err(NonoError::ConfigParse(
            "--path or --host is required".to_string(),
        ));
    };

    // Output result
    if args.json {
        let json = serde_json::to_string_pretty(&result)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {}", e)))?;
        println!("{}", json);
    } else {
        print_result(&result);
    }

    Ok(())
}

/// Run a command inside the sandbox
fn run_sandbox(args: SandboxArgs, command: Vec<String>, silent: bool) -> Result<()> {
    // Check if we have a command to run
    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut command_iter = command.into_iter();
    let program = OsString::from(command_iter.next().ok_or(NonoError::NoCommand)?);
    let cmd_args: Vec<OsString> = command_iter.map(OsString::from).collect();

    // Dry run mode - just show what would happen
    if args.dry_run {
        let prepared = prepare_sandbox(&args, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} secret(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(&program, &cmd_args, silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args, silent)?;
    execute_sandboxed(
        program,
        cmd_args,
        &prepared.caps,
        prepared.secrets,
        prepared.interactive,
        silent,
    )
}

/// Run an interactive shell inside the sandbox
fn run_shell(args: ShellArgs, silent: bool) -> Result<()> {
    let shell_path = args
        .shell
        .or_else(|| {
            std::env::var("SHELL")
                .ok()
                .filter(|s| !s.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/bin/sh"));

    // Dry run mode - just show what would happen
    if args.sandbox.dry_run {
        let prepared = prepare_sandbox(&args.sandbox, silent)?;
        if !prepared.secrets.is_empty() && !silent {
            eprintln!(
                "  Would inject {} secret(s) as environment variables",
                prepared.secrets.len()
            );
        }
        output::print_dry_run(shell_path.as_os_str(), &[], silent);
        return Ok(());
    }

    let prepared = prepare_sandbox(&args.sandbox, silent)?;

    if !silent {
        eprintln!(
            "{}",
            "Exit the shell with Ctrl-D or 'exit'.".truecolor(150, 150, 150)
        );
        eprintln!();
    }

    // Shell is always interactive - needs TTY preservation
    execute_sandboxed(
        shell_path.into_os_string(),
        vec![],
        &prepared.caps,
        prepared.secrets,
        true, // Force interactive for shell
        silent,
    )
}

fn execute_sandboxed(
    program: OsString,
    cmd_args: Vec<OsString>,
    caps: &CapabilitySet,
    loaded_secrets: Vec<nono::LoadedSecret>,
    interactive: bool,
    silent: bool,
) -> Result<()> {
    // Check if command is blocked using config module
    if let Some(blocked) =
        config::check_blocked_command(&program, caps.allowed_commands(), caps.blocked_commands())?
    {
        return Err(NonoError::BlockedCommand {
            command: blocked,
            reason: "This command is blocked by default due to destructive potential. \
                     Use --allow-command to override if you understand the risks."
                .to_string(),
        });
    }

    // Convert OsString command to String for exec_strategy
    let command: Vec<String> = std::iter::once(program.to_string_lossy().into_owned())
        .chain(cmd_args.iter().map(|s| s.to_string_lossy().into_owned()))
        .collect();

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Resolve the program path BEFORE applying the sandbox
    let resolved_program = exec_strategy::resolve_program(&command[0])?;

    // Write capability state file BEFORE applying sandbox
    let cap_file = write_capability_state_file(caps, silent);
    let cap_file_path = cap_file.unwrap_or_else(|| std::path::PathBuf::from("/dev/null"));

    // Apply the sandbox
    output::print_applying_sandbox(silent);
    Sandbox::apply(caps)?;
    output::print_sandbox_active(silent);

    // Build environment variables for the command
    let env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|s| (s.env_var.as_str(), s.value.as_str()))
        .collect();

    // Determine execution strategy
    let strategy = if interactive {
        exec_strategy::ExecStrategy::Direct
    } else {
        exec_strategy::ExecStrategy::Monitor
    };

    // Determine threading context for fork safety
    let threading = if !loaded_secrets.is_empty() {
        exec_strategy::ThreadingContext::KeyringExpected
    } else {
        exec_strategy::ThreadingContext::Strict
    };

    info!(
        "Executing with strategy: {:?}, threading: {:?}",
        strategy, threading
    );

    // Create execution config
    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps,
        env_vars,
        cap_file: &cap_file_path,
        no_diagnostics: silent,
        threading,
    };

    // Execute based on strategy
    match strategy {
        exec_strategy::ExecStrategy::Direct => {
            exec_strategy::execute_direct(&config)?;
            unreachable!("execute_direct only returns on error");
        }
        exec_strategy::ExecStrategy::Monitor => {
            let exit_code = exec_strategy::execute_monitor(&config)?;
            // Clean up capability state file after child exits
            if cap_file_path.exists() {
                let _ = std::fs::remove_file(&cap_file_path);
            }
            std::process::exit(exit_code);
        }
        exec_strategy::ExecStrategy::Supervised => Err(NonoError::SandboxInit(
            "Supervised mode not yet implemented".to_string(),
        )),
    }
}

/// Result of sandbox preparation
struct PreparedSandbox {
    caps: CapabilitySet,
    secrets: Vec<nono::LoadedSecret>,
    /// Whether the profile indicates interactive mode (needs TTY)
    interactive: bool,
}

fn prepare_sandbox(args: &SandboxArgs, silent: bool) -> Result<PreparedSandbox> {
    // Reinitialize tracing with verbose level if requested.
    // Uses tracing_subscriber directly instead of mutating process env vars
    // (std::env::set_var is unsound in multi-threaded context).
    if args.verbose > 0 {
        let filter = match args.verbose {
            1 => "info",
            2 => "debug",
            _ => "trace",
        };
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::new(filter))
                .with_target(false)
                .finish(),
        );
    }

    // Clean up stale state files from previous nono runs
    sandbox_state::cleanup_stale_state_files();

    // Load profile once if specified (used for both capabilities and secrets)
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        let prof = profile::load_profile(profile_name, args.trust_unsigned)?;

        // Install hooks defined in the profile (idempotent - only installs if needed)
        if !prof.hooks.hooks.is_empty() {
            match hooks::install_profile_hooks(&prof.hooks.hooks) {
                Ok(results) => {
                    for (target, result) in results {
                        match result {
                            hooks::HookInstallResult::Installed => {
                                if !silent {
                                    eprintln!(
                                        "  Installing {} hook to ~/.claude/hooks/nono-hook.sh",
                                        target
                                    );
                                }
                            }
                            hooks::HookInstallResult::Updated => {
                                if !silent {
                                    eprintln!("  Updating {} hook (new version available)", target);
                                }
                            }
                            hooks::HookInstallResult::AlreadyInstalled
                            | hooks::HookInstallResult::Skipped => {
                                // Silent - hook already set up
                            }
                        }
                    }
                }
                Err(e) => {
                    // Hook installation failure is non-fatal - warn and continue
                    tracing::warn!("Failed to install profile hooks: {}", e);
                    if !silent {
                        eprintln!("  Warning: Failed to install hooks: {}", e);
                    }
                }
            }
        }

        Some(prof)
    } else {
        None
    };

    // Resolve the working directory
    let workdir = args
        .workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    // Extract config before profile is consumed for secrets
    let profile_workdir_access = loaded_profile.as_ref().map(|p| p.workdir.access.clone());
    let profile_interactive = loaded_profile
        .as_ref()
        .map(|p| p.interactive)
        .unwrap_or(false);

    // Build capabilities from profile or arguments
    let mut caps = if let Some(ref prof) = loaded_profile {
        CapabilitySet::from_profile(prof, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };

    // Auto-include CWD based on profile [workdir] config or default behavior
    let cwd_access = if let Some(ref access) = profile_workdir_access {
        match access {
            WorkdirAccess::Read => Some(AccessMode::Read),
            WorkdirAccess::Write => Some(AccessMode::Write),
            WorkdirAccess::ReadWrite => Some(AccessMode::ReadWrite),
            WorkdirAccess::None => None,
        }
    } else {
        // No profile: default to read-only CWD access
        Some(AccessMode::Read)
    };

    if let Some(access) = cwd_access {
        // Canonicalize CWD for path comparison
        let cwd_canonical =
            workdir
                .canonicalize()
                .map_err(|e| NonoError::PathCanonicalization {
                    path: workdir.clone(),
                    source: e,
                })?;

        // Only auto-add if CWD is not already covered by existing capabilities
        if !caps.path_covered(&cwd_canonical) {
            if args.allow_cwd {
                // --allow-cwd: add without prompting
                info!("Auto-including CWD with {} access (--allow-cwd)", access);
                let cap = FsCapability::new_dir(workdir.clone(), access)?;
                caps.add_fs(cap);
            } else if silent {
                // Silent mode: cannot prompt, require --allow-cwd
                return Err(NonoError::CwdPromptRequired);
            } else {
                // Interactive: prompt user for confirmation
                let confirmed = output::prompt_cwd_sharing(&cwd_canonical, &access)?;
                if confirmed {
                    let cap = FsCapability::new_dir(workdir.clone(), access)?;
                    caps.add_fs(cap);
                } else {
                    info!("User declined CWD sharing. Continuing without automatic CWD access.");
                }
            }
            caps.deduplicate();
        }
    }

    // Check if any capabilities are specified
    if !caps.has_fs() && caps.is_network_blocked() {
        return Err(NonoError::NoCapabilities);
    }

    // Build secret mappings from profile and/or CLI
    let profile_secrets = loaded_profile
        .map(|p| p.secrets.mappings)
        .unwrap_or_default();

    let secret_mappings =
        nono::keystore::build_secret_mappings(args.secrets.as_deref(), &profile_secrets);

    // Load secrets from keystore BEFORE sandbox is applied
    let loaded_secrets = if !secret_mappings.is_empty() {
        info!(
            "Loading {} secret(s) from system keystore",
            secret_mappings.len()
        );
        if !silent {
            eprintln!(
                "  Loading {} secret(s) from keystore...",
                secret_mappings.len()
            );
        }
        nono::keystore::load_secrets(nono::keystore::DEFAULT_SERVICE, &secret_mappings)?
    } else {
        Vec::new()
    };

    // Print capability summary
    output::print_capabilities(&caps, args.verbose, silent);

    // Check platform support
    if !Sandbox::is_supported() {
        return Err(NonoError::SandboxInit(Sandbox::support_info().details));
    }

    info!("{}", Sandbox::support_info().details);

    Ok(PreparedSandbox {
        caps,
        secrets: loaded_secrets,
        interactive: profile_interactive,
    })
}

fn write_capability_state_file(caps: &CapabilitySet, silent: bool) -> Option<std::path::PathBuf> {
    // Write sandbox state for `nono why --self`.
    let cap_file = std::env::temp_dir().join(format!(".nono-{}.json", std::process::id()));
    let state = sandbox_state::SandboxState::from_caps(caps);
    if let Err(e) = state.write_to_file(&cap_file) {
        error!(
            "Failed to write capability state file: {}. \
             Sandboxed processes will not be able to query their own capabilities using 'nono why --self'.",
            e
        );
        if !silent {
            eprintln!(
                "  WARNING: Capability state file could not be written.\n  \
                 The sandbox is active, but 'nono why --self' will not work inside this sandbox."
            );
        }
        None
    } else {
        Some(cap_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_paths_defined() {
        let loaded_policy = policy::load_embedded_policy().expect("policy must load");
        let paths = policy::get_sensitive_paths(&loaded_policy).expect("must resolve");
        assert!(paths.iter().any(|(p, _)| p.contains("ssh")));
        assert!(paths.iter().any(|(p, _)| p.contains("aws")));
    }

    #[test]
    fn test_dangerous_commands_defined() {
        let loaded_policy = policy::load_embedded_policy().expect("policy must load");
        let commands = policy::get_dangerous_commands(&loaded_policy);
        assert!(commands.contains("rm"));
        assert!(commands.contains("dd"));
        assert!(commands.contains("chmod"));
    }

    #[test]
    fn test_check_blocked_command_basic() {
        assert!(config::check_blocked_command("rm", &[], &[])
            .expect("policy must load")
            .is_some());
        assert!(config::check_blocked_command("dd", &[], &[])
            .expect("policy must load")
            .is_some());
        assert!(config::check_blocked_command("chmod", &[], &[])
            .expect("policy must load")
            .is_some());

        assert!(config::check_blocked_command("echo", &[], &[])
            .expect("policy must load")
            .is_none());
        assert!(config::check_blocked_command("ls", &[], &[])
            .expect("policy must load")
            .is_none());
        assert!(config::check_blocked_command("cat", &[], &[])
            .expect("policy must load")
            .is_none());
    }

    #[test]
    fn test_check_blocked_command_with_path() {
        assert!(config::check_blocked_command("/bin/rm", &[], &[])
            .expect("policy must load")
            .is_some());
        assert!(config::check_blocked_command("/usr/bin/dd", &[], &[])
            .expect("policy must load")
            .is_some());
        assert!(config::check_blocked_command("./rm", &[], &[])
            .expect("policy must load")
            .is_some());
    }

    #[test]
    fn test_check_blocked_command_allow_override() {
        let allowed = vec!["rm".to_string()];
        assert!(config::check_blocked_command("rm", &allowed, &[])
            .expect("policy must load")
            .is_none());
        assert!(config::check_blocked_command("dd", &allowed, &[])
            .expect("policy must load")
            .is_some());
    }

    #[test]
    fn test_check_blocked_command_extra_blocked() {
        let extra = vec!["custom-dangerous".to_string()];
        assert!(
            config::check_blocked_command("custom-dangerous", &[], &extra)
                .expect("policy must load")
                .is_some()
        );
        assert!(config::check_blocked_command("rm", &[], &extra)
            .expect("policy must load")
            .is_some());
    }

    #[test]
    fn test_check_sensitive_path() {
        assert!(config::check_sensitive_path("~/.ssh")
            .expect("policy must load")
            .is_some());
        assert!(config::check_sensitive_path("~/.aws")
            .expect("policy must load")
            .is_some());
        assert!(config::check_sensitive_path("~/.bashrc")
            .expect("policy must load")
            .is_some());

        assert!(config::check_sensitive_path("/tmp")
            .expect("policy must load")
            .is_none());
        assert!(config::check_sensitive_path("~/Documents")
            .expect("policy must load")
            .is_none());
    }
}
