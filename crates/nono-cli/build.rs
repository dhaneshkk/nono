//! Build script for nono-cli
//!
//! Embeds policy, built-in profiles, hook scripts, and the macOS DYLD shim
//! into the binary at compile time.

use std::env;
use std::fs;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::Command;

fn main() {
    // Rebuild if data files change
    println!("cargo:rerun-if-changed=data/");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // === Embed policy JSON ===
    let policy_path = Path::new("data/policy.json");
    if policy_path.exists() {
        let content = fs::read_to_string(policy_path).expect("Failed to read policy.json");

        // Write to OUT_DIR for include_str! macro
        fs::write(out_path.join("policy.json"), &content)
            .expect("Failed to write policy.json to OUT_DIR");

        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/policy.json not found");
        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=0");
    }

    // === Embed hook script ===
    let hook_path = Path::new("data/hooks/nono-hook.sh");
    if hook_path.exists() {
        let content = fs::read_to_string(hook_path).expect("Failed to read hook script");
        fs::write(out_path.join("nono-hook.sh"), &content)
            .expect("Failed to write hook script to OUT_DIR");
    }

    // === Compile and embed macOS DYLD shim ===
    #[cfg(target_os = "macos")]
    {
        let shim_src = Path::new("../../shim/nono_shim.c");
        println!("cargo:rerun-if-changed=../../shim/nono_shim.c");

        if shim_src.exists() {
            let dylib_path = out_path.join("libnono_shim.dylib");

            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
            let arch_flag = match target_arch.as_str() {
                "aarch64" => "-arch arm64",
                "x86_64" => "-arch x86_64",
                _ => "",
            };

            let mut cmd = Command::new("cc");
            cmd.arg("-dynamiclib")
                .arg("-O2")
                .arg("-Wall")
                .arg("-Wextra")
                .arg("-o")
                .arg(&dylib_path)
                .arg(shim_src);

            if !arch_flag.is_empty() {
                for flag in arch_flag.split_whitespace() {
                    cmd.arg(flag);
                }
            }

            let status = cmd
                .status()
                .expect("Failed to invoke cc to compile DYLD shim");

            assert!(
                status.success(),
                "Failed to compile DYLD shim: exit code {:?}",
                status.code()
            );

            // Read the compiled dylib and write to OUT_DIR for include_bytes!
            let dylib_bytes = fs::read(&dylib_path).expect("Failed to read compiled shim dylib");
            fs::write(out_path.join("nono_shim.dylib"), dylib_bytes)
                .expect("Failed to write shim dylib to OUT_DIR");

            println!("cargo:rustc-env=NONO_SHIM_COMPILED=1");
        } else {
            println!("cargo:warning=shim/nono_shim.c not found, DYLD shim will not be available");
            // Write an empty file so include_bytes! doesn't fail
            fs::write(out_path.join("nono_shim.dylib"), [])
                .expect("Failed to write empty shim placeholder");
            println!("cargo:rustc-env=NONO_SHIM_COMPILED=0");
        }
    }

    // On non-macOS, write empty placeholder
    #[cfg(not(target_os = "macos"))]
    {
        fs::write(out_path.join("nono_shim.dylib"), [])
            .expect("Failed to write empty shim placeholder");
    }
}
