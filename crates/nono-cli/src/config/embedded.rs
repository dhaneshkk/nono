//! Embedded configuration loading
//!
//! Loads policy and platform-specific data compiled into the binary at build time.

/// Embedded policy JSON (compiled into binary by build.rs)
const EMBEDDED_POLICY_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/policy.json"));

/// Embedded DYLD interposition shim for macOS (compiled by build.rs).
/// Currently unused -- the DYLD shim approach is disabled pending arm64 stability work.
/// Kept so build.rs does not need modification and the shim can be re-enabled later.
#[allow(dead_code)]
const EMBEDDED_SHIM_DYLIB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/nono_shim.dylib"));

/// Get the embedded policy JSON string
///
/// This is the raw JSON for the group-based policy file, compiled into the binary.
/// Used by the policy resolver to parse and resolve groups at runtime.
pub fn embedded_policy_json() -> &'static str {
    EMBEDDED_POLICY_JSON
}

/// Get the embedded macOS DYLD shim bytes.
///
/// Returns the compiled `libnono_shim.dylib` that interposes `open()`/`openat()`
/// for transparent capability expansion. Empty on non-macOS or if the shim
/// was not compiled. Currently unused -- the DYLD shim is disabled pending
/// arm64 stability work.
#[allow(dead_code)]
pub fn embedded_shim_dylib() -> &'static [u8] {
    EMBEDDED_SHIM_DYLIB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_policy() {
        let json = embedded_policy_json();
        assert!(!json.is_empty());
        // Verify it's valid JSON
        let policy: serde_json::Value =
            serde_json::from_str(json).expect("Failed to parse embedded policy.json");
        assert!(policy.get("groups").is_some());
    }

    #[test]
    fn test_embedded_shim_dylib() {
        let bytes = embedded_shim_dylib();
        // On macOS with the shim source present, this should be non-empty
        #[cfg(target_os = "macos")]
        assert!(
            !bytes.is_empty(),
            "Embedded shim dylib should not be empty on macOS"
        );
        // On other platforms, it's an empty placeholder
        #[cfg(not(target_os = "macos"))]
        assert!(bytes.is_empty());
    }
}
