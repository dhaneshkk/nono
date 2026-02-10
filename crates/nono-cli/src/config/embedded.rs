//! Embedded configuration loading
//!
//! Loads policy compiled into the binary at build time.

/// Embedded policy JSON (compiled into binary by build.rs)
const EMBEDDED_POLICY_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/policy.json"));

/// Get the embedded policy JSON string
///
/// This is the raw JSON for the group-based policy file, compiled into the binary.
/// Used by the policy resolver to parse and resolve groups at runtime.
pub fn embedded_policy_json() -> &'static str {
    EMBEDDED_POLICY_JSON
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
}
