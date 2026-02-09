//! Secure credential loading from system keystore
//!
//! This module provides functionality to load secrets from the system keystore
//! (macOS Keychain / Linux Secret Service) and return them as zeroized strings.
//!
//! All secrets are wrapped in `Zeroizing<String>` to ensure they are securely
//! cleared from memory after use.

use crate::error::{NonoError, Result};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// A credential loaded from the keystore
pub struct LoadedSecret {
    /// The environment variable name to set
    pub env_var: String,
    /// The secret value (automatically zeroized when dropped)
    pub value: Zeroizing<String>,
}

/// The default service name for secrets in the keystore
pub const DEFAULT_SERVICE: &str = "nono";

/// Load secrets from the system keystore
///
/// # Arguments
/// * `service` - The service name in the keystore (e.g., "nono")
/// * `mappings` - Map of keystore account name -> env var name
///
/// # Returns
/// Vector of loaded secrets ready to be set as env vars
///
/// # Example
///
/// ```no_run
/// use nono::keystore::{load_secrets, DEFAULT_SERVICE};
/// use std::collections::HashMap;
///
/// let mut mappings = HashMap::new();
/// mappings.insert("api_key".to_string(), "API_KEY".to_string());
///
/// let secrets = load_secrets(DEFAULT_SERVICE, &mappings)?;
/// for secret in secrets {
///     std::env::set_var(&secret.env_var, secret.value.as_str());
/// }
/// # Ok::<(), nono::NonoError>(())
/// ```
#[must_use = "loaded secrets should be used to set environment variables"]
pub fn load_secrets(
    service: &str,
    mappings: &HashMap<String, String>,
) -> Result<Vec<LoadedSecret>> {
    let mut secrets = Vec::with_capacity(mappings.len());

    for (account, env_var) in mappings {
        tracing::debug!("Loading secret '{}' -> ${}", account, env_var);
        let secret = load_single_secret(service, account)?;
        secrets.push(LoadedSecret {
            env_var: env_var.clone(),
            value: secret,
        });
    }

    Ok(secrets)
}

/// Load a single secret from the keystore
fn load_single_secret(service: &str, account: &str) -> Result<Zeroizing<String>> {
    let entry = keyring::Entry::new(service, account).map_err(|e| {
        NonoError::KeystoreAccess(format!(
            "Failed to access keystore for '{}': {}",
            account, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => {
            tracing::debug!("Successfully loaded secret '{}'", account);
            Ok(Zeroizing::new(password))
        }
        Err(keyring::Error::NoEntry) => Err(NonoError::SecretNotFound(account.to_string())),
        Err(keyring::Error::Ambiguous(creds)) => Err(NonoError::KeystoreAccess(format!(
            "Multiple entries ({}) found for '{}' - please resolve manually",
            creds.len(),
            account
        ))),
        Err(e) => Err(NonoError::KeystoreAccess(format!(
            "Cannot access '{}': {}",
            account, e
        ))),
    }
}

/// Build secret mappings from a comma-separated list of account names
///
/// Auto-generates environment variable names by uppercasing the account name
/// (e.g., `openai_api_key` -> `OPENAI_API_KEY`).
///
/// # Example
///
/// ```
/// use nono::keystore::build_mappings_from_list;
///
/// let mappings = build_mappings_from_list("openai_api_key,anthropic_key");
/// assert_eq!(mappings.get("openai_api_key"), Some(&"OPENAI_API_KEY".to_string()));
/// assert_eq!(mappings.get("anthropic_key"), Some(&"ANTHROPIC_KEY".to_string()));
/// ```
#[must_use]
pub fn build_mappings_from_list(accounts: &str) -> HashMap<String, String> {
    let mut mappings = HashMap::new();

    for account in accounts.split(',') {
        let account = account.trim();
        if !account.is_empty() {
            let env_var = account.to_uppercase();
            mappings.insert(account.to_string(), env_var);
        }
    }

    mappings
}

/// Build secret mappings from CLI argument and/or profile secrets
///
/// Merges secrets from both sources, with CLI taking precedence.
///
/// # Arguments
/// * `cli_secrets` - Optional comma-separated list from CLI (--secrets flag)
/// * `profile_secrets` - Mappings from profile's [secrets] section
///
/// # Returns
/// Combined map of account name -> env var name
#[must_use]
pub fn build_secret_mappings(
    cli_secrets: Option<&str>,
    profile_secrets: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut combined = profile_secrets.clone();

    // CLI secrets override profile secrets
    if let Some(secrets_str) = cli_secrets {
        let cli_mappings = build_mappings_from_list(secrets_str);
        combined.extend(cli_mappings);
    }

    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_mappings_from_list() {
        let mappings = build_mappings_from_list("openai_api_key,anthropic_api_key");

        assert_eq!(mappings.len(), 2);
        assert_eq!(
            mappings.get("openai_api_key"),
            Some(&"OPENAI_API_KEY".to_string())
        );
        assert_eq!(
            mappings.get("anthropic_api_key"),
            Some(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn test_build_mappings_handles_whitespace() {
        let mappings = build_mappings_from_list(" key1 , key2 , key3 ");

        assert_eq!(mappings.len(), 3);
        assert!(mappings.contains_key("key1"));
        assert!(mappings.contains_key("key2"));
        assert!(mappings.contains_key("key3"));
    }

    #[test]
    fn test_build_mappings_empty() {
        let mappings = build_mappings_from_list("");
        assert!(mappings.is_empty());
    }
}
