//! Credential loading and management for reverse proxy mode.
//!
//! Loads API credentials from the system keystore at proxy startup.
//! Credentials are stored in `Zeroizing<String>` and injected into
//! requests via headers, URL paths, query parameters, or Basic Auth.
//! The sandboxed agent never sees the real credentials.

use crate::config::{InjectMode, RouteConfig};
use crate::error::{ProxyError, Result};
use base64::Engine;
use std::collections::HashMap;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// A loaded credential ready for injection.
#[derive(Debug)]
pub struct LoadedCredential {
    /// Injection mode
    pub inject_mode: InjectMode,
    /// Upstream URL (e.g., "https://api.openai.com")
    pub upstream: String,
    /// Raw credential value from keystore (for modes that need it directly)
    pub raw_credential: Zeroizing<String>,

    // --- Header mode ---
    /// Header name to inject (e.g., "Authorization")
    pub header_name: String,
    /// Formatted header value (e.g., "Bearer sk-...")
    pub header_value: Zeroizing<String>,

    // --- URL path mode ---
    /// Pattern to match in incoming path (with {} placeholder)
    pub path_pattern: Option<String>,
    /// Pattern for outgoing path (with {} placeholder)
    pub path_replacement: Option<String>,

    // --- Query param mode ---
    /// Query parameter name
    pub query_param_name: Option<String>,
}

/// Credential store for all configured routes.
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from route prefix to loaded credential
    credentials: HashMap<String, LoadedCredential>,
}

impl CredentialStore {
    /// Load credentials for all configured routes from the system keystore.
    ///
    /// Routes without a `credential_key` are skipped (no credential injection).
    /// Returns an error if any configured credential fails to load.
    pub fn load(routes: &[RouteConfig]) -> Result<Self> {
        let mut credentials = HashMap::new();

        for route in routes {
            if let Some(ref key) = route.credential_key {
                debug!(
                    "Loading credential for route prefix: {} (mode: {:?})",
                    route.prefix, route.inject_mode
                );

                let secret = load_from_keyring(key)?;

                // Format header value based on mode
                let header_value = match route.inject_mode {
                    InjectMode::Header => {
                        Zeroizing::new(route.credential_format.replace("{}", &secret))
                    }
                    InjectMode::BasicAuth => {
                        // Base64 encode the credential for Basic auth
                        let encoded =
                            base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
                        Zeroizing::new(format!("Basic {}", encoded))
                    }
                    // For url_path and query_param, header_value is not used
                    InjectMode::UrlPath | InjectMode::QueryParam => Zeroizing::new(String::new()),
                };

                credentials.insert(
                    route.prefix.clone(),
                    LoadedCredential {
                        inject_mode: route.inject_mode.clone(),
                        upstream: route.upstream.clone(),
                        raw_credential: secret,
                        header_name: route.inject_header.clone(),
                        header_value,
                        path_pattern: route.path_pattern.clone(),
                        path_replacement: route.path_replacement.clone(),
                        query_param_name: route.query_param_name.clone(),
                    },
                );
            }
        }

        Ok(Self { credentials })
    }

    /// Create an empty credential store (no credential injection).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            credentials: HashMap::new(),
        }
    }

    /// Get a credential for a route prefix, if configured.
    #[must_use]
    pub fn get(&self, prefix: &str) -> Option<&LoadedCredential> {
        self.credentials.get(prefix)
    }

    /// Check if any credentials are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Number of loaded credentials.
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }
}

/// The keyring service name used by nono for all credentials.
const KEYRING_SERVICE: &str = "nono";

/// Load a secret from the system keyring.
fn load_from_keyring(account: &str) -> Result<Zeroizing<String>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, account).map_err(|e| {
        ProxyError::Credential(format!(
            "failed to create keyring entry for '{}': {}",
            account, e
        ))
    })?;

    match entry.get_password() {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(keyring::Error::NoEntry) => {
            warn!("No keyring entry found for account: {}", account);
            Err(ProxyError::Credential(format!(
                "secret not found in keyring for account '{}'",
                account
            )))
        }
        Err(e) => Err(ProxyError::Credential(format!(
            "failed to load secret for '{}': {}",
            account, e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_credential_store() {
        let store = CredentialStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get("/openai").is_none());
    }

    #[test]
    fn test_load_no_credential_routes() {
        let routes = vec![RouteConfig {
            prefix: "/test".to_string(),
            upstream: "https://example.com".to_string(),
            credential_key: None,
            inject_mode: InjectMode::Header,
            inject_header: "Authorization".to_string(),
            credential_format: "Bearer {}".to_string(),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
        }];
        let store = CredentialStore::load(&routes);
        assert!(store.is_ok());
        let store = store.unwrap_or_else(|_| CredentialStore::empty());
        assert!(store.is_empty());
    }
}
