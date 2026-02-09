//! Query API for checking sandbox permissions
//!
//! This module provides utilities for querying what operations are permitted
//! by a given capability set, without actually applying the sandbox.

use crate::capability::{AccessMode, CapabilitySet};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Result of querying whether an operation is permitted
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryResult {
    /// The operation is allowed
    Allowed(AllowReason),
    /// The operation is denied
    Denied(DenyReason),
}

/// Reason why an operation is allowed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AllowReason {
    /// Path is covered by a granted capability
    GrantedPath {
        /// The capability that grants access
        granted_path: String,
        /// The access mode granted
        access: String,
    },
    /// Network access is not blocked
    NetworkAllowed,
}

/// Reason why an operation is denied
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DenyReason {
    /// Path is not covered by any capability
    PathNotGranted,
    /// Path is covered but with insufficient access
    InsufficientAccess {
        /// The access mode that was granted
        granted: String,
        /// The access mode that was requested
        requested: String,
    },
    /// Network access is blocked
    NetworkBlocked,
}

/// Context for querying sandbox permissions
#[derive(Debug)]
pub struct QueryContext {
    caps: CapabilitySet,
}

impl QueryContext {
    /// Create a new query context for the given capabilities
    #[must_use]
    pub fn new(caps: CapabilitySet) -> Self {
        Self { caps }
    }

    /// Query whether a path operation is permitted
    #[must_use]
    pub fn query_path(&self, path: &Path, requested: AccessMode) -> QueryResult {
        // Check if any capability covers this path
        for cap in self.caps.fs_capabilities() {
            let covers = if cap.is_file {
                // File capability - must be exact match
                cap.resolved == path
            } else {
                // Directory capability - path must be under the directory
                path.starts_with(&cap.resolved)
            };

            if covers {
                // Check if access mode is sufficient
                let sufficient = matches!(
                    (cap.access, requested),
                    (AccessMode::ReadWrite, _)
                        | (AccessMode::Read, AccessMode::Read)
                        | (AccessMode::Write, AccessMode::Write)
                );

                if sufficient {
                    return QueryResult::Allowed(AllowReason::GrantedPath {
                        granted_path: cap.resolved.display().to_string(),
                        access: cap.access.to_string(),
                    });
                } else {
                    return QueryResult::Denied(DenyReason::InsufficientAccess {
                        granted: cap.access.to_string(),
                        requested: requested.to_string(),
                    });
                }
            }
        }

        QueryResult::Denied(DenyReason::PathNotGranted)
    }

    /// Query whether network access is permitted
    #[must_use]
    pub fn query_network(&self) -> QueryResult {
        if self.caps.is_network_blocked() {
            QueryResult::Denied(DenyReason::NetworkBlocked)
        } else {
            QueryResult::Allowed(AllowReason::NetworkAllowed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};
    use std::path::PathBuf;

    #[test]
    fn test_query_path_granted() {
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: PathBuf::from("/test"),
            resolved: PathBuf::from("/test"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let ctx = QueryContext::new(caps);

        // Path under granted directory should be allowed
        let result = ctx.query_path(Path::new("/test/file.txt"), AccessMode::Read);
        assert!(matches!(result, QueryResult::Allowed(_)));

        // Path outside granted directory should be denied
        let result = ctx.query_path(Path::new("/other/file.txt"), AccessMode::Read);
        assert!(matches!(
            result,
            QueryResult::Denied(DenyReason::PathNotGranted)
        ));
    }

    #[test]
    fn test_query_network() {
        let caps_allowed = CapabilitySet::new();
        let ctx = QueryContext::new(caps_allowed);
        assert!(matches!(ctx.query_network(), QueryResult::Allowed(_)));

        let caps_blocked = CapabilitySet::new().block_network();
        let ctx = QueryContext::new(caps_blocked);
        assert!(matches!(
            ctx.query_network(),
            QueryResult::Denied(DenyReason::NetworkBlocked)
        ));
    }
}
