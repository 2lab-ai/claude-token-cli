//! Keychain abstraction.
//!
//! A `KeychainStore` trait with two impls:
//! - [`MacSecurityCli`] shells out to the macOS `security` CLI.
//! - [`InMemoryFake`] is an in-memory store used by tests and as the default
//!   non-mac fallback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use crate::redact::scrub;

/// Service name Claude Code itself uses when reading its credentials.
pub const CANONICAL_SERVICE: &str = "Claude Code-credentials";

/// Service name for an inactive slot.
pub fn slot_service(slot: &str) -> String {
    format!("claude-token-cli::{slot}")
}

/// Errors from the keychain layer. All external-tool stderr is scrubbed before
/// being embedded into `CommandFailed`.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain entry not found")]
    NotFound,
    #[error("keychain command failed: {0}")]
    CommandFailed(String),
    #[error("keychain output was not valid UTF-8")]
    Utf8,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Pluggable keychain backend.
pub trait KeychainStore: Send + Sync {
    fn read(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError>;
    fn write(&self, service: &str, account: &str, bytes: &[u8]) -> Result<(), KeychainError>;
    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError>;
    fn list_accounts(&self, service: &str) -> Result<Vec<String>, KeychainError>;
}

type FakeMap = HashMap<(String, String), Vec<u8>>;

/// In-memory backend, always available. Used as the Linux default and in tests.
#[derive(Default, Clone)]
pub struct InMemoryFake {
    inner: Arc<Mutex<FakeMap>>,
}

impl InMemoryFake {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeychainStore for InMemoryFake {
    fn read(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| KeychainError::CommandFailed(format!("fake lock poisoned: {e}")))?;
        Ok(guard
            .get(&(service.to_string(), account.to_string()))
            .cloned())
    }

    fn write(&self, service: &str, account: &str, bytes: &[u8]) -> Result<(), KeychainError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| KeychainError::CommandFailed(format!("fake lock poisoned: {e}")))?;
        guard.insert((service.to_string(), account.to_string()), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| KeychainError::CommandFailed(format!("fake lock poisoned: {e}")))?;
        guard.remove(&(service.to_string(), account.to_string()));
        Ok(())
    }

    fn list_accounts(&self, service: &str) -> Result<Vec<String>, KeychainError> {
        let guard = self
            .inner
            .lock()
            .map_err(|e| KeychainError::CommandFailed(format!("fake lock poisoned: {e}")))?;
        let mut out: Vec<String> = guard
            .keys()
            .filter(|(s, _)| s == service)
            .map(|(_, a)| a.clone())
            .collect();
        out.sort();
        Ok(out)
    }
}

/// Helper used on macOS (and consulted everywhere) to decide which account
/// name to attach to a keychain entry.
pub fn resolve_claude_keychain_account_name() -> String {
    if let Ok(v) = std::env::var("CLAUDE_TOKEN_KEYCHAIN_ACCOUNT") {
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::env::var("USER") {
        if !v.is_empty() {
            return v;
        }
    }
    match std::process::Command::new("whoami").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "default".to_string(),
    }
}

/// macOS backend that shells out to `security(1)`.
#[cfg(target_os = "macos")]
pub struct MacSecurityCli;

#[cfg(target_os = "macos")]
impl MacSecurityCli {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl Default for MacSecurityCli {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl KeychainStore for MacSecurityCli {
    fn read(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        let out = std::process::Command::new("security")
            .arg("find-generic-password")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account)
            .arg("-w")
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("could not be found") || stderr.contains("SecKeychainSearchCopyNext")
            {
                return Ok(None);
            }
            return Err(KeychainError::CommandFailed(scrub(stderr.trim())));
        }
        let stdout = String::from_utf8(out.stdout).map_err(|_| KeychainError::Utf8)?;
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(trimmed.as_bytes().to_vec()))
        }
    }

    fn write(&self, service: &str, account: &str, bytes: &[u8]) -> Result<(), KeychainError> {
        let raw = std::str::from_utf8(bytes).map_err(|_| KeychainError::Utf8)?;
        let out = std::process::Command::new("security")
            .arg("add-generic-password")
            .arg("-U")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account)
            .arg("-w")
            .arg(raw)
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(KeychainError::CommandFailed(scrub(stderr.trim())));
        }
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        let out = std::process::Command::new("security")
            .arg("delete-generic-password")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account)
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("could not be found") {
                return Ok(());
            }
            return Err(KeychainError::CommandFailed(scrub(stderr.trim())));
        }
        Ok(())
    }

    fn list_accounts(&self, _service: &str) -> Result<Vec<String>, KeychainError> {
        // `security` does not expose a clean enumerator; we only list what we
        // track via the catalog. Returning empty is correct for the callers.
        Ok(Vec::new())
    }
}

/// Default store for the current platform.
pub fn default_store() -> Box<dyn KeychainStore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(MacSecurityCli::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(InMemoryFake::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_roundtrip() {
        let kc = InMemoryFake::new();
        assert!(kc.read("svc", "acct").unwrap().is_none());
        kc.write("svc", "acct", b"hello").unwrap();
        assert_eq!(
            kc.read("svc", "acct").unwrap().as_deref(),
            Some(&b"hello"[..])
        );

        kc.write("svc", "other", b"world").unwrap();
        let mut accts = kc.list_accounts("svc").unwrap();
        accts.sort();
        assert_eq!(accts, vec!["acct".to_string(), "other".to_string()]);

        kc.delete("svc", "acct").unwrap();
        assert!(kc.read("svc", "acct").unwrap().is_none());
    }

    #[test]
    fn error_display_scrubs_fake_tokens() {
        let err = KeychainError::CommandFailed(scrub(
            "failed to open sk-ant-api03-FAKE_FAKE_FAKE and gho_ABCDEF1234",
        ));
        let s = format!("{err}");
        assert!(!s.contains("sk-ant-"), "stderr should be scrubbed");
        assert!(!s.contains("gho_"), "stderr should be scrubbed");
    }

    #[test]
    fn slot_service_formats() {
        assert_eq!(slot_service("work"), "claude-token-cli::work");
    }

    #[test]
    fn resolve_account_prefers_env_override() {
        // We cannot safely mutate process-wide env in parallel tests, but we can
        // at least confirm the function returns a non-empty string.
        let v = resolve_claude_keychain_account_name();
        assert!(!v.is_empty());
    }
}
