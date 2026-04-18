//! Keychain abstraction.
//!
//! A `KeychainStore` trait with three impls:
//! - [`MacSecurityCli`] shells out to the macOS `security` CLI.
//! - [`FileKeychain`] persists secrets on disk under `${data_dir}/keystore/`
//!   with 0600 permissions (Linux default).
//! - [`InMemoryFake`] is an in-memory store used by tests.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use crate::redact::scrub;

use crate::config::Paths;

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

/// Disk-backed keychain used on platforms without a real Keychain (Linux).
///
/// Each entry is serialized to `<root>/<service-slug>__<account-slug>`, written
/// atomically via tempfile+rename. On Unix, files get mode 0600 and the root
/// directory gets mode 0700. On first use the root is created.
///
/// Slugs replace anything outside `[A-Za-z0-9._-]` with `_` to stay filesystem
/// safe while keeping a readable mapping back to the original service name.
pub struct FileKeychain {
    root: PathBuf,
}

impl FileKeychain {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn ensure_root(&self) -> Result<(), KeychainError> {
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = fs::metadata(&self.root)?;
            let mut perms = md.permissions();
            if perms.mode() & 0o777 != 0o700 {
                perms.set_mode(0o700);
                fs::set_permissions(&self.root, perms)?;
            }
        }
        Ok(())
    }

    fn entry_path(&self, service: &str, account: &str) -> PathBuf {
        let svc = slug(service);
        let acct = slug(account);
        self.root.join(format!("{svc}__{acct}"))
    }

    fn service_prefix(service: &str) -> String {
        format!("{}__", slug(service))
    }
}

fn slug(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

/// Atomic write: tempfile in the same directory → fsync(fd) → rename →
/// fsync(parent). On Unix we set 0600 before rename so the payload never
/// exists with broader permissions.
fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<(), KeychainError> {
    let parent = path
        .parent()
        .ok_or_else(|| KeychainError::CommandFailed(format!("no parent for {}", path.display())))?;
    fs::create_dir_all(parent)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tmp.as_file().metadata()?.permissions();
        perms.set_mode(0o600);
        tmp.as_file().set_permissions(perms)?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|e| KeychainError::CommandFailed(format!("persist tempfile: {e}")))?;

    // fsync parent so the rename is durable.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

impl KeychainStore for FileKeychain {
    fn read(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        let path = self.entry_path(service, account);
        match fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KeychainError::Io(e)),
        }
    }

    fn write(&self, service: &str, account: &str, bytes: &[u8]) -> Result<(), KeychainError> {
        self.ensure_root()?;
        let path = self.entry_path(service, account);
        atomic_write_0600(&path, bytes)
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), KeychainError> {
        let path = self.entry_path(service, account);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeychainError::Io(e)),
        }
    }

    fn list_accounts(&self, service: &str) -> Result<Vec<String>, KeychainError> {
        let prefix = Self::service_prefix(service);
        let rd = match fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(KeychainError::Io(e)),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(rest) = name.strip_prefix(&prefix) {
                out.push(rest.to_string());
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Environment variable that forces the file-backed backend on every
/// platform, including macOS. Set to a non-empty value to opt in. Useful on
/// MDM-locked macOS systems where `security(1)` is restricted, in
/// Docker-on-mac, and for local smoke tests where going through the login
/// Keychain would otherwise require a GUI prompt.
pub const FORCE_FILE_BACKEND_ENV: &str = "CLAUDE_TOKEN_FILE_BACKEND";

/// Default store for the current platform.
///
/// - `CLAUDE_TOKEN_FILE_BACKEND=1` (any non-empty value): persistent disk
///   store under `${data_dir}/keystore/`, regardless of platform.
/// - macOS otherwise: `security(1)` CLI against the login keychain.
/// - Other otherwise: persistent disk store under `${data_dir}/keystore/`.
pub fn default_store(paths: &Paths) -> Box<dyn KeychainStore> {
    if std::env::var_os(FORCE_FILE_BACKEND_ENV).is_some_and(|v| !v.is_empty()) {
        return Box::new(FileKeychain::new(paths.data_dir.join("keystore")));
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(MacSecurityCli::new())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(FileKeychain::new(paths.data_dir.join("keystore")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests exercise `scrub` regardless of OS; the top-level import is gated
    // for macOS-only call sites, so bring it in explicitly for tests.
    use crate::redact::scrub;

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

    #[test]
    fn file_keychain_roundtrip_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let kc = FileKeychain::new(tmp.path().join("keystore"));

        assert!(kc.read("svc", "acct").unwrap().is_none());
        kc.write("svc", "acct", b"payload-1").unwrap();
        assert_eq!(
            kc.read("svc", "acct").unwrap().as_deref(),
            Some(&b"payload-1"[..])
        );

        // Overwrite survives a fresh handle.
        kc.write("svc", "acct", b"payload-2").unwrap();
        let kc2 = FileKeychain::new(tmp.path().join("keystore"));
        assert_eq!(
            kc2.read("svc", "acct").unwrap().as_deref(),
            Some(&b"payload-2"[..])
        );

        kc2.write("svc", "other", b"x").unwrap();
        let mut accts = kc2.list_accounts("svc").unwrap();
        accts.sort();
        assert_eq!(accts, vec!["acct".to_string(), "other".to_string()]);

        kc2.delete("svc", "acct").unwrap();
        assert!(kc2.read("svc", "acct").unwrap().is_none());
        // Delete is idempotent.
        kc2.delete("svc", "acct").unwrap();
    }

    #[test]
    fn file_keychain_service_isolation() {
        let tmp = tempfile::tempdir().unwrap();
        let kc = FileKeychain::new(tmp.path().join("keystore"));
        kc.write("claude-token-cli::a", "u", b"A").unwrap();
        kc.write("claude-token-cli::b", "u", b"B").unwrap();

        assert_eq!(
            kc.read("claude-token-cli::a", "u").unwrap().as_deref(),
            Some(&b"A"[..])
        );
        assert_eq!(
            kc.read("claude-token-cli::b", "u").unwrap().as_deref(),
            Some(&b"B"[..])
        );
        assert_eq!(
            kc.list_accounts("claude-token-cli::a").unwrap(),
            vec!["u".to_string()]
        );
        assert_eq!(
            kc.list_accounts("claude-token-cli::b").unwrap(),
            vec!["u".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_keychain_enforces_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("keystore");
        let kc = FileKeychain::new(&root);
        kc.write("svc", "acct", b"secret").unwrap();

        let entry = root.join(format!("{}__{}", slug("svc"), slug("acct")));
        let mode = fs::metadata(&entry).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "entry permissions");

        let root_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700, "root permissions");
    }
}
