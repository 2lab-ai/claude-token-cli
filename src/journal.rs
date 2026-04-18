//! Two-store write-ahead journal.
//!
//! Each mutation produces a `<slot>.pending.json` journal entry before any
//! keychain / disk write. On startup the CLI replays any surviving entries to
//! bring keychain and disk back into agreement.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::Paths;

type HmacSha256 = Hmac<Sha256>;

/// What kind of mutation produced this journal entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    RefreshActive,
    UseSwap,
    AddSlot,
}

/// Journal record. `prev_hash` is `None` on first write for a slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub op: Op,
    pub slot: String,
    pub prev_hash: Option<String>,
    pub new_hash: String,
    pub op_id: String,
    pub timestamp_ms: i64,
}

/// Journal handle keyed by per-install HMAC secret.
pub struct Journal {
    hmac_key: Vec<u8>,
    journal_dir: PathBuf,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("journal_dir", &self.journal_dir)
            .field("hmac_key", &"[REDACTED]")
            .finish()
    }
}

impl Journal {
    /// Open (or create) the journal rooted at `paths.journal_dir`, loading
    /// the HMAC key from `paths.hmac_key` (generated on first use).
    pub fn open(paths: &Paths) -> Result<Self> {
        fs::create_dir_all(&paths.journal_dir)?;
        let hmac_key = load_or_create_hmac_key(&paths.hmac_key)?;
        Ok(Self {
            hmac_key,
            journal_dir: paths.journal_dir.clone(),
        })
    }

    /// HMAC-SHA256 of canonical credential bytes, hex-encoded.
    pub fn hash_credentials(&self, bytes: &[u8]) -> String {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.hmac_key).expect("hmac accepts any key size");
        mac.update(bytes);
        hex::encode(mac.finalize().into_bytes())
    }

    fn entry_path(&self, slot: &str) -> PathBuf {
        self.journal_dir.join(format!("{slot}.pending.json"))
    }

    /// Atomically write the journal entry for this slot.
    pub fn write_entry(&self, entry: &JournalEntry) -> Result<PathBuf> {
        fs::create_dir_all(&self.journal_dir)?;
        let path = self.entry_path(&entry.slot);
        let tmp = tempfile::Builder::new()
            .prefix(".journal-")
            .suffix(".tmp")
            .tempfile_in(&self.journal_dir)?;
        {
            let mut f: &File = tmp.as_file();
            let bytes = serde_json::to_vec_pretty(entry)?;
            f.write_all(&bytes)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        tmp.persist(&path).map_err(|e| anyhow!(e))?;
        if let Ok(dir) = File::open(&self.journal_dir) {
            let _ = dir.sync_all();
        }
        Ok(path)
    }

    /// Remove the pending journal for a given slot (no-op if absent).
    pub fn clear(&self, slot: &str) -> Result<()> {
        let path = self.entry_path(slot);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("remove journal {}", path.display()))?;
        }
        Ok(())
    }

    /// List all pending journal entries.
    pub fn pending(&self) -> Result<Vec<JournalEntry>> {
        let mut out = Vec::new();
        if !self.journal_dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&self.journal_dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if !p
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.ends_with(".pending.json"))
                .unwrap_or(false)
            {
                continue;
            }
            let bytes = fs::read(&p).with_context(|| format!("read journal {}", p.display()))?;
            let parsed: JournalEntry = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse journal {} as JournalEntry", p.display()))?;
            out.push(parsed);
        }
        Ok(out)
    }
}

/// Open an exclusive lock handle on the state lockfile.
///
/// Callers hold the `RwLock` for the duration of the critical section; dropping
/// releases the advisory lock.
pub fn state_lock(paths: &Paths) -> Result<fd_lock::RwLock<File>> {
    if let Some(parent) = paths.state_lock.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&paths.state_lock)?;
    Ok(fd_lock::RwLock::new(file))
}

fn load_or_create_hmac_key(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        #[cfg(unix)]
        {
            let meta = fs::metadata(path)?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(anyhow!(
                    "hmac key at {} has permissions {:o}, expected 600",
                    path.display(),
                    mode
                ));
            }
        }
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(anyhow!("hmac key has wrong length ({})", bytes.len()));
        }
        return Ok(bytes);
    }
    // Generate a fresh key.
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(unix)]
    {
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&key)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = OpenOptions::new().create_new(true).write(true).open(path)?;
        f.write_all(&key)?;
        f.sync_all()?;
    }

    Ok(key.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{resolve_paths_with_overrides, PathOverrides};

    fn test_paths() -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        let ov = PathOverrides {
            config_dir: Some(tmp.path().join("cfg")),
            data_dir: Some(tmp.path().join("data")),
            home_dir: Some(home),
        };
        let paths = resolve_paths_with_overrides(&ov).unwrap();
        (tmp, paths)
    }

    #[test]
    fn hash_is_stable() {
        let (_t, p) = test_paths();
        let j = Journal::open(&p).unwrap();
        let h1 = j.hash_credentials(b"hello");
        let h2 = j.hash_credentials(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(h1, j.hash_credentials(b"world"));
        assert_eq!(h1.len(), 64); // hex sha256
    }

    #[test]
    fn write_read_clear_roundtrip() {
        let (_t, p) = test_paths();
        let j = Journal::open(&p).unwrap();
        let entry = JournalEntry {
            op: Op::RefreshActive,
            slot: "work".into(),
            prev_hash: Some("a".repeat(64)),
            new_hash: "b".repeat(64),
            op_id: "op-1".into(),
            timestamp_ms: 1700000000000,
        };
        j.write_entry(&entry).unwrap();

        let pending = j.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].slot, "work");

        j.clear("work").unwrap();
        assert_eq!(j.pending().unwrap().len(), 0);
    }

    #[test]
    fn malformed_json_is_rejected() {
        let (_t, p) = test_paths();
        let j = Journal::open(&p).unwrap();
        fs::write(p.journal_dir.join("bad.pending.json"), b"not json").unwrap();
        let err = j.pending().unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("parse journal") || s.contains("expected"));
    }

    #[cfg(unix)]
    #[test]
    fn hmac_key_permissions_enforced() {
        let (_t, p) = test_paths();
        // First call creates the key with 0600.
        let _ = Journal::open(&p).unwrap();
        // Corrupt perms and expect failure on reopen.
        let meta = fs::metadata(&p.hmac_key).unwrap();
        let mut perms = meta.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&p.hmac_key, perms).unwrap();

        let err = Journal::open(&p).unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("permissions"));
    }
}
