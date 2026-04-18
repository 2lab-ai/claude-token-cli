//! Slot catalog: persistent index of registered credential slots.
//!
//! The catalog lives in `slots.json` and is the source of truth for "which
//! slot is currently active". Individual credential blobs live in the Keychain
//! (or in a 0600 file on Linux); this file only records slot metadata.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;

/// Current on-disk catalog format version.
pub const CATALOG_VERSION: u32 = 1;

/// Persistent slot registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotCatalog {
    pub version: u32,
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub slots: Vec<SlotEntry>,
}

impl Default for SlotCatalog {
    fn default() -> Self {
        Self {
            version: CATALOG_VERSION,
            active: None,
            slots: Vec::new(),
        }
    }
}

/// Metadata for a single registered slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotEntry {
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(rename = "subscription_type", default)]
    pub subscription_type: Option<String>,
    /// Unix milliseconds when the slot was first registered.
    pub created_at: i64,
}

/// Errors specific to slot catalog operations.
#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    #[error("invalid slot name (must match ^[a-z0-9][a-z0-9_-]{{0,31}}$)")]
    InvalidName,
    #[error("slot name is reserved")]
    Reserved,
    #[error("slot not found: {0}")]
    NotFound(String),
    #[error("duplicate slot name: {0}")]
    Duplicate(String),
    #[error("unsupported catalog version: {found} (expected {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

static NAME_RE: OnceLock<Regex> = OnceLock::new();
static INDEX_RE: OnceLock<Regex> = OnceLock::new();
static RESERVED_HASH_RE: OnceLock<Regex> = OnceLock::new();

fn name_re() -> &'static Regex {
    NAME_RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9_\-]{0,31}$").expect("valid regex"))
}

fn index_re() -> &'static Regex {
    INDEX_RE.get_or_init(|| Regex::new(r"^#(\d+)$").expect("valid regex"))
}

fn reserved_hash_re() -> &'static Regex {
    RESERVED_HASH_RE.get_or_init(|| Regex::new(r"^#\d+$").expect("valid regex"))
}

/// Validate a slot name against the catalog naming rules.
pub fn validate_slot_name(name: &str) -> Result<(), SlotError> {
    if name.is_empty() {
        return Err(SlotError::InvalidName);
    }
    if name == "all" {
        return Err(SlotError::Reserved);
    }
    if reserved_hash_re().is_match(name) {
        return Err(SlotError::Reserved);
    }
    if !name_re().is_match(name) {
        return Err(SlotError::InvalidName);
    }
    Ok(())
}

/// Derive a slot name from an email address.
///
/// - lowercase the local-part,
/// - replace any char outside `[a-z0-9_-]` with `-`,
/// - prefix with `u-` if the result starts with a digit,
/// - truncate to 32 chars.
pub fn derive_slot_name_from_email(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("").to_lowercase();
    let mut cleaned: String = local
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '_' | '-' => c,
            _ => '-',
        })
        .collect();
    if cleaned.starts_with(|c: char| c.is_ascii_digit()) {
        cleaned = format!("u-{cleaned}");
    }
    if cleaned.len() > 32 {
        cleaned.truncate(32);
    }
    if cleaned.is_empty() {
        cleaned = "u-slot".to_string();
    }
    cleaned
}

impl SlotCatalog {
    /// Load from `path`, or return an empty catalog if the file doesn't exist.
    pub fn load_or_default(path: &Path) -> Result<Self, SlotError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        let cat: SlotCatalog = serde_json::from_slice(&bytes)?;
        if cat.version != CATALOG_VERSION {
            return Err(SlotError::UnsupportedVersion {
                found: cat.version,
                expected: CATALOG_VERSION,
            });
        }
        Ok(cat)
    }

    /// Atomically persist via tempfile + fsync(fd) + rename + fsync(parent).
    pub fn save_atomic(&self, path: &Path) -> Result<(), SlotError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        let tmp = tempfile::Builder::new()
            .prefix(".slots-")
            .suffix(".tmp")
            .tempfile_in(parent)?;

        {
            let mut f: &File = tmp.as_file();
            let bytes = serde_json::to_vec_pretty(self)?;
            f.write_all(&bytes)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }

        tmp.persist(path).map_err(|e| SlotError::Io(e.error))?;

        // fsync the parent directory so the rename is durable.
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn find(&self, name: &str) -> Option<&SlotEntry> {
        self.slots.iter().find(|s| s.name == name)
    }

    pub fn find_mut(&mut self, name: &str) -> Option<&mut SlotEntry> {
        self.slots.iter_mut().find(|s| s.name == name)
    }

    /// Insert a new entry, or replace an entry with the same `name`.
    pub fn insert_or_replace(&mut self, entry: SlotEntry) {
        if let Some(pos) = self.slots.iter().position(|s| s.name == entry.name) {
            self.slots[pos] = entry;
        } else {
            self.slots.push(entry);
        }
    }

    /// Remove the named slot. Returns `Ok(())` if it existed.
    pub fn remove(&mut self, name: &str) -> Result<(), SlotError> {
        let pos = self
            .slots
            .iter()
            .position(|s| s.name == name)
            .ok_or_else(|| SlotError::NotFound(name.to_string()))?;
        self.slots.remove(pos);
        if self.active.as_deref() == Some(name) {
            self.active = None;
        }
        Ok(())
    }

    /// Resolve a selector of the form `#N` (1-based index) or a slot name.
    pub fn resolve_by_index_or_name(&self, selector: &str) -> Result<&SlotEntry, SlotError> {
        if let Some(caps) = index_re().captures(selector) {
            let idx: usize = caps[1]
                .parse()
                .map_err(|_| SlotError::NotFound(selector.to_string()))?;
            if idx == 0 || idx > self.slots.len() {
                return Err(SlotError::NotFound(selector.to_string()));
            }
            return Ok(&self.slots[idx - 1]);
        }
        self.find(selector)
            .ok_or_else(|| SlotError::NotFound(selector.to_string()))
    }

    pub fn resolve_owned(&self, selector: &str) -> Result<SlotEntry, SlotError> {
        self.resolve_by_index_or_name(selector).cloned()
    }
}

/// Utility: path to where a slot's inactive-credentials file lives on Linux
/// (used when Keychain is not available).
pub fn linux_slot_creds_path(data_dir: &Path, slot: &str) -> PathBuf {
    data_dir.join(format!("slot-{slot}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        for n in ["abc", "a1", "a_b-c", "user-123", "a"] {
            assert!(validate_slot_name(n).is_ok(), "name {n:?} should be valid");
        }
    }

    #[test]
    fn invalid_names() {
        let too_long = "a".repeat(33);
        let cases: &[(&str, &str)] = &[
            ("ABC", "uppercase"),
            ("-abc", "leading hyphen"),
            ("", "empty"),
            (&too_long, "too long"),
        ];
        for (n, why) in cases {
            assert!(
                matches!(validate_slot_name(n), Err(SlotError::InvalidName)),
                "{why}"
            );
        }
    }

    #[test]
    fn reserved_names() {
        assert!(matches!(
            validate_slot_name("all"),
            Err(SlotError::Reserved)
        ));
        assert!(matches!(validate_slot_name("#1"), Err(SlotError::Reserved)));
        assert!(matches!(
            validate_slot_name("#99"),
            Err(SlotError::Reserved)
        ));
    }

    #[test]
    fn derive_from_email_basic() {
        assert_eq!(derive_slot_name_from_email("foo@bar.com"), "foo");
    }

    #[test]
    fn derive_from_email_punct() {
        assert_eq!(
            derive_slot_name_from_email("foo.bar+baz@x.com"),
            "foo-bar-baz"
        );
    }

    #[test]
    fn derive_from_email_leading_digit() {
        assert_eq!(derive_slot_name_from_email("123@x.com"), "u-123");
    }

    #[test]
    fn derive_from_email_truncates() {
        let long = format!("{}@x.com", "a".repeat(64));
        let derived = derive_slot_name_from_email(&long);
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn catalog_insert_find_resolve() {
        let mut cat = SlotCatalog::default();
        cat.insert_or_replace(SlotEntry {
            name: "work".into(),
            email: Some("w@x.com".into()),
            subscription_type: Some("team".into()),
            created_at: 1,
        });
        cat.insert_or_replace(SlotEntry {
            name: "home".into(),
            email: None,
            subscription_type: None,
            created_at: 2,
        });

        assert!(cat.find("work").is_some());
        assert_eq!(cat.resolve_by_index_or_name("#1").unwrap().name, "work");
        assert_eq!(cat.resolve_by_index_or_name("#2").unwrap().name, "home");
        assert!(cat.resolve_by_index_or_name("#9").is_err());
        assert!(cat.resolve_by_index_or_name("nope").is_err());

        // insert_or_replace replaces by name
        cat.insert_or_replace(SlotEntry {
            name: "work".into(),
            email: Some("new@x.com".into()),
            subscription_type: None,
            created_at: 99,
        });
        assert_eq!(cat.slots.len(), 2);
        assert_eq!(
            cat.find("work").unwrap().email.as_deref(),
            Some("new@x.com")
        );
    }

    #[test]
    fn catalog_save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("slots.json");
        let mut cat = SlotCatalog {
            active: Some("work".into()),
            ..SlotCatalog::default()
        };
        cat.insert_or_replace(SlotEntry {
            name: "work".into(),
            email: Some("w@x.com".into()),
            subscription_type: Some("team".into()),
            created_at: 42,
        });
        cat.save_atomic(&path).unwrap();

        let loaded = SlotCatalog::load_or_default(&path).unwrap();
        assert_eq!(loaded.active.as_deref(), Some("work"));
        assert_eq!(loaded.slots.len(), 1);
    }

    #[test]
    fn catalog_load_missing_returns_default() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nope.json");
        let loaded = SlotCatalog::load_or_default(&path).unwrap();
        assert!(loaded.slots.is_empty());
        assert!(loaded.active.is_none());
    }

    #[test]
    fn catalog_rejects_future_version() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("slots.json");
        std::fs::write(&path, br#"{"version":99,"slots":[]}"#).unwrap();
        let err = SlotCatalog::load_or_default(&path).unwrap_err();
        assert!(matches!(err, SlotError::UnsupportedVersion { .. }));
    }

    #[test]
    fn remove_clears_active_if_matches() {
        let mut cat = SlotCatalog::default();
        cat.insert_or_replace(SlotEntry {
            name: "work".into(),
            email: None,
            subscription_type: None,
            created_at: 1,
        });
        cat.active = Some("work".into());
        cat.remove("work").unwrap();
        assert!(cat.active.is_none());
    }
}
