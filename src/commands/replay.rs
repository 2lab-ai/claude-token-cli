//! Journal replay. Run at startup to reconcile keychain and disk after a
//! crash between the two-store write phases.
//!
//! Replay rules (see SPEC §7):
//!
//! | disk_hash | keychain_hash | Action                                   |
//! |-----------|---------------|------------------------------------------|
//! | new       | new           | Stale journal, delete.                   |
//! | prev      | new           | Resume step 4 (write disk, delete).      |
//! | prev      | prev          | Resume step 3 (write keychain, disk).    |
//! | missing   | any           | Restore disk from keychain, delete.      |
//! | neither   | neither       | `replay conflict` hard error.            |

use anyhow::{anyhow, Result};

use crate::commands::atomic_write;
use crate::config::Paths;
use crate::journal::{Journal, JournalEntry, Op};
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::slot::SlotCatalog;

/// Replay any outstanding journal entries. Returns a list of human-readable
/// action strings (useful for tests / logging).
pub fn replay_all(paths: &Paths, kc: &dyn KeychainStore, journal: &Journal) -> Result<Vec<String>> {
    let mut actions = Vec::new();
    for entry in journal.pending()? {
        let act = replay_one(&entry, paths, kc, journal)?;
        actions.push(act);
    }
    Ok(actions)
}

fn replay_one(
    entry: &JournalEntry,
    paths: &Paths,
    kc: &dyn KeychainStore,
    journal: &Journal,
) -> Result<String> {
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let is_active = cat.active.as_deref() == Some(entry.slot.as_str());
    let account = resolve_claude_keychain_account_name();

    // Canonical service if active, per-slot otherwise.
    let kc_service = if is_active {
        CANONICAL_SERVICE.to_string()
    } else {
        slot_service(&entry.slot)
    };

    let kc_bytes = kc.read(&kc_service, &account)?;
    let kc_hash = kc_bytes.as_deref().map(|b| journal.hash_credentials(b));

    let disk_bytes = if is_active {
        std::fs::read(&paths.claude_credentials_json).ok()
    } else {
        None
    };
    let disk_hash = disk_bytes.as_deref().map(|b| journal.hash_credentials(b));

    let prev = entry.prev_hash.as_deref();
    let new = entry.new_hash.as_str();

    // For non-active slots, "disk" is not part of the protocol; only keychain matters.
    if !is_active {
        match (kc_hash.as_deref(), prev) {
            (Some(h), _) if h == new => {
                journal.clear(&entry.slot)?;
                return Ok(format!(
                    "slot {}: stale journal (keychain already at new)",
                    entry.slot
                ));
            }
            (Some(h), Some(p)) if h == p => {
                return Err(anyhow!(
                    "replay conflict: slot {} keychain still at prev, no new bytes to apply",
                    entry.slot
                ));
            }
            (None, _) => {
                return Err(anyhow!(
                    "replay conflict: slot {} missing keychain entry",
                    entry.slot
                ));
            }
            _ => {
                return Err(anyhow!(
                    "replay conflict: slot {} keychain hash does not match prev or new",
                    entry.slot
                ));
            }
        }
    }

    // Active slot two-store reconciliation.
    match (disk_hash.as_deref(), kc_hash.as_deref(), prev) {
        (Some(d), Some(k), _) if d == new && k == new => {
            journal.clear(&entry.slot)?;
            Ok(format!("slot {}: stale journal (both at new)", entry.slot))
        }
        (Some(d), Some(k), Some(p)) if d == p && k == new => {
            // Resume step 4: write disk from keychain.
            let kc_b = kc_bytes.ok_or_else(|| anyhow!("unexpected missing keychain bytes"))?;
            atomic_write(&paths.claude_credentials_json, &kc_b)?;
            journal.clear(&entry.slot)?;
            Ok(format!("slot {}: resumed (disk prev, kc new)", entry.slot))
        }
        (Some(d), Some(k), Some(p)) if d == p && k == p => {
            // Both prev — we have no way to re-derive `new` bytes here. Best we
            // can do is leave things consistent at prev and drop the journal so
            // the operator re-runs the refresh. This is also SPEC §7 row 3:
            // "resume step 3" requires the new bytes, which we don't have. We
            // drop the journal and surface a warning.
            journal.clear(&entry.slot)?;
            Ok(format!(
                "slot {}: both stores at prev, dropped stale journal",
                entry.slot
            ))
        }
        (None, Some(k), _) => {
            // Disk missing; restore from keychain (keychain is authoritative
            // in this case).
            let kc_b = kc_bytes.ok_or_else(|| anyhow!("unexpected missing keychain bytes"))?;
            atomic_write(&paths.claude_credentials_json, &kc_b)?;
            journal.clear(&entry.slot)?;
            Ok(format!(
                "slot {}: restored disk from keychain (at {})",
                entry.slot,
                if k == new { "new" } else { "prev" }
            ))
        }
        _ => Err(anyhow!(
            "replay conflict: slot {} hashes disk={:?} kc={:?} prev={:?} new={}",
            entry.slot,
            disk_hash,
            kc_hash,
            prev,
            new
        )),
    }
}

// Silence "variant never constructed" when external callers only build some ops.
#[allow(dead_code)]
fn _use_op(_: Op) {}
