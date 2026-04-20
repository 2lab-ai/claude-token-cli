//! `claude-token export <name>` — write a slot's credentials to disk.
//!
//! Unlike `use`, this does not journal a swap, does not touch the canonical
//! keychain entry, and does not change the active slot. It just reads the
//! stored credential blob for the given slot and writes it atomically to the
//! target path (default: `~/.claude/.credentials.json`).

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::commands::atomic_write;
use crate::config::Paths;
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::slot::SlotCatalog;

#[derive(Debug, Clone)]
pub struct ExportArgs {
    pub selector: String,
    pub path: Option<PathBuf>,
}

pub fn run(args: &ExportArgs, paths: &Paths, kc: &dyn KeychainStore) -> Result<PathBuf> {
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let target = cat.resolve_owned(&args.selector)?;

    let account = resolve_claude_keychain_account_name();

    // Per SPEC §8, the active slot's authoritative source is the canonical
    // keychain entry (refresh_one writes canonical + disk for active, and only
    // archives for inactive). Reading the archive first would hand back stale
    // bytes for the active slot whenever a refresh has happened since the last
    // `use` swap. So: canonical-first for active, archive-only for inactive.
    let bytes = if cat.active.as_deref() == Some(target.name.as_str()) {
        kc.read(CANONICAL_SERVICE, &account)
            .context("read canonical keychain entry")?
            .or_else(|| {
                kc.read(&slot_service(&target.name), &account)
                    .ok()
                    .flatten()
            })
            .ok_or_else(|| anyhow!("no stored credentials for slot {}", target.name))?
    } else {
        kc.read(&slot_service(&target.name), &account)
            .context("read slot keychain entry")?
            .ok_or_else(|| anyhow!("no stored credentials for slot {}", target.name))?
    };

    let out_path = args
        .path
        .clone()
        .unwrap_or_else(|| paths.claude_credentials_json.clone());
    atomic_write(&out_path, &bytes)
        .with_context(|| format!("write credentials to {}", out_path.display()))?;
    Ok(out_path)
}
