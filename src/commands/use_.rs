//! `claude-token use` — swap the active slot.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use crate::commands::atomic_write;
use crate::config::Paths;
use crate::journal::{state_lock, Journal, JournalEntry, Op};
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::slot::SlotCatalog;

/// Run `use <selector>`.
pub fn run(
    selector: &str,
    paths: &Paths,
    kc: &dyn KeychainStore,
    journal: &Journal,
    shutdown: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let mut cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let target = cat.resolve_owned(selector)?;
    if cat.active.as_deref() == Some(target.name.as_str()) {
        return Ok(());
    }

    let check_shutdown = || -> Result<()> {
        if let Some(flag) = &shutdown {
            if flag.load(Ordering::SeqCst) {
                return Err(anyhow!("shutdown signaled, aborting swap"));
            }
        }
        Ok(())
    };

    let mut lock_handle = state_lock(paths).context("open state lock")?;
    let _guard = lock_handle.write().context("acquire state lock")?;

    let account = resolve_claude_keychain_account_name();

    check_shutdown()?;

    // 1. Read current active creds (keychain first, disk fallback).
    let current_active_name = cat.active.clone();
    let current_bytes = if current_active_name.is_some() {
        match kc
            .read(CANONICAL_SERVICE, &account)
            .context("read canonical keychain")?
        {
            Some(b) => Some(b),
            None => std::fs::read(&paths.claude_credentials_json).ok(),
        }
    } else {
        None
    };

    // 2. Read target creds from its slot keychain entry.
    let target_bytes = kc
        .read(&slot_service(&target.name), &account)
        .context("read target slot keychain")?
        .ok_or_else(|| anyhow!("no stored credentials for slot {}", target.name))?;

    check_shutdown()?;

    // 3. Journal the swap.
    let prev_hash = current_bytes
        .as_deref()
        .map(|b| journal.hash_credentials(b));
    let new_hash = journal.hash_credentials(&target_bytes);
    let entry = JournalEntry {
        op: Op::UseSwap,
        slot: target.name.clone(),
        prev_hash,
        new_hash,
        op_id: format!("use-{}", chrono::Utc::now().timestamp_millis()),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };
    journal.write_entry(&entry).context("write journal")?;

    check_shutdown()?;

    // 4. Archive current active under its slot name (if any).
    if let (Some(name), Some(bytes)) = (current_active_name.as_deref(), current_bytes.as_deref()) {
        kc.write(&slot_service(name), &account, bytes)
            .context("archive current active")?;
    }

    check_shutdown()?;

    // 5. Write target bytes to canonical keychain.
    kc.write(CANONICAL_SERVICE, &account, &target_bytes)
        .context("write canonical keychain")?;

    check_shutdown()?;

    // 6. Write target bytes to disk (the commit point).
    atomic_write(&paths.claude_credentials_json, &target_bytes)
        .context("write credentials disk")?;

    // 7. Update catalog.
    cat.active = Some(target.name.clone());
    cat.save_atomic(&paths.slots_json).context("save catalog")?;

    // 8. Clear journal.
    journal.clear(&target.name).context("clear journal")?;
    Ok(())
}
