//! `claude-token refresh` — refresh one slot or `--all`.

use anyhow::{anyhow, Context, Result};

use crate::commands::atomic_write;
use crate::config::Paths;
use crate::credentials::Credentials;
use crate::journal::{state_lock, Journal, JournalEntry, Op};
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::oauth;
use crate::slot::SlotCatalog;

/// Seven hour buffer — the spec window for proactive refresh.
pub const REFRESH_BUFFER_SECS: i64 = 7 * 3600;

pub struct RefreshArgs {
    pub selector: Option<String>,
    pub all: bool,
    pub force: bool,
}

/// Returns the number of slots that were actually refreshed.
pub fn run(
    args: &RefreshArgs,
    paths: &Paths,
    kc: &dyn KeychainStore,
    journal: &Journal,
) -> Result<usize> {
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let targets: Vec<String> = if args.all {
        cat.slots.iter().map(|s| s.name.clone()).collect()
    } else if let Some(sel) = &args.selector {
        vec![cat.resolve_owned(sel)?.name]
    } else {
        match cat.active.clone() {
            Some(a) => vec![a],
            None => return Err(anyhow!("no active slot and no selector given")),
        }
    };

    let active = cat.active.clone();
    let mut refreshed = 0usize;
    for name in targets {
        if refresh_one(
            &name,
            active.as_deref() == Some(&name),
            args.force,
            paths,
            kc,
            journal,
        )? {
            refreshed += 1;
        }
    }
    Ok(refreshed)
}

fn refresh_one(
    name: &str,
    is_active: bool,
    force: bool,
    paths: &Paths,
    kc: &dyn KeychainStore,
    journal: &Journal,
) -> Result<bool> {
    let account = resolve_claude_keychain_account_name();

    let bytes = if is_active {
        match kc
            .read(CANONICAL_SERVICE, &account)
            .context("read canonical keychain")?
        {
            Some(b) => b,
            None => std::fs::read(&paths.claude_credentials_json)
                .with_context(|| format!("read active disk creds for {name}"))?,
        }
    } else {
        kc.read(&slot_service(name), &account)
            .context("read slot keychain")?
            .ok_or_else(|| anyhow!("no stored credentials for slot {name}"))?
    };

    let mut creds = Credentials::from_bytes(&bytes)?;
    if !force && !creds.needs_refresh(REFRESH_BUFFER_SECS) {
        tracing::info!(%name, "skip: not due for refresh");
        return Ok(false);
    }

    let client = oauth::default_client()?;
    let token = oauth::refresh(&client, &creds.oauth.refresh_token)?;

    creds.apply_refresh(
        token.access_token,
        token.refresh_token,
        token.expires_in,
        token.scope.as_deref(),
    );
    let new_bytes = creds.to_bytes()?;

    let prev_hash = journal.hash_credentials(&bytes);
    let new_hash = journal.hash_credentials(&new_bytes);
    let entry = JournalEntry {
        op: Op::RefreshActive,
        slot: name.to_string(),
        prev_hash: Some(prev_hash),
        new_hash,
        op_id: format!("refresh-{}", chrono::Utc::now().timestamp_millis()),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };

    if is_active {
        let mut lock_handle = state_lock(paths).context("open state lock")?;
        let _guard = lock_handle.write().context("acquire state lock")?;

        journal.write_entry(&entry)?;
        kc.write(CANONICAL_SERVICE, &account, &new_bytes)
            .context("write canonical keychain")?;
        atomic_write(&paths.claude_credentials_json, &new_bytes)?;
        journal.clear(name)?;
    } else {
        journal.write_entry(&entry)?;
        kc.write(&slot_service(name), &account, &new_bytes)
            .context("write slot keychain")?;
        journal.clear(name)?;
    }
    Ok(true)
}
