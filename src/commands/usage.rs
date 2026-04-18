//! `claude-token usage` — show 5h / 7d / 7d-opus buckets.

use anyhow::{anyhow, Context, Result};

use crate::commands::Format;
use crate::config::Paths;
use crate::credentials::Credentials;
use crate::format::{format_bucket, format_expires};
use crate::journal::Journal;
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::oauth::{self, UsageResult, UsageSnapshot};
use crate::slot::SlotCatalog;

pub struct UsageCmdArgs {
    pub selector: Option<String>,
    pub format: Format,
}

pub fn run(
    args: &UsageCmdArgs,
    paths: &Paths,
    kc: &dyn KeychainStore,
    journal: &Journal,
) -> Result<String> {
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let name = match &args.selector {
        Some(s) => cat.resolve_owned(s)?.name,
        None => cat
            .active
            .clone()
            .ok_or_else(|| anyhow!("no active slot and no selector given"))?,
    };
    let is_active = cat.active.as_deref() == Some(name.as_str());
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
        kc.read(&slot_service(&name), &account)
            .context("read slot keychain")?
            .ok_or_else(|| anyhow!("no stored credentials for slot {name}"))?
    };

    let creds = Credentials::from_bytes(&bytes)?;
    let client = oauth::default_client()?;

    let snap = match oauth::usage(&client, &creds.oauth.access_token)? {
        UsageResult::Ok(s) => s,
        UsageResult::Unauthorized => {
            // One refresh retry.
            let mut refreshed = creds.clone();
            let token = oauth::refresh(&client, &creds.oauth.refresh_token)?;
            refreshed.apply_refresh(
                token.access_token,
                token.refresh_token,
                token.expires_in,
                token.scope.as_deref(),
            );
            let new_bytes = refreshed.to_bytes()?;
            // Persist updated creds so we don't refresh every call.
            let prev_hash = journal.hash_credentials(&bytes);
            let new_hash = journal.hash_credentials(&new_bytes);
            let entry = crate::journal::JournalEntry {
                op: crate::journal::Op::RefreshActive,
                slot: name.clone(),
                prev_hash: Some(prev_hash),
                new_hash,
                op_id: format!("usage-refresh-{}", chrono::Utc::now().timestamp_millis()),
                timestamp_ms: chrono::Utc::now().timestamp_millis(),
            };
            journal.write_entry(&entry)?;
            if is_active {
                kc.write(CANONICAL_SERVICE, &account, &new_bytes)?;
                crate::commands::atomic_write(&paths.claude_credentials_json, &new_bytes)?;
            } else {
                kc.write(&slot_service(&name), &account, &new_bytes)?;
            }
            journal.clear(&name)?;

            match oauth::usage(&client, &refreshed.oauth.access_token)? {
                UsageResult::Ok(s) => s,
                UsageResult::Unauthorized => {
                    return Err(anyhow!("still unauthorized after refresh"))
                }
            }
        }
    };

    render(&snap, args.format, &creds, &name)
}

fn render(snap: &UsageSnapshot, fmt: Format, creds: &Credentials, name: &str) -> Result<String> {
    match fmt {
        Format::Json => Ok(serde_json::to_string_pretty(&snap.raw)?),
        Format::Pretty => {
            let mut s = String::new();
            s.push_str(&format!("slot: {}\n", name));
            s.push_str(&format!(
                "expires: {}\n",
                format_expires(creds.oauth.expires_at)
            ));
            s.push_str(&format!(
                "5h:       {}\n",
                format_bucket(snap.five_hour.as_ref())
            ));
            s.push_str(&format!(
                "7d:       {}\n",
                format_bucket(snap.seven_day.as_ref())
            ));
            s.push_str(&format!(
                "7d opus:  {}\n",
                format_bucket(snap.seven_day_opus.as_ref())
            ));
            Ok(s)
        }
    }
}
