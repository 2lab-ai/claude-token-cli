//! `claude-token list` — default subcommand.

use std::fmt::Write as _;

use anyhow::Result;

use crate::commands::Format;
use crate::config::Paths;
use crate::credentials::Credentials;
use crate::format::{format_bucket, format_expires, json_list, list_table, SlotView};
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::oauth::{self, UsageResult};
use crate::slot::SlotCatalog;

pub struct ListArgs {
    pub format: Format,
    pub debug: bool,
    pub detail: bool,
    pub no_usage: bool,
}

pub fn run(args: &ListArgs, paths: &Paths, kc: &dyn KeychainStore) -> Result<String> {
    if args.debug {
        return debug_dump(paths, kc);
    }
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let active = cat.active.as_deref();
    let account = resolve_claude_keychain_account_name();
    let client = if args.no_usage {
        None
    } else {
        oauth::default_client().ok()
    };

    let mut views: Vec<SlotView> = Vec::with_capacity(cat.slots.len());
    for s in &cat.slots {
        let is_active = Some(s.name.as_str()) == active;
        let creds_bytes = if is_active {
            kc.read(CANONICAL_SERVICE, &account)
                .ok()
                .flatten()
                .or_else(|| std::fs::read(&paths.claude_credentials_json).ok())
        } else {
            kc.read(&slot_service(&s.name), &account).ok().flatten()
        };

        let mut expires_in = "unknown".to_string();
        let mut five_hour = "-".to_string();
        let mut seven_day = "-".to_string();
        let mut seven_day_opus = "-".to_string();

        if let Some(b) = creds_bytes.as_deref() {
            match Credentials::from_bytes(b) {
                Ok(c) => {
                    expires_in = format_expires(c.oauth.expires_at);
                    if let Some(cli) = client.as_ref() {
                        match oauth::usage(cli, &c.oauth.access_token) {
                            Ok(UsageResult::Ok(snap)) => {
                                five_hour = format_bucket(snap.five_hour.as_ref());
                                seven_day = format_bucket(snap.seven_day.as_ref());
                                seven_day_opus = format_bucket(snap.seven_day_opus.as_ref());
                            }
                            Ok(UsageResult::Unauthorized) => {
                                five_hour = "401".into();
                                seven_day = "401".into();
                                seven_day_opus = "401".into();
                            }
                            Err(_) => {
                                five_hour = "err".into();
                                seven_day = "err".into();
                                seven_day_opus = "err".into();
                            }
                        }
                    }
                }
                Err(_) => {
                    expires_in = "parse-err".to_string();
                }
            }
        }

        views.push(SlotView {
            marker: if is_active { "*" } else { " " },
            name: s.name.clone(),
            email: s.email.clone().unwrap_or_default(),
            plan: s.subscription_type.clone().unwrap_or_default(),
            expires_in,
            five_hour,
            seven_day,
            seven_day_opus,
        });
    }

    match args.format {
        Format::Pretty => Ok(list_table(&views, args.detail)),
        Format::Json => Ok(serde_json::to_string_pretty(&json_list(&views))?),
    }
}

/// Everything-dump for local inspection. Prints raw keychain bytes and
/// on-disk credentials verbatim — tokens are **not** redacted. Only run this
/// on a machine you trust and don't paste the output anywhere.
fn debug_dump(paths: &Paths, kc: &dyn KeychainStore) -> Result<String> {
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let account = resolve_claude_keychain_account_name();
    let mut out = String::new();

    writeln!(out, "# claude-token list --debug")?;
    writeln!(out, "# WARNING: raw tokens are printed unredacted")?;
    writeln!(out)?;

    writeln!(out, "[paths]")?;
    writeln!(
        out,
        "  config_dir              = {}",
        paths.config_dir.display()
    )?;
    writeln!(
        out,
        "  data_dir                = {}",
        paths.data_dir.display()
    )?;
    writeln!(
        out,
        "  slots_json              = {}",
        paths.slots_json.display()
    )?;
    writeln!(
        out,
        "  journal_dir             = {}",
        paths.journal_dir.display()
    )?;
    writeln!(
        out,
        "  hmac_key                = {}",
        paths.hmac_key.display()
    )?;
    writeln!(
        out,
        "  daemon_lock             = {}",
        paths.daemon_lock.display()
    )?;
    writeln!(
        out,
        "  state_lock              = {}",
        paths.state_lock.display()
    )?;
    writeln!(
        out,
        "  claude_credentials_json = {}",
        paths.claude_credentials_json.display()
    )?;
    writeln!(out)?;

    writeln!(out, "[keychain account] {}", account)?;
    writeln!(out)?;

    writeln!(out, "[catalog]")?;
    writeln!(out, "  version = {}", cat.version)?;
    writeln!(out, "  active  = {:?}", cat.active)?;
    writeln!(out, "  slots   = {}", cat.slots.len())?;
    writeln!(out)?;

    writeln!(out, "[canonical keychain]  service = {}", CANONICAL_SERVICE)?;
    dump_keychain_entry(&mut out, kc, CANONICAL_SERVICE, &account)?;
    writeln!(out)?;

    writeln!(
        out,
        "[disk credentials]  {}",
        paths.claude_credentials_json.display()
    )?;
    match std::fs::read(&paths.claude_credentials_json) {
        Ok(bytes) => dump_bytes(&mut out, &bytes)?,
        Err(e) => writeln!(out, "  <missing or unreadable: {e}>")?,
    }
    writeln!(out)?;

    for (i, s) in cat.slots.iter().enumerate() {
        let svc = slot_service(&s.name);
        let is_active = cat.active.as_deref() == Some(s.name.as_str());
        writeln!(
            out,
            "[slot #{}]  name = {}  active = {}",
            i + 1,
            s.name,
            is_active
        )?;
        writeln!(out, "  email             = {:?}", s.email)?;
        writeln!(out, "  subscription_type = {:?}", s.subscription_type)?;
        writeln!(out, "  created_at_ms     = {}", s.created_at)?;
        writeln!(out, "  keychain.service  = {}", svc)?;
        writeln!(out, "  keychain.account  = {}", account)?;
        dump_keychain_entry(&mut out, kc, &svc, &account)?;
        writeln!(out)?;
    }

    Ok(out)
}

fn dump_keychain_entry(
    out: &mut String,
    kc: &dyn KeychainStore,
    service: &str,
    account: &str,
) -> Result<()> {
    match kc.read(service, account) {
        Ok(Some(bytes)) => dump_bytes(out, &bytes),
        Ok(None) => {
            writeln!(out, "  <no entry>")?;
            Ok(())
        }
        Err(e) => {
            writeln!(out, "  <read error: {e}>")?;
            Ok(())
        }
    }
}

fn dump_bytes(out: &mut String, bytes: &[u8]) -> Result<()> {
    writeln!(out, "  bytes = {}", bytes.len())?;
    match std::str::from_utf8(bytes) {
        Ok(s) => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
                let pretty = serde_json::to_string_pretty(&v)?;
                for line in pretty.lines() {
                    writeln!(out, "    {line}")?;
                }
                if let Ok(creds) = Credentials::from_bytes(bytes) {
                    writeln!(
                        out,
                        "  parsed.expires = {}",
                        format_expires(creds.oauth.expires_at)
                    )?;
                    writeln!(out, "  parsed.scopes  = {:?}", creds.oauth.scopes)?;
                }
            } else {
                for line in s.lines() {
                    writeln!(out, "    {line}")?;
                }
            }
        }
        Err(_) => {
            writeln!(out, "    <binary, {} bytes>", bytes.len())?;
        }
    }
    Ok(())
}
