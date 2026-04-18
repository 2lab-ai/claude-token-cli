//! `claude-token list` — default subcommand.

use anyhow::Result;

use crate::commands::Format;
use crate::config::Paths;
use crate::credentials::Credentials;
use crate::format::{format_expires, json_list, list_table, SlotView};
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::slot::SlotCatalog;

pub struct ListArgs {
    pub format: Format,
}

pub fn run(args: &ListArgs, paths: &Paths, kc: &dyn KeychainStore) -> Result<String> {
    let cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let active = cat.active.as_deref();
    let account = resolve_claude_keychain_account_name();

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

        let expires_in = match creds_bytes
            .as_deref()
            .and_then(|b| Credentials::from_bytes(b).ok())
        {
            Some(c) => format_expires(c.oauth.expires_at),
            None => "unknown".to_string(),
        };

        views.push(SlotView {
            marker: if is_active { "*" } else { " " },
            name: s.name.clone(),
            email: s.email.clone().unwrap_or_default(),
            plan: s.subscription_type.clone().unwrap_or_default(),
            expires_in,
            five_hour: "-".to_string(),
            seven_day: "-".to_string(),
            seven_day_opus: "-".to_string(),
        });
    }

    match args.format {
        Format::Pretty => Ok(list_table(&views)),
        Format::Json => Ok(serde_json::to_string_pretty(&json_list(&views))?),
    }
}
