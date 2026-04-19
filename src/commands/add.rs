//! `claude-token add` — register a new slot.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use crate::config::Paths;
use crate::credentials::Credentials;
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
use crate::oauth::{self, ProfileResult, UsageResult};
use crate::slot::{
    derive_slot_name_from_email, validate_slot_name, SlotCatalog, SlotEntry, SlotError,
};

/// Source for the new credential blob.
#[derive(Debug, Clone)]
pub enum AddSource {
    /// Read from the canonical keychain entry.
    Keychain,
    /// Read from a file on disk.
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct AddArgs {
    pub from: AddSource,
    pub name: Option<String>,
}

/// Register a slot and persist the credentials into the keychain under
/// `slot_service(name)`. Does **not** swap `active`. If the catalog has no
/// active slot yet, the new slot becomes active.
pub fn run(args: &AddArgs, paths: &Paths, kc: &dyn KeychainStore) -> Result<String> {
    let account = resolve_claude_keychain_account_name();

    let bytes = match &args.from {
        AddSource::Keychain => kc
            .read(CANONICAL_SERVICE, &account)
            .context("read canonical keychain entry")?
            .ok_or_else(|| anyhow!("no canonical keychain entry found"))?,
        AddSource::File(p) => {
            std::fs::read(p).with_context(|| format!("read credentials file {}", p.display()))?
        }
    };

    let mut creds = Credentials::from_bytes(&bytes)?;

    // Best-effort: fill in email from `/api/oauth/profile` (unlocked by the
    // `user:profile` scope). Fall back to probing `/api/oauth/usage` for an
    // email field in case the response shape changes. Any failure is ignored;
    // the user can still pass `--name` explicitly.
    if creds.oauth.email.is_none() {
        if let Ok(client) = oauth::default_client() {
            if let Ok(ProfileResult::Ok(snap)) = oauth::profile(&client, &creds.oauth.access_token)
            {
                creds.oauth.email = snap.email;
            }
            if creds.oauth.email.is_none() {
                if let Ok(UsageResult::Ok(snap)) = oauth::usage(&client, &creds.oauth.access_token)
                {
                    if let Some(email) = snap.raw.get("email").and_then(|v| v.as_str()) {
                        creds.oauth.email = Some(email.to_string());
                    }
                }
            }
        }
    }

    let name = match &args.name {
        Some(n) => n.clone(),
        None => {
            let email = creds
                .oauth
                .email
                .as_deref()
                .ok_or_else(|| anyhow!("no --name given and credentials have no email"))?;
            derive_slot_name_from_email(email)
        }
    };
    validate_slot_name(&name)?;

    let mut cat = SlotCatalog::load_or_default(&paths.slots_json)?;

    if cat.find(&name).is_some() {
        return Err(SlotError::Duplicate(name).into());
    }

    // Persist the credential bytes. Re-serialize from the parsed form so we
    // store the canonical pretty+trailing-\n shape regardless of input.
    let canonical = creds.to_bytes()?;
    kc.write(&slot_service(&name), &account, &canonical)
        .context("write slot keychain entry")?;

    cat.insert_or_replace(SlotEntry {
        name: name.clone(),
        email: creds.oauth.email.clone(),
        subscription_type: creds.oauth.subscription_type.clone(),
        created_at: chrono::Utc::now().timestamp_millis(),
    });
    if cat.active.is_none() {
        cat.active = Some(name.clone());
    }
    cat.save_atomic(&paths.slots_json)?;
    Ok(name)
}
