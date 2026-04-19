//! `claude-token remove <name>` — delete a slot.
//!
//! Removes the slot's credential blob from the keychain and drops its entry
//! from the catalog. If the slot is currently active, the canonical keychain
//! entry and `~/.claude/.credentials.json` are left untouched — the user can
//! `use` another slot to replace them.

use std::io::{self, Write as _};

use anyhow::{anyhow, Context, Result};

use crate::config::Paths;
use crate::keychain::{resolve_claude_keychain_account_name, slot_service, KeychainStore};
use crate::slot::SlotCatalog;

#[derive(Debug, Clone)]
pub struct RemoveArgs {
    pub selector: String,
    pub yes: bool,
}

pub fn run(args: &RemoveArgs, paths: &Paths, kc: &dyn KeychainStore) -> Result<String> {
    let mut cat = SlotCatalog::load_or_default(&paths.slots_json)?;
    let target = cat.resolve_owned(&args.selector)?;
    let is_active = cat.active.as_deref() == Some(target.name.as_str());

    if !args.yes {
        let suffix = if is_active { " (active)" } else { "" };
        eprint!("remove slot '{}'{}? [y/N] ", target.name, suffix);
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("read confirmation")?;
        let ans = line.trim().to_ascii_lowercase();
        if ans != "y" && ans != "yes" {
            return Err(anyhow!("aborted"));
        }
    }

    let account = resolve_claude_keychain_account_name();
    kc.delete(&slot_service(&target.name), &account)
        .context("delete slot keychain entry")?;

    cat.remove(&target.name)?;
    cat.save_atomic(&paths.slots_json)
        .context("save catalog")?;

    Ok(target.name)
}
