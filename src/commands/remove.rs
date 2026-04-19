//! `claude-token remove <name>` — delete a slot.
//!
//! Removes the slot's credential blob from the keychain and drops its entry
//! from the catalog. When the removed slot is the **active** one, the
//! canonical keychain entry and `~/.claude/.credentials.json` are also cleaned
//! so Claude Code is not left looking at orphaned bytes. The critical section
//! is protected by the same `state_lock` used by the two-store write protocol
//! (SPEC §7) to prevent interleaving with an in-flight `use` or `refresh`.

use std::io::{self, Write as _};

use anyhow::{anyhow, Context, Result};

use crate::config::Paths;
use crate::journal::state_lock;
use crate::keychain::{
    resolve_claude_keychain_account_name, slot_service, KeychainStore, CANONICAL_SERVICE,
};
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

    // Hold the state lock across all keychain + disk mutations so this cannot
    // race with `use` / `refresh` on the same slot.
    let mut lock_handle = state_lock(paths).context("open state lock")?;
    let _guard = lock_handle.write().context("acquire state lock")?;

    let account = resolve_claude_keychain_account_name();

    // If the target is active, tear down the canonical keychain entry and the
    // Claude Code credentials file before removing the archive. Errors from
    // `NotFound` on the disk file are benign — the user may have already
    // cleaned it manually.
    if is_active {
        kc.delete(CANONICAL_SERVICE, &account)
            .context("delete canonical keychain entry")?;
        match std::fs::remove_file(&paths.claude_credentials_json) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "remove credentials file {}",
                        paths.claude_credentials_json.display()
                    )
                });
            }
        }
    }

    // Always drop the slot's archive entry. `delete` is idempotent in both
    // keychain backends (Mac + file-backed), so this is safe if the archive
    // was never written (e.g. the slot was added but never swapped).
    kc.delete(&slot_service(&target.name), &account)
        .context("delete slot keychain entry")?;

    cat.remove(&target.name)?;
    cat.save_atomic(&paths.slots_json).context("save catalog")?;

    Ok(target.name)
}
