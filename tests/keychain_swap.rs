//! R3: `use` swap crash + replay recovery.

use std::fs;

use claude_token_cli::commands::r#use as use_cmd;
use claude_token_cli::commands::replay;
use claude_token_cli::config::{resolve_paths_with_overrides, PathOverrides, Paths};
use claude_token_cli::journal::Journal;
use claude_token_cli::keychain::{
    resolve_claude_keychain_account_name, slot_service, InMemoryFake, KeychainStore,
    CANONICAL_SERVICE,
};
use claude_token_cli::slot::{SlotCatalog, SlotEntry};

fn setup_with_two_slots() -> (tempfile::TempDir, Paths, InMemoryFake, Journal) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(home.join(".claude")).unwrap();
    let ov = PathOverrides {
        config_dir: Some(tmp.path().join("cfg")),
        data_dir: Some(tmp.path().join("data")),
        home_dir: Some(home),
    };
    let paths = resolve_paths_with_overrides(&ov).unwrap();
    let kc = InMemoryFake::new();
    let journal = Journal::open(&paths).unwrap();

    let mut cat = SlotCatalog {
        active: Some("a".into()),
        ..SlotCatalog::default()
    };
    cat.insert_or_replace(SlotEntry {
        name: "a".into(),
        email: None,
        subscription_type: None,
        created_at: 0,
    });
    cat.insert_or_replace(SlotEntry {
        name: "b".into(),
        email: None,
        subscription_type: None,
        created_at: 0,
    });
    cat.save_atomic(&paths.slots_json).unwrap();

    (tmp, paths, kc, journal)
}

const A_CREDS: &[u8] =
    b"{\"claudeAiOauth\":{\"accessToken\":\"at-a\",\"refreshToken\":\"rt-a\",\"scopes\":[]}}\n";
const B_CREDS: &[u8] =
    b"{\"claudeAiOauth\":{\"accessToken\":\"at-b\",\"refreshToken\":\"rt-b\",\"scopes\":[]}}\n";

#[test]
fn full_use_swap_roundtrips() {
    let (_t, paths, kc, journal) = setup_with_two_slots();
    let account = resolve_claude_keychain_account_name();

    // Seed the canonical keychain + disk with A, and archive B.
    kc.write(CANONICAL_SERVICE, &account, A_CREDS).unwrap();
    fs::write(&paths.claude_credentials_json, A_CREDS).unwrap();
    kc.write(&slot_service("a"), &account, A_CREDS).unwrap();
    kc.write(&slot_service("b"), &account, B_CREDS).unwrap();

    use_cmd::run("b", &paths, &kc, &journal, None).unwrap();

    // Canonical + disk must now hold B.
    assert_eq!(
        kc.read(CANONICAL_SERVICE, &account).unwrap().unwrap(),
        B_CREDS
    );
    assert_eq!(fs::read(&paths.claude_credentials_json).unwrap(), B_CREDS);
    assert_eq!(
        kc.read(&slot_service("a"), &account).unwrap().unwrap(),
        A_CREDS
    );

    let cat = SlotCatalog::load_or_default(&paths.slots_json).unwrap();
    assert_eq!(cat.active.as_deref(), Some("b"));
    assert!(journal.pending().unwrap().is_empty());
}

#[test]
fn use_resolve_by_index() {
    let (_t, paths, kc, journal) = setup_with_two_slots();
    let account = resolve_claude_keychain_account_name();
    kc.write(CANONICAL_SERVICE, &account, A_CREDS).unwrap();
    fs::write(&paths.claude_credentials_json, A_CREDS).unwrap();
    kc.write(&slot_service("a"), &account, A_CREDS).unwrap();
    kc.write(&slot_service("b"), &account, B_CREDS).unwrap();

    use_cmd::run("#2", &paths, &kc, &journal, None).unwrap();
    let cat = SlotCatalog::load_or_default(&paths.slots_json).unwrap();
    assert_eq!(cat.active.as_deref(), Some("b"));
}

#[test]
fn crash_after_archive_replay_restores() {
    // Manually simulate: a was archived, canonical got new=B, but disk is stale
    // at A. Journal says prev=A, new=B. Replay must push disk to B.
    let (_t, paths, kc, journal) = setup_with_two_slots();
    let account = resolve_claude_keychain_account_name();
    kc.write(&slot_service("a"), &account, A_CREDS).unwrap();
    kc.write(&slot_service("b"), &account, B_CREDS).unwrap();
    kc.write(CANONICAL_SERVICE, &account, B_CREDS).unwrap();
    fs::write(&paths.claude_credentials_json, A_CREDS).unwrap();

    // For replay purposes, what matters is that the *active* slot hashes
    // match. Set cat.active=b (partial: catalog was updated but disk write
    // crashed) and write a journal for "b".
    let mut cat = SlotCatalog::load_or_default(&paths.slots_json).unwrap();
    cat.active = Some("b".into());
    cat.save_atomic(&paths.slots_json).unwrap();

    let entry = claude_token_cli::journal::JournalEntry {
        op: claude_token_cli::journal::Op::UseSwap,
        slot: "b".into(),
        prev_hash: Some(journal.hash_credentials(A_CREDS)),
        new_hash: journal.hash_credentials(B_CREDS),
        op_id: "swap-test".into(),
        timestamp_ms: 1,
    };
    journal.write_entry(&entry).unwrap();

    replay::replay_all(&paths, &kc, &journal).unwrap();

    assert_eq!(fs::read(&paths.claude_credentials_json).unwrap(), B_CREDS);
    assert!(journal.pending().unwrap().is_empty());
}
