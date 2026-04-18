//! R1: two-store atomicity + journal replay crash scenarios.

use std::fs;

use claude_token_cli::commands::replay;
use claude_token_cli::config::{resolve_paths_with_overrides, PathOverrides, Paths};
use claude_token_cli::journal::{Journal, JournalEntry, Op};
use claude_token_cli::keychain::{
    resolve_claude_keychain_account_name, InMemoryFake, KeychainStore, CANONICAL_SERVICE,
};
use claude_token_cli::slot::{SlotCatalog, SlotEntry};

fn setup() -> (tempfile::TempDir, Paths, InMemoryFake, Journal) {
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

    // Active slot "work" registered.
    let mut cat = SlotCatalog {
        active: Some("work".into()),
        ..SlotCatalog::default()
    };
    cat.insert_or_replace(SlotEntry {
        name: "work".into(),
        email: Some("w@x.com".into()),
        subscription_type: None,
        created_at: 0,
    });
    cat.save_atomic(&paths.slots_json).unwrap();

    (tmp, paths, kc, journal)
}

const PREV: &[u8] =
    b"{\"claudeAiOauth\":{\"accessToken\":\"at-prev\",\"refreshToken\":\"rt-prev\"}}";
const NEW: &[u8] = b"{\"claudeAiOauth\":{\"accessToken\":\"at-new\",\"refreshToken\":\"rt-new\"}}";

fn write_journal(journal: &Journal, slot: &str, prev: Option<&[u8]>, new: &[u8]) {
    let entry = JournalEntry {
        op: Op::RefreshActive,
        slot: slot.into(),
        prev_hash: prev.map(|b| journal.hash_credentials(b)),
        new_hash: journal.hash_credentials(new),
        op_id: "test-op".into(),
        timestamp_ms: 1,
    };
    journal.write_entry(&entry).unwrap();
}

#[test]
fn crash_scenario_a_both_prev_clears_journal() {
    // Both keychain + disk still at prev. Replay has no way to get "new" bytes;
    // it clears the stale journal so subsequent writes can proceed.
    let (_t, paths, kc, journal) = setup();
    let account = resolve_claude_keychain_account_name();
    kc.write(CANONICAL_SERVICE, &account, PREV).unwrap();
    fs::write(&paths.claude_credentials_json, PREV).unwrap();
    write_journal(&journal, "work", Some(PREV), NEW);

    let actions = replay::replay_all(&paths, &kc, &journal).unwrap();
    assert_eq!(actions.len(), 1);
    assert!(actions[0].contains("prev"), "{actions:?}");
    assert!(journal.pending().unwrap().is_empty());
}

#[test]
fn crash_scenario_b_kc_new_disk_prev_resumes_disk_write() {
    let (_t, paths, kc, journal) = setup();
    let account = resolve_claude_keychain_account_name();
    kc.write(CANONICAL_SERVICE, &account, NEW).unwrap();
    fs::write(&paths.claude_credentials_json, PREV).unwrap();
    write_journal(&journal, "work", Some(PREV), NEW);

    replay::replay_all(&paths, &kc, &journal).unwrap();
    let on_disk = fs::read(&paths.claude_credentials_json).unwrap();
    assert_eq!(on_disk, NEW, "replay must push keychain->disk");
    assert!(journal.pending().unwrap().is_empty());
}

#[test]
fn crash_scenario_c_kc_new_disk_new_stale_journal() {
    let (_t, paths, kc, journal) = setup();
    let account = resolve_claude_keychain_account_name();
    kc.write(CANONICAL_SERVICE, &account, NEW).unwrap();
    fs::write(&paths.claude_credentials_json, NEW).unwrap();
    write_journal(&journal, "work", Some(PREV), NEW);

    let actions = replay::replay_all(&paths, &kc, &journal).unwrap();
    assert!(actions[0].contains("stale"));
    assert!(journal.pending().unwrap().is_empty());
}

#[test]
fn crash_scenario_d_conflict_errors() {
    let (_t, paths, kc, journal) = setup();
    let account = resolve_claude_keychain_account_name();
    // Both stores at some unrelated value (neither prev nor new)
    let other: &[u8] =
        b"{\"claudeAiOauth\":{\"accessToken\":\"at-other\",\"refreshToken\":\"rt-other\"}}";
    kc.write(CANONICAL_SERVICE, &account, other).unwrap();
    fs::write(&paths.claude_credentials_json, other).unwrap();
    write_journal(&journal, "work", Some(PREV), NEW);

    let err = replay::replay_all(&paths, &kc, &journal).unwrap_err();
    let s = format!("{err:#}");
    assert!(s.contains("replay conflict"), "got: {s}");
    // Journal intentionally left for operator.
    assert_eq!(journal.pending().unwrap().len(), 1);
}

#[test]
fn missing_disk_restores_from_keychain() {
    let (_t, paths, kc, journal) = setup();
    let account = resolve_claude_keychain_account_name();
    kc.write(CANONICAL_SERVICE, &account, NEW).unwrap();
    // no disk file
    if paths.claude_credentials_json.exists() {
        fs::remove_file(&paths.claude_credentials_json).unwrap();
    }
    write_journal(&journal, "work", Some(PREV), NEW);

    replay::replay_all(&paths, &kc, &journal).unwrap();
    let on_disk = fs::read(&paths.claude_credentials_json).unwrap();
    assert_eq!(on_disk, NEW);
}
