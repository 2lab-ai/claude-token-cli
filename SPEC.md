# claude-token-cli — Design Spec (v3, Oracle 97/100)

> Source of truth: [`soma-work#574`](https://github.com/2lab-ai/soma-work/issues/574). This document is the
> implementation contract.

## 1. Problem

Claude Code stores its OAuth credentials in two places on a developer machine:

1. macOS Keychain, service name `Claude Code-credentials`.
2. A fallback file at `~/.claude/.credentials.json`.

Tokens rotate frequently (new `refresh_token` on every `/v1/oauth/token` call),
quotas (`5h` / `7d` / `7d_sonnet`) are exposed only through an undocumented OAuth usage endpoint,
and developers often juggle multiple accounts (personal, team). The existing
single-slot `cauth` tool in `2lab-ai/agent-island` solves part of this but is buried inside
a larger project. This crate is the standalone, multi-slot successor.

## 2. Goals

- **F1** — Byte-identical roundtrip between the Keychain blob and `~/.claude/.credentials.json`.
- **F2** — Query `GET api.anthropic.com/api/oauth/usage` and show `5h %`, `7d %`, `7d_sonnet %`, `resets_at`. 401 auto-retries once after a refresh.
- **F3** — Proactive refresh when `expires_at < now + 7h`, handling `refresh_token` rotation, with atomic multi-store writes.
- **F4** — Multi-slot registry: register N accounts, switch which one Claude Code sees via `claude-token use`.
- **Self-contained binary** — One `cargo install` gets you a single binary. No Python, no Homebrew tap needed.

## 3. Non-goals (first PR)

- `crates.io` publish, cargo-dist release binaries, `doctor` command, real-Keychain macOS CI — deferred to PR2.
- API-key (`sk-ant-...`) management — out of scope entirely.
- Slack / Discord notifications — out of scope.

## 4. OAuth constants (inherited from `cauth`)

- `CLIENT_ID = 9d1c250a-e61b-44d9-88ed-5944d1962f5e`
- `TOKEN_ENDPOINT = https://platform.claude.com/v1/oauth/token`
- `USAGE_ENDPOINT = https://api.anthropic.com/api/oauth/usage`
- `DEFAULT_SCOPE = "user:profile user:inference user:sessions:claude_code user:mcp_servers"`
- Usage request must include header `anthropic-beta: oauth-2025-04-20`.

## 5. File & path layout

| Purpose | macOS | Linux |
|---|---|---|
| Config (slot catalog) | `~/Library/Application Support/ai.2lab.claude-token-cli/slots.json` | `~/.config/claude-token-cli/slots.json` |
| Data (journal, keys, locks) | same as config_dir | `~/.local/share/claude-token-cli/` |
| Claude Code credentials | `~/.claude/.credentials.json` | same |
| Legacy migration source | `~/.claude/claude-token-cli.json` → renamed `.moved` on first run | same |

Resolution via `directories::ProjectDirs::from("ai", "2lab", "claude-token-cli")`.

## 6. Catalog schema (`slots.json`)

```json
{
  "version": 1,
  "active": "work",
  "slots": [
    {
      "name": "work",
      "email": "z@2lab.ai",
      "plan": "team",
      "rate_limit_tier": "tier4",
      "last_expires_at": "2026-04-18T12:34:56Z",
      "last_five_hour_percent": 42.1,
      "last_seven_day_percent": 10.8,
      "last_seven_day_sonnet_percent": 7.5,
      "last_resets_at": "2026-04-18T17:00:00Z"
    }
  ]
}
```

- `version` must be `1`; unknown versions → hard error with migration hint.
- Slot `name` regex: `^[a-z0-9][a-z0-9_-]{0,31}$`. Reserved names: `all`, anything matching `#\d+`.
- Credentials themselves live in Keychain (macOS) or in the catalog under `slots[].creds` (Linux plaintext, file mode `0600`).

## 7. Two-store write protocol (R1 + R2)

Applies to `refresh` and `use` on the active slot. Ordered so that disk is the
**commit point observed by Claude Code**.

1. Acquire `fd_lock` exclusive on `${data_dir}/.state.lock`.
2. Write journal `${data_dir}/journal/<slot>.pending.json` via `tempfile → fsync(fd) → rename → fsync(parent)`.
   - Journal entry: `{ op, slot, prev_hash, new_hash, op_id, timestamp }`.
   - Hashes = `HMAC-SHA256(per-install key, canonical credentials JSON bytes)`.
3. **Write Keychain** (`security add-generic-password -U -a <acct> -s <svc> -w <payload>`).
4. **Write disk** `~/.claude/.credentials.json` via the same tempfile pattern.
5. Delete journal file.
6. Release lock.

### Replay (startup scan)

For each `journal/*.pending.json`:

| `disk_hash`           | `keychain_hash`       | Action                                                             |
|-----------------------|-----------------------|--------------------------------------------------------------------|
| `new`                 | `new`                 | Stale journal, delete.                                             |
| `prev`                | `new`                 | Resume step 4 (write disk, delete journal).                        |
| `prev`                | `prev`                | Resume step 3 (write Keychain, then disk, delete).                 |
| anything vs. empty    | —                     | Restore Keychain from disk (disk is authoritative when active).    |
| otherwise             | —                     | `replay conflict` hard error, bail, require operator.              |

Goal: a crash / SIGKILL during any step leaves recoverable state, **never a split-brain where
Claude Code sees a token that the Keychain has invalidated**.

## 8. Multi-slot Keychain identity (R3)

- Canonical account name / service (for Claude Code's consumption): resolved via `cauth`'s
  `resolve_claude_keychain_account_name` (service = `Claude Code-credentials`, account =
  whatever existing entry uses, fallback to `$USER`).
- Only the **active** slot lives at that canonical location.
- Inactive slots live under service `claude-token-cli::<slot-slug>` (same account). Claude Code
  never sees them.
- `use <name>` swap (journaled):
  - (a) archive current active → `claude-token-cli::<current_name>`;
  - (b) restore target ← `claude-token-cli::<target_name>` to canonical **and** disk;
  - (c) update `catalog.active`, clear journals.
- On Linux, no Keychain: all inactive slots live in the catalog file (plaintext, `0600`).

## 9. Secrecy & redaction (R4 + R5)

- All token fields are `secrecy::SecretString`. Manual `Debug` impls redact to `[REDACTED]`.
- `.expose_secret()` is allowed **only** in `credentials.rs` and `oauth.rs`. Elsewhere:
  `#[deny(clippy::disallowed_methods)]` or equivalent lint.
- Errors that carry token material wrap the string in a `RedactedString` newtype that
  `Display`s as `[REDACTED]`.
- Defense-in-depth regex scrubber strips `sk-ant-[A-Za-z0-9_-]+` and `gho_[A-Za-z0-9]+` from
  error `Display` output. Test asserts no `refresh_token` / `access_token` leaks on any
  refresh / usage failure path.

## 10. Daemon concurrency (F5 / R4)

- Exclusive `fd_lock` on `${data_dir}/daemon.lock`. Refuse to start if held.
- Main loop:
  ```rust
  crossbeam::select! {
      recv(shutdown_rx) -> _ => break,
      recv(crossbeam::channel::tick(interval)) -> _ => refresh_all(),
  }
  ```
- `interval` = `Duration::from_secs(refresh_interval_minutes * 60)`.
  Default 30 min; overridable via env `CLAUDE_TOKEN_REFRESH_INTERVAL_MINUTES`.
- `shutdown_rx` fed by a `signal-hook` handler for `SIGINT` / `SIGTERM`. SIGTERM during sleep
  exits in milliseconds.
- Per slot: refresh iff `expires_at < now + 7h`. Sequential, with a 0–2 s jitter between slots.

## 11. Signal & ENOSPC handling (F11)

- `signal-hook` installs `SIGINT` / `SIGTERM` handlers that set `SHUTDOWN: AtomicBool` and
  fan-out to `shutdown_rx`.
- Critical sections (steps 2–5 of the two-store protocol) check `SHUTDOWN` at entry and then
  run to completion (< 100 ms).
- `io::ErrorKind::StorageFull` maps to a dedicated `CliError::StorageFull` variant.
  On ENOSPC we **do not** touch the Keychain — the disk write failed before Keychain was
  consistent with it.

## 12. CLI surface

```
claude-token add [--from keychain|file] [--name <slug>]
claude-token                                     (= claude-token list)
claude-token list                                [--format pretty|json]
claude-token use <name|#N>
claude-token refresh [<name>|--all]
claude-token usage [<name>]                      [--format pretty|json]
claude-token daemon
```

Global flags: `--format {pretty,json}`, `-v` (info), `-vv` (debug).

## 13. Test strategy

- `trait KeychainStore { fn read; fn write; fn delete; fn list }` with two impls:
  - `MacSecurityCli` (`cfg(target_os = "macos")`).
  - `InMemoryFake` — always available; used by all unit / integration tests so ubuntu CI exercises the same logic.
- `tests/roundtrip.rs` — parse → serialize → parse idempotence + byte-identical storage.
- `tests/journal_replay.rs` — crash between any two steps → replay reaches a consistent state (each of the five table rows in §7).
- `tests/keychain_swap.rs` — `use` crash between archive / restore → replay completes swap.
- `tests/refresh_mock.rs` — `wiremock` cases: happy, rotated `refresh_token`, 400, 401, 500. Assert error `Display` does not contain the refresh token.
- `tests/usage_mock.rs` — `wiremock` cases: 200, 401 → refresh → retry succeeds, 401 → refresh fails. Leak assertion on all error paths.
- `tests/redaction.rs` — `RedactedString` `Debug` / `Display` + provenance scrubber.

## 14. CI

- Matrix: `ubuntu-latest`, `macos-14`.
- Rust stable pinned in `rust-toolchain.toml` (1.78+).
- Steps: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, `cargo audit` (warn-only), `cargo deny check` (warn-only).
- Real-Keychain integration test is deferred to PR2.

## 15. Crate layout

```
.
├── Cargo.toml
├── rust-toolchain.toml
├── LICENSE-MIT · LICENSE-APACHE · README.md · SPEC.md · .gitignore
├── .github/workflows/ci.yml
├── src/
│   ├── main.rs           # clap + tracing + dispatch + shutdown wiring
│   ├── lib.rs            # pub re-exports
│   ├── config.rs         # ProjectDirs + legacy migration + path helpers
│   ├── slot.rs           # SlotCatalog, name validation
│   ├── credentials.rs    # Credentials struct (SecretString fields, flatten extra)
│   ├── redact.rs         # RedactedString newtype + scrubber
│   ├── journal.rs        # JournalEntry + HMAC key + write + replay
│   ├── keychain.rs       # trait KeychainStore + MacSecurityCli + InMemoryFake
│   ├── oauth.rs          # refresh + usage clients, reqwest blocking + rustls
│   ├── format.rs         # KST+UTC+relative, tabled renderer
│   ├── signal.rs         # signal-hook SIGINT/SIGTERM -> shutdown channel
│   └── commands/
│       ├── mod.rs
│       ├── add.rs · list.rs · use_.rs · refresh.rs · usage.rs · daemon.rs
└── tests/
    ├── roundtrip.rs · journal_replay.rs · keychain_swap.rs
    └── refresh_mock.rs · usage_mock.rs · redaction.rs
```

## 16. Dependencies

Runtime: `clap (derive)`, `reqwest (blocking, rustls-tls)`, `serde`, `serde_json (preserve_order)`,
`chrono`, `chrono-tz`, `tempfile`, `fd-lock`, `thiserror`, `anyhow`, `tabled`, `secrecy`,
`tracing`, `tracing-subscriber`, `directories`, `signal-hook`, `crossbeam-channel`, `sha2`,
`hmac`, `hex`, `regex`, `base64`, `rand`.

Dev: `wiremock`, `tokio (macros, rt-multi-thread)`, `assert_cmd`, `predicates`, `tempfile`.

## 17. License

Dual MIT / Apache-2.0.

## 18. Reference

`2lab-ai/agent-island`
[`cauth/src/main.rs`](https://github.com/2lab-ai/agent-island/blob/main/cauth/src/main.rs)
commit `a6ca08c28ffe311760ac18bb759279253a5c6e3a`.

Key functions to port:

- `refresh_claude_credentials_always` (L1758–1804)
- `default_refresh_client` (L2586–2635)
- `default_usage_client` (L2637–2665)
- Keychain read / write via `security` CLI (L1811–1862)
- Scope constants (L22–25)
