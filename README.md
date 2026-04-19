# claude-token-cli

Standalone Rust CLI for managing Claude Code OAuth credentials.

- **F1**: Bridge macOS Keychain ↔ `~/.claude/.credentials.json` (byte-identical roundtrip).
- **F2**: Query 5h / 7d / 7d-sonnet usage quotas against Anthropic OAuth usage API, with auto-refresh on 401.
- **F3**: Periodic `refresh_token` rotation (7h proactive buffer) with two-store atomic write (Keychain → disk → journal clear).
- **F4**: Multi-slot registry — register several accounts (personal / team) and swap which one Claude Code sees.

Spun out of the single-slot `cauth` tool in [`2lab-ai/agent-island`](https://github.com/2lab-ai/agent-island) to make installation, updates, and cron integration trivial.

See [`SPEC.md`](./SPEC.md) for the full design contract (v3, Oracle-reviewed).

## Install

```sh
# From source (requires stable Rust 1.78+)
cargo install --git https://github.com/2lab-ai/claude-token-cli
```

`cargo install` drops the binary at `~/.cargo/bin/claude-token` — make sure that directory is on your `PATH`.

Release binaries and `crates.io` publish are tracked for PR2.

## Commands

| Command | Description |
|---|---|
| `claude-token add [--from keychain\|file] [--path <file>] [--name <slug>]` | Register the current source (Keychain on macOS, file elsewhere) as a slot. Name defaults to the email local-part. |
| `claude-token` / `claude-token list [--format pretty\|json] [--debug] [--detail] [--no-usage]` | Show all slots: `[*] active`, name, email, plan, `expires (KST+UTC+relative)`, `5h %`, `7d %`. `--detail` adds a `7d sonnet` column. `--no-usage` skips the per-slot usage API round-trip. `--debug` dumps raw paths + catalog entries + keychain payloads byte-for-byte (tokens **not redacted** — local inspection only). |
| `claude-token use <name\|#N>` | Swap the active slot — updates `.credentials.json` **and** macOS Keychain atomically. |
| `claude-token refresh [<name>\|--all] [--force]` | Force a refresh. Default is the active slot only. `--force` bypasses the 7h proactive check. |
| `claude-token usage [<name>] [--format pretty\|json]` | Latest `5h / 7d / 7d_sonnet` snapshot. |
| `claude-token daemon` | Foreground refresh loop. Launched by `launchd` / `cron` (samples below). |
| `claude-token export <name\|#N> [--path <file>]` | Copy a slot's stored credentials to a file (default `~/.claude/.credentials.json`). Read-only — no swap, no journal. Active slot reads the canonical keychain first; inactive slots read the archive at `claude-token-cli::<slot>`. |
| `claude-token remove <name\|#N> [--yes]` | Delete a slot. The archive blob is always dropped; when the removed slot is **active**, the canonical keychain entry and `~/.claude/.credentials.json` are cleaned too so Claude Code is not left pointing at orphan bytes. |

Global flags: `--format {pretty,json}`, `-v` / `-vv` (log level).

## First run on macOS

`claude-token add` reads `Claude Code-credentials` from your Keychain. macOS shows an "Always Allow" prompt the first time — click it once. For unattended daemon mode, whitelist the binary afterwards:

```sh
security set-generic-password-partition-list \
  -S apple-tool:,apple: \
  -a "$USER" \
  -s "Claude Code-credentials"
```

## Scheduling

### launchd (macOS)

`~/Library/LaunchAgents/ai.2lab.claude-token-cli.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>              <string>ai.2lab.claude-token-cli</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/YOURNAME/.cargo/bin/claude-token</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>          <true/>
    <key>KeepAlive</key>          <true/>
    <key>ProcessType</key>        <string>Background</string>
    <key>Nice</key>               <integer>5</integer>
    <key>StandardOutPath</key>    <string>/tmp/claude-token-cli.out.log</string>
    <key>StandardErrorPath</key>  <string>/tmp/claude-token-cli.err.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>           <string>/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
```

Load with `launchctl bootstrap gui/$UID ~/Library/LaunchAgents/ai.2lab.claude-token-cli.plist`.

### crontab (Linux / Docker)

```cron
*/30 * * * * $HOME/.cargo/bin/claude-token refresh --all >> /tmp/claude-token-cli.log 2>&1
```

Or run `claude-token daemon` under `systemd`.

## Linux / Docker behavior

No Keychain. All slots are stored **in plaintext** in the catalog file (`${XDG_CONFIG_HOME:-~/.config}/claude-token-cli/slots.json`) with permissions `0600`. Treat that file like any other secret — don't sync it to iCloud / Dropbox / cloud backups and don't commit it.

## File layout

- `${config_dir}/slots.json` — slot catalog (version, active, slots).
- `${data_dir}/journal/*.pending.json` — replay log for crash-safe writes.
- `${data_dir}/hmac.key` — per-install HMAC-SHA256 key (`0600`).
- `${data_dir}/daemon.lock` — `fd-lock` exclusive lock for the refresh daemon.
- `~/.claude/.credentials.json` — Claude Code's own credentials file (owned by Claude Code; we only swap its contents on `use` / `refresh`).

On macOS, `config_dir` = `~/Library/Application Support/ai.2lab.claude-token-cli/`, `data_dir` is the same. On Linux, `config_dir` = `~/.config/claude-token-cli/`, `data_dir` = `~/.local/share/claude-token-cli/`.

Legacy path `~/.claude/claude-token-cli.json` is auto-migrated on first run (the old path is renamed to `.moved`).

### Environment overrides

Each path slot can be redirected via an environment variable, for Docker/Kubernetes bind mounts, CI smoke tests, or sandboxed systems where the platform defaults aren't writable:

| Variable | Overrides | Contents when set |
|----------|-----------|-------------------|
| `CLAUDE_TOKEN_CONFIG_DIR` | `config_dir` | `slots.json` |
| `CLAUDE_TOKEN_DATA_DIR` | `data_dir` | `journal/`, `hmac.key`, `daemon.lock`, `.state.lock`, `keystore/` (non-mac only) |
| `CLAUDE_TOKEN_HOME_DIR` | `$HOME` (only when locating `.claude/.credentials.json`) | `.claude/.credentials.json` |
| `CLAUDE_TOKEN_FILE_BACKEND` | Keychain backend selection | When set to any non-empty value, forces the file-backed store under `${data_dir}/keystore/` even on macOS. Intended for MDM-locked systems, Docker-on-mac, and CI smoke tests. |

Empty strings are treated as unset. Any variable you leave unset keeps the platform default.

Example — run the CLI fully under `/tmp/ctcli`:

```bash
export CLAUDE_TOKEN_CONFIG_DIR=/tmp/ctcli/config
export CLAUDE_TOKEN_DATA_DIR=/tmp/ctcli/data
export CLAUDE_TOKEN_HOME_DIR=/tmp/ctcli/home
mkdir -p /tmp/ctcli/home/.claude
claude-token list
```

## Out of scope (first PR)

- `crates.io` publish
- Pre-built release binaries (cargo-dist)
- `claude-token doctor` diagnostic command
- Slack / Discord notifications
- API-key (`sk-ant-...`) management — this tool handles OAuth only

## License

Dual-licensed under either of:

- MIT ([LICENSE-MIT](./LICENSE-MIT))
- Apache-2.0 ([LICENSE-APACHE](./LICENSE-APACHE))

at your option.

## Reference

Ported from [`2lab-ai/agent-island` `cauth/src/main.rs`](https://github.com/2lab-ai/agent-island/blob/main/cauth/src/main.rs) (commit `a6ca08c28ffe311760ac18bb759279253a5c6e3a`).
