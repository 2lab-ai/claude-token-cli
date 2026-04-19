//! `claude-token` binary entrypoint.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use claude_token_cli::commands::{
    add::{self as add_cmd, AddArgs, AddSource},
    daemon as daemon_cmd,
    export::{self as export_cmd, ExportArgs},
    list::{self as list_cmd, ListArgs},
    r#use as use_cmd,
    refresh::{self as refresh_cmd, RefreshArgs},
    remove::{self as remove_cmd, RemoveArgs},
    replay,
    usage::{self as usage_cmd, UsageCmdArgs},
    Format,
};
use claude_token_cli::config;
use claude_token_cli::journal::Journal;
use claude_token_cli::keychain;

#[derive(Parser, Debug)]
#[command(
    name = "claude-token",
    about = "Manage Claude Code OAuth credentials",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Default output format for commands that support it.
    #[arg(long, global = true, default_value = "pretty")]
    format: FormatArg,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Register a slot (from the keychain or a file).
    Add(AddCliArgs),
    /// List slots (default subcommand).
    List(ListCliArgs),
    /// Switch the active slot.
    Use(UseCliArgs),
    /// Refresh OAuth tokens for a slot or all.
    Refresh(RefreshCliArgs),
    /// Show usage for a slot.
    Usage(UsageCliArgs),
    /// Run the background refresher daemon.
    Daemon,
    /// Write a slot's credentials to disk (default: `~/.claude/.credentials.json`).
    Export(ExportCliArgs),
    /// Remove a slot (catalog entry + keychain blob).
    Remove(RemoveCliArgs),
}

#[derive(clap::Args, Debug)]
struct AddCliArgs {
    /// Source: `keychain` (default) or `file`.
    #[arg(long, default_value = "keychain")]
    from: String,
    /// Required when `--from file`.
    #[arg(long)]
    path: Option<PathBuf>,
    /// Explicit slot name (otherwise derived from email).
    #[arg(long)]
    name: Option<String>,
}

#[derive(clap::Args, Debug, Default)]
struct ListCliArgs {
    /// Dump every path, catalog entry, and raw keychain/disk byte for inspection.
    /// Prints tokens unredacted — use only locally.
    #[arg(long)]
    debug: bool,
    /// Include the opus-only weekly bucket column (labeled `7d sonnet`).
    #[arg(long)]
    detail: bool,
    /// Skip the per-slot `/api/oauth/usage` call.
    #[arg(long)]
    no_usage: bool,
}

#[derive(clap::Args, Debug)]
struct UseCliArgs {
    /// Slot name or `#N` index.
    selector: String,
}

#[derive(clap::Args, Debug)]
struct RefreshCliArgs {
    /// Slot name to refresh.
    selector: Option<String>,
    /// Refresh every slot.
    #[arg(long)]
    all: bool,
    /// Refresh even if `needs_refresh` is false.
    #[arg(long)]
    force: bool,
}

#[derive(clap::Args, Debug)]
struct UsageCliArgs {
    /// Slot name (default: active).
    selector: Option<String>,
}

#[derive(clap::Args, Debug)]
struct ExportCliArgs {
    /// Slot name or `#N` index.
    selector: String,
    /// Target file (default: `~/.claude/.credentials.json`).
    #[arg(long)]
    path: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct RemoveCliArgs {
    /// Slot name or `#N` index.
    selector: String,
    /// Skip the confirmation prompt.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FormatArg {
    Pretty,
    Json,
}

impl From<FormatArg> for Format {
    fn from(v: FormatArg) -> Self {
        match v {
            FormatArg::Pretty => Format::Pretty,
            FormatArg::Json => Format::Json,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let paths = config::resolve_paths()?;
    config::migrate_legacy(&paths)?;

    let journal = Journal::open(&paths).context("open journal")?;
    let kc = keychain::default_store(&paths);

    // Best-effort replay.
    match replay::replay_all(&paths, kc.as_ref(), &journal) {
        Ok(actions) => {
            for a in actions {
                tracing::info!(action = %a, "replay");
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "replay conflict");
            return Err(e);
        }
    }

    let fmt: Format = cli.format.into();

    match cli
        .command
        .unwrap_or_else(|| Command::List(ListCliArgs::default()))
    {
        Command::Add(a) => {
            let from = match a.from.to_ascii_lowercase().as_str() {
                "keychain" => AddSource::Keychain,
                "file" => AddSource::File(
                    a.path
                        .ok_or_else(|| anyhow::anyhow!("--from file requires --path <PATH>"))?,
                ),
                other => anyhow::bail!("unknown --from: {other}"),
            };
            let args = AddArgs { from, name: a.name };
            let name = add_cmd::run(&args, &paths, kc.as_ref())?;
            println!("added slot: {name}");
        }
        Command::List(l) => {
            let args = ListArgs {
                format: fmt,
                debug: l.debug,
                detail: l.detail,
                no_usage: l.no_usage,
            };
            let out = list_cmd::run(&args, &paths, kc.as_ref())?;
            println!("{out}");
        }
        Command::Use(u) => {
            use_cmd::run(&u.selector, &paths, kc.as_ref(), &journal, None)?;
            println!("switched to: {}", u.selector);
        }
        Command::Refresh(r) => {
            let args = RefreshArgs {
                selector: r.selector,
                all: r.all,
                force: r.force,
            };
            let n = refresh_cmd::run(&args, &paths, kc.as_ref(), &journal)?;
            println!("refreshed: {n}");
        }
        Command::Usage(u) => {
            let args = UsageCmdArgs {
                selector: u.selector,
                format: fmt,
            };
            let out = usage_cmd::run(&args, &paths, kc.as_ref(), &journal)?;
            println!("{out}");
        }
        Command::Daemon => {
            daemon_cmd::run(&paths, kc.as_ref(), &journal)?;
        }
        Command::Export(e) => {
            let args = ExportArgs {
                selector: e.selector,
                path: e.path,
            };
            let out = export_cmd::run(&args, &paths, kc.as_ref())?;
            println!("exported to: {}", out.display());
        }
        Command::Remove(r) => {
            let args = RemoveArgs {
                selector: r.selector,
                yes: r.yes,
            };
            let name = remove_cmd::run(&args, &paths, kc.as_ref())?;
            println!("removed slot: {name}");
        }
    }

    Ok(())
}
