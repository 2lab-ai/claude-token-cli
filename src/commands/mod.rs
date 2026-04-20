//! Command handlers dispatched by `main`.
//!
//! Each submodule implements one `claude-token <subcommand>`. They reuse the
//! library primitives in `credentials`, `keychain`, `journal`, and `oauth`.

pub mod add;
pub mod daemon;
pub mod export;
pub mod list;
pub mod refresh;
pub mod remove;
pub mod usage;
#[path = "use_.rs"]
pub mod r#use;

pub mod replay;

use std::path::Path;

use anyhow::{Context, Result};
use tempfile::Builder as TempBuilder;

/// Atomically write `bytes` to `path` via tempfile + fsync + rename + fsync parent.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = TempBuilder::new()
        .prefix(".ctcli-")
        .suffix(".tmp")
        .tempfile_in(parent)?;
    {
        use std::io::Write as _;
        let mut f = tmp.as_file();
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!(e))
        .with_context(|| format!("persist {}", path.display()))?;
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Output format for commands that support `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pretty,
    Json,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pretty" | "text" | "table" => Ok(Format::Pretty),
            "json" => Ok(Format::Json),
            other => Err(format!("unknown format: {other}")),
        }
    }
}
