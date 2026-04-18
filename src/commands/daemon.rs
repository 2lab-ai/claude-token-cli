//! `claude-token daemon` — periodically refresh all due slots.

use std::fs::OpenOptions;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{select, tick};
use rand::Rng;

use crate::commands::refresh::{self as refresh_cmd, RefreshArgs};
use crate::config::Paths;
use crate::journal::Journal;
use crate::keychain::KeychainStore;
use crate::signal;

const DEFAULT_INTERVAL_MINUTES: u64 = 30;

pub fn run(paths: &Paths, kc: &dyn KeychainStore, journal: &Journal) -> Result<()> {
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&paths.daemon_lock)
        .with_context(|| format!("open daemon lock {}", paths.daemon_lock.display()))?;
    let mut lock = fd_lock::RwLock::new(lock_file);
    let _guard = lock
        .try_write()
        .map_err(|_| anyhow!("daemon already running (lock held)"))?;

    let (_flag, shutdown_rx) = signal::install_shutdown()?;

    let interval_min: u64 = std::env::var("CLAUDE_TOKEN_REFRESH_INTERVAL_MINUTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_MINUTES);
    let interval = Duration::from_secs(interval_min * 60);

    tracing::info!(?interval, "daemon started");

    // Prime an immediate tick before sleeping so we don't wait an interval
    // on startup.
    refresh_all_needed(paths, kc, journal);

    let tick_rx = tick(interval);
    loop {
        select! {
            recv(shutdown_rx) -> _ => {
                tracing::info!("daemon received shutdown");
                break;
            }
            recv(tick_rx) -> _ => {
                refresh_all_needed(paths, kc, journal);
            }
        }
    }
    Ok(())
}

fn refresh_all_needed(paths: &Paths, kc: &dyn KeychainStore, journal: &Journal) {
    let args = RefreshArgs {
        selector: None,
        all: true,
        force: false,
    };
    match refresh_cmd::run(&args, paths, kc, journal) {
        Ok(n) => tracing::info!(refreshed = n, "daemon refresh sweep complete"),
        Err(e) => tracing::error!(error = %e, "daemon refresh sweep failed"),
    }
    // Random jitter 0..=2000ms before returning so concurrent daemons drift apart.
    let jitter_ms = rand::thread_rng().gen_range(0..=2000);
    std::thread::sleep(Duration::from_millis(jitter_ms));
}
