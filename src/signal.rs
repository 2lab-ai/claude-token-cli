//! SIGINT / SIGTERM wiring.
//!
//! Installs a `signal-hook` handler that flips a shared atomic bool **and**
//! fans out on a crossbeam channel so blocking `select!`s wake up in milliseconds.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};

/// Install SIGINT + SIGTERM handlers and return the shutdown atomic + receiver.
pub fn install_shutdown() -> Result<(Arc<AtomicBool>, Receiver<()>)> {
    let flag = Arc::new(AtomicBool::new(false));
    let (tx, rx): (Sender<()>, Receiver<()>) = crossbeam_channel::bounded(1);

    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;
        let mut signals = Signals::new([SIGINT, SIGTERM])?;
        let flag_clone = flag.clone();
        std::thread::spawn(move || {
            for _sig in signals.forever() {
                flag_clone.store(true, Ordering::SeqCst);
                // non-blocking; if the bounded(1) slot is full, we've already notified.
                let _ = tx.try_send(());
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = tx;
    }

    Ok((flag, rx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_channel_constructs() {
        let (flag, _rx) = install_shutdown().unwrap();
        assert!(!flag.load(Ordering::SeqCst));
    }
}
