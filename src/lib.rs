//! `claude-token-cli` library crate.
//!
//! The binary re-exports these modules so integration tests can reach into
//! library-level APIs without going through `clap`.

pub mod commands;
pub mod config;
pub mod credentials;
pub mod format;
pub mod journal;
pub mod keychain;
pub mod oauth;
pub mod redact;
pub mod signal;
pub mod slot;

pub use credentials::Credentials;
pub use journal::{Journal, JournalEntry, Op};
pub use keychain::{default_store, InMemoryFake, KeychainError, KeychainStore, CANONICAL_SERVICE};
pub use oauth::{OAuthError, TokenResponse, UsageResult, UsageSnapshot};
pub use slot::{SlotCatalog, SlotEntry, SlotError};
