//! Redacted string newtype and defense-in-depth scrubber.
//!
//! All token-bearing strings that might reach `Display` output are wrapped in
//! [`RedactedString`], which renders as `[REDACTED]`. A regex scrubber strips
//! any remaining Claude API keys or GitHub OAuth tokens that somehow escape.

use regex::Regex;
use std::fmt;
use std::sync::OnceLock;

/// A string that must not be displayed verbatim.
///
/// Wraps the inner value and renders `[REDACTED]` on both `Debug` and `Display`.
/// The underlying string can only be obtained by calling [`RedactedString::reveal`],
/// which is audited via clippy / review.
#[derive(Clone)]
pub struct RedactedString(String);

impl RedactedString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Reveal the underlying string.
    ///
    /// Only callers in `credentials.rs` and `oauth.rs` are allowed to call this —
    /// enforced via the `clippy::disallowed_methods` lint in `Cargo.toml` /
    /// module-level `#![deny(...)]` attributes.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedactedString([REDACTED])")
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<&str> for RedactedString {
    fn from(v: &str) -> Self {
        Self::new(v)
    }
}

impl From<String> for RedactedString {
    fn from(v: String) -> Self {
        Self(v)
    }
}

static SCRUB_RE: OnceLock<Regex> = OnceLock::new();

fn scrub_regex() -> &'static Regex {
    SCRUB_RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            sk-ant-[A-Za-z0-9_\-]+            # Anthropic API keys
            | gho_[A-Za-z0-9]+                # GitHub OAuth tokens
            | eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+  # JWT-shaped tokens
            ",
        )
        .expect("valid regex")
    })
}

/// Scrub obvious token shapes out of an error message.
///
/// This is defense-in-depth. Primary safety comes from not inserting tokens
/// into error chains in the first place via [`RedactedString`].
pub fn scrub(input: &str) -> String {
    scrub_regex().replace_all(input, "[REDACTED]").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let r = RedactedString::new("super-secret");
        assert_eq!(format!("{:?}", r), "RedactedString([REDACTED])");
    }

    #[test]
    fn display_redacts() {
        let r = RedactedString::new("super-secret");
        assert_eq!(format!("{}", r), "[REDACTED]");
    }

    #[test]
    fn reveal_returns_inner() {
        let r = RedactedString::new("super-secret");
        assert_eq!(r.reveal(), "super-secret");
    }

    #[test]
    fn scrub_anthropic_key() {
        let input = "request failed: sk-ant-api03-abcDEF_gh-123 is invalid";
        let out = scrub(input);
        assert!(!out.contains("sk-ant-"));
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn scrub_gh_token() {
        let input = "cloned with gho_abc123DEF456 failed";
        let out = scrub(input);
        assert!(!out.contains("gho_"));
    }

    #[test]
    fn scrub_leaves_normal_text() {
        let input = "connection refused at example.com";
        assert_eq!(scrub(input), input);
    }
}
