//! Token-leak regression tests.

use claude_token_cli::oauth::OAuthError;
use claude_token_cli::redact::{scrub, RedactedString};

#[test]
fn redacted_string_display_and_debug() {
    let r = RedactedString::new("super-secret-token");
    assert_eq!(format!("{r}"), "[REDACTED]");
    assert_eq!(format!("{r:?}"), "RedactedString([REDACTED])");
}

#[test]
fn scrub_strips_known_shapes() {
    let input = "body with sk-ant-FOOBAR and gho_BAR and leftover";
    let out = scrub(input);
    assert!(!out.contains("sk-ant-"));
    assert!(!out.contains("gho_"));
    assert!(out.contains("leftover"));
}

#[test]
fn oauth_error_does_not_leak_seeded_tokens() {
    // seed both access-token and refresh-token shaped strings
    let access = "at-secret-xyz";
    let refresh = "rt-secret-xyz";
    let leaky_body = format!("invalid refresh token: {refresh} (access was {access})");
    let err = OAuthError::Status {
        code: 400,
        body: RedactedString::new(scrub(&leaky_body)),
    };
    let d = format!("{err}");
    let dbg = format!("{err:?}");
    assert!(!d.contains(access), "Display leaks access: {d}");
    assert!(!d.contains(refresh), "Display leaks refresh: {d}");
    assert!(!dbg.contains(access), "Debug leaks access: {dbg}");
    assert!(!dbg.contains(refresh), "Debug leaks refresh: {dbg}");
}

#[test]
fn oauth_error_network_has_no_secret_bleed() {
    let err = OAuthError::Network("connect timed out".into());
    let d = format!("{err}");
    assert!(d.contains("connect timed out"));
    assert!(!d.contains("sk-ant-"));
}
