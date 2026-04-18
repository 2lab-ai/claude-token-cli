//! Claude Code OAuth credentials (`~/.claude/.credentials.json` shape) with
//! byte-identical roundtrip.
//!
//! The file format follows what Claude Code itself writes: a top-level JSON
//! object with `claudeAiOauth` as the known canonical field. Unknown fields at
//! both the top level and inside `claudeAiOauth` are preserved via
//! `#[serde(flatten)] extra: serde_json::Map<String, Value>` so that future
//! Claude Code versions adding new fields do not cause silent data loss when
//! we roundtrip a credentials file.

use crate::redact::RedactedString;
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[allow(clippy::disallowed_methods)]
fn serialize_secret<S: Serializer>(s: &SecretString, ser: S) -> Result<S::Ok, S::Error> {
    use secrecy::ExposeSecret;
    ser.serialize_str(s.expose_secret())
}

fn deserialize_secret<'de, D: Deserializer<'de>>(de: D) -> Result<SecretString, D::Error> {
    let s = String::deserialize(de)?;
    Ok(SecretString::new(s))
}

#[allow(clippy::disallowed_methods)]
mod expose {
    //! Localized `ExposeSecret` usage. Only this module and `oauth.rs` should
    //! call `.expose_secret()`. Other modules must route through here.
    use secrecy::{ExposeSecret, SecretString};

    pub(super) fn reveal(s: &SecretString) -> &str {
        s.expose_secret()
    }
}

/// OAuth credentials payload stored in the Keychain blob / `~/.claude/.credentials.json`.
///
/// Mirrors the shape Claude Code itself writes. The inner `claudeAiOauth` object
/// is what the Anthropic refresh / usage endpoints consume.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    #[serde(rename = "claudeAiOauth")]
    pub oauth: OAuthPayload,

    /// Preserve unknown top-level fields verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The OAuth block Claude Code writes.
///
/// Known fields are typed; anything else is preserved via [`extra`].
/// All token material is wrapped in [`SecretString`] so it never renders in
/// `Debug` / `Display`.
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthPayload {
    #[serde(
        rename = "accessToken",
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub access_token: SecretString,

    #[serde(
        rename = "refreshToken",
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub refresh_token: SecretString,

    /// Unix epoch in **milliseconds**.
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<i64>,

    #[serde(default)]
    pub scopes: Vec<String>,

    #[serde(default)]
    pub email: Option<String>,

    #[serde(rename = "subscriptionType", default)]
    pub subscription_type: Option<String>,

    #[serde(rename = "rateLimitTier", default)]
    pub rate_limit_tier: Option<String>,

    /// Preserve unknown OAuth fields verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl std::fmt::Debug for OAuthPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthPayload")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("email", &self.email)
            .field("subscription_type", &self.subscription_type)
            .field("rate_limit_tier", &self.rate_limit_tier)
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("oauth", &self.oauth)
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Error parsing / serializing credentials.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error("credentials are not valid UTF-8 JSON: {0}")]
    NotUtf8(#[from] std::str::Utf8Error),

    #[error("credentials are not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("missing refresh_token in stored credentials")]
    MissingRefreshToken,

    #[error("missing access_token in stored credentials")]
    MissingAccessToken,
}

impl Credentials {
    /// Parse credentials from their canonical JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CredentialsError> {
        let s = std::str::from_utf8(bytes)?;
        let parsed: Credentials = serde_json::from_str(s)?;
        if parsed.oauth.access_token().is_empty() {
            return Err(CredentialsError::MissingAccessToken);
        }
        if parsed.oauth.refresh_token().is_empty() {
            return Err(CredentialsError::MissingRefreshToken);
        }
        Ok(parsed)
    }

    /// Serialize to canonical JSON bytes (pretty, trailing newline).
    ///
    /// Canonical form is what we store in the Keychain and on disk. Parsing
    /// and re-serializing these bytes yields identical bytes (roundtrip
    /// invariant).
    pub fn to_bytes(&self) -> Result<Vec<u8>, CredentialsError> {
        let mut v = serde_json::to_vec_pretty(self)?;
        if !v.ends_with(b"\n") {
            v.push(b'\n');
        }
        Ok(v)
    }

    /// Canonical SHA-256 of the serialized form (used for cache / equality tests).
    pub fn sha256(&self) -> Result<Vec<u8>, CredentialsError> {
        let bytes = self.to_bytes()?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Ok(h.finalize().to_vec())
    }

    pub fn scopes_as_string(&self) -> String {
        self.oauth.scopes.join(" ")
    }

    /// Update token fields after a successful refresh, preserving unknown fields.
    pub fn apply_refresh(
        &mut self,
        access_token: SecretString,
        refresh_token: SecretString,
        expires_in_seconds: Option<f64>,
        scope_string: Option<&str>,
    ) {
        self.oauth.access_token = access_token;
        self.oauth.refresh_token = refresh_token;
        if let Some(secs) = expires_in_seconds {
            let ms = chrono::Utc::now().timestamp_millis() + (secs * 1000.0).round() as i64;
            self.oauth.expires_at = Some(ms);
        }
        if let Some(scope_str) = scope_string {
            let scopes: Vec<String> = scope_str
                .split_whitespace()
                .map(|s| s.to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            self.oauth.scopes = scopes;
        }
    }

    /// True when the access token is within `buffer_seconds` of expiry.
    pub fn needs_refresh(&self, buffer_seconds: i64) -> bool {
        match self.oauth.expires_at {
            None => true, // unknown -> play safe, refresh
            Some(ms) => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                now_ms + buffer_seconds * 1000 > ms
            }
        }
    }
}

impl OAuthPayload {
    /// Access-token bytes for HTTP requests. Kept inside `credentials.rs` so
    /// the `.expose_secret()` call is audited in exactly one place.
    pub fn access_token(&self) -> &str {
        expose::reveal(&self.access_token)
    }

    /// Refresh-token bytes for HTTP requests. Same audit boundary as above.
    pub fn refresh_token(&self) -> &str {
        expose::reveal(&self.refresh_token)
    }

    /// Wrap either token as a [`RedactedString`] for use in error messages.
    pub fn access_token_redacted(&self) -> RedactedString {
        RedactedString::new(self.access_token())
    }
}

impl Credentials {
    /// Produce a new `Credentials` with the given tokens. Useful for tests and
    /// for seeding a fresh slot. Leaves `extra` empty and defaults scopes to
    /// Anthropic's standard Claude Code scope set.
    pub fn new_with_defaults(access_token: &str, refresh_token: &str) -> Self {
        Credentials {
            oauth: OAuthPayload {
                access_token: SecretString::new(access_token.to_string()),
                refresh_token: SecretString::new(refresh_token.to_string()),
                expires_at: None,
                scopes: vec![
                    "user:profile".into(),
                    "user:inference".into(),
                    "user:sessions:claude_code".into(),
                    "user:mcp_servers".into(),
                ],
                email: None,
                subscription_type: None,
                rate_limit_tier: None,
                extra: Map::new(),
            },
            extra: Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_json() -> &'static str {
        r#"{
  "claudeAiOauth": {
    "accessToken": "at-abc",
    "refreshToken": "rt-xyz",
    "expiresAt": 1234567890000,
    "scopes": ["user:profile", "user:inference"],
    "email": "z@2lab.ai",
    "subscriptionType": "team",
    "rateLimitTier": "tier4"
  }
}
"#
    }

    #[test]
    fn parses_minimal() {
        let c = Credentials::from_bytes(minimal_json().as_bytes()).unwrap();
        assert_eq!(c.oauth.email.as_deref(), Some("z@2lab.ai"));
        assert_eq!(c.oauth.scopes.len(), 2);
    }

    #[test]
    fn roundtrip_idempotent() {
        let first = Credentials::from_bytes(minimal_json().as_bytes()).unwrap();
        let serialized = first.to_bytes().unwrap();
        let second = Credentials::from_bytes(&serialized).unwrap();
        let serialized2 = second.to_bytes().unwrap();
        assert_eq!(serialized, serialized2, "round-trip must be byte-identical");
    }

    #[test]
    fn preserves_unknown_top_level_field() {
        let input = r#"{
  "claudeAiOauth": {
    "accessToken": "at",
    "refreshToken": "rt",
    "scopes": []
  },
  "unknownTop": {"keep": true}
}
"#;
        let c = Credentials::from_bytes(input.as_bytes()).unwrap();
        assert!(c.extra.contains_key("unknownTop"));
        let out = String::from_utf8(c.to_bytes().unwrap()).unwrap();
        assert!(out.contains("unknownTop"));
        assert!(out.contains("\"keep\""));
    }

    #[test]
    fn preserves_unknown_oauth_field() {
        let input = r#"{
  "claudeAiOauth": {
    "accessToken": "at",
    "refreshToken": "rt",
    "scopes": [],
    "futureField": 42
  }
}
"#;
        let c = Credentials::from_bytes(input.as_bytes()).unwrap();
        assert!(c.oauth.extra.contains_key("futureField"));
        let out = String::from_utf8(c.to_bytes().unwrap()).unwrap();
        assert!(out.contains("futureField"));
    }

    #[test]
    fn debug_redacts_tokens() {
        let c = Credentials::from_bytes(minimal_json().as_bytes()).unwrap();
        let dbg = format!("{:?}", c);
        assert!(!dbg.contains("at-abc"));
        assert!(!dbg.contains("rt-xyz"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn missing_access_token_errors() {
        let input = r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"rt","scopes":[]}}"#;
        let err = Credentials::from_bytes(input.as_bytes()).unwrap_err();
        assert!(matches!(err, CredentialsError::MissingAccessToken));
    }

    #[test]
    fn needs_refresh_past_buffer() {
        let mut c = Credentials::new_with_defaults("at", "rt");
        // already expired
        c.oauth.expires_at = Some(chrono::Utc::now().timestamp_millis() - 1);
        assert!(c.needs_refresh(0));

        // expires in 1 hour, buffer is 7h -> needs refresh
        c.oauth.expires_at = Some(chrono::Utc::now().timestamp_millis() + 3_600_000);
        assert!(c.needs_refresh(7 * 3600));

        // expires in 10 hours, buffer is 7h -> no refresh
        c.oauth.expires_at = Some(chrono::Utc::now().timestamp_millis() + 10 * 3_600_000);
        assert!(!c.needs_refresh(7 * 3600));
    }
}
