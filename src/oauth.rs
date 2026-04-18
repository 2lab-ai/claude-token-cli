//! OAuth refresh + usage clients.
//!
//! This module is the only place (besides `credentials.rs`) allowed to call
//! `.expose_secret()` on the `SecretString` token fields. All error variants
//! carry a [`RedactedString`] so `Display` / `Debug` never leak token bytes.

#![deny(clippy::disallowed_methods)]

use std::time::Duration;

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;

use crate::redact::{scrub, RedactedString};

pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
pub const BETA_HEADER: (&str, &str) = ("anthropic-beta", "oauth-2025-04-20");
pub const USER_AGENT: &str = "claude-token-cli/0.1";

/// Parsed refresh response.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    #[serde(default)]
    pub expires_in: Option<f64>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// Usage bucket (single window).
#[derive(Debug, Clone, Default)]
pub struct Bucket {
    pub utilization: Option<f64>,
    pub resets_at: Option<DateTime<Utc>>,
}

/// Parsed usage response.
#[derive(Debug, Clone, Default)]
pub struct UsageSnapshot {
    pub five_hour: Option<Bucket>,
    pub seven_day: Option<Bucket>,
    pub seven_day_opus: Option<Bucket>,
    pub raw: serde_json::Value,
}

/// Usage call outcome: a snapshot or an `Unauthorized` signal that the
/// caller should refresh + retry.
#[derive(Debug)]
pub enum UsageResult {
    Ok(UsageSnapshot),
    Unauthorized,
}

/// Errors from this module. `Display` never contains raw tokens.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("network error: {0}")]
    Network(String),
    #[error("http {code}: {body}")]
    Status { code: u16, body: RedactedString },
    #[error("bad json: {0}")]
    BadJson(String),
    #[error("response missing access_token")]
    MissingToken,
}

fn build_client() -> Result<reqwest::blocking::Client, OAuthError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| OAuthError::Network(e.to_string()))
}

/// Shared `reqwest::blocking::Client` suitable for refresh + usage.
pub fn default_client() -> Result<reqwest::blocking::Client, OAuthError> {
    build_client()
}

/// POST `/v1/oauth/token` with `grant_type=refresh_token`.
pub fn refresh(
    client: &reqwest::blocking::Client,
    refresh_token: &SecretString,
) -> Result<TokenResponse, OAuthError> {
    refresh_to(client, TOKEN_URL, refresh_token)
}

/// Like [`refresh`] but lets the caller override the endpoint (test / mock).
pub fn refresh_to(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    refresh_token: &SecretString,
) -> Result<TokenResponse, OAuthError> {
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token.expose_secret(),
    });
    let resp = client
        .post(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header(BETA_HEADER.0, BETA_HEADER.1)
        .json(&body)
        .send()
        .map_err(|e| OAuthError::Network(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| OAuthError::Network(e.to_string()))?;

    if !status.is_success() {
        return Err(OAuthError::Status {
            code: status.as_u16(),
            body: RedactedString::new(scrub(&truncate_chars(&text, 200))),
        });
    }

    let parsed: TokenResponse =
        serde_json::from_str(&text).map_err(|e| OAuthError::BadJson(e.to_string()))?;
    if parsed.access_token.expose_secret().is_empty() {
        return Err(OAuthError::MissingToken);
    }
    Ok(parsed)
}

/// GET `api/oauth/usage`. Returns `Unauthorized` for 401 (caller should refresh).
pub fn usage(
    client: &reqwest::blocking::Client,
    access_token: &SecretString,
) -> Result<UsageResult, OAuthError> {
    usage_from(client, USAGE_URL, access_token)
}

/// Like [`usage`] but lets the caller override the endpoint.
pub fn usage_from(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    access_token: &SecretString,
) -> Result<UsageResult, OAuthError> {
    let resp = client
        .get(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header(BETA_HEADER.0, BETA_HEADER.1)
        .bearer_auth(access_token.expose_secret())
        .send()
        .map_err(|e| OAuthError::Network(e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 401 {
        return Ok(UsageResult::Unauthorized);
    }
    let text = resp
        .text()
        .map_err(|e| OAuthError::Network(e.to_string()))?;

    if !status.is_success() {
        return Err(OAuthError::Status {
            code: status.as_u16(),
            body: RedactedString::new(scrub(&truncate_chars(&text, 200))),
        });
    }
    let root: Value =
        serde_json::from_str(&text).map_err(|e| OAuthError::BadJson(e.to_string()))?;

    let snap = UsageSnapshot {
        five_hour: parse_bucket(root.get("five_hour")),
        seven_day: parse_bucket(root.get("seven_day")),
        seven_day_opus: parse_bucket(root.get("seven_day_opus")),
        raw: root,
    };
    Ok(UsageResult::Ok(snap))
}

fn parse_bucket(v: Option<&Value>) -> Option<Bucket> {
    let v = v?;
    if v.is_null() {
        return None;
    }
    let obj = v.as_object()?;
    let utilization = obj.get("utilization").and_then(|x| x.as_f64());
    let resets_at = obj
        .get("resets_at")
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    Some(Bucket {
        utilization,
        resets_at,
    })
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_never_leaks() {
        let err = OAuthError::Status {
            code: 400,
            body: RedactedString::new("raw rt-secret-xyz should not show"),
        };
        let shown = format!("{err}");
        assert!(!shown.contains("rt-secret-xyz"));
        assert!(shown.contains("[REDACTED]"));
    }

    #[test]
    fn parse_bucket_shape() {
        let v = serde_json::json!({
            "utilization": 12.5,
            "resets_at": "2026-04-18T12:00:00Z"
        });
        let b = parse_bucket(Some(&v)).unwrap();
        assert_eq!(b.utilization, Some(12.5));
        assert!(b.resets_at.is_some());
    }

    #[test]
    fn parse_bucket_handles_null() {
        let v = serde_json::Value::Null;
        assert!(parse_bucket(Some(&v)).is_none());
    }
}
