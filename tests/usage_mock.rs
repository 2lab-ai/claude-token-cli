//! wiremock-based tests for the usage flow.

use claude_token_cli::oauth::{self, OAuthError, UsageResult};
use secrecy::SecretString;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_client() -> reqwest::blocking::Client {
    oauth::default_client().unwrap()
}

/// Returns `true` if the current environment can bind a TCP listener.
/// Used to skip wiremock tests in restricted sandboxes.
fn can_bind_loopback() -> bool {
    std::net::TcpListener::bind("127.0.0.1:0").is_ok()
}

macro_rules! skip_if_sandboxed {
    () => {
        if !can_bind_loopback() {
            eprintln!("skipping: sandbox blocks TCP listen");
            return;
        }
    };
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_200_parses_buckets() {
    skip_if_sandboxed!();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/oauth/usage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "five_hour": { "utilization": 50.0, "resets_at": "2026-04-18T12:00:00Z" },
            "seven_day": { "utilization": 12.5, "resets_at": "2026-04-25T12:00:00Z" },
            "seven_day_opus": { "utilization": 3.0, "resets_at": "2026-04-25T12:00:00Z" },
            "email": "e@x.com"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/api/oauth/usage", server.uri());
    let at = SecretString::new("at-ok".to_string());
    let client = build_client();

    let result = tokio::task::spawn_blocking(move || oauth::usage_from(&client, &endpoint, &at))
        .await
        .unwrap()
        .unwrap();
    match result {
        UsageResult::Ok(snap) => {
            let five = snap.five_hour.unwrap();
            assert_eq!(five.utilization, Some(50.0));
            assert!(five.resets_at.is_some());
            assert!(snap.seven_day.is_some());
            assert!(snap.seven_day_opus.is_some());
        }
        _ => panic!("expected UsageResult::Ok"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_401_returns_unauthorized() {
    skip_if_sandboxed!();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/oauth/usage"))
        .respond_with(ResponseTemplate::new(401).set_body_string("no"))
        .mount(&server)
        .await;

    let endpoint = format!("{}/api/oauth/usage", server.uri());
    let at = SecretString::new("at-bad".to_string());
    let client = build_client();

    let result = tokio::task::spawn_blocking(move || oauth::usage_from(&client, &endpoint, &at))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, UsageResult::Unauthorized));
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_401_then_refresh_then_200() {
    // Orchestrate: first usage call 401, refresh returns fresh creds,
    // second usage call (with new token) returns 200.
    skip_if_sandboxed!();
    let server = MockServer::start().await;

    // First usage -> 401
    Mock::given(method("GET"))
        .and(path("/api/oauth/usage"))
        .and(wiremock::matchers::header("authorization", "Bearer at-old"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    // Refresh -> rotated token
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-fresh",
            "refresh_token": "rt-fresh",
            "expires_in": 3600.0
        })))
        .mount(&server)
        .await;

    // Second usage with new token -> 200
    Mock::given(method("GET"))
        .and(path("/api/oauth/usage"))
        .and(wiremock::matchers::header(
            "authorization",
            "Bearer at-fresh",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "five_hour": { "utilization": 11.0, "resets_at": "2026-04-18T12:00:00Z" }
        })))
        .mount(&server)
        .await;

    let usage_ep = format!("{}/api/oauth/usage", server.uri());
    let refresh_ep = format!("{}/v1/oauth/token", server.uri());

    let client = build_client();
    let old_at = SecretString::new("at-old".to_string());
    let old_rt = SecretString::new("rt-old".to_string());

    let result = tokio::task::spawn_blocking(move || {
        let first = oauth::usage_from(&client, &usage_ep, &old_at)?;
        assert!(matches!(first, UsageResult::Unauthorized));

        let token = oauth::refresh_to(&client, &refresh_ep, &old_rt)?;
        let second = oauth::usage_from(&client, &usage_ep, &token.access_token)?;
        Ok::<_, OAuthError>(second)
    })
    .await
    .unwrap()
    .unwrap();

    match result {
        UsageResult::Ok(snap) => {
            assert_eq!(snap.five_hour.unwrap().utilization, Some(11.0));
        }
        _ => panic!("expected Ok"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_401_refresh_fails_keeps_secrets_clean() {
    skip_if_sandboxed!();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/oauth/usage"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("invalid: rt-secret-xyz access at-secret-xyz"),
        )
        .mount(&server)
        .await;

    let usage_ep = format!("{}/api/oauth/usage", server.uri());
    let refresh_ep = format!("{}/v1/oauth/token", server.uri());
    let client = build_client();
    let at = SecretString::new("at-secret-xyz".to_string());
    let rt = SecretString::new("rt-secret-xyz".to_string());

    let err = tokio::task::spawn_blocking(move || {
        let first = oauth::usage_from(&client, &usage_ep, &at)?;
        assert!(matches!(first, UsageResult::Unauthorized));
        let err = oauth::refresh_to(&client, &refresh_ep, &rt).unwrap_err();
        Ok::<_, OAuthError>(err)
    })
    .await
    .unwrap()
    .unwrap();

    let d = format!("{err}");
    let dbg = format!("{err:?}");
    for tok in ["at-secret-xyz", "rt-secret-xyz"] {
        assert!(!d.contains(tok), "Display leaks {tok}: {d}");
        assert!(!dbg.contains(tok), "Debug leaks {tok}: {dbg}");
    }
}
