//! wiremock-based tests for the refresh flow.

use claude_token_cli::credentials::Credentials;
use claude_token_cli::oauth::{self, OAuthError};
use secrecy::SecretString;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn build_client() -> reqwest::blocking::Client {
    oauth::default_client().unwrap()
}

/// Returns `true` if the current environment can bind a TCP listener.
/// Used to skip wiremock tests in restricted sandboxes (e.g. seatbelt);
/// full CI environments bind successfully and run the tests normally.
fn can_bind_loopback() -> bool {
    std::net::TcpListener::bind("127.0.0.1:0").is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_happy_path() {
    if !can_bind_loopback() {
        eprintln!("skipping: sandbox blocks TCP listen");
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-new",
            "refresh_token": "rt-new",
            "expires_in": 3600.0,
            "scope": "user:profile user:inference",
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/v1/oauth/token", server.uri());
    let rt = SecretString::new("rt-old".to_string());
    let client = build_client();

    let token = tokio::task::spawn_blocking(move || oauth::refresh_to(&client, &endpoint, &rt))
        .await
        .unwrap()
        .unwrap();

    // Apply to credentials and verify.
    let mut creds = Credentials::new_with_defaults("at-old", "rt-old");
    creds.apply_refresh(
        token.access_token,
        token.refresh_token,
        token.expires_in,
        token.scope.as_deref(),
    );
    assert_eq!(creds.oauth.access_token(), "at-new");
    assert_eq!(creds.oauth.refresh_token(), "rt-new");
    assert!(creds.oauth.expires_at.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_rotates_refresh_token() {
    if !can_bind_loopback() {
        eprintln!("skipping: sandbox blocks TCP listen");
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-new",
            "refresh_token": "rt-rotated",
            "expires_in": 3600.0,
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/v1/oauth/token", server.uri());
    let rt = SecretString::new("rt-old".to_string());
    let client = build_client();

    let token = tokio::task::spawn_blocking(move || oauth::refresh_to(&client, &endpoint, &rt))
        .await
        .unwrap()
        .unwrap();

    use secrecy::ExposeSecret;
    #[allow(clippy::disallowed_methods)]
    let rot = token.refresh_token.expose_secret().to_string();
    assert_eq!(rot, "rt-rotated", "rotated refresh_token must differ");
    assert_ne!(rot, "rt-old");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_400_body_is_scrubbed() {
    if !can_bind_loopback() {
        eprintln!("skipping: sandbox blocks TCP listen");
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("invalid refresh token: rt-secret-xyz and key sk-ant-leak-abc"),
        )
        .mount(&server)
        .await;

    let endpoint = format!("{}/v1/oauth/token", server.uri());
    let rt = SecretString::new("rt-secret-xyz".to_string());
    let client = build_client();

    let err = tokio::task::spawn_blocking(move || oauth::refresh_to(&client, &endpoint, &rt))
        .await
        .unwrap()
        .unwrap_err();

    assert!(matches!(err, OAuthError::Status { code: 400, .. }));
    let shown = format!("{err}");
    let dbg = format!("{err:?}");
    assert!(
        !shown.contains("rt-secret-xyz"),
        "Display leaks refresh: {shown}"
    );
    assert!(
        !shown.contains("sk-ant-"),
        "Display contains sk-ant: {shown}"
    );
    assert!(!dbg.contains("rt-secret-xyz"), "Debug leaks refresh: {dbg}");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_500_errors() {
    if !can_bind_loopback() {
        eprintln!("skipping: sandbox blocks TCP listen");
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/oauth/token"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let endpoint = format!("{}/v1/oauth/token", server.uri());
    let rt = SecretString::new("rt".to_string());
    let client = build_client();

    let err = tokio::task::spawn_blocking(move || oauth::refresh_to(&client, &endpoint, &rt))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, OAuthError::Status { code: 500, .. }));
}
