//! F1: byte-identical roundtrip.

use claude_token_cli::credentials::Credentials;
use claude_token_cli::keychain::{InMemoryFake, KeychainStore};

fn sample_json() -> &'static [u8] {
    br#"{
  "claudeAiOauth": {
    "accessToken": "at-12345",
    "refreshToken": "rt-67890",
    "expiresAt": 1735689600000,
    "scopes": [
      "user:profile",
      "user:inference"
    ],
    "email": "z@2lab.ai",
    "subscriptionType": "team",
    "rateLimitTier": "tier4",
    "futureField": 123
  },
  "topLevelUnknown": {
    "hello": "world"
  }
}
"#
}

#[test]
fn parse_serialize_is_byte_identical() {
    let original = sample_json();
    let parsed = Credentials::from_bytes(original).expect("parse sample");
    let serialized = parsed.to_bytes().expect("serialize");
    assert_eq!(
        serialized.as_slice(),
        original,
        "byte-identical roundtrip expected; got {}",
        String::from_utf8_lossy(&serialized)
    );
}

#[test]
fn idempotent_roundtrip_via_keychain() {
    let kc = InMemoryFake::new();
    let bytes = sample_json();
    kc.write("svc", "acct", bytes).unwrap();

    let read = kc.read("svc", "acct").unwrap().expect("present");
    let creds = Credentials::from_bytes(&read).expect("parse after kc roundtrip");
    let back = creds.to_bytes().expect("serialize after kc roundtrip");
    assert_eq!(back.as_slice(), bytes);

    // Write back out and round-trip one more time.
    kc.write("svc", "acct", &back).unwrap();
    let read2 = kc.read("svc", "acct").unwrap().unwrap();
    assert_eq!(read2.as_slice(), bytes);
}
