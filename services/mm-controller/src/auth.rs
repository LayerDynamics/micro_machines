//! Bearer-token verification for the REST API (SPEC-1 FR-29).
//!
//! The control plane accepts two kinds of token, chosen per request by the JWT's
//! `alg`/`kid` header:
//!
//! - **HS256** signed with a configured shared secret — for service/dev tokens and
//!   the integration tests, which mint their own accepted tokens offline.
//! - **RS256** verified against a **JWKS fetched from an OIDC issuer's discovery
//!   document** ([`fetch_oidc_jwks`]) — real identity-provider tokens, validated by
//!   `kid`, issuer, and expiry.
//!
//! At least one source must be configured. The verifier is pure (no IO); discovery
//! happens once at startup, so verification stays fast and deterministic.
use anyhow::Context;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

use crate::authz::Claims;

/// Verifies and decodes the JWTs the control plane accepts.
pub struct JwtVerifier {
    /// HS256 key, if a shared secret is configured.
    hs256: Option<DecodingKey>,
    /// RS256 keys by `kid`, from the OIDC JWKS.
    rs256: Vec<(String, DecodingKey)>,
    /// Expected `iss` for RS256 tokens (the OIDC issuer), if configured.
    issuer: Option<String>,
}

impl JwtVerifier {
    /// HS256-only verifier (the configured shared secret). Convenience for dev/tests.
    pub fn hs256(secret: &[u8]) -> Self {
        Self {
            hs256: Some(DecodingKey::from_secret(secret)),
            rs256: Vec::new(),
            issuer: None,
        }
    }

    /// Build a verifier from any combination of an HS256 secret and an OIDC JWKS
    /// (with its issuer). At least one source must be present, or this errors — a
    /// verifier that accepts nothing is a misconfiguration, not a valid state.
    pub fn new(
        hs256_secret: Option<&[u8]>,
        jwks: Option<&JwkSet>,
        issuer: Option<String>,
    ) -> anyhow::Result<Self> {
        let hs256 = hs256_secret.map(DecodingKey::from_secret);
        let mut rs256 = Vec::new();
        if let Some(jwks) = jwks {
            for jwk in &jwks.keys {
                let Some(kid) = jwk.common.key_id.clone() else {
                    continue; // a key with no kid can't be selected by token header
                };
                let key = DecodingKey::from_jwk(jwk)
                    .with_context(|| format!("building decoding key for kid {kid}"))?;
                rs256.push((kid, key));
            }
        }
        anyhow::ensure!(
            hs256.is_some() || !rs256.is_empty(),
            "no token verification configured: set an HS256 secret and/or an OIDC issuer"
        );
        Ok(Self {
            hs256,
            rs256,
            issuer,
        })
    }

    /// Verify a token's signature + claims and return them, selecting the key by the
    /// token's `alg` (HS256 → shared secret; RS256 → JWKS key matching `kid`).
    pub fn verify(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let header = decode_header(token)?;
        match header.alg {
            Algorithm::HS256 => {
                let key = self.hs256.as_ref().ok_or_else(|| {
                    jsonwebtoken::errors::Error::from(ErrorKind::InvalidAlgorithm)
                })?;
                let mut validation = Validation::new(Algorithm::HS256);
                validation.validate_aud = false;
                decode::<Claims>(token, key, &validation).map(|d| d.claims)
            }
            Algorithm::RS256 => {
                let kid = header
                    .kid
                    .ok_or_else(|| jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))?;
                let key = self
                    .rs256
                    .iter()
                    .find(|(k, _)| *k == kid)
                    .map(|(_, k)| k)
                    .ok_or_else(|| jsonwebtoken::errors::Error::from(ErrorKind::InvalidToken))?;
                let mut validation = Validation::new(Algorithm::RS256);
                validation.validate_aud = false;
                if let Some(issuer) = &self.issuer {
                    validation.set_issuer(&[issuer]);
                }
                decode::<Claims>(token, key, &validation).map(|d| d.claims)
            }
            _ => Err(jsonwebtoken::errors::Error::from(
                ErrorKind::InvalidAlgorithm,
            )),
        }
    }
}

/// Fetch an OIDC provider's JWKS via its discovery document
/// (`<issuer>/.well-known/openid-configuration` → `jwks_uri` → JWKS). Run once at
/// startup; the resulting [`JwkSet`] is handed to [`JwtVerifier::new`].
pub async fn fetch_oidc_jwks(issuer: &str) -> anyhow::Result<JwkSet> {
    let base = issuer.trim_end_matches('/');
    let http = reqwest::Client::new();
    let discovery: serde_json::Value = http
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .context("fetching OIDC discovery document")?
        .error_for_status()
        .context("OIDC discovery returned an error status")?
        .json()
        .await
        .context("parsing OIDC discovery document")?;
    let jwks_uri = discovery
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .context("OIDC discovery document has no jwks_uri")?;
    let jwks: JwkSet = http
        .get(jwks_uri)
        .send()
        .await
        .context("fetching JWKS")?
        .error_for_status()
        .context("JWKS endpoint returned an error status")?
        .json()
        .await
        .context("parsing JWKS")?;
    Ok(jwks)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{encode, EncodingKey, Header};

    use super::*;

    const ISSUER: &str = "https://issuer.test";

    fn hs_token(secret: &[u8], sub: &str, exp: i64) -> String {
        let claims = Claims {
            sub: sub.into(),
            iss: ISSUER.into(),
            aud: "mm".into(),
            exp,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn accepts_a_valid_hs256_token_and_recovers_the_subject() {
        let secret = b"test-secret";
        let v = JwtVerifier::hs256(secret);
        assert_eq!(
            v.verify(&hs_token(secret, "alice", 32_503_680_000))
                .unwrap()
                .sub,
            "alice"
        );
    }

    #[test]
    fn rejects_a_wrong_hs256_signature() {
        let v = JwtVerifier::hs256(b"the-real-secret");
        let t = hs_token(b"a-different-secret", "mallory", 32_503_680_000);
        assert!(v.verify(&t).is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let secret = b"test-secret";
        let v = JwtVerifier::hs256(secret);
        assert!(v.verify(&hs_token(secret, "alice", 1)).is_err());
    }

    #[test]
    fn empty_verifier_is_a_configuration_error() {
        assert!(JwtVerifier::new(None, None, None).is_err());
    }

    // --- RS256 via JWKS (OIDC) --------------------------------------------
    // A fixed 2048-bit RSA test key and the matching JWKS (kid "test-key").

    const RSA_PRIV: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDGDrjpVB7PdIOg\n2MHdNG687iXcoPNY6OG5pcwG+ZlS0r2Q9/SogiSIT4l8uAl5DSxoKal/bxbU/8G2\nLmAUjQFGOWECjAZWhOithciZpWLiSuZZwtdVDj/BE7LX5pf770L0cyscdFxCBTEK\nH160kSUuGd0SqF7s8p8MsdE5ifPH6gBxJGR56CdT40iMsC3P30CICeIS219YY7Xy\nNOmOhOQf1ExvwIPHHpVchzarHtBBGTTZxTO11zS1qpAjBl95a/zvJCiYVb3/RFx3\n9GwmVXPCxeDfuqwZzf8Ow9o659okcQWa/b7TvxUJ+4bEF+PSsuAUe6CPg6s897MG\n0k8JCk4HAgMBAAECggEANMlZuT5lU89vAaCj0swVs58ZUjtHgGvZNXyd60H8/lkS\nkx+zAnJlQDtKnoYCaFP9gOmRtlgqUqyzuVWU4AVQ0KGcXGxriAW2agEdHO46c6uY\nx1WpxI6eqVwRr39TBJ+ZTcOgOt48dJAjqNoBiMiiiy3zgPSFEEv93glKhTZiVeZt\nHm9BN4SRcxDpn93Pp/4OXqgAwh3ckPpH/0j+IWofcBx0q7aUPMCXNhrT/20I71UR\nz2Z5EleZTXid5LDc/fhBhJtA/GxPgTwnVJzCMtxZpSjvw0r+UU+4+0tFXL4zS5B5\nUO3k7kEqX6aQGo0mgELjGuC6rLjvaBGOXF0tJHx7oQKBgQDhc4U2t9MyHxR4u7MX\nGeIL6TmCBdcS4wB15tL3Ig+f17UbOhfe+dGmqwrxB77ZZxSOv/PoetHOPi8/c3rO\nlZj9Zj1tyZPz7f1S5qJCEgmT6aROO159jLFjS+tSnUQkr0xF1MJ52OWW6iGjVMUp\ntpwRMP1HfJvSe8U/i42DCu95UQKBgQDg5PbuOg+M2ENkTTkRpImqVB7Wpaqx/AWY\n7RLe4Yc1RTTx+vE8l2mDNYmMjkx7GpflzfPvKbeJerjOqn4K/kZony6cF8yXjd/7\nNT/VDK6IV9cXUkJzhNSVYqsG+mAv5iV0UXohycO4ECe+7LBKnSkfgFFB4ZBcpVYP\nNHTroCn71wKBgQDBMLujguxgU8+4EafKkOxqJoWYDKcbURhQ7+Yxzacz4qUX2rUf\n5lUoDAPJPUjmhPVRyd0Zhz2IDTNxnORMaFb8NYNIM+crrPFZ+7ZpBYndjOW2ABvd\nXBWZsDHLzmXZRboHUOUBgsJiiukeTALT1t5vwNoZSwc/273P0ScHdvR0sQKBgQCe\nl9iq1rbwk/GyYeLE1ktemkPFCr79FMS9uzF7i39VyaA0pMpJ+Fyn8rE1NYQpq+9C\nV6KWHc0YXjrFQuXvyrDMRrUPzpiwp5Q0CrEhBPhvncJI5/GElT90uUfye84o+Rug\nk3SVLzueKYZd1XvcokfFty+WTgMH0nCF+HAbWa9BsQKBgQDYtmsnv6YPYE+yjtlt\n0b0cWa5ENnVkJS+//jolDeeVyJHWthYmW9kkWIQNE0EQV4k0gNJGXHPDWSPC7jyx\nDoZEVSQPYrOzpg7RnOpzQfcd3EO4eO4euP7FWHw27Rp6LLmMSs79ngeT3WWDm84Y\nGSf7eXWw8QylSI+XKUkjWk4a1g==\n-----END PRIVATE KEY-----\n";

    const JWKS: &str = r#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"test-key","n":"xg646VQez3SDoNjB3TRuvO4l3KDzWOjhuaXMBvmZUtK9kPf0qIIkiE-JfLgJeQ0saCmpf28W1P_Bti5gFI0BRjlhAowGVoTorYXImaVi4krmWcLXVQ4_wROy1-aX--9C9HMrHHRcQgUxCh9etJElLhndEqhe7PKfDLHROYnzx-oAcSRkeegnU-NIjLAtz99AiAniEttfWGO18jTpjoTkH9RMb8CDxx6VXIc2qx7QQRk02cUztdc0taqQIwZfeWv87yQomFW9_0Rcd_RsJlVzwsXg37qsGc3_DsPaOufaJHEFmv2-078VCfuGxBfj0rLgFHugj4OrPPezBtJPCQpOBw","e":"AQAB"}]}"#;

    fn rs_token(sub: &str, iss: &str, kid: &str, exp: i64) -> String {
        let claims = Claims {
            sub: sub.into(),
            iss: iss.into(),
            aud: "mm".into(),
            exp,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(RSA_PRIV.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn oidc_verifier() -> JwtVerifier {
        let jwks: JwkSet = serde_json::from_str(JWKS).unwrap();
        JwtVerifier::new(None, Some(&jwks), Some(ISSUER.to_string())).unwrap()
    }

    #[test]
    fn accepts_rs256_token_via_jwks() {
        let v = oidc_verifier();
        let t = rs_token("alice", ISSUER, "test-key", 32_503_680_000);
        assert_eq!(v.verify(&t).unwrap().sub, "alice");
    }

    #[test]
    fn rejects_rs256_token_with_wrong_issuer() {
        let v = oidc_verifier();
        let t = rs_token("alice", "https://evil.example", "test-key", 32_503_680_000);
        assert!(v.verify(&t).is_err());
    }

    #[test]
    fn rejects_rs256_token_with_unknown_kid() {
        let v = oidc_verifier();
        let t = rs_token("alice", ISSUER, "some-other-kid", 32_503_680_000);
        assert!(v.verify(&t).is_err());
    }

    #[test]
    fn hs256_only_verifier_rejects_rs256_tokens() {
        let v = JwtVerifier::hs256(b"secret");
        let t = rs_token("alice", ISSUER, "test-key", 32_503_680_000);
        assert!(v.verify(&t).is_err());
    }

    /// Exercise the real discovery flow (`/.well-known/openid-configuration` →
    /// `jwks_uri` → JWKS) against a local HTTP server standing in for the OIDC
    /// provider, then verify a token against the fetched JWKS end to end.
    #[tokio::test]
    async fn fetches_jwks_via_oidc_discovery_and_verifies() {
        use axum::extract::State;
        use axum::routing::get;
        use axum::{Json, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let discovery = serde_json::json!({
            "issuer": ISSUER,
            "jwks_uri": format!("http://127.0.0.1:{port}/jwks"),
        });
        let jwks: serde_json::Value = serde_json::from_str(JWKS).unwrap();

        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(
                    |State((d, _)): State<(serde_json::Value, serde_json::Value)>| async move {
                        Json(d)
                    },
                ),
            )
            .route(
                "/jwks",
                get(
                    |State((_, j)): State<(serde_json::Value, serde_json::Value)>| async move {
                        Json(j)
                    },
                ),
            )
            .with_state((discovery, jwks));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let fetched = fetch_oidc_jwks(&format!("http://127.0.0.1:{port}"))
            .await
            .expect("fetch jwks via discovery");
        let verifier = JwtVerifier::new(None, Some(&fetched), Some(ISSUER.to_string())).unwrap();
        let token = rs_token("carol", ISSUER, "test-key", 32_503_680_000);
        assert_eq!(verifier.verify(&token).unwrap().sub, "carol");
    }
}
