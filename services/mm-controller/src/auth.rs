//! Bearer-token verification for the REST API (SPEC-1 FR-29).
//!
//! The verifying key comes from **configuration**, not live OIDC discovery: an
//! HS256 shared secret (or, later, an injected RS256 public key). That keeps token
//! verification offline and deterministic — the integration tests mint their own
//! accepted tokens with the same secret, with no external identity provider. Full
//! OIDC/JWKS discovery is a later enhancement layered on this same seam.
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::authz::Claims;

/// Verifies and decodes the JWTs the control plane accepts.
pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl JwtVerifier {
    /// Build a verifier for HS256 tokens signed with `secret`. `exp` is enforced
    /// (with jsonwebtoken's default leeway); audience is not pinned for M2.
    pub fn hs256(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;
        Self {
            key: DecodingKey::from_secret(secret),
            validation,
        }
    }

    /// Verify a token's signature + expiry and return its claims, or an error if
    /// the signature is bad, the token is malformed, or it has expired.
    pub fn verify(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        decode::<Claims>(token, &self.key, &self.validation).map(|data| data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn token(secret: &[u8], sub: &str, exp: i64) -> String {
        let claims = Claims {
            sub: sub.into(),
            iss: "https://issuer".into(),
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
    fn accepts_a_valid_token_and_recovers_the_subject() {
        let secret = b"test-secret";
        let v = JwtVerifier::hs256(secret);
        // exp far in the future.
        let t = token(secret, "alice", 32_503_680_000);
        assert_eq!(v.verify(&t).unwrap().sub, "alice");
    }

    #[test]
    fn rejects_a_wrong_signature() {
        let v = JwtVerifier::hs256(b"the-real-secret");
        let t = token(b"a-different-secret", "mallory", 32_503_680_000);
        assert!(v.verify(&t).is_err());
    }

    #[test]
    fn rejects_an_expired_token() {
        let secret = b"test-secret";
        let v = JwtVerifier::hs256(secret);
        let t = token(secret, "alice", 1); // 1970 — long expired
        assert!(v.verify(&t).is_err());
    }
}
