//! Keys and signers shared by the integration tests: the RFC 8037 Appendix A.1 Ed25519 key and
//! the RFC 7515 Appendix A.3 P-256 key, behind `Signer`.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_kit::jose::{Jwk, JwsAlgorithm, SignError, Signer};
use serde_json::json;

/// RFC 8037 Appendix A.1.
pub(crate) const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
pub(crate) const RFC8037_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

/// RFC 7515 Appendix A.3.
pub(crate) const RFC7515_A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
pub(crate) const RFC7515_A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
pub(crate) const RFC7515_A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

pub(crate) fn decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) struct Ed25519Signer {
    pub(crate) key: ed25519_dalek::SigningKey,
    pub(crate) kid: Option<String>,
}

impl Ed25519Signer {
    /// The RFC 8037 key.
    pub(crate) fn rfc8037() -> Self {
        let d: [u8; 32] = decode(RFC8037_D).try_into().unwrap();
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&d),
            kid: None,
        }
    }

    pub(crate) fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    pub(crate) fn public_jwk(&self) -> Jwk {
        Jwk::from_ed25519_public(self.key.verifying_key().as_bytes()).unwrap()
    }
}

#[async_trait::async_trait]
impl Signer for Ed25519Signer {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::EdDSA
    }

    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(signing_input).to_bytes().to_vec())
    }
}

pub(crate) struct Es256Signer {
    pub(crate) key: p256::ecdsa::SigningKey,
    pub(crate) kid: Option<String>,
}

impl Es256Signer {
    /// The RFC 7515 A.3 key.
    pub(crate) fn rfc7515_a3() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::from_slice(&decode(RFC7515_A3_D)).unwrap(),
            kid: None,
        }
    }

    pub(crate) fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same shape as the other signers' `public_jwk`"
    )]
    pub(crate) fn public_jwk(&self) -> Jwk {
        serde_json::from_value(json!({
            "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
        }))
        .unwrap()
    }
}

#[async_trait::async_trait]
impl Signer for Es256Signer {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::ES256
    }

    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = self.key.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

/// A compact JWS of `header` and `payload` with a placeholder signature: enough to parse and
/// process an SD-JWT whose signature is not under test.
pub(crate) fn unsigned_jwt(header: &serde_json::Value, payload: &serde_json::Value) -> String {
    format!(
        "{}.{}.{}",
        encode(serde_json::to_string(header).unwrap().as_bytes()),
        encode(serde_json::to_string(payload).unwrap().as_bytes()),
        encode(&[0u8; 64])
    )
}
