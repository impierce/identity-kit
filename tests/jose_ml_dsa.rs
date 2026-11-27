//! ML-DSA in JOSE (RFC 9964): verification of the RFC 9964 Appendix A.1 JWS and of NIST ACVP
//! signatures (`tests/acvp/`), and the external μ of remote signers.

use identity_kit::jose::{
    CompactJws, DefaultVerifier, Jwk, JwkError, JwsAlgorithm, JwsVerifier as _, VerificationError,
    ml_dsa_external_mu,
};
#[cfg(feature = "ml-dsa")]
use identity_kit::jose::{JwsHeader, SignError, Signer, encode_compact};
#[cfg(feature = "ml-dsa")]
use serde_json::Value;

/// RFC 9964 Appendix A.1: the ML-DSA-44 key of the all-zero seed and a JWS it signed.
const RFC9964_A1_JWK: &str = include_str!("vectors/rfc9964/ml_dsa_44_jwk.json");
const RFC9964_A1_JWS: &str = include_str!("vectors/rfc9964/ml_dsa_44_jws.txt");

/// The public part of the RFC 9964 Appendix A.1 key.
fn rfc9964_public() -> Jwk {
    serde_json::from_str::<Jwk>(RFC9964_A1_JWK)
        .unwrap()
        .public()
}

fn rfc9964_jws() -> CompactJws {
    CompactJws::decode(RFC9964_A1_JWS.trim()).unwrap()
}

#[cfg(feature = "ml-dsa")]
/// One ACVP sigGen test case: its public key as an `AKP` JWK, and a hex field of it.
struct Acvp(Value);

#[cfg(feature = "ml-dsa")]
impl Acvp {
    fn load(json: &str) -> Self {
        Self(serde_json::from_str(json).unwrap())
    }

    fn bytes(&self, field: &str) -> Vec<u8> {
        hex(self.0["test"][field].as_str().unwrap())
    }

    fn public_jwk(&self, alg: JwsAlgorithm) -> Jwk {
        Jwk::from_ml_dsa_public(alg, &self.bytes("pk")).unwrap()
    }
}

#[cfg(feature = "ml-dsa")]
fn hex(digits: &str) -> Vec<u8> {
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
        .collect()
}

#[cfg(feature = "ml-dsa")]
#[test]
fn rfc9964_ml_dsa_44_verifies() {
    let jws = rfc9964_jws();

    let result = jws.verify(&DefaultVerifier, &rfc9964_public());

    assert_eq!(result, Ok(()));
}

#[cfg(feature = "ml-dsa")]
#[test]
fn acvp_ml_dsa_65_verifies() {
    let vector = Acvp::load(include_str!("acvp/ml_dsa_65_sig_gen_tc44.json"));

    let result = DefaultVerifier.verify(
        JwsAlgorithm::MlDsa65,
        &vector.bytes("message"),
        &vector.bytes("signature"),
        &vector.public_jwk(JwsAlgorithm::MlDsa65),
    );

    assert_eq!(result, Ok(()));
}

#[cfg(feature = "ml-dsa")]
#[test]
fn acvp_ml_dsa_87_verifies() {
    let vector = Acvp::load(include_str!("acvp/ml_dsa_87_sig_gen_tc70.json"));

    let result = DefaultVerifier.verify(
        JwsAlgorithm::MlDsa87,
        &vector.bytes("message"),
        &vector.bytes("signature"),
        &vector.public_jwk(JwsAlgorithm::MlDsa87),
    );

    assert_eq!(result, Ok(()));
}

#[cfg(feature = "ml-dsa")]
#[test]
fn ml_dsa_signature_of_the_wrong_length_is_invalid() {
    let jws = rfc9964_jws();
    let truncated = &jws.signature()[1..];

    let result = DefaultVerifier.verify(
        JwsAlgorithm::MlDsa44,
        jws.signing_input(),
        truncated,
        &rfc9964_public(),
    );

    assert_eq!(
        result,
        Err(VerificationError::InvalidSignatureLength {
            expected: 2420,
            actual: 2419,
        })
    );
}

#[cfg(feature = "ml-dsa")]
#[test]
fn altered_ml_dsa_signature_is_invalid() {
    let jws = rfc9964_jws();
    let mut altered = jws.signature().to_vec();
    altered[0] ^= 0x01;

    let result = DefaultVerifier.verify(
        JwsAlgorithm::MlDsa44,
        jws.signing_input(),
        &altered,
        &rfc9964_public(),
    );

    assert_eq!(result, Err(VerificationError::InvalidSignature));
}

#[test]
fn akp_key_refuses_another_alg() {
    let jws = rfc9964_jws();

    let result = DefaultVerifier.verify(
        JwsAlgorithm::MlDsa65,
        jws.signing_input(),
        jws.signature(),
        &rfc9964_public(),
    );

    assert_eq!(
        result,
        Err(VerificationError::AlgorithmMismatch {
            alg: JwsAlgorithm::MlDsa65,
            key_alg: "ML-DSA-44".to_owned(),
        })
    );
}

#[cfg(not(feature = "ml-dsa"))]
#[test]
fn ml_dsa_verification_without_the_feature_is_disabled() {
    let jws = rfc9964_jws();

    let result = jws.verify(&DefaultVerifier, &rfc9964_public());

    assert_eq!(
        result,
        Err(VerificationError::UnsupportedAlgorithm(
            JwsAlgorithm::MlDsa44
        ))
    );
}

// ---------------------------------------------------------------------------------------------
// External μ
// ---------------------------------------------------------------------------------------------

/// ML-DSA-44 tcId 5: deterministic, empty context, with its expanded private key.
#[cfg(feature = "ml-dsa")]
const ACVP_ML_DSA_44: &str = include_str!("acvp/ml_dsa_44_sig_gen_tc5.json");

/// The ACVP ML-DSA-44 key signing a precomputed μ deterministically, the way a remote signer
/// (AWS KMS `EXTERNAL_MU`) signs.
#[cfg(feature = "ml-dsa")]
struct ExternalMuSigner {
    key: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa44>,
}

#[cfg(feature = "ml-dsa")]
impl ExternalMuSigner {
    #[expect(
        deprecated,
        reason = "ACVP sigGen vectors give the expanded private key, not the seed"
    )]
    fn acvp() -> Self {
        let sk = Acvp::load(ACVP_ML_DSA_44).bytes("sk");
        let sk =
            ml_dsa::ExpandedSigningKeyBytes::<ml_dsa::MlDsa44>::try_from(sk.as_slice()).unwrap();
        Self {
            key: ml_dsa::ExpandedSigningKey::from_expanded(&sk),
        }
    }

    fn sign_mu(&self, mu: [u8; 64]) -> Vec<u8> {
        self.key.sign_mu_deterministic(&mu.into()).encode().to_vec()
    }
}

#[cfg(feature = "ml-dsa")]
#[async_trait::async_trait]
impl Signer for ExternalMuSigner {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::MlDsa44
    }

    fn kid(&self) -> Option<&str> {
        None
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        let public = Acvp::load(ACVP_ML_DSA_44).public_jwk(JwsAlgorithm::MlDsa44);
        let mu = ml_dsa_external_mu(&public, signing_input).map_err(SignError::new)?;
        Ok(self.sign_mu(mu))
    }
}

/// ACVP gives no μ for a message, so the deterministic signature over μ pins it: a different μ
/// gives a different signature.
#[cfg(feature = "ml-dsa")]
#[test]
fn acvp_external_mu_matches() {
    let vector = Acvp::load(ACVP_ML_DSA_44);
    let mu = ml_dsa_external_mu(
        &vector.public_jwk(JwsAlgorithm::MlDsa44),
        &vector.bytes("message"),
    )
    .unwrap();

    let signature = ExternalMuSigner::acvp().sign_mu(mu);

    assert_eq!(signature, vector.bytes("signature"));
}

#[cfg(feature = "ml-dsa")]
#[tokio::test]
async fn signature_over_external_mu_verifies_as_jws() {
    let token = encode_compact(
        &JwsHeader::new(JwsAlgorithm::MlDsa44),
        b"{\"iss\":\"did:example:issuer\"}",
        &ExternalMuSigner::acvp(),
    )
    .await
    .unwrap();

    let result = CompactJws::decode(&token).unwrap().verify(
        &DefaultVerifier,
        &Acvp::load(ACVP_ML_DSA_44).public_jwk(JwsAlgorithm::MlDsa44),
    );

    assert_eq!(result, Ok(()));
}

#[test]
fn external_mu_refuses_a_non_ml_dsa_key() {
    // RFC 8037 Appendix A.2.
    let ed25519: Jwk = serde_json::from_str(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )
    .unwrap();

    let result = ml_dsa_external_mu(&ed25519, b"");

    assert_eq!(
        result,
        Err(JwkError::UnexpectedKeyType {
            expected: "ML-DSA",
            kty: "OKP".to_owned(),
            crv: Some("Ed25519".to_owned()),
        })
    );
}

#[cfg(not(feature = "ml-dsa"))]
#[test]
fn external_mu_without_the_feature_is_disabled() {
    let result = ml_dsa_external_mu(&rfc9964_public(), b"");

    assert_eq!(
        result,
        Err(JwkError::FeatureDisabled {
            key: "ML-DSA",
            feature: "ml-dsa",
        })
    );
}
