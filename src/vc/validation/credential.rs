//! `JwtCredentialValidator`.

use std::collections::BTreeSet;

use crate::did::{Did, DidUrl, Uri, VerificationRelationship};
use crate::jose::{CompactJws, DefaultVerifier, JwsHeader, JwsVerifier};
use crate::vc::{Credential, CredentialV2, Jwt, JwtClaims, Party};

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{
    CredentialStatus, CredentialValidationOptions, KeyResolver, StatusCheck, StatusPolicy,
    ValidationError, check_statuses,
};

/// A validated or decoded VCDM 1.1 credential JWT: its header, its claims (custom ones
/// included) and the credential they map to.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecodedCredential {
    /// The JWS header.
    pub header: JwsHeader,
    /// The claims set, `vc` included.
    pub claims: JwtClaims,
    /// The credential, with the registered claims mapped back into it.
    pub credential: Credential,
}

/// A validated or decoded VCDM 2.0 credential JWT: its header, its claims and the credential.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecodedCredentialV2 {
    /// The JWS header.
    pub header: JwsHeader,
    /// The claims set, which is the credential plus any registered claims.
    pub claims: JwtClaims,
    /// The credential.
    pub credential: CredentialV2,
}

/// Validates credential JWTs, see the [module documentation](super) for the checks.
///
/// # Examples
///
/// A `did:key` issuer signs a credential about a subject, and the verifier validates it with a
/// resolver that knows `did:key`.
///
/// ```
/// # #[cfg(feature = "did-key")]
/// # {
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::did::Uri;
/// use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, SignError, Signer};
/// use identity_kit::methods::DidKey;
/// use identity_kit::resolver::Resolver;
/// use identity_kit::vc::validation::{CredentialValidationOptions, JwtCredentialValidator, TimeOptions};
/// use identity_kit::vc::{Credential, Jwt, Subject};
///
/// // The Ed25519 key of RFC 8037 Appendix A.1 behind a `Signer`.
/// struct Issuer(ed25519_dalek::SigningKey);
///
/// #[async_trait::async_trait]
/// impl Signer for Issuer {
///     fn alg(&self) -> JwsAlgorithm { JwsAlgorithm::EdDSA }
///     fn kid(&self) -> Option<&str> { None }
///     async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, SignError> {
///         use ed25519_dalek::Signer as _;
///         Ok(self.0.sign(input).to_bytes().to_vec())
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let secret: [u8; 32] = identity_kit::jose::Jwk::from_ed25519_public(&[0; 32]).map(|_| [
///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
///     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
/// ])?;
/// let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
/// let jwk = Jwk::from_ed25519_public(signing_key.verifying_key().as_bytes())?;
/// let issuer = DidKey::did(&jwk)?;
/// let kid = issuer.join(&format!("#{}", issuer.method_specific_id()))?;
///
/// let credential = Credential::new(
///     &issuer,
///     Utc.with_ymd_and_hms(2010, 1, 1, 0, 0, 0).unwrap(),
///     Subject::new(Uri::parse("did:example:ebfeb1f712ebc6f1c276e12ec21")?),
/// );
/// let header = JwsHeader::new(JwsAlgorithm::EdDSA).with_typ("JWT").with_kid(kid.as_str());
/// let jwt = Jwt::sign(&header, &credential.to_jwt_claims()?, &Issuer(signing_key)).await?;
///
/// let resolver = Resolver::builder().with(DidKey::default()).build();
/// let validator = JwtCredentialValidator::new(resolver, DefaultVerifier);
/// let options = CredentialValidationOptions::new()
///     .with_time(TimeOptions::at(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()));
/// let decoded = validator.validate(&jwt, &options).await?;
/// assert_eq!(decoded.credential, credential);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct JwtCredentialValidator<R, V = DefaultVerifier> {
    resolver: R,
    verifier: V,
    status: Option<Box<dyn StatusCheck>>,
}

impl<R: KeyResolver, V: JwsVerifier> JwtCredentialValidator<R, V> {
    /// A validator resolving keys with `resolver` and verifying signatures with `verifier`,
    /// without a status check.
    pub fn new(resolver: R, verifier: V) -> Self {
        Self {
            resolver,
            verifier,
            status: None,
        }
    }

    /// This validator checking `credentialStatus` with `check`.
    #[must_use]
    pub fn with_status_check(mut self, check: impl StatusCheck + 'static) -> Self {
        self.status = Some(Box::new(check));
        self
    }

    /// The key resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// The signature verifier.
    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    /// Whether a status check is configured.
    pub fn has_status_check(&self) -> bool {
        self.status.is_some()
    }

    /// Validates a VCDM 1.1 credential JWT.
    ///
    /// # Errors
    ///
    /// The first [`ValidationError`] found, in the order the [module documentation](super)
    /// lists the checks.
    pub async fn validate(
        &self,
        jwt: &Jwt,
        options: &CredentialValidationOptions,
    ) -> Result<DecodedCredential, ValidationError> {
        let jws = jwt.decode()?;
        let decoded = decode(&jws, &options.additional_typ)?;
        let kid = self
            .verify(&jws, VerificationRelationship::AssertionMethod)
            .await?;
        check_controller(&decoded.credential.issuer, &kid, "issuer")?;
        options.time.check_claims(&decoded.claims)?;
        options.time.check(
            Some(decoded.credential.issuance_date),
            decoded.credential.expiration_date,
            None,
        )?;
        self.check_status(
            decoded
                .credential
                .credential_status
                .iter()
                .map(CredentialStatus::Vcdm),
            options.status,
            options.time.now(),
        )
        .await?;
        Ok(decoded)
    }

    /// Validates a VCDM 2.0 credential JWT, whose `typ` is `vc+jwt` when present.
    ///
    /// # Errors
    ///
    /// As [`validate`](Self::validate).
    pub async fn validate_v2(
        &self,
        jwt: &Jwt,
        options: &CredentialValidationOptions,
    ) -> Result<DecodedCredentialV2, ValidationError> {
        let jws = jwt.decode()?;
        let decoded = decode_v2(&jws, &options.additional_typ)?;
        let kid = self
            .verify(&jws, VerificationRelationship::AssertionMethod)
            .await?;
        check_controller(&decoded.credential.issuer, &kid, "issuer")?;
        options.time.check_claims(&decoded.claims)?;
        options.time.check(
            decoded.credential.valid_from,
            decoded.credential.valid_until,
            None,
        )?;
        self.check_status(
            decoded.credential.statuses().map(CredentialStatus::Vcdm),
            options.status,
            options.time.now(),
        )
        .await?;
        Ok(decoded)
    }

    /// Resolves the key of `jws` under `relationship` and verifies the signature; the `kid`.
    pub(super) async fn verify(
        &self,
        jws: &CompactJws,
        relationship: VerificationRelationship,
    ) -> Result<DidUrl, ValidationError> {
        let kid = jws.kid().ok_or(ValidationError::MissingKid)?;
        let kid = DidUrl::parse(kid).map_err(|source| ValidationError::InvalidKid {
            kid: kid.to_owned(),
            source,
        })?;
        if kid.path().is_some() || kid.query().is_some() {
            return Err(ValidationError::KidWithParameters(kid));
        }
        let key = self
            .resolver
            .resolve_key(&kid, relationship)
            .await
            .map_err(|source| ValidationError::KeyResolution {
                kid: kid.clone(),
                source,
            })?;
        jws.verify(&self.verifier, &key)?;
        Ok(kid)
    }

    /// Checks every status entry with this validator's check, per `policy`, at `now`.
    pub(super) async fn check_status<'a>(
        &self,
        statuses: impl IntoIterator<Item = CredentialStatus<'a>>,
        policy: StatusPolicy,
        now: DateTime<Utc>,
    ) -> Result<(), ValidationError> {
        check_statuses(self.status.as_deref(), statuses, policy, now).await
    }
}

impl<R: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for JwtCredentialValidator<R, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JwtCredentialValidator")
            .field("resolver", &self.resolver)
            .field("verifier", &self.verifier)
            .field("status", &self.status.as_ref().map(|_| "StatusCheck"))
            .finish()
    }
}

/// Decodes a VCDM 1.1 credential JWT without verifying or validating anything.
///
/// # Errors
///
/// [`ValidationError::Jws`], [`ValidationError::Payload`], [`ValidationError::UnexpectedTyp`]
/// or [`ValidationError::Credential`] when the token does not decode to a credential, and
/// [`ValidationError::SdJwtPayload`] when it is the issuer-signed JWT of an SD-JWT.
pub fn decode_credential(jwt: &Jwt) -> Result<DecodedCredential, ValidationError> {
    decode(&jwt.decode()?, &NO_TYP)
}

/// Decodes a VCDM 2.0 credential JWT without verifying or validating anything.
///
/// # Errors
///
/// As [`decode_credential`].
pub fn decode_credential_v2(jwt: &Jwt) -> Result<DecodedCredentialV2, ValidationError> {
    decode_v2(&jwt.decode()?, &NO_TYP)
}

/// No `typ` besides the profile's own.
pub(super) static NO_TYP: BTreeSet<String> = BTreeSet::new();

/// Decodes a VCDM 1.1 credential JWT whose `typ`, when present, is `JWT` or one of
/// `additional_typ`.
pub(super) fn decode(
    jws: &CompactJws,
    additional_typ: &BTreeSet<String>,
) -> Result<DecodedCredential, ValidationError> {
    check_typ(jws.header(), "JWT", additional_typ)?;
    let claims = plain_claims(jws)?;
    let credential = Credential::from_jwt_claims(&claims)?;
    Ok(DecodedCredential {
        header: jws.header().clone(),
        claims,
        credential,
    })
}

/// Decodes a VCDM 2.0 credential JWT: `typ` is `vc+jwt` when present (VC-JOSE-COSE §3.1.1),
/// or one of `additional_typ`, so a token typed for another purpose is never read as a
/// credential.
pub(super) fn decode_v2(
    jws: &CompactJws,
    additional_typ: &BTreeSet<String>,
) -> Result<DecodedCredentialV2, ValidationError> {
    check_typ(jws.header(), CredentialV2::JWT_TYP, additional_typ)?;
    let claims = plain_claims(jws)?;
    let credential = CredentialV2::from_jwt_claims(&claims)?;
    Ok(DecodedCredentialV2 {
        header: jws.header().clone(),
        claims,
        credential,
    })
}

/// The claims set of `jws`, refused when it is the issuer-signed JWT of an SD-JWT: see
/// [`ValidationError::SdJwtPayload`].
pub(super) fn plain_claims(jws: &CompactJws) -> Result<JwtClaims, ValidationError> {
    let claims: JwtClaims = serde_json::from_slice(jws.payload())
        .map_err(|e| ValidationError::Payload(e.to_string()))?;
    match claims
        .additional
        .iter()
        .find_map(|(name, value)| sd_jwt_member(name, value))
    {
        Some(claim) => Err(ValidationError::SdJwtPayload { claim }),
        None => Ok(claims),
    }
}

/// The names RFC 9901 §4.2 reserves in the payload of an SD-JWT: `_sd` and `_sd_alg` as
/// member names, and `...` as the one member of an array element standing for a digest.
const SD_JWT_NAMES: [&str; 2] = ["_sd", "_sd_alg"];
const ELLIPSIS: &str = "...";

/// The SD-JWT name the member `name` with `value` is, or holds anywhere below it. serde_json
/// limits the nesting of a parsed payload, so the recursion is bounded.
fn sd_jwt_member(name: &str, value: &Value) -> Option<&'static str> {
    SD_JWT_NAMES
        .into_iter()
        .find(|reserved| *reserved == name)
        .or_else(|| sd_jwt_name_in(value))
}

/// As [`sd_jwt_member`], for the members and elements of `value`.
fn sd_jwt_name_in(value: &Value) -> Option<&'static str> {
    match value {
        Value::Object(object) => object
            .iter()
            .find_map(|(name, value)| sd_jwt_member(name, value)),
        Value::Array(array) => array.iter().find_map(|element| match element {
            Value::Object(object)
                if object.len() == 1 && object.get(ELLIPSIS).is_some_and(Value::is_string) =>
            {
                Some(ELLIPSIS)
            }
            element => sd_jwt_name_in(element),
        }),
        _ => None,
    }
}

/// Rejects a header `typ` other than `expected` and `additional`, when one is present.
pub(super) fn check_typ(
    header: &JwsHeader,
    expected: &'static str,
    additional: &BTreeSet<String>,
) -> Result<(), ValidationError> {
    match header.typ.as_deref() {
        Some(found) if found != expected && !additional.contains(found) => {
            Err(ValidationError::UnexpectedTyp {
                expected,
                found: found.to_owned(),
            })
        }
        _ => Ok(()),
    }
}

/// Checks that `party` is the DID of `kid`, the controller of the signing key.
pub(super) fn check_controller(
    party: &Party,
    kid: &DidUrl,
    role: &'static str,
) -> Result<(), ValidationError> {
    let id = party.id();
    let did = Did::parse(id.as_str()).map_err(|_| ValidationError::NotDid {
        role,
        id: id.to_string(),
    })?;
    if did != *kid.did() {
        return Err(mismatch(role, id.clone(), kid.clone()));
    }
    Ok(())
}

/// The mismatch error for `role`.
fn mismatch(role: &'static str, id: Uri, kid: DidUrl) -> ValidationError {
    if role == "holder" {
        ValidationError::HolderMismatch { holder: id, kid }
    } else {
        ValidationError::IssuerMismatch { issuer: id, kid }
    }
}
