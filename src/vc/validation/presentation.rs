//! `JwtPresentationValidator`.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use serde_json::Value;

use crate::did::{Uri, VerificationRelationship};
use crate::jose::{CompactJws, DefaultVerifier, JwsHeader, JwsVerifier};
use crate::vc::{CredentialError, Jwt, JwtClaims, Party, Presentation, PresentationV2, Subject};

use super::credential::{NO_TYP, check_controller, check_typ, decode, decode_v2};
use super::{
    DecodedCredential, DecodedCredentialV2, FailFast, JwtCredentialValidator, KeyResolver,
    PresentationValidationError, PresentationValidationOptions, StatusCheck,
    SubjectHolderRelationship, ValidationError,
};

/// A validated or decoded VCDM 1.1 presentation JWT: its header, its claims (custom ones
/// included), the presentation, and its credentials decoded.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecodedPresentation {
    /// The JWS header.
    pub header: JwsHeader,
    /// The claims set, `vp` included.
    pub claims: JwtClaims,
    /// The presentation, with `iss` and `jti` mapped back into it.
    pub presentation: Presentation,
    /// The presented credentials, in the order of `verifiableCredential`.
    pub credentials: Vec<DecodedCredential>,
}

impl DecodedPresentation {
    /// The holder: `holder` of the presentation, which decoding set from `iss`.
    pub fn holder(&self) -> Option<&Uri> {
        self.presentation.holder.as_ref().map(Party::id)
    }
}

/// A validated or decoded VCDM 2.0 presentation JWT (`vp+jwt`): its header, its claims, the
/// presentation, and its enveloped credentials unwrapped and decoded.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DecodedPresentationV2 {
    /// The JWS header.
    pub header: JwsHeader,
    /// The claims set, which is the presentation plus any registered claims.
    pub claims: JwtClaims,
    /// The presentation, with `iss` and `jti` mapped into `holder` and `id` when those are
    /// absent.
    pub presentation: PresentationV2,
    /// The presented credentials, in the order of `verifiableCredential`.
    pub credentials: Vec<DecodedCredentialV2>,
}

impl DecodedPresentationV2 {
    /// The holder: `holder` of the presentation, or `iss` when it has none.
    pub fn holder(&self) -> Option<&Uri> {
        self.presentation.holder.as_ref().map(Party::id)
    }
}

/// Validates presentation JWTs and the credential JWTs they carry, see the [module
/// documentation](super) for the checks.
///
/// Built over a [`JwtCredentialValidator`], which validates the credentials with the same key
/// resolver, verifier and status check.
///
/// Each profile has its own method, as for credentials: [`validate`](Self::validate) for the
/// VCDM 1.1 JWT profile (`typ` `JWT`, the `vp` claim, credentials as JWTs) and
/// [`validate_v2`](Self::validate_v2) for VCDM 2.0 secured with VC-JOSE-COSE (`typ`
/// `vp+jwt`, the payload is the presentation, credentials enveloped). Neither accepts the
/// other's `typ`. A verifier that takes both picks by `typ`:
///
/// ```
/// # #[cfg(feature = "did-key")]
/// # {
/// use identity_kit::jose::DefaultVerifier;
/// use identity_kit::methods::DidKey;
/// use identity_kit::resolver::Resolver;
/// use identity_kit::vc::validation::{JwtPresentationValidator, PresentationValidationOptions};
/// use identity_kit::vc::{Jwt, PresentationV2};
///
/// async fn holder_of(
///     validator: &JwtPresentationValidator<Resolver>,
///     jwt: &Jwt,
///     options: &PresentationValidationOptions,
/// ) -> Result<Option<String>, Box<dyn std::error::Error>> {
///     let holder = if jwt.decode()?.header().typ.as_deref() == Some(PresentationV2::JWT_TYP) {
///         validator.validate_v2(jwt, options).await?.holder().cloned()
///     } else {
///         validator.validate(jwt, options).await?.holder().cloned()
///     };
///     Ok(holder.map(|holder| holder.to_string()))
/// }
///
/// let resolver = Resolver::builder().with(DidKey::default()).build();
/// let _validator = JwtPresentationValidator::new(resolver, DefaultVerifier);
/// # }
/// ```
pub struct JwtPresentationValidator<R, V = DefaultVerifier> {
    credentials: JwtCredentialValidator<R, V>,
}

impl<R: KeyResolver, V: JwsVerifier> JwtPresentationValidator<R, V> {
    /// A validator resolving keys with `resolver` and verifying signatures with `verifier`,
    /// without a status check.
    pub fn new(resolver: R, verifier: V) -> Self {
        Self {
            credentials: JwtCredentialValidator::new(resolver, verifier),
        }
    }

    /// A validator over `credentials`, sharing its resolver, verifier and status check.
    pub fn from_credential_validator(credentials: JwtCredentialValidator<R, V>) -> Self {
        Self { credentials }
    }

    /// This validator checking `credentialStatus` with `check`.
    #[must_use]
    pub fn with_status_check(mut self, check: impl StatusCheck + 'static) -> Self {
        self.credentials = self.credentials.with_status_check(check);
        self
    }

    /// The credential validator.
    pub fn credential_validator(&self) -> &JwtCredentialValidator<R, V> {
        &self.credentials
    }

    /// Validates a presentation JWT and every credential it carries.
    ///
    /// # Errors
    ///
    /// A [`PresentationValidationError`] naming what failed: the presentation (in which case
    /// no credential was validated), or the credentials that failed, all of them under
    /// [`FailFast::AllErrors`].
    pub async fn validate(
        &self,
        jwt: &Jwt,
        options: &PresentationValidationOptions,
    ) -> Result<DecodedPresentation, PresentationValidationError> {
        let mut decoded = self
            .validate_presentation(jwt, options)
            .await
            .map_err(PresentationValidationError::presentation)?;
        let holder = decoded.holder().cloned();
        let mut errors = BTreeMap::new();
        for (index, credential) in decoded
            .presentation
            .verifiable_credential
            .iter()
            .enumerate()
        {
            let result = self
                .credentials
                .validate(credential, &options.credentials)
                .await
                .and_then(|validated| {
                    let credential = &validated.credential;
                    check_subject_holder(
                        &credential.properties,
                        credential.credential_subject.iter(),
                        holder.as_ref(),
                        options.subject_holder,
                    )?;
                    Ok(validated)
                });
            match result {
                Ok(validated) => decoded.credentials.push(validated),
                Err(error) => {
                    errors.insert(index, error);
                    if options.fail_fast == FailFast::FirstError {
                        break;
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(decoded)
        } else {
            Err(PresentationValidationError::credentials(errors))
        }
    }

    /// Validates a VCDM 2.0 presentation JWT secured with VC-JOSE-COSE and every credential
    /// it envelopes.
    ///
    /// The checks are those of [`validate`](Self::validate), with the profile's own shape:
    /// `typ`, when present, is `vp+jwt` (or one of `options.additional_typ`); the payload is
    /// the presentation, with `iss` and `jti` agreeing with `holder` and `id` and no `vp`
    /// claim; the holder, from `holder` or else `iss`, is required and is the DID of `kid`.
    /// Each credential is unwrapped from its `EnvelopedVerifiableCredential` and validated with
    /// [`JwtCredentialValidator::validate_v2`]; an envelope of another media type (an SD-JWT
    /// or COSE credential) fails for that credential alone.
    ///
    /// # Errors
    ///
    /// As [`validate`](Self::validate).
    pub async fn validate_v2(
        &self,
        jwt: &Jwt,
        options: &PresentationValidationOptions,
    ) -> Result<DecodedPresentationV2, PresentationValidationError> {
        let mut decoded = self
            .validate_presentation_v2(jwt, options)
            .await
            .map_err(PresentationValidationError::presentation)?;
        let holder = decoded.holder().cloned();
        let mut errors = BTreeMap::new();
        for (index, enveloped) in decoded
            .presentation
            .verifiable_credential
            .iter()
            .enumerate()
        {
            let result = match enveloped.to_jwt() {
                Ok(credential) => self
                    .credentials
                    .validate_v2(&credential, &options.credentials)
                    .await
                    .and_then(|validated| {
                        let credential = &validated.credential;
                        check_subject_holder(
                            &credential.properties,
                            credential.credential_subject.iter(),
                            holder.as_ref(),
                            options.subject_holder,
                        )?;
                        Ok(validated)
                    }),
                Err(error) => Err(error.into()),
            };
            match result {
                Ok(validated) => decoded.credentials.push(validated),
                Err(error) => {
                    errors.insert(index, error);
                    if options.fail_fast == FailFast::FirstError {
                        break;
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(decoded)
        } else {
            Err(PresentationValidationError::credentials(errors))
        }
    }

    /// Validates the presentation JWT itself; the credentials are left to decode.
    async fn validate_presentation(
        &self,
        jwt: &Jwt,
        options: &PresentationValidationOptions,
    ) -> Result<DecodedPresentation, ValidationError> {
        let jws = jwt.decode()?;
        check_typ(jws.header(), "JWT", &options.additional_typ)?;
        let claims: JwtClaims = serde_json::from_slice(jws.payload())
            .map_err(|e| ValidationError::Payload(e.to_string()))?;
        let presentation = Presentation::from_jwt_claims(&claims)?;
        self.check_holder_and_claims(&jws, presentation.holder.as_ref(), "iss", &claims, options)
            .await?;
        Ok(DecodedPresentation {
            header: jws.header().clone(),
            claims,
            presentation,
            credentials: Vec::new(),
        })
    }

    /// Validates the VCDM 2.0 presentation JWT itself; the credentials are left to unwrap.
    async fn validate_presentation_v2(
        &self,
        jwt: &Jwt,
        options: &PresentationValidationOptions,
    ) -> Result<DecodedPresentationV2, ValidationError> {
        let jws = jwt.decode()?;
        let (claims, presentation) = decode_payload_v2(&jws, &options.additional_typ)?;
        self.check_holder_and_claims(
            &jws,
            presentation.holder.as_ref(),
            "holder",
            &claims,
            options,
        )
        .await?;
        Ok(DecodedPresentationV2 {
            header: jws.header().clone(),
            claims,
            presentation,
            credentials: Vec::new(),
        })
    }

    /// The checks both profiles share once the payload is decoded: the signature under a key
    /// resolved for `authentication`, the holder (reported missing as `missing`) is the DID
    /// of `kid`, the time claims, the audience and the nonce.
    async fn check_holder_and_claims(
        &self,
        jws: &CompactJws,
        holder: Option<&Party>,
        missing: &'static str,
        claims: &JwtClaims,
        options: &PresentationValidationOptions,
    ) -> Result<(), ValidationError> {
        let kid = self
            .credentials
            .verify(jws, VerificationRelationship::Authentication)
            .await?;
        let holder = holder.ok_or(CredentialError::MissingClaim(missing))?;
        check_controller(holder, &kid, "holder")?;
        options.time.check_claims(claims)?;
        if let Some(expected) = &options.audience
            && !claims.audiences().any(|aud| aud == expected)
        {
            return Err(ValidationError::AudienceMismatch {
                expected: expected.clone(),
                found: claims.aud.clone(),
            });
        }
        if let Some(expected) = &options.nonce {
            let found = claims.additional.get("nonce").and_then(Value::as_str);
            if found != Some(expected.as_str()) {
                return Err(ValidationError::NonceMismatch {
                    expected: expected.clone(),
                    found: found.map(str::to_owned),
                });
            }
        }
        Ok(())
    }
}

impl<R: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for JwtPresentationValidator<R, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JwtPresentationValidator")
            .field("credentials", &self.credentials)
            .finish()
    }
}

/// Decodes a VCDM 1.1 presentation JWT and its credentials without verifying or validating
/// anything.
///
/// # Errors
///
/// [`ValidationError::Jws`], [`ValidationError::Payload`], [`ValidationError::UnexpectedTyp`]
/// or [`ValidationError::Credential`] when the token or one of its credentials does not decode.
pub fn decode_presentation(jwt: &Jwt) -> Result<DecodedPresentation, ValidationError> {
    decode_presentation_with(jwt, &NO_TYP, &NO_TYP)
}

/// [`decode_presentation`] also accepting `presentation_typ` on the presentation and
/// `credential_typ` on its credentials.
pub(crate) fn decode_presentation_with(
    jwt: &Jwt,
    presentation_typ: &BTreeSet<String>,
    credential_typ: &BTreeSet<String>,
) -> Result<DecodedPresentation, ValidationError> {
    let jws = jwt.decode()?;
    check_typ(jws.header(), "JWT", presentation_typ)?;
    let claims: JwtClaims = serde_json::from_slice(jws.payload())
        .map_err(|e| ValidationError::Payload(e.to_string()))?;
    let presentation = Presentation::from_jwt_claims(&claims)?;
    let credentials = presentation
        .verifiable_credential
        .iter()
        .map(|credential| decode(&credential.decode()?, credential_typ))
        .collect::<Result<_, _>>()?;
    Ok(DecodedPresentation {
        header: jws.header().clone(),
        claims,
        presentation,
        credentials,
    })
}

/// Decodes a VCDM 2.0 presentation JWT and unwraps and decodes its credentials without
/// verifying or validating anything.
///
/// # Errors
///
/// [`ValidationError::Jws`], [`ValidationError::Payload`], [`ValidationError::UnexpectedTyp`]
/// or [`ValidationError::Credential`] when the token, or one of its credentials, does not
/// decode; an envelope of a media type other than `application/vc+jwt` is a
/// [`CredentialError::UnsupportedMediaType`].
pub fn decode_presentation_v2(jwt: &Jwt) -> Result<DecodedPresentationV2, ValidationError> {
    let jws = jwt.decode()?;
    let (claims, presentation) = decode_payload_v2(&jws, &NO_TYP)?;
    let credentials = presentation
        .verifiable_credential
        .iter()
        .map(|enveloped| decode_v2(&enveloped.to_jwt()?.decode()?, &NO_TYP))
        .collect::<Result<_, _>>()?;
    Ok(DecodedPresentationV2 {
        header: jws.header().clone(),
        claims,
        presentation,
        credentials,
    })
}

/// The claims and presentation of a VCDM 2.0 presentation JWT whose `typ`, when present, is
/// `vp+jwt` or one of `additional_typ`.
fn decode_payload_v2(
    jws: &CompactJws,
    additional_typ: &BTreeSet<String>,
) -> Result<(JwtClaims, PresentationV2), ValidationError> {
    check_typ(jws.header(), PresentationV2::JWT_TYP, additional_typ)?;
    let claims: JwtClaims = serde_json::from_slice(jws.payload())
        .map_err(|e| ValidationError::Payload(e.to_string()))?;
    let presentation = PresentationV2::from_jwt_claims(&claims)?;
    Ok((claims, presentation))
}

/// Checks `subjects` of a credential with `properties` against `holder` per `relationship`.
fn check_subject_holder<'a>(
    properties: &IndexMap<String, Value>,
    subjects: impl Iterator<Item = &'a Subject>,
    holder: Option<&Uri>,
    relationship: SubjectHolderRelationship,
) -> Result<(), ValidationError> {
    let required = match relationship {
        SubjectHolderRelationship::AlwaysSubject => true,
        SubjectHolderRelationship::SubjectOnNonTransferable => properties
            .get("nonTransferable")
            .is_some_and(|value| value == &Value::Bool(true)),
        SubjectHolderRelationship::Any => false,
    };
    if !required {
        return Ok(());
    }
    // The presentation validator sets the holder before validating credentials.
    let holder = holder.expect("a validated presentation has a holder");
    for subject in subjects {
        if subject.id.as_ref() != Some(holder) {
            return Err(ValidationError::SubjectHolderMismatch {
                subject: subject.id.clone(),
                holder: holder.clone(),
            });
        }
    }
    Ok(())
}
