//! `JwtPresentationValidator`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::did::{Uri, VerificationRelationship};
use crate::jose::{DefaultVerifier, JwsHeader, JwsVerifier};
use crate::vc::{Jwt, JwtClaims, Party, Presentation};

use super::credential::{NO_TYP, check_controller, check_typ, decode};
use super::{
    DecodedCredential, FailFast, JwtCredentialValidator, KeyResolver, PresentationValidationError,
    PresentationValidationOptions, StatusCheck, SubjectHolderRelationship, ValidationError,
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

/// Validates presentation JWTs and the credential JWTs they carry, see the [module
/// documentation](super) for the checks.
///
/// Built over a [`JwtCredentialValidator`], which validates the credentials with the same key
/// resolver, verifier and status check.
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
                    check_subject_holder(&validated, holder.as_ref(), options.subject_holder)?;
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
        let kid = self
            .credentials
            .verify(&jws, VerificationRelationship::Authentication)
            .await?;
        let holder = presentation
            .holder
            .as_ref()
            .ok_or(crate::vc::CredentialError::MissingClaim("iss"))?;
        check_controller(holder, &kid, "holder")?;
        options.time.check_claims(&claims)?;
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
        Ok(DecodedPresentation {
            header: jws.header().clone(),
            claims,
            presentation,
            credentials: Vec::new(),
        })
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

/// Checks the subjects of `credential` against `holder` per `relationship`.
fn check_subject_holder(
    credential: &DecodedCredential,
    holder: Option<&Uri>,
    relationship: SubjectHolderRelationship,
) -> Result<(), ValidationError> {
    let required = match relationship {
        SubjectHolderRelationship::AlwaysSubject => true,
        SubjectHolderRelationship::SubjectOnNonTransferable => credential
            .credential
            .properties
            .get("nonTransferable")
            .is_some_and(|value| value == &Value::Bool(true)),
        SubjectHolderRelationship::Any => false,
    };
    if !required {
        return Ok(());
    }
    // The presentation validator sets the holder before validating credentials.
    let holder = holder.expect("a validated presentation has a holder");
    for subject in credential.credential.credential_subject.iter() {
        if subject.id.as_ref() != Some(holder) {
            return Err(ValidationError::SubjectHolderMismatch {
                subject: subject.id.clone(),
                holder: holder.clone(),
            });
        }
    }
    Ok(())
}
