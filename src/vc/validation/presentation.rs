//! `JwtPresentationValidator`.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use serde_json::Value;

use crate::did::Uri;
use crate::jose::{CompactJws, DefaultVerifier, JwsHeader, JwsVerifier};
#[cfg(feature = "sd-jwt")]
use crate::sd_jwt_vc::{SdJwtCredentialV2, SdJwtCredentialValidator, SdJwtValidationOptions};
use crate::vc::{
    CredentialError, CredentialV2, EnvelopedVc, Jwt, JwtClaims, Party, Presentation,
    PresentationV2, Subject,
};

#[cfg(feature = "sd-jwt")]
use super::CredentialStatus;
use super::credential::{NO_TYP, check_controller, check_typ, decode, decode_v2, plain_claims};
use super::{
    DecodedCredential, DecodedCredentialV2, FailFast, JwtCredentialValidator, KeyResolver, KeyRole,
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
    /// The presented credentials, in the order of `verifiableCredential`, each in the form
    /// its envelope held.
    pub credentials: Vec<PresentedCredentialV2>,
}

impl DecodedPresentationV2 {
    /// The holder: `holder` of the presentation, or `iss` when it has none.
    pub fn holder(&self) -> Option<&Uri> {
        self.presentation.holder.as_ref().map(Party::id)
    }
}

/// A credential unwrapped from an `EnvelopedVerifiableCredential` of a VCDM 2.0
/// presentation: secured as a JWT (`application/vc+jwt`) or, with the `sd-jwt` feature, with
/// SD-JWT (`application/vc+sd-jwt`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PresentedCredentialV2 {
    /// A `vc+jwt` credential, decoded.
    Jwt(Box<DecodedCredentialV2>),
    /// A `vc+sd-jwt` credential, with the disclosures it was presented with applied.
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    SdJwt(Box<SdJwtCredentialV2>),
}

impl PresentedCredentialV2 {
    /// The credential, whichever way it was secured.
    pub fn credential(&self) -> &CredentialV2 {
        match self {
            Self::Jwt(decoded) => &decoded.credential,
            #[cfg(feature = "sd-jwt")]
            Self::SdJwt(credential) => credential.credential(),
        }
    }

    /// The header of the JWT securing it (the issuer-signed JWT, for SD-JWT).
    pub fn header(&self) -> &JwsHeader {
        match self {
            Self::Jwt(decoded) => &decoded.header,
            #[cfg(feature = "sd-jwt")]
            Self::SdJwt(credential) => credential.header(),
        }
    }

    /// The decoded JWT, when the credential was secured as one.
    pub fn as_jwt(&self) -> Option<&DecodedCredentialV2> {
        match self {
            Self::Jwt(decoded) => Some(decoded),
            #[cfg(feature = "sd-jwt")]
            Self::SdJwt(_) => None,
        }
    }

    /// The SD-JWT credential, when the credential was secured with SD-JWT.
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    pub fn as_sd_jwt(&self) -> Option<&SdJwtCredentialV2> {
        match self {
            Self::SdJwt(credential) => Some(credential),
            Self::Jwt(_) => None,
        }
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
/// other's `typ`. A verifier that takes both picks by `typ`, and since `typ` is optional in
/// both profiles, picks a token without one by its payload: VCDM 1.1 puts the presentation in
/// a `vp` claim, VCDM 2.0 never has one.
///
/// ```
/// # #[cfg(feature = "did-key")]
/// # {
/// use identity_kit::jose::DefaultVerifier;
/// use identity_kit::methods::DidKey;
/// use identity_kit::resolver::Resolver;
/// use identity_kit::vc::validation::{JwtPresentationValidator, PresentationValidationOptions};
/// use identity_kit::vc::{Jwt, JwtClaims, PresentationV2};
///
/// /// Whether `jwt` is a VCDM 2.0 presentation rather than a VCDM 1.1 one.
/// fn is_v2(jwt: &Jwt) -> Result<bool, Box<dyn std::error::Error>> {
///     let jws = jwt.decode()?;
///     Ok(match jws.header().typ.as_deref() {
///         Some(typ) => typ == PresentationV2::JWT_TYP,
///         None => {
///             let claims: JwtClaims = serde_json::from_slice(jws.payload())?;
///             !claims.additional.contains_key("vp")
///         }
///     })
/// }
///
/// async fn holder_of(
///     validator: &JwtPresentationValidator<Resolver>,
///     jwt: &Jwt,
///     options: &PresentationValidationOptions,
/// ) -> Result<Option<String>, Box<dyn std::error::Error>> {
///     let holder = if is_v2(jwt)? {
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
    /// claim; the holder, from `holder` or else `iss`, is required and owns the signing key
    /// ([`KeyReference::binds_to`](crate::resolver::KeyReference::binds_to)).
    /// Each credential is unwrapped from its `EnvelopedVerifiableCredential` and validated
    /// under `options.credentials`: an `application/vc+jwt` one with
    /// [`JwtCredentialValidator::validate_v2`]; with the `sd-jwt` feature, an
    /// `application/vc+sd-jwt` one as `SdJwtCredentialValidator::validate_v2` of `sd_jwt_vc`
    /// does, with its `credentialStatus` entries and its `status` claim checked by this
    /// validator's [`StatusCheck`] and the key binding of `options.key_binding` required when
    /// set (none by default: the presentation JWT already proves holder control). An envelope
    /// of another media type (a COSE credential) fails for that credential alone.
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
            match self
                .validate_enveloped(enveloped, holder.as_ref(), options)
                .await
            {
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

    /// Validates the credential `enveloped` holds, by its media type, and its subjects
    /// against `holder`.
    async fn validate_enveloped(
        &self,
        enveloped: &EnvelopedVc,
        holder: Option<&Uri>,
        options: &PresentationValidationOptions,
    ) -> Result<PresentedCredentialV2, ValidationError> {
        #[cfg(feature = "sd-jwt")]
        if enveloped.is_sd_jwt() {
            let sd_jwt = enveloped.to_sd_jwt()?;
            let credential =
                SdJwtCredentialV2::from_sd_jwt_with(sd_jwt, &options.credentials.additional_typ)
                    .map_err(crate::sd_jwt_vc::SdJwtValidationError::from)?;
            // No status policy here: the status is checked below, for both kinds of entry.
            let sd_jwt_options = SdJwtValidationOptions {
                time: options.credentials.time,
                key_binding: options.key_binding.clone(),
                ..SdJwtValidationOptions::default()
            };
            let validated = SdJwtCredentialValidator::new(
                self.credentials.resolver(),
                self.credentials.verifier(),
            )
            .validate_credential_v2_unchecked_status(credential, &sd_jwt_options)
            .await?;
            let credential = validated.credential;
            self.credentials
                .check_status(
                    credential
                        .credential()
                        .statuses()
                        .map(CredentialStatus::Vcdm)
                        .chain(credential.status().map(CredentialStatus::SdJwt)),
                    options.credentials.status,
                    options.credentials.time.now(),
                )
                .await?;
            check_subject_holder(
                &credential.credential().properties,
                credential.credential().credential_subject.iter(),
                holder,
                options.subject_holder,
            )?;
            return Ok(PresentedCredentialV2::SdJwt(Box::new(credential)));
        }
        let jwt = enveloped.to_jwt()?;
        let validated = self
            .credentials
            .validate_v2(&jwt, &options.credentials)
            .await?;
        check_subject_holder(
            &validated.credential.properties,
            validated.credential.credential_subject.iter(),
            holder,
            options.subject_holder,
        )?;
        Ok(PresentedCredentialV2::Jwt(Box::new(validated)))
    }

    /// Validates the presentation JWT itself; the credentials are left to decode.
    async fn validate_presentation(
        &self,
        jwt: &Jwt,
        options: &PresentationValidationOptions,
    ) -> Result<DecodedPresentation, ValidationError> {
        let jws = jwt.decode()?;
        check_typ(jws.header(), "JWT", &options.additional_typ)?;
        let claims = plain_claims(&jws)?;
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
    /// resolved for [`KeyRole::Subject`], the key belongs to the holder (reported missing as
    /// `missing`), the time claims, the audience and the nonce.
    async fn check_holder_and_claims(
        &self,
        jws: &CompactJws,
        holder: Option<&Party>,
        missing: &'static str,
        claims: &JwtClaims,
        options: &PresentationValidationOptions,
    ) -> Result<(), ValidationError> {
        let (reference, key) = self
            .credentials
            .verify(
                jws,
                KeyRole::Subject,
                holder.map(|holder| holder.id().as_str()),
            )
            .await?;
        let holder = holder.ok_or(CredentialError::MissingClaim(missing))?;
        check_controller(holder, &reference, &key, "holder")?;
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
/// or [`ValidationError::Credential`] when the token or one of its credentials does not decode,
/// and [`ValidationError::SdJwtPayload`] when one of them is the issuer-signed JWT of an
/// SD-JWT.
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
    let claims = plain_claims(&jws)?;
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
/// verifying or validating anything. A credential secured with SD-JWT (feature `sd-jwt`) has
/// its disclosures processed, which checks the digests, but no signature is verified.
///
/// # Errors
///
/// [`ValidationError::Jws`], [`ValidationError::Payload`], [`ValidationError::UnexpectedTyp`]
/// or [`ValidationError::Credential`] when the token, or one of its credentials, does not
/// decode, and `ValidationError::SdJwt` when an SD-JWT credential does not; an envelope of
/// a media type other than `application/vc+jwt` (or `application/vc+sd-jwt`) is a
/// [`CredentialError::UnsupportedMediaType`]. A `vp+jwt` payload, or a `vc+jwt` one, that is
/// the issuer-signed JWT of an SD-JWT is a [`ValidationError::SdJwtPayload`].
pub fn decode_presentation_v2(jwt: &Jwt) -> Result<DecodedPresentationV2, ValidationError> {
    let jws = jwt.decode()?;
    let (claims, presentation) = decode_payload_v2(&jws, &NO_TYP)?;
    let credentials = presentation
        .verifiable_credential
        .iter()
        .map(decode_enveloped)
        .collect::<Result<_, _>>()?;
    Ok(DecodedPresentationV2 {
        header: jws.header().clone(),
        claims,
        presentation,
        credentials,
    })
}

/// Decodes the credential `enveloped` holds, by its media type.
fn decode_enveloped(enveloped: &EnvelopedVc) -> Result<PresentedCredentialV2, ValidationError> {
    #[cfg(feature = "sd-jwt")]
    if enveloped.is_sd_jwt() {
        let credential = SdJwtCredentialV2::from_sd_jwt(enveloped.to_sd_jwt()?)
            .map_err(crate::sd_jwt_vc::SdJwtValidationError::from)?;
        return Ok(PresentedCredentialV2::SdJwt(Box::new(credential)));
    }
    Ok(PresentedCredentialV2::Jwt(Box::new(decode_v2(
        &enveloped.to_jwt()?.decode()?,
        &NO_TYP,
    )?)))
}

/// The claims and presentation of a VCDM 2.0 presentation JWT whose `typ`, when present, is
/// `vp+jwt` or one of `additional_typ`.
fn decode_payload_v2(
    jws: &CompactJws,
    additional_typ: &BTreeSet<String>,
) -> Result<(JwtClaims, PresentationV2), ValidationError> {
    check_typ(jws.header(), PresentationV2::JWT_TYP, additional_typ)?;
    let claims = plain_claims(jws)?;
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
