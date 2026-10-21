//! Validation of credential and presentation JWTs: signature, binding to the issuer or holder,
//! validity period, audience, nonce and status.
//!
//! The validators take two extension points: a [`KeyResolver`] (from
//! [`resolver`](crate::resolver), re-exported here), which turns the [`KeyReference`] of a JWT
//! into the public key of its signer, and a [`JwsVerifier`](crate::jose::JwsVerifier), which
//! checks the signature and is [`DefaultVerifier`](crate::jose::DefaultVerifier) unless an
//! application substitutes its own. The crate's [`Resolver`](crate::resolver::Resolver)
//! resolves DID URLs; a [`CompositeKeyResolver`](crate::resolver::CompositeKeyResolver) adds
//! keys by value ([`JwkResolver`](crate::resolver::JwkResolver)) or the key sets of HTTPS
//! issuers (`JwksResolver`, feature `jwks`). A [`StatusCheck`] is a third, optional extension
//! point, for `credentialStatus`, shared with the SD-JWT validators, which hand it the
//! `status` claim.
//!
//! # What is checked
//!
//! For a credential ([`JwtCredentialValidator`]):
//!
//! 1. The token is a compact JWS whose header names its key
//!    ([`KeyReference::from_jws`], with the issuer as `iss`): a `kid` that is a DID URL of the
//!    form `did:…#fragment`, a `#fragment` relative to a DID issuer, a `kid` into the key set of
//!    an HTTPS issuer, or a `jwk`, `x5c` or `jku` header. A path or DID parameters such as
//!    `versionId` in a DID URL are refused, so the signer cannot pick the document version its
//!    key is looked up in (ADR 0004). When `typ` is present it names the profile: `JWT` for
//!    VCDM 1.1, `vc+jwt` for VCDM 2.0, or one of the values the options add
//!    (`CredentialValidationOptions::additional_typ`).
//! 2. The payload is a claims set that maps to a [`Credential`](crate::vc::Credential) (or a
//!    [`CredentialV2`](crate::vc::CredentialV2)), with its registered claims agreeing with the
//!    credential.
//! 3. The key the reference names is resolved for [`KeyRole::Issuer`] (`assertionMethod` in a
//!    DID document) and verifies the signature.
//! 4. The key belongs to the issuer ([`KeyReference::binds_to`]): the issuer is the DID of the
//!    DID URL, the `did:jwk` or thumbprint of a key by value, or the HTTPS issuer of the key
//!    set.
//! 5. `nbf`, `exp` and `iat`, and the credential's own validity period, hold at the validation
//!    time, within the leeway.
//! 6. `credentialStatus` passes the [`StatusCheck`], per the [`StatusPolicy`].
//!
//! For a presentation ([`JwtPresentationValidator`]): the same for the presentation JWT, with
//! the key resolved for [`KeyRole::Subject`] (`authentication`) and bound to the holder, plus the expected
//! audience and nonce; then every credential it carries is validated as above, and its subject
//! is checked against the holder per the [`SubjectHolderRelationship`]. A VCDM 1.1
//! presentation (`typ` `JWT`, [`validate`](JwtPresentationValidator::validate)) carries
//! credential JWTs in its `vp` claim; a VCDM 2.0 one (`typ` `vp+jwt`,
//! [`validate_v2`](JwtPresentationValidator::validate_v2)) is the payload itself and envelopes
//! `vc+jwt` credentials and, with the `sd-jwt` feature, `vc+sd-jwt` ones (validated as
//! `SdJwtCredentialValidator::validate_v2` of `sd_jwt_vc` does, with the key binding the
//! presentation options require); an envelope of another media type fails for that
//! credential alone.
//!
//! Everything a verifier decides by policy (which issuers to trust, which credential types to
//! accept, what the claims must say) is left to the application, which gets the decoded
//! credential back. [`decode_credential`], [`decode_credential_v2`], [`decode_presentation`]
//! and [`decode_presentation_v2`] decode without verifying, for a look at a token before
//! deciding how to validate it; [`extract_issuer`] and [`extract_holder`] read just the signer's DID.

use core::time::Duration;
use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};

use crate::did::Did;
pub use crate::resolver::{
    KeyReference, KeyReferenceError, KeyResolutionError, KeyResolver, KeyRole,
};
use crate::vc::{Jwt, JwtClaims, TypedObject, claims};

mod credential;
mod error;
mod presentation;

pub use credential::{
    DecodedCredential, DecodedCredentialV2, JwtCredentialValidator, decode_credential,
    decode_credential_v2,
};
pub use error::{PresentationValidationError, StatusError, ValidationError};
#[cfg(feature = "linked-vp")]
pub(crate) use presentation::decode_presentation_with;
pub use presentation::{
    DecodedPresentation, DecodedPresentationV2, JwtPresentationValidator, PresentedCredentialV2,
    decode_presentation, decode_presentation_v2,
};

/// A status entry of a credential, of either credential format, for a [`StatusCheck`].
///
/// # Examples
///
/// ```
/// use identity_kit::vc::TypedObject;
/// use identity_kit::vc::validation::CredentialStatus;
///
/// let entry: TypedObject = serde_json::from_value(serde_json::json!({
///     "id": "https://example.com/credentials/status/3#94567",
///     "type": "BitstringStatusListEntry",
/// }))?;
/// assert_eq!(CredentialStatus::Vcdm(&entry).mechanism(), "BitstringStatusListEntry");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum CredentialStatus<'a> {
    /// A `credentialStatus` entry of a VCDM credential.
    Vcdm(&'a TypedObject),
    /// The `status` claim of an SD-JWT VC, or of a VCDM 2.0 credential secured with SD-JWT
    /// (IETF Token Status List and other mechanisms).
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    SdJwt(&'a crate::sd_jwt_vc::Status),
}

impl CredentialStatus<'_> {
    /// What a check reports as [`StatusError::Unsupported`] for this entry: the `type` of a
    /// `credentialStatus` entry, or the names of the mechanisms in a `status` claim
    /// (`status_list`, and the members of other mechanisms), comma separated.
    pub fn mechanism(&self) -> String {
        match self {
            Self::Vcdm(entry) => entry.object_type().to_owned(),
            #[cfg(feature = "sd-jwt")]
            Self::SdJwt(status) => status
                .mechanisms()
                .map(|mechanism| match mechanism {
                    crate::sd_jwt_vc::StatusMechanism::StatusList(_) => "status_list",
                    crate::sd_jwt_vc::StatusMechanism::Other { name, .. } => name,
                })
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

/// Checks the status of a credential: fetches the status list, bitmap or registry an entry
/// points to and reports whether the credential is still good.
///
/// One check serves both credential formats: the validators hand it every `credentialStatus`
/// entry of a VCDM credential as [`CredentialStatus::Vcdm`] and the `status` claim of an
/// SD-JWT credential as `CredentialStatus::SdJwt` (feature `sd-jwt`), so an application
/// implements status checking once. A check that does not understand an entry reports
/// [`StatusError::Unsupported`], which the [`StatusPolicy`] decides about. `StatusListCheck`
/// of `sd_jwt_vc::validation` (features `sd-jwt` and `did-web`) checks the Token Status List
/// and reports every VCDM entry as unsupported.
///
/// # Examples
///
/// A check that knows only the Token Status List, and only the list it was given:
///
/// ```
/// use chrono::{DateTime, Utc};
/// use identity_kit::vc::validation::{CredentialStatus, StatusCheck, StatusError};
///
/// struct Revoked;
///
/// #[async_trait::async_trait]
/// impl StatusCheck for Revoked {
///     async fn check(&self, status: CredentialStatus<'_>, _: DateTime<Utc>) -> Result<(), StatusError> {
///         match status {
///             #[cfg(feature = "sd-jwt")]
///             CredentialStatus::SdJwt(status) if status.status_list.is_some() => {
///                 Err(StatusError::Invalid("revoked".to_owned()))
///             }
///             other => Err(StatusError::Unsupported(other.mechanism())),
///         }
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait StatusCheck: Send + Sync {
    /// Checks `status` at the validation time `now`, against which a check judges what it
    /// fetched (the expiry of a status list token, for instance).
    ///
    /// # Errors
    ///
    /// A [`StatusError`]: [`Unsupported`](StatusError::Unsupported) for an entry or mechanism
    /// the check does not know, [`Unavailable`](StatusError::Unavailable) when the status
    /// could not be obtained, [`Invalid`](StatusError::Invalid) when the credential is revoked
    /// or suspended.
    async fn check(
        &self,
        status: CredentialStatus<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), StatusError>;
}

macro_rules! forward_status_check {
    ($($ty:ty),* $(,)?) => {
        $(
            #[async_trait::async_trait]
            impl<T: StatusCheck + ?Sized> StatusCheck for $ty {
                async fn check(
                    &self,
                    status: CredentialStatus<'_>,
                    now: DateTime<Utc>,
                ) -> Result<(), StatusError> {
                    (**self).check(status, now).await
                }
            }
        )*
    };
}

forward_status_check!(&T, Box<T>, Arc<T>);

/// Checks every entry of `statuses` with `check` per `policy`, at `now`.
pub(crate) async fn check_statuses<'a>(
    check: Option<&dyn StatusCheck>,
    statuses: impl IntoIterator<Item = CredentialStatus<'a>>,
    policy: StatusPolicy,
    now: DateTime<Utc>,
) -> Result<(), ValidationError> {
    if policy == StatusPolicy::SkipAll {
        return Ok(());
    }
    for status in statuses {
        let result = match check {
            Some(check) => check.check(status, now).await,
            None => Err(StatusError::Unsupported(status.mechanism())),
        };
        match result {
            Ok(()) => {}
            Err(StatusError::Unsupported(_)) if policy == StatusPolicy::SkipUnsupported => {}
            Err(StatusError::Unsupported(mechanism)) => {
                return Err(ValidationError::StatusUnchecked(mechanism));
            }
            Err(error) => return Err(ValidationError::Status(error)),
        }
    }
    Ok(())
}

/// What to do about a status entry: a `credentialStatus` entry, or the `status` claim of an
/// SD-JWT credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusPolicy {
    /// Every entry must pass the validator's [`StatusCheck`]; without one, or for a type it
    /// does not support, validation fails.
    #[default]
    Strict,
    /// Entries of a type the [`StatusCheck`] does not support, or any entry when there is no
    /// check, are ignored.
    SkipUnsupported,
    /// `credentialStatus` is ignored.
    SkipAll,
}

/// Whether to stop at the first failing credential of a presentation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailFast {
    /// Stop at the first credential that fails.
    #[default]
    FirstError,
    /// Validate every credential and report all failures.
    AllErrors,
}

/// How the subject of a presented credential must relate to the holder presenting it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubjectHolderRelationship {
    /// Every subject of every credential must be the holder. A bearer credential fails.
    #[default]
    AlwaysSubject,
    /// As [`AlwaysSubject`](Self::AlwaysSubject), but only for credentials whose
    /// `nonTransferable` property is `true`.
    SubjectOnNonTransferable,
    /// Not checked.
    Any,
}

/// The validation time and the clock skew allowed around it.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::vc::validation::TimeOptions;
///
/// let fixed = TimeOptions::at(Utc.with_ymd_and_hms(2019, 11, 6, 0, 0, 0).unwrap())
///     .with_leeway(Duration::from_secs(60));
/// assert_eq!(fixed.now().to_rfc3339(), "2019-11-06T00:00:00+00:00");
/// assert_eq!(fixed.leeway, Duration::from_secs(60));
/// assert!(TimeOptions::default().now() > fixed.now());
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimeOptions {
    /// The validation time; the current time when `None`.
    pub now: Option<DateTime<Utc>>,
    /// How far `nbf`, `exp` and `iat` may miss the validation time and still pass; zero by
    /// default.
    pub leeway: Duration,
}

impl TimeOptions {
    /// Options validating at `now`.
    pub fn at(now: DateTime<Utc>) -> Self {
        Self {
            now: Some(now),
            leeway: Duration::ZERO,
        }
    }

    /// These options with `leeway`.
    #[must_use]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// The validation time.
    pub fn now(&self) -> DateTime<Utc> {
        self.now.unwrap_or_else(Utc::now)
    }

    /// The leeway as a `chrono` delta, saturated.
    fn delta(&self) -> TimeDelta {
        TimeDelta::from_std(self.leeway).unwrap_or(TimeDelta::MAX)
    }

    /// Checks that `now` is within `[not_before, expires)` with the leeway, and that
    /// `issued_at` is not in the future.
    ///
    /// # Errors
    ///
    /// [`ValidationError::NotYetValid`], [`ValidationError::Expired`] or
    /// [`ValidationError::IssuedInFuture`].
    pub fn check(
        &self,
        not_before: Option<DateTime<Utc>>,
        expires: Option<DateTime<Utc>>,
        issued_at: Option<DateTime<Utc>>,
    ) -> Result<(), ValidationError> {
        let now = self.now();
        let delta = self.delta();
        // A leeway past the range `chrono` represents saturates rather than overflowing.
        let latest = now
            .checked_add_signed(delta)
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let earliest = now
            .checked_sub_signed(delta)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        if let Some(not_before) = not_before
            && not_before > latest
        {
            return Err(ValidationError::NotYetValid { not_before, now });
        }
        if let Some(expired_at) = expires
            && expired_at <= earliest
        {
            return Err(ValidationError::Expired { expired_at, now });
        }
        if let Some(issued_at) = issued_at
            && issued_at > latest
        {
            return Err(ValidationError::IssuedInFuture { issued_at, now });
        }
        Ok(())
    }

    /// Checks the registered time claims of `claims`: `nbf`, `exp` and `iat`.
    ///
    /// # Errors
    ///
    /// As [`check`](Self::check), or [`ValidationError::Credential`] for a claim out of
    /// range.
    pub fn check_claims(&self, claims: &JwtClaims) -> Result<(), ValidationError> {
        self.check(
            timestamp(claims.nbf, "nbf")?,
            timestamp(claims.exp, "exp")?,
            timestamp(claims.iat, "iat")?,
        )
    }
}

/// The time a `NumericDate` claim names.
fn timestamp(
    value: Option<i64>,
    claim: &'static str,
) -> Result<Option<DateTime<Utc>>, ValidationError> {
    value
        .map(|value| {
            JwtClaims::timestamp(value).ok_or_else(|| {
                ValidationError::Credential(crate::vc::CredentialError::InvalidClaim {
                    claim,
                    reason: format!("{value} is out of range"),
                })
            })
        })
        .transpose()
}

/// Options of [`JwtCredentialValidator`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CredentialValidationOptions {
    /// The validation time and leeway.
    pub time: TimeOptions,
    /// What to do about `credentialStatus`.
    pub status: StatusPolicy,
    /// Header `typ` values accepted besides the profile's own (`JWT` for VCDM 1.1, `vc+jwt`
    /// for VCDM 2.0); none by default. A token without `typ` is always accepted.
    pub additional_typ: BTreeSet<String>,
}

impl CredentialValidationOptions {
    /// Default options: validate now without leeway, [`StatusPolicy::Strict`].
    pub fn new() -> Self {
        Self::default()
    }

    /// These options with `time`.
    #[must_use]
    pub fn with_time(mut self, time: TimeOptions) -> Self {
        self.time = time;
        self
    }

    /// These options with `status`.
    #[must_use]
    pub fn with_status(mut self, status: StatusPolicy) -> Self {
        self.status = status;
        self
    }

    /// These options also accepting a credential whose header `typ` is `typ`.
    #[must_use]
    pub fn with_additional_typ(mut self, typ: impl Into<String>) -> Self {
        self.additional_typ.insert(typ.into());
        self
    }
}

/// Options of [`JwtPresentationValidator`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PresentationValidationOptions {
    /// The validation time and leeway of the presentation JWT.
    pub time: TimeOptions,
    /// The audience the presentation must name in `aud`, if any is required.
    pub audience: Option<String>,
    /// The `nonce` the presentation must carry, if one is required.
    pub nonce: Option<String>,
    /// How credential subjects must relate to the holder.
    pub subject_holder: SubjectHolderRelationship,
    /// The options every presented credential is validated with.
    pub credentials: CredentialValidationOptions,
    /// Whether to stop at the first failing credential.
    pub fail_fast: FailFast,
    /// Header `typ` values accepted for the presentation JWT besides the profile's own (`JWT`
    /// for VCDM 1.1, `vp+jwt` for VCDM 2.0), by both profiles; none by default. A token
    /// without `typ` is always accepted. The credentials' own are
    /// [`CredentialValidationOptions::additional_typ`].
    pub additional_typ: BTreeSet<String>,
    /// The key binding every enveloped credential secured with SD-JWT must prove, if any
    /// is required; none by default, since the presentation JWT already proves holder
    /// control. See [`JwtPresentationValidator::validate_v2`].
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    pub key_binding: Option<crate::sd_jwt_vc::KeyBindingOptions>,
}

impl PresentationValidationOptions {
    /// Default options: validate now without leeway, no audience or nonce required,
    /// [`SubjectHolderRelationship::AlwaysSubject`], default credential options,
    /// [`FailFast::FirstError`].
    pub fn new() -> Self {
        Self::default()
    }

    /// These options with `time`, for the presentation JWT only.
    #[must_use]
    pub fn with_time(mut self, time: TimeOptions) -> Self {
        self.time = time;
        self
    }

    /// These options requiring `audience`.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// These options requiring `nonce`.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// These options with `relationship`.
    #[must_use]
    pub fn with_subject_holder(mut self, relationship: SubjectHolderRelationship) -> Self {
        self.subject_holder = relationship;
        self
    }

    /// These options validating credentials with `credentials`.
    #[must_use]
    pub fn with_credentials(mut self, credentials: CredentialValidationOptions) -> Self {
        self.credentials = credentials;
        self
    }

    /// These options with `fail_fast`.
    #[must_use]
    pub fn with_fail_fast(mut self, fail_fast: FailFast) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// These options also accepting a presentation whose header `typ` is `typ`.
    #[must_use]
    pub fn with_additional_typ(mut self, typ: impl Into<String>) -> Self {
        self.additional_typ.insert(typ.into());
        self
    }

    /// These options requiring `key_binding` of every enveloped credential secured with
    /// SD-JWT.
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    #[must_use]
    pub fn with_key_binding(mut self, key_binding: crate::sd_jwt_vc::KeyBindingOptions) -> Self {
        self.key_binding = Some(key_binding);
        self
    }
}

/// The DID of the issuer of a credential JWT, read without verifying anything: `iss`, else
/// the `issuer` of the `vc` claim (VCDM 1.1) or of the payload (VCDM 2.0).
///
/// # Errors
///
/// [`ValidationError::Jws`] or [`ValidationError::Payload`] when the token does not decode,
/// [`ValidationError::Credential`] when it names no issuer, and [`ValidationError::NotDid`]
/// when the issuer is not a DID.
pub fn extract_issuer(jwt: &Jwt) -> Result<Did, ValidationError> {
    let claims = decode_claims(jwt)?;
    let issuer = claims
        .iss
        .clone()
        .or_else(|| property_id(&claims, "vc", "issuer"))
        .ok_or(crate::vc::CredentialError::MissingClaim("iss"))?;
    Did::parse(&issuer).map_err(|_| ValidationError::NotDid {
        role: "issuer",
        id: issuer,
    })
}

/// The DID of the holder of a presentation JWT, read without verifying anything: `iss`, else
/// the `holder` of the `vp` claim (VCDM 1.1) or of the payload (VCDM 2.0).
///
/// # Errors
///
/// As [`extract_issuer`], for the holder.
pub fn extract_holder(jwt: &Jwt) -> Result<Did, ValidationError> {
    let claims = decode_claims(jwt)?;
    let holder = claims
        .iss
        .clone()
        .or_else(|| property_id(&claims, "vp", "holder"))
        .ok_or(crate::vc::CredentialError::MissingClaim("iss"))?;
    Did::parse(&holder).map_err(|_| ValidationError::NotDid {
        role: "holder",
        id: holder,
    })
}

/// The identifier of `property` in the `container` claim (VCDM 1.1), or in the payload.
fn property_id(claims: &JwtClaims, container: &str, property: &str) -> Option<String> {
    let value = match claims.additional.get(container) {
        Some(container) => container.get(property)?,
        None => claims.additional.get(property)?,
    };
    claims::id_of(value).map(str::to_owned)
}

/// The claims set of `jwt`, unverified.
pub(super) fn decode_claims(jwt: &Jwt) -> Result<JwtClaims, ValidationError> {
    let jws = jwt.decode()?;
    serde_json::from_slice(jws.payload()).map_err(|e| ValidationError::Payload(e.to_string()))
}
