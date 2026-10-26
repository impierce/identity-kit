//! Validation of SD-JWT credentials: issuer signature and binding, time claims, key binding,
//! status.
//!
//! [`SdJwtCredentialValidator`] is the SD-JWT counterpart of
//! [`JwtCredentialValidator`](crate::vc::validation::JwtCredentialValidator), over the same
//! [`KeyResolver`] and [`JwsVerifier`]. It validates both SD-JWT credential types
//! ([two SD-JWT credential types](super#two-sd-jwt-credential-types)):
//! [`validate`](SdJwtCredentialValidator::validate) an SD-JWT VC,
//! [`validate_v2`](SdJwtCredentialValidator::validate_v2) a VCDM 2.0 credential secured with
//! SD-JWT. Each checks, in order:
//!
//! 1. The SD-JWT parses as an [`SdJwtVc`] (`typ`, disclosures, claims; RFC 9901 §7.1 steps 3
//!    to 5, SD-JWT VC §2.2) or as an [`SdJwtCredentialV2`] (`typ` `vc+sd-jwt` when present,
//!    or one of `options.additional_typ`; disclosures; the payload as a
//!    [`CredentialV2`](crate::vc::CredentialV2) with its registered claims agreeing with it).
//! 2. The header of the issuer-signed JWT names its key ([`KeyReference::from_jws`], with the
//!    issuer, `iss` or the credential's `issuer`, as `iss`): a `kid` that is a DID URL of the
//!    form `did:…#fragment` (a path or DID parameters such as `versionId` are refused, as in
//!    the JWT validators, ADR 0004), a `#fragment` relative to a DID issuer, a `kid` into the
//!    JWT VC issuer metadata of an HTTPS issuer (SD-JWT VC §3.5, resolved by `JwksResolver`
//!    with the `jwks` feature), or a `jwk`, `x5c` or `jku` header. The key is resolved for
//!    [`KeyRole::Issuer`], verifies the signature, and belongs to the issuer
//!    ([`KeyReference::binds_to`]).
//! 3. `nbf`, `exp` and `iat` hold at the validation time, and so do `validFrom` and
//!    `validUntil` of a VCDM 2.0 credential.
//! 4. When the options require key binding (RFC 9901 §7.3): the SD-JWT+KB carries a key
//!    binding JWT with `typ: kb+jwt`, signed by the holder's key, for the expected audience
//!    and nonce, issued within the window, with an `sd_hash` over the presented SD-JWT. The
//!    holder's key is `cnf.jwk`, used as it is since the issuer signed it, or else the key
//!    `cnf.kid` names, an absolute DID URL resolved for [`KeyRole::Subject`]
//!    (`authentication`); see [`KeyReference::from_confirmation`].
//! 5. `status` (as [`CredentialStatus::StatusClaim`]) and the `credentialStatus` entries of a VCDM
//!    2.0 credential (as [`CredentialStatus::Vcdm`]) pass the [`StatusCheck`], per the
//!    [`StatusPolicy`].
//!
//! Type metadata is a separate step the application runs when its policy asks for it:
//! [`TypeMetadata::check_claims`](super::TypeMetadata::check_claims).

use core::time::Duration;
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use super::{
    Confirmation, SdJwt, SdJwtCredentialV2, SdJwtCredentialV2Error, SdJwtVc, SdJwtVcError,
};
use crate::did::Uri;
use crate::jose::{DefaultVerifier, Jwk, JwsVerifier};
use crate::resolver::{KeyReference, KeyReferenceError, KeyResolver, KeyRole};
use crate::vc::validation::{
    CredentialStatus, StatusCheck, StatusPolicy, TimeOptions, ValidationError, check_statuses,
};
use crate::vc::{CredentialError, JwtClaims};

/// Moved to [`status_list::StatusListCheck`](crate::status_list::StatusListCheck).
#[cfg(feature = "did-web")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-web")))]
#[deprecated(since = "0.3.0", note = "moved to `status_list::StatusListCheck`")]
pub type StatusListCheck<C, R, V = DefaultVerifier> = crate::status_list::StatusListCheck<C, R, V>;

/// What a key binding JWT must prove (RFC 9901 §7.3, step 5).
///
/// The key binding JWT must be signed by the holder's key the credential's `cnf` names: by
/// value in `cnf.jwk`, or by reference in `cnf.kid`, an absolute DID URL the validator's
/// [`KeyResolver`] resolves for [`KeyRole::Subject`] (`authentication`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyBindingOptions {
    /// The audience the key binding JWT must name: this verifier.
    pub audience: String,
    /// The nonce it must carry: the one of this transaction.
    pub nonce: String,
    /// The time its `iat` is checked against, with leeway.
    pub time: TimeOptions,
    /// How old it may be, if bounded.
    pub max_age: Option<Duration>,
}

impl KeyBindingOptions {
    /// Key binding for `audience` with `nonce`, checked at the current time with no age
    /// bound.
    pub fn new(audience: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            nonce: nonce.into(),
            time: TimeOptions::default(),
            max_age: None,
        }
    }

    /// These options checking `iat` against `time`.
    #[must_use]
    pub fn with_time(mut self, time: TimeOptions) -> Self {
        self.time = time;
        self
    }

    /// These options rejecting a key binding JWT older than `max_age`.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }
}

/// Options of [`SdJwtCredentialValidator`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SdJwtValidationOptions {
    /// The validation time and leeway of the issuer-signed JWT.
    pub time: TimeOptions,
    /// The key binding required, if any; a key binding JWT is not verified otherwise.
    pub key_binding: Option<KeyBindingOptions>,
    /// What to do about `status` (and `credentialStatus`).
    pub status: StatusPolicy,
    /// Whether to reject the pre-standard `typ: vc+sd-jwt` on an SD-JWT VC.
    pub reject_legacy_typ: bool,
    /// Header `typ` values accepted for a VCDM 2.0 credential besides `vc+sd-jwt`; none by
    /// default. A token without `typ` is always accepted there. An SD-JWT VC's `typ` is fixed
    /// by its specification and not affected.
    pub additional_typ: BTreeSet<String>,
}

impl SdJwtValidationOptions {
    /// Default options: validate now without leeway, no key binding required,
    /// [`StatusPolicy::Strict`], `vc+sd-jwt` accepted.
    pub fn new() -> Self {
        Self::default()
    }

    /// These options with `time`.
    #[must_use]
    pub fn with_time(mut self, time: TimeOptions) -> Self {
        self.time = time;
        self
    }

    /// These options requiring `key_binding`.
    #[must_use]
    pub fn with_key_binding(mut self, key_binding: KeyBindingOptions) -> Self {
        self.key_binding = Some(key_binding);
        self
    }

    /// These options with `status`.
    #[must_use]
    pub fn with_status(mut self, status: StatusPolicy) -> Self {
        self.status = status;
        self
    }

    /// These options rejecting `typ: vc+sd-jwt` on an SD-JWT VC.
    #[must_use]
    pub fn rejecting_legacy_typ(mut self) -> Self {
        self.reject_legacy_typ = true;
        self
    }

    /// These options also accepting a VCDM 2.0 credential whose header `typ` is `typ`.
    #[must_use]
    pub fn with_additional_typ(mut self, typ: impl Into<String>) -> Self {
        self.additional_typ.insert(typ.into());
        self
    }
}

/// Why an SD-JWT credential did not validate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtValidationError {
    /// The SD-JWT is not a well-formed SD-JWT VC.
    #[error(transparent)]
    Credential(#[from] SdJwtVcError),
    /// The SD-JWT is not a well-formed VCDM 2.0 credential secured with SD-JWT.
    #[error(transparent)]
    CredentialV2(#[from] SdJwtCredentialV2Error),
    /// The issuer-signed JWT has the pre-standard `typ: vc+sd-jwt`, which the options reject.
    #[error("header `typ` is the pre-standard `vc+sd-jwt`")]
    LegacyTyp,
    /// A check shared with the JWT validators failed: `kid`, key resolution, signature,
    /// issuer binding, time, audience, nonce, status.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Key binding is required and the SD-JWT carries no key binding JWT.
    #[error("key binding is required, but the SD-JWT has no key binding JWT")]
    KeyBindingRequired,
    /// Key binding is required and `cnf` names no key this crate can look for: there is no
    /// `cnf`, or [`KeyReference::from_confirmation`] refuses it.
    #[error("key binding is required, but `cnf` carries no usable key reference: {0}")]
    NoHolderKey(KeyReferenceError),
    /// The key binding JWT is older than allowed.
    #[error("key binding JWT issued at {} is older than {max_age:?} (now is {})", issued_at.to_rfc3339(), now.to_rfc3339())]
    KeyBindingTooOld {
        /// Its `iat`.
        issued_at: DateTime<Utc>,
        /// The validation time.
        now: DateTime<Utc>,
        /// The bound.
        max_age: Duration,
    },
    /// The key binding JWT's `sd_hash` is not the digest of the presented SD-JWT.
    #[error("key binding `sd_hash` {found:?} is not the digest {expected:?} of the SD-JWT")]
    SdHashMismatch {
        /// The digest of the SD-JWT.
        expected: String,
        /// The `sd_hash` found.
        found: Option<String>,
    },
}

/// A validated SD-JWT VC.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedSdJwtVc {
    /// The credential, with the presented disclosures applied.
    pub credential: SdJwtVc,
    /// Where the issuer-signed JWT says its key is.
    pub issuer_key: KeyReference,
    /// The claims of the key binding JWT, when key binding was required and verified.
    pub key_binding: Option<JwtClaims>,
    /// The holder's key that verified the key binding JWT, and where `cnf` said it is (a DID
    /// URL to compare with the presentation's holder or the credential subject, say), when key
    /// binding was required and verified.
    pub holder_key: Option<(KeyReference, Jwk)>,
}

/// A validated VCDM 2.0 credential secured with SD-JWT.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedSdJwtCredentialV2 {
    /// The credential, with the presented disclosures applied.
    pub credential: SdJwtCredentialV2,
    /// Where the issuer-signed JWT says its key is.
    pub issuer_key: KeyReference,
    /// The claims of the key binding JWT, when key binding was required and verified.
    pub key_binding: Option<JwtClaims>,
    /// The holder's key that verified the key binding JWT, and where `cnf` said it is, when key
    /// binding was required and verified.
    pub holder_key: Option<(KeyReference, Jwk)>,
}

/// Validates SD-JWT credentials; see the [module documentation](self) for the checks.
pub struct SdJwtCredentialValidator<R, V = DefaultVerifier> {
    resolver: R,
    verifier: V,
    status: Option<Box<dyn StatusCheck>>,
}

impl<R: KeyResolver, V: JwsVerifier> SdJwtCredentialValidator<R, V> {
    /// A validator resolving keys with `resolver` and verifying signatures with `verifier`,
    /// without a status check.
    pub fn new(resolver: R, verifier: V) -> Self {
        Self {
            resolver,
            verifier,
            status: None,
        }
    }

    /// This validator checking the `status` claim and, for a VCDM 2.0 credential, the
    /// `credentialStatus` entries with `check`.
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

    /// Validates `sd_jwt` as an SD-JWT VC.
    ///
    /// # Errors
    ///
    /// The first [`SdJwtValidationError`] found, in the order the [module
    /// documentation](self) lists the checks.
    pub async fn validate(
        &self,
        sd_jwt: &SdJwt,
        options: &SdJwtValidationOptions,
    ) -> Result<ValidatedSdJwtVc, SdJwtValidationError> {
        let credential = SdJwtVc::from_sd_jwt(sd_jwt.clone())?;
        self.validate_credential(credential, options).await
    }

    /// Validates the parsed `credential`.
    ///
    /// # Errors
    ///
    /// As [`validate`](Self::validate).
    pub async fn validate_credential(
        &self,
        credential: SdJwtVc,
        options: &SdJwtValidationOptions,
    ) -> Result<ValidatedSdJwtVc, SdJwtValidationError> {
        if options.reject_legacy_typ && credential.has_legacy_typ() {
            return Err(SdJwtValidationError::LegacyTyp);
        }
        let claims = credential.claims();
        let issuer = claims
            .iss
            .as_deref()
            .ok_or(CredentialError::MissingClaim("iss"))
            .map_err(ValidationError::from)?;
        let (issuer_key, key) = self
            .verify_issuer_signature(credential.sd_jwt(), issuer)
            .await?;
        check_issuer(issuer, &issuer_key, &key)?;

        let mut time_claims = JwtClaims::new();
        time_claims.nbf = claims.nbf;
        time_claims.exp = claims.exp;
        time_claims.iat = claims.iat;
        options.time.check_claims(&time_claims)?;

        let (key_binding, holder_key) = match &options.key_binding {
            Some(required) => {
                let (claims, holder_key) = self
                    .check_key_binding(credential.sd_jwt(), credential.confirmation(), required)
                    .await?;
                (Some(claims), Some(holder_key))
            }
            None => (None, None),
        };

        self.check_status(
            claims
                .status
                .iter()
                .map(CredentialStatus::StatusClaim)
                .collect(),
            options,
        )
        .await?;

        Ok(ValidatedSdJwtVc {
            credential,
            issuer_key,
            key_binding,
            holder_key,
        })
    }

    /// Validates `sd_jwt` as a VCDM 2.0 credential secured with SD-JWT (VC-JOSE-COSE §3.2.1).
    ///
    /// # Errors
    ///
    /// The first [`SdJwtValidationError`] found, in the order the [module
    /// documentation](self) lists the checks.
    pub async fn validate_v2(
        &self,
        sd_jwt: &SdJwt,
        options: &SdJwtValidationOptions,
    ) -> Result<ValidatedSdJwtCredentialV2, SdJwtValidationError> {
        let credential =
            SdJwtCredentialV2::from_sd_jwt_with(sd_jwt.clone(), &options.additional_typ)?;
        self.validate_credential_v2(credential, options).await
    }

    /// Validates the parsed `credential`.
    ///
    /// # Errors
    ///
    /// As [`validate_v2`](Self::validate_v2).
    pub async fn validate_credential_v2(
        &self,
        credential: SdJwtCredentialV2,
        options: &SdJwtValidationOptions,
    ) -> Result<ValidatedSdJwtCredentialV2, SdJwtValidationError> {
        let validated = self
            .validate_credential_v2_unchecked_status(credential, options)
            .await?;
        let credential = &validated.credential;
        self.check_status(
            credential
                .credential()
                .statuses()
                .map(CredentialStatus::Vcdm)
                .chain(credential.status().map(CredentialStatus::StatusClaim))
                .collect(),
            options,
        )
        .await?;
        Ok(validated)
    }

    /// Steps 2 to 4 of [`validate_credential_v2`](Self::validate_credential_v2): everything
    /// but the status checks, which the presentation validator runs with its own check.
    pub(crate) async fn validate_credential_v2_unchecked_status(
        &self,
        credential: SdJwtCredentialV2,
        options: &SdJwtValidationOptions,
    ) -> Result<ValidatedSdJwtCredentialV2, SdJwtValidationError> {
        let vc = credential.credential();
        let issuer = vc.issuer.id().as_str();
        let (issuer_key, key) = self
            .verify_issuer_signature(credential.sd_jwt(), issuer)
            .await?;
        check_issuer(issuer, &issuer_key, &key)?;
        options.time.check_claims(credential.claims())?;
        options.time.check(vc.valid_from, vc.valid_until, None)?;
        let (key_binding, holder_key) = match &options.key_binding {
            Some(required) => {
                let (claims, holder_key) = self
                    .check_key_binding(credential.sd_jwt(), credential.confirmation(), required)
                    .await?;
                (Some(claims), Some(holder_key))
            }
            None => (None, None),
        };
        Ok(ValidatedSdJwtCredentialV2 {
            credential,
            issuer_key,
            key_binding,
            holder_key,
        })
    }

    /// Resolves the key the issuer-signed JWT names, `issuer` being its issuer, for
    /// [`KeyRole::Issuer`] and verifies the signature; the reference and the key.
    async fn verify_issuer_signature(
        &self,
        sd_jwt: &SdJwt,
        issuer: &str,
    ) -> Result<(KeyReference, Jwk), ValidationError> {
        let jws = sd_jwt.jwt().decode()?;
        let reference = KeyReference::from_jws(&jws, Some(issuer))?;
        let key = self
            .resolver
            .resolve_key(&reference, KeyRole::Issuer)
            .await
            .map_err(|source| ValidationError::KeyResolution {
                key: Box::new(reference.clone()),
                source,
            })?;
        jws.verify(&self.verifier, &key)?;
        Ok((reference, key))
    }

    /// The holder's key `cnf` names: `cnf.jwk` as it is, since the issuer signed it, or the
    /// key a `cnf.kid` resolves to for [`KeyRole::Subject`].
    async fn holder_key(
        &self,
        cnf: Option<&Confirmation>,
    ) -> Result<(KeyReference, Jwk), SdJwtValidationError> {
        let cnf = cnf.ok_or(SdJwtValidationError::NoHolderKey(
            KeyReferenceError::Missing,
        ))?;
        let reference =
            KeyReference::from_confirmation(cnf).map_err(SdJwtValidationError::NoHolderKey)?;
        let key = match &reference {
            KeyReference::Jwk(jwk) => jwk.public(),
            reference => self
                .resolver
                .resolve_key(reference, KeyRole::Subject)
                .await
                .map_err(|source| ValidationError::KeyResolution {
                    key: Box::new(reference.clone()),
                    source,
                })?,
        };
        Ok((reference, key))
    }

    /// RFC 9901 §7.3, step 5: the key binding JWT of `sd_jwt`, signed by the key `cnf` names;
    /// its claims and that key.
    async fn check_key_binding(
        &self,
        sd_jwt: &SdJwt,
        cnf: Option<&Confirmation>,
        required: &KeyBindingOptions,
    ) -> Result<(JwtClaims, (KeyReference, Jwk)), SdJwtValidationError> {
        let kb_jwt = sd_jwt
            .key_binding_jwt()
            .ok_or(SdJwtValidationError::KeyBindingRequired)?;
        let holder_key = self.holder_key(cnf).await?;
        let jws = kb_jwt.decode().map_err(ValidationError::from)?;
        match jws.header().typ.as_deref() {
            Some(super::KB_JWT_TYP) => {}
            found => {
                return Err(ValidationError::UnexpectedTyp {
                    expected: super::KB_JWT_TYP,
                    found: found.unwrap_or("").to_owned(),
                }
                .into());
            }
        }
        jws.verify(&self.verifier, &holder_key.1)
            .map_err(ValidationError::from)?;
        let claims: JwtClaims =
            serde_json::from_slice(jws.payload()).map_err(ValidationError::Payload)?;

        if !claims.audiences().any(|aud| aud == required.audience) {
            return Err(ValidationError::AudienceMismatch {
                expected: required.audience.clone(),
                found: claims.aud.clone(),
            }
            .into());
        }
        let nonce = claims.additional.get("nonce").and_then(|v| v.as_str());
        if nonce != Some(required.nonce.as_str()) {
            return Err(ValidationError::NonceMismatch {
                expected: required.nonce.clone(),
                found: nonce.map(str::to_owned),
            }
            .into());
        }
        let iat = claims
            .iat
            .ok_or(CredentialError::MissingClaim("iat"))
            .map_err(ValidationError::from)?;
        let issued_at = JwtClaims::timestamp(iat).ok_or_else(|| {
            ValidationError::from(CredentialError::InvalidClaim {
                claim: "iat",
                reason: format!("{iat} is out of range"),
            })
        })?;
        required.time.check(None, None, Some(issued_at))?;
        if let Some(max_age) = required.max_age {
            let now = required.time.now();
            // A `max_age` beyond what `chrono` represents bounds nothing.
            let oldest = chrono::TimeDelta::from_std(max_age)
                .ok()
                .and_then(|delta| now.checked_sub_signed(delta))
                .unwrap_or(DateTime::<Utc>::MIN_UTC);
            if issued_at < oldest {
                return Err(SdJwtValidationError::KeyBindingTooOld {
                    issued_at,
                    now,
                    max_age,
                });
            }
        }
        let alg = sd_jwt.hash_algorithm().map_err(SdJwtVcError::from)?;
        let expected = sd_jwt.sd_hash(alg);
        let found = claims.additional.get("sd_hash").and_then(|v| v.as_str());
        if found != Some(expected.as_str()) {
            return Err(SdJwtValidationError::SdHashMismatch {
                expected,
                found: found.map(str::to_owned),
            });
        }
        Ok((claims, holder_key))
    }

    /// Checks every status entry with this validator's check, per the policy, at the
    /// validation time.
    async fn check_status(
        &self,
        statuses: Vec<CredentialStatus<'_>>,
        options: &SdJwtValidationOptions,
    ) -> Result<(), SdJwtValidationError> {
        Ok(check_statuses(
            self.status.as_deref(),
            statuses,
            options.status,
            options.time.now(),
        )
        .await?)
    }
}

/// Checks that `key`, which `reference` resolved to, belongs to `issuer`
/// ([`KeyReference::binds_to`]).
fn check_issuer(issuer: &str, reference: &KeyReference, key: &Jwk) -> Result<(), ValidationError> {
    if !reference.binds_to(Some(issuer), key) {
        return Err(ValidationError::IssuerMismatch {
            issuer: Uri::parse(issuer).map_err(|e| CredentialError::InvalidClaim {
                claim: "iss",
                reason: e.to_string(),
            })?,
            key: Box::new(reference.clone()),
        });
    }
    Ok(())
}

impl<R: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for SdJwtCredentialValidator<R, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdJwtCredentialValidator")
            .field("resolver", &self.resolver)
            .field("verifier", &self.verifier)
            .field("status", &self.status.as_ref().map(|_| "StatusCheck"))
            .finish()
    }
}
