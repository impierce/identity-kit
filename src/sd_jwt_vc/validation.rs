//! Validation of SD-JWT VCs: issuer signature and binding, time claims, key binding, status.
//!
//! [`SdJwtCredentialValidator`] is the SD-JWT counterpart of
//! [`JwtCredentialValidator`](crate::vc::validation::JwtCredentialValidator), over the same
//! [`KeyResolver`] and [`JwsVerifier`]. It checks, in order:
//!
//! 1. The SD-JWT parses as an [`SdJwtVc`]: `typ`, disclosures, claims (RFC 9901 §7.1 steps 3
//!    to 5, SD-JWT VC §2.2).
//! 2. The `kid` of the issuer-signed JWT is a DID URL of the form `did:…#fragment` (a path or
//!    DID parameters such as `versionId` are refused, as in the JWT validators, ADR 0004),
//!    resolved under `assertionMethod`, and verifies the signature; `iss` is the DID of that
//!    `kid`. (Issuers identified by an HTTPS `iss` with JWT VC issuer metadata, and `x5c`
//!    chains, are not resolved by this crate.)
//! 3. `nbf`, `exp` and `iat` hold at the validation time.
//! 4. When the options require key binding (RFC 9901 §7.3): the SD-JWT+KB carries a key
//!    binding JWT with `typ: kb+jwt`, signed by the key in `cnf`, for the expected audience
//!    and nonce, issued within the window, with an `sd_hash` over the presented SD-JWT.
//! 5. `status` passes the [`SdJwtStatusCheck`], per the [`StatusPolicy`].
//!
//! Type metadata is a separate step the application runs when its policy asks for it:
//! [`TypeMetadata::check_claims`](super::TypeMetadata::check_claims).

use core::time::Duration;

use chrono::{DateTime, Utc};

use super::{SdJwt, SdJwtVc, SdJwtVcError, Status};
use crate::did::{Did, DidUrl, Uri, VerificationRelationship};
use crate::jose::{DefaultVerifier, JwsVerifier};
use crate::vc::validation::{KeyResolver, StatusError, StatusPolicy, TimeOptions, ValidationError};
use crate::vc::{CredentialError, JwtClaims};

#[cfg(feature = "did-web")]
pub use status_list::StatusListCheck;

/// Checks the `status` claim of an SD-JWT VC.
///
/// [`StatusListCheck`] implements it for the Token Status List over an HTTP client; an
/// application implements it for other mechanisms or other ways of obtaining a list. A check
/// that understands none of the mechanisms in `status` reports [`StatusError::Unsupported`],
/// which the [`StatusPolicy`] decides about.
#[async_trait::async_trait]
pub trait SdJwtStatusCheck: Send + Sync {
    /// Checks `status` at `now`.
    ///
    /// # Errors
    ///
    /// [`StatusError::Unsupported`] for mechanisms the check does not know,
    /// [`StatusError::Unavailable`] when the status could not be obtained,
    /// [`StatusError::Invalid`] when the credential is revoked or suspended.
    async fn check(&self, status: &Status, now: DateTime<Utc>) -> Result<(), StatusError>;
}

/// What a key binding JWT must prove (RFC 9901 §7.3, step 5).
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
    /// What to do about `status`.
    pub status: StatusPolicy,
    /// Whether to reject the pre-standard `typ: vc+sd-jwt`.
    pub reject_legacy_typ: bool,
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

    /// These options rejecting `typ: vc+sd-jwt`.
    #[must_use]
    pub fn rejecting_legacy_typ(mut self) -> Self {
        self.reject_legacy_typ = true;
        self
    }
}

/// Why an SD-JWT VC did not validate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtValidationError {
    /// The SD-JWT is not a well-formed SD-JWT VC.
    #[error(transparent)]
    Credential(#[from] SdJwtVcError),
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
    /// Key binding is required and the credential carries no holder key in `cnf`.
    #[error("key binding is required, but `cnf` carries no `jwk`")]
    NoHolderKey,
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
    /// The verification method that signed it.
    pub kid: DidUrl,
    /// The claims of the key binding JWT, when key binding was required and verified.
    pub key_binding: Option<JwtClaims>,
}

/// Validates SD-JWT VCs; see the [module documentation](self) for the checks.
pub struct SdJwtCredentialValidator<R, V = DefaultVerifier> {
    resolver: R,
    verifier: V,
    status: Option<Box<dyn SdJwtStatusCheck>>,
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

    /// This validator checking `status` with `check`.
    #[must_use]
    pub fn with_status_check(mut self, check: impl SdJwtStatusCheck + 'static) -> Self {
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
        let jws = credential
            .sd_jwt()
            .jwt()
            .decode()
            .map_err(ValidationError::from)?;
        let kid = jws.kid().ok_or(ValidationError::MissingKid)?;
        let kid = DidUrl::parse(kid).map_err(|source| ValidationError::InvalidKid {
            kid: kid.to_owned(),
            source,
        })?;
        if kid.path().is_some() || kid.query().is_some() {
            return Err(ValidationError::KidWithParameters(kid).into());
        }
        let key = self
            .resolver
            .resolve_key(&kid, VerificationRelationship::AssertionMethod)
            .await
            .map_err(|source| ValidationError::KeyResolution {
                kid: kid.clone(),
                source,
            })?;
        jws.verify(&self.verifier, &key)
            .map_err(ValidationError::from)?;

        let claims = credential.claims();
        let issuer = claims
            .iss
            .as_deref()
            .ok_or(CredentialError::MissingClaim("iss"))
            .map_err(ValidationError::from)?;
        let issuer_did = Did::parse(issuer).map_err(|_| ValidationError::NotDid {
            role: "issuer",
            id: issuer.to_owned(),
        })?;
        if issuer_did != *kid.did() {
            return Err(ValidationError::IssuerMismatch {
                issuer: Uri::from(issuer_did),
                kid,
            }
            .into());
        }

        let mut time_claims = JwtClaims::new();
        time_claims.nbf = claims.nbf;
        time_claims.exp = claims.exp;
        time_claims.iat = claims.iat;
        options.time.check_claims(&time_claims)?;

        let key_binding = match &options.key_binding {
            Some(required) => Some(self.check_key_binding(&credential, required)?),
            None => None,
        };

        if let Some(status) = &claims.status {
            self.check_status(status, options).await?;
        }

        Ok(ValidatedSdJwtVc {
            credential,
            kid,
            key_binding,
        })
    }

    /// RFC 9901 §7.3, step 5.
    fn check_key_binding(
        &self,
        credential: &SdJwtVc,
        required: &KeyBindingOptions,
    ) -> Result<JwtClaims, SdJwtValidationError> {
        let sd_jwt = credential.sd_jwt();
        let kb_jwt = sd_jwt
            .key_binding_jwt()
            .ok_or(SdJwtValidationError::KeyBindingRequired)?;
        let holder_key = credential
            .holder_key()
            .ok_or(SdJwtValidationError::NoHolderKey)?;
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
        jws.verify(&self.verifier, holder_key)
            .map_err(ValidationError::from)?;
        let claims: JwtClaims = serde_json::from_slice(jws.payload())
            .map_err(|e| ValidationError::Payload(e.to_string()))?;

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
            let delta = chrono::TimeDelta::from_std(max_age).unwrap_or(chrono::TimeDelta::MAX);
            if issued_at < now - delta {
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
        Ok(claims)
    }

    /// Checks `status` per the policy.
    async fn check_status(
        &self,
        status: &Status,
        options: &SdJwtValidationOptions,
    ) -> Result<(), SdJwtValidationError> {
        if options.status == StatusPolicy::SkipAll {
            return Ok(());
        }
        let names = || {
            status
                .mechanisms()
                .map(|m| match m {
                    super::StatusMechanism::StatusList(_) => "status_list".to_owned(),
                    super::StatusMechanism::Other { name, .. } => name.to_owned(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let result = match &self.status {
            Some(check) => check.check(status, options.time.now()).await,
            None => Err(StatusError::Unsupported(names())),
        };
        match result {
            Ok(()) => Ok(()),
            Err(StatusError::Unsupported(_)) if options.status == StatusPolicy::SkipUnsupported => {
                Ok(())
            }
            Err(StatusError::Unsupported(mechanism)) => {
                Err(ValidationError::StatusUnchecked(mechanism).into())
            }
            Err(error) => Err(ValidationError::Status(error).into()),
        }
    }
}

impl<R: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug for SdJwtCredentialValidator<R, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdJwtCredentialValidator")
            .field("resolver", &self.resolver)
            .field("verifier", &self.verifier)
            .field("status", &self.status.as_ref().map(|_| "SdJwtStatusCheck"))
            .finish()
    }
}

#[cfg(feature = "did-web")]
mod status_list {
    use chrono::{DateTime, Utc};
    use url::Url;

    use super::SdJwtStatusCheck;
    use crate::did::{DidUrl, VerificationRelationship};
    use crate::jose::{DefaultVerifier, JwsVerifier};
    use crate::methods::web::HttpClient;
    use crate::sd_jwt_vc::{Status, StatusListToken, StatusMechanism};
    use crate::vc::Jwt;
    use crate::vc::validation::{KeyResolver, StatusError};

    /// A [`SdJwtStatusCheck`] for the Token Status List: fetches the status list token from
    /// the referenced URI with an [`HttpClient`], verifies it was signed by the key its `kid`
    /// names, resolved under `assertionMethod`, and reads the status at the referenced
    /// index (Token Status List §8).
    ///
    /// The check trusts the key `kid` resolves to; whether that key may speak for the list is
    /// the application's policy to enforce around it, by restricting the resolver, say.
    pub struct StatusListCheck<C, R, V = DefaultVerifier> {
        client: C,
        resolver: R,
        verifier: V,
    }

    impl<C: HttpClient, R: KeyResolver, V: JwsVerifier> StatusListCheck<C, R, V> {
        /// A check fetching with `client`, resolving the status issuer's key with `resolver`
        /// and verifying with `verifier`.
        pub fn new(client: C, resolver: R, verifier: V) -> Self {
            Self {
                client,
                resolver,
                verifier,
            }
        }

        /// The status list token at `uri`, fetched and verified.
        async fn fetch(&self, uri: &str) -> Result<StatusListToken, StatusError> {
            let url = Url::parse(uri)
                .map_err(|e| StatusError::Unavailable(format!("`uri` {uri:?}: {e}")))?;
            let response = self
                .client
                .get(&url)
                .await
                .map_err(|e| StatusError::Unavailable(format!("fetching {uri}: {e}")))?;
            if !(200..300).contains(&response.status) {
                return Err(StatusError::Unavailable(format!(
                    "fetching {uri}: HTTP {}",
                    response.status
                )));
            }
            let body = String::from_utf8(response.body)
                .map_err(|_| StatusError::Unavailable(format!("{uri}: body is not UTF-8")))?;
            let jwt = Jwt::new(body.trim())
                .map_err(|e| StatusError::Unavailable(format!("{uri}: {e}")))?;
            let (header, token) = StatusListToken::decode(&jwt)
                .map_err(|e| StatusError::Unavailable(format!("{uri}: {e}")))?;
            let kid = header
                .kid
                .as_deref()
                .ok_or_else(|| StatusError::Unavailable(format!("{uri}: no `kid`")))?;
            let kid = DidUrl::parse(kid).map_err(|e| {
                StatusError::Unavailable(format!("{uri}: `kid` {kid:?} is not a DID URL: {e}"))
            })?;
            if kid.path().is_some() || kid.query().is_some() {
                return Err(StatusError::Unavailable(format!(
                    "{uri}: `kid` `{kid}` carries a path or DID parameters"
                )));
            }
            let key = self
                .resolver
                .resolve_key(&kid, VerificationRelationship::AssertionMethod)
                .await
                .map_err(|e| StatusError::Unavailable(format!("{uri}: resolving `kid`: {e}")))?;
            jwt.decode()
                .map_err(|e| StatusError::Unavailable(format!("{uri}: {e}")))?
                .verify(&self.verifier, &key)
                .map_err(|e| StatusError::Unavailable(format!("{uri}: signature: {e}")))?;
            Ok(token)
        }
    }

    #[async_trait::async_trait]
    impl<C: HttpClient, R: KeyResolver, V: JwsVerifier> SdJwtStatusCheck for StatusListCheck<C, R, V> {
        async fn check(&self, status: &Status, now: DateTime<Utc>) -> Result<(), StatusError> {
            let Some(reference) = &status.status_list else {
                let names: Vec<&str> = status
                    .mechanisms()
                    .filter_map(|m| match m {
                        StatusMechanism::Other { name, .. } => Some(name),
                        _ => None,
                    })
                    .collect();
                return Err(StatusError::Unsupported(names.join(", ")));
            };
            let token = self.fetch(&reference.uri).await?;
            let status_type = token
                .status_of(reference, now)
                .map_err(|e| StatusError::Unavailable(e.to_string()))?;
            if status_type.is_valid() {
                Ok(())
            } else {
                Err(StatusError::Invalid(status_type.to_string()))
            }
        }
    }

    impl<C: core::fmt::Debug, R: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug
        for StatusListCheck<C, R, V>
    {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("StatusListCheck")
                .field("client", &self.client)
                .field("resolver", &self.resolver)
                .field("verifier", &self.verifier)
                .finish()
        }
    }
}
