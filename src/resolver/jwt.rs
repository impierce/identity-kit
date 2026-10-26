//! `JwtValidator`: validation of a JWT that is not a credential or a presentation.

use core::fmt;
use core::time::Duration;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;

use super::{KeyReference, KeyReferenceError, KeyResolutionError, KeyResolver, KeyRole};
use crate::jose::{
    CompactJws, DefaultVerifier, Jwk, JwsAlgorithm, JwsError, JwsHeader, JwsVerifier, JwtClaims,
    OneOrMany, VerificationError,
};

/// Validates a compact JWT that is neither a credential nor a presentation: an OAuth 2.0 access
/// token (RFC 9068), an ID token, a request object.
///
/// The checks follow RFC 7519 §7.2 and the best current practices of RFC 8725, in this order:
///
/// 1. The token is a compact JWS ([`CompactJws::decode`]), whose `alg` is one the options allow
///    (RFC 8725 §3.1) and whose header `typ` is the one the options expect, if they expect one
///    (RFC 8725 §3.11). `typ` is compared as RFC 7515 §4.1.9 says: ignoring case and an
///    `application/` prefix.
/// 2. The payload is a JSON claims set.
/// 3. The key the header names ([`KeyReference::from_jws`], with the `iss` of the claims) is
///    resolved for the [`KeyRole`] of the options and verifies the signature.
/// 4. Under [`IssuerBinding::KeyOfIssuer`], the default, the key belongs to `iss`
///    ([`KeyReference::binds_to`]): `iss` is the DID of a `kid` DID URL, the HTTPS issuer of a
///    key set, or the `did:jwk` or thumbprint of a key by value.
/// 5. `iss` is the expected issuer, and `aud` includes the expected audience, when the options
///    name them.
/// 6. `exp`, `nbf` and `iat` hold at the validation time, within the leeway.
/// 7. Every claim the options require is present.
///
/// What else a token must say (a `scope`, a `client_id`, a `nonce`) is the application's to
/// check, on the claims it gets back. Explicit typing is what keeps one kind of JWT from being
/// accepted as another (RFC 8725 §3.11); name the `typ` whenever the token has one.
///
/// # Examples
///
/// An authorization server signs an access token with the Ed25519 key of RFC 8037 Appendix
/// A.1, naming it by a DID URL while its `iss` is its HTTPS URL. The resource server pins that
/// one key: its resolver knows no other, so the key need not belong to `iss`. A resolver that
/// returns any key a token carries, such as [`JwkResolver`](super::JwkResolver), must never be
/// combined with [`IssuerBinding::Any`]: anyone could sign with their own key.
///
/// ```
/// use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, JwtClaims, SignError, Signer, encode_compact};
/// use identity_kit::resolver::{
///     IssuerBinding, JwtValidationError, JwtValidationOptions, JwtValidator, KeyReference,
///     KeyResolutionError, KeyResolver, KeyRole,
/// };
///
/// struct Server(ed25519_dalek::SigningKey);
///
/// #[async_trait::async_trait]
/// impl Signer for Server {
///     fn alg(&self) -> JwsAlgorithm { JwsAlgorithm::EdDSA }
///     fn kid(&self) -> Option<&str> { None }
///     async fn sign(&self, input: &[u8]) -> Result<Vec<u8>, SignError> {
///         use ed25519_dalek::Signer as _;
///         Ok(self.0.sign(input).to_bytes().to_vec())
///     }
/// }
///
/// /// The authorization server's one key, under the one DID URL it signs with.
/// struct Pinned(Jwk);
///
/// #[async_trait::async_trait]
/// impl KeyResolver for Pinned {
///     async fn resolve_key(&self, key: &KeyReference, _: KeyRole) -> Result<Jwk, KeyResolutionError> {
///         match key {
///             KeyReference::DidUrl(url) if url.as_str() == "did:example:as#key-1" => Ok(self.0.clone()),
///             other => Err(KeyResolutionError::unsupported(other)),
///         }
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let secret = [
///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
///     0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
/// ];
/// let server = Server(ed25519_dalek::SigningKey::from_bytes(&secret));
/// let key = Jwk::from_ed25519_public(server.0.verifying_key().as_bytes())?;
///
/// let header = JwsHeader::new(JwsAlgorithm::EdDSA)
///     .with_typ("at+jwt")
///     .with_kid("did:example:as#key-1");
/// let mut claims = JwtClaims::new()
///     .with_iss("https://as.example.com")
///     .with_sub("5ba552d67")
///     .with_aud("https://rs.example.com")
///     .with_jti("dbe39bf3a3ba4238a513f51d6e1691c4")
///     .with_claim("client_id", "s6BhdRkqt3")
///     .with_claim("scope", "openid profile");
/// claims.iat = Some(1_700_000_000);
/// claims.exp = Some(1_700_003_600);
/// let token = encode_compact(&header, &serde_json::to_vec(&claims)?, &server).await?;
///
/// // The key is the pinned one, not the DID of `iss`, so the binding is waived.
/// let validator = JwtValidator::new(Pinned(key.clone()), DefaultVerifier);
/// let options = JwtValidationOptions::new()
///     .with_typ("at+jwt")
///     .with_algorithm(JwsAlgorithm::EdDSA)
///     .with_issuer("https://as.example.com")
///     .with_audience("https://rs.example.com")
///     .with_issuer_binding(IssuerBinding::Any)
///     .with_required_claims(["exp", "iat", "jti", "sub", "client_id"])
///     .at(1_700_000_100);
/// let validated = validator.validate(&token, &options).await?;
/// assert_eq!(validated.claims.sub.as_deref(), Some("5ba552d67"));
/// assert_eq!(validated.key, key);
///
/// // A token naming any other key is refused.
/// let forged = encode_compact(
///     &JwsHeader::new(JwsAlgorithm::EdDSA).with_typ("at+jwt").with_kid("did:example:attacker#key-1"),
///     &serde_json::to_vec(&claims)?,
///     &server,
/// )
/// .await?;
/// let error = validator.validate(&forged, &options).await.unwrap_err();
/// assert!(matches!(error, JwtValidationError::KeyResolution { .. }));
///
/// // An hour and a minute later it has expired.
/// let error = validator.validate(&token, &options.at(1_700_003_660)).await.unwrap_err();
/// assert!(matches!(error, JwtValidationError::Expired { expired_at: 1_700_003_600, .. }));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct JwtValidator<R, V = DefaultVerifier> {
    resolver: R,
    verifier: V,
}

impl<R: KeyResolver, V: JwsVerifier> JwtValidator<R, V> {
    /// A validator resolving keys with `resolver` and verifying signatures with `verifier`.
    pub fn new(resolver: R, verifier: V) -> Self {
        Self { resolver, verifier }
    }

    /// The key resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// The signature verifier.
    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    /// Validates `token`, returning its claims as a [`JwtClaims`] set.
    ///
    /// # Errors
    ///
    /// The first [`JwtValidationError`] found, in the order [`JwtValidator`] lists the checks.
    pub async fn validate(
        &self,
        token: &str,
        options: &JwtValidationOptions,
    ) -> Result<ValidatedJwt, JwtValidationError> {
        self.validate_as(token, options).await
    }

    /// Validates `token`, returning its claims read into `T`, once the registered claims have
    /// been checked.
    ///
    /// # Errors
    ///
    /// As [`validate`](Self::validate), and [`JwtValidationError::Claims`] when the payload
    /// does not fit `T`.
    pub async fn validate_as<T: DeserializeOwned>(
        &self,
        token: &str,
        options: &JwtValidationOptions,
    ) -> Result<ValidatedJwt<T>, JwtValidationError> {
        let jws = CompactJws::decode(token)?;
        let header = jws.header();
        if !options.allows(header.alg) {
            return Err(JwtValidationError::DisallowedAlgorithm(header.alg));
        }
        if let Some(expected) = &options.typ
            && !header
                .typ
                .as_deref()
                .is_some_and(|typ| same_typ(typ, expected))
        {
            return Err(JwtValidationError::UnexpectedTyp {
                expected: expected.clone(),
                found: header.typ.clone(),
            });
        }
        let claims: JwtClaims =
            serde_json::from_slice(jws.payload()).map_err(JwtValidationError::Payload)?;

        let reference = KeyReference::from_jws(&jws, claims.iss.as_deref())?;
        let key = self
            .resolver
            .resolve_key(&reference, options.role)
            .await
            .map_err(|source| JwtValidationError::KeyResolution {
                key: Box::new(reference.clone()),
                source,
            })?;
        jws.verify(&self.verifier, &key)?;
        if options.issuer_binding == IssuerBinding::KeyOfIssuer
            && !reference.binds_to(claims.iss.as_deref(), &key)
        {
            return Err(JwtValidationError::KeyNotIssuers {
                issuer: claims.iss.clone(),
                key: Box::new(reference),
            });
        }

        if let Some(expected) = &options.issuer
            && claims.iss.as_ref() != Some(expected)
        {
            return Err(JwtValidationError::IssuerMismatch {
                expected: expected.clone(),
                found: claims.iss.clone(),
            });
        }
        if let Some(expected) = &options.audience
            && !claims.audiences().any(|audience| audience == expected)
        {
            return Err(JwtValidationError::AudienceMismatch {
                expected: expected.clone(),
                found: claims.aud.clone(),
            });
        }
        options.check_times(&claims)?;
        for claim in &options.required_claims {
            if !has_claim(&claims, claim) {
                return Err(JwtValidationError::MissingClaim(claim.clone()));
            }
        }

        let typed = serde_json::from_slice(jws.payload()).map_err(JwtValidationError::Claims)?;
        Ok(ValidatedJwt {
            header: header.clone(),
            claims: typed,
            key,
            key_reference: reference,
        })
    }
}

impl<R: fmt::Debug, V: fmt::Debug> fmt::Debug for JwtValidator<R, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtValidator")
            .field("resolver", &self.resolver)
            .field("verifier", &self.verifier)
            .finish()
    }
}

/// Whether the header `typ` `found` is the media type `expected`: compared ignoring ASCII case,
/// with an `application/` prefix on either side optional (RFC 7515 §4.1.9).
fn same_typ(found: &str, expected: &str) -> bool {
    fn bare(typ: &str) -> &str {
        match typ.get(..12) {
            Some(prefix) if prefix.eq_ignore_ascii_case("application/") => &typ[12..],
            _ => typ,
        }
    }
    bare(found).eq_ignore_ascii_case(bare(expected))
}

/// Whether `claims` has the claim `name`, registered or not.
fn has_claim(claims: &JwtClaims, name: &str) -> bool {
    match name {
        "iss" => claims.iss.is_some(),
        "sub" => claims.sub.is_some(),
        "aud" => claims.aud.is_some(),
        "exp" => claims.exp.is_some(),
        "nbf" => claims.nbf.is_some(),
        "iat" => claims.iat.is_some(),
        "jti" => claims.jti.is_some(),
        other => claims.additional.contains_key(other),
    }
}

/// A JWT that passed [`JwtValidator::validate`]: its header, its claims and the key that signed
/// it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedJwt<T = JwtClaims> {
    /// The JWS header.
    pub header: JwsHeader,
    /// The claims, as a [`JwtClaims`] set or the type [`JwtValidator::validate_as`] read them
    /// into.
    pub claims: T,
    /// The public key that verified the signature.
    pub key: Jwk,
    /// Where the header said the key was.
    pub key_reference: KeyReference,
}

/// Whether the key that signed a token must belong to its issuer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IssuerBinding {
    /// The key must belong to `iss` ([`KeyReference::binds_to`]): a `kid` DID URL of the DID
    /// `iss`, a key of the key set of the HTTPS `iss`, or a key by value whose `did:jwk` or
    /// thumbprint is `iss`, or which comes with no `iss` at all.
    #[default]
    KeyOfIssuer,
    /// Any key the [`KeyResolver`] resolves is accepted, whatever `iss` says: for a resolver
    /// that only resolves keys the application trusts, such as an authorization server's
    /// signing keys behind a `kid` that is a DID URL of a DID other than its `iss` URL.
    ///
    /// Never with a resolver that returns a key the token itself carries, such as
    /// [`JwkResolver`](super::JwkResolver) for a `jwk` header, or one that resolves any DID:
    /// the issuer binding is then the only thing tying the key to `iss`, and without it anyone
    /// can sign a token with their own key.
    Any,
}

/// Options of [`JwtValidator`]: what the token must be, and when.
///
/// The default accepts every algorithm the crate verifies, any `typ`, any issuer and audience,
/// with the key bound to `iss`, at the current time without leeway, and requires no claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct JwtValidationOptions {
    /// The algorithms accepted; every algorithm when empty.
    pub algorithms: BTreeSet<JwsAlgorithm>,
    /// The header `typ` the token must have, if any.
    pub typ: Option<String>,
    /// The `iss` the token must have, if any.
    pub issuer: Option<String>,
    /// The audience the token's `aud` must include, if any.
    pub audience: Option<String>,
    /// The role the signing key is resolved for: [`KeyRole::Issuer`] (`assertionMethod` in a
    /// DID document) by default, [`KeyRole::Subject`] (`authentication`) for a token that
    /// proves possession.
    pub role: KeyRole,
    /// Whether the signing key must belong to `iss`.
    pub issuer_binding: IssuerBinding,
    /// Claims that must be present, registered or not.
    pub required_claims: BTreeSet<String>,
    /// The validation time in seconds since the Unix epoch; the current time when `None`.
    pub now: Option<i64>,
    /// How far `exp`, `nbf` and `iat` may miss the validation time and still pass.
    pub leeway: Duration,
}

impl JwtValidationOptions {
    /// The default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// These options also accepting `alg`. Once one algorithm is named, only the named ones
    /// are accepted.
    #[must_use]
    pub fn with_algorithm(mut self, alg: JwsAlgorithm) -> Self {
        self.algorithms.insert(alg);
        self
    }

    /// These options requiring the header `typ` to be `typ`.
    #[must_use]
    pub fn with_typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    /// These options requiring `iss` to be `issuer`.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// These options requiring `aud` to include `audience`.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// These options resolving the signing key for `role`.
    #[must_use]
    pub fn with_role(mut self, role: KeyRole) -> Self {
        self.role = role;
        self
    }

    /// These options with `binding`.
    #[must_use]
    pub fn with_issuer_binding(mut self, binding: IssuerBinding) -> Self {
        self.issuer_binding = binding;
        self
    }

    /// These options also requiring every claim of `claims`.
    #[must_use]
    pub fn with_required_claims<I, S>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.required_claims
            .extend(claims.into_iter().map(Into::into));
        self
    }

    /// These options validating at `now`, in seconds since the Unix epoch.
    #[must_use]
    pub fn at(mut self, now: i64) -> Self {
        self.now = Some(now);
        self
    }

    /// These options with `leeway`.
    #[must_use]
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// The validation time, in seconds since the Unix epoch.
    pub fn now(&self) -> i64 {
        self.now.unwrap_or_else(|| {
            let since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO);
            i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX)
        })
    }

    /// Whether `alg` is accepted.
    fn allows(&self, alg: JwsAlgorithm) -> bool {
        self.algorithms.is_empty() || self.algorithms.contains(&alg)
    }

    /// Checks `exp`, `nbf` and `iat` at the validation time, within the leeway.
    fn check_times(&self, claims: &JwtClaims) -> Result<(), JwtValidationError> {
        let now = self.now();
        let leeway = i64::try_from(self.leeway.as_secs()).unwrap_or(i64::MAX);
        let latest = now.saturating_add(leeway);
        let earliest = now.saturating_sub(leeway);
        if let Some(expired_at) = claims.exp
            && expired_at <= earliest
        {
            return Err(JwtValidationError::Expired { expired_at, now });
        }
        if let Some(not_before) = claims.nbf
            && not_before > latest
        {
            return Err(JwtValidationError::NotYetValid { not_before, now });
        }
        if let Some(issued_at) = claims.iat
            && issued_at > latest
        {
            return Err(JwtValidationError::IssuedInFuture { issued_at, now });
        }
        Ok(())
    }
}

/// Why a JWT did not pass [`JwtValidator::validate`].
///
/// Times are `NumericDate` seconds since the Unix epoch.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwtValidationError {
    /// The token is not a compact JWS this crate decodes.
    #[error("invalid JWS: {0}")]
    Jws(#[from] JwsError),
    /// The header `alg` is not one the options accept.
    #[error("algorithm `{0}` is not accepted")]
    DisallowedAlgorithm(JwsAlgorithm),
    /// The header `typ` is not the one the options require, or is missing.
    #[error("header `typ` is {found:?}, not `{expected}`")]
    UnexpectedTyp {
        /// The `typ` required.
        expected: String,
        /// The `typ` found.
        found: Option<String>,
    },
    /// The payload is not a JSON claims set; the source is the JSON error.
    #[error("the payload is not a JWT claims set: {0}")]
    Payload(#[source] serde_json::Error),
    /// The header names no key this crate can look for.
    #[error(transparent)]
    KeyReference(#[from] KeyReferenceError),
    /// The key the token names could not be resolved.
    #[error("resolving key {key}: {source}")]
    KeyResolution {
        /// Where the token says its key is.
        key: Box<KeyReference>,
        /// What went wrong.
        #[source]
        source: KeyResolutionError,
    },
    /// The signature does not verify under the resolved key.
    #[error("signature: {0}")]
    Signature(#[from] VerificationError),
    /// The key that signed the token does not belong to its `iss`.
    #[error("signing key {key} does not belong to issuer {issuer:?}")]
    KeyNotIssuers {
        /// The `iss`, if the token has one.
        issuer: Option<String>,
        /// Where the token says its key is.
        key: Box<KeyReference>,
    },
    /// `iss` is not the expected issuer.
    #[error("issuer {found:?} is not {expected:?}")]
    IssuerMismatch {
        /// The issuer expected.
        expected: String,
        /// The `iss` found.
        found: Option<String>,
    },
    /// `aud` does not include the expected audience.
    #[error("audience {found:?} does not include {expected:?}")]
    AudienceMismatch {
        /// The audience expected.
        expected: String,
        /// The `aud` found.
        found: Option<OneOrMany<String>>,
    },
    /// The token has expired.
    #[error("expired at {expired_at} (now is {now})")]
    Expired {
        /// The `exp`.
        expired_at: i64,
        /// The validation time.
        now: i64,
    },
    /// The token is not valid yet.
    #[error("not valid before {not_before} (now is {now})")]
    NotYetValid {
        /// The `nbf`.
        not_before: i64,
        /// The validation time.
        now: i64,
    },
    /// The token claims to have been issued in the future.
    #[error("issued at {issued_at}, after now ({now})")]
    IssuedInFuture {
        /// The `iat`.
        issued_at: i64,
        /// The validation time.
        now: i64,
    },
    /// A claim the options require is missing.
    #[error("missing claim `{0}`")]
    MissingClaim(String),
    /// The claims do not fit the type [`JwtValidator::validate_as`] reads them into; the source
    /// is the JSON error.
    #[error("the claims do not fit the expected type: {0}")]
    Claims(#[source] serde_json::Error),
}
