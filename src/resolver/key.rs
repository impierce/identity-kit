//! `KeyReference`, `KeyRole` and `KeyResolver`: where a token says its key is, and the trait
//! that finds it.

use core::fmt;
use std::error::Error;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use url::Url;

use super::{DereferenceError, Resolver};
use crate::did::{Did, DidError, DidUrl, VerificationRelationship};
use crate::jose::{CompactJws, Jwk, base64url};

/// Where a token says the key that signed it is (ADR 0006).
///
/// A JWT names its key in one of several ways: a DID URL in `kid`, a `#fragment` in `kid`
/// relative to a DID `iss`, a `kid` into the key set an HTTPS `iss` publishes, the key itself in
/// a `jwk` header, a certificate chain in `x5c`, or a key set URL in `jku`.
/// [`from_jws`](Self::from_jws) reads which from a JWS header; `sd_jwt_vc` builds one from a
/// `cnf` claim. A [`KeyResolver`] turns it into a key.
///
/// Resolving a reference says nothing about trust: a key by value resolves to itself whoever
/// made the token. Once the signature verifies, [`binds_to`](Self::binds_to) checks that the key
/// belongs to the party the token claims.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{CompactJws, JwtClaims};
/// use identity_kit::resolver::{KeyReference, KeyReferenceError};
///
/// // {"alg":"EdDSA","kid":"#key-1"}.{"iss":"did:example:123"}
/// let jws = CompactJws::decode(
///     "eyJhbGciOiJFZERTQSIsImtpZCI6IiNrZXktMSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMifQ.c2lnbmF0dXJl",
/// )?;
/// let claims: JwtClaims = jws.claims()?;
/// let reference = KeyReference::from_jws(&jws, claims.iss.as_deref())?;
/// assert_eq!(reference.to_string(), "did:example:123#key-1");
///
/// // A relative `kid` needs a DID to resolve against.
/// assert!(matches!(
///     KeyReference::from_jws(&jws, None),
///     Err(KeyReferenceError::RelativeKidWithoutIssuer(_))
/// ));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyReference {
    /// A verification method: a `kid` that is an absolute DID URL, or a `#fragment` joined with
    /// a DID `iss`.
    DidUrl(DidUrl),
    /// The public key itself, from a `jwk` header or `cnf.jwk`.
    Jwk(Box<Jwk>),
    /// An `x5c` certificate chain, DER, leaf first. No resolver in the crate handles it yet.
    X509Chain(Vec<Vec<u8>>),
    /// The key `kid` names in the key set of the HTTPS issuer `issuer` (SD-JWT VC §3.5).
    Jwks {
        /// The issuer, the `iss` of the token.
        issuer: Url,
        /// The `kid` of the key in the issuer's key set.
        kid: String,
    },
    /// The key set at `url`, from `jku`, and the `kid` that selects a key in it. No resolver in
    /// the crate handles it yet.
    Jku {
        /// The key set URL.
        url: Url,
        /// The `kid`, if the token has one.
        kid: Option<String>,
    },
}

impl KeyReference {
    /// Where the key of `jws` is, given the `iss` of its claims (when `iss` is a string).
    ///
    /// The header parameters are tried in this order, and the first that applies decides:
    ///
    /// 1. A `kid` that parses as a DID URL is [`DidUrl`](Self::DidUrl). A path or DID
    ///    parameters such as `versionId` are refused: they could select a document version
    ///    that still lists a retired key (ADR 0004).
    /// 2. A `kid` starting with `#` is joined with `iss` into a [`DidUrl`](Self::DidUrl) when
    ///    `iss` is a DID, and refused otherwise.
    /// 3. Another `kid`, with an `https` `iss`, is [`Jwks`](Self::Jwks).
    /// 4. A `jwk` header is [`Jwk`](Self::Jwk); a private key there is refused.
    /// 5. An `x5c` header is [`X509Chain`](Self::X509Chain), each certificate base64-decoded
    ///    but not parsed.
    /// 6. A `jku` header is [`Jku`](Self::Jku), with the `kid` when there is one.
    ///
    /// A `kid` that none of the first three cases takes is an error when no `jwk`, `x5c` or
    /// `jku` follows.
    ///
    /// # Errors
    ///
    /// A [`KeyReferenceError`]: [`Missing`](KeyReferenceError::Missing) when the header names no
    /// key, otherwise the parameter that is wrong.
    pub fn from_jws(jws: &CompactJws, iss: Option<&str>) -> Result<Self, KeyReferenceError> {
        let header = jws.header();
        let mut kid_error = None;
        if let Some(kid) = header.kid.as_deref() {
            match Self::from_kid(kid, iss)? {
                Ok(reference) => return Ok(reference),
                Err(source) => {
                    kid_error = Some(KeyReferenceError::InvalidKid {
                        kid: kid.to_owned(),
                        source,
                    });
                }
            }
        }
        if let Some(jwk) = &header.jwk {
            if jwk.is_private() {
                return Err(KeyReferenceError::InvalidJwk(
                    "the `jwk` header holds a private key".to_owned(),
                ));
            }
            return Ok(Self::Jwk(Box::new(jwk.clone())));
        }
        if let Some(x5c) = header.additional.get("x5c") {
            return x5c_chain(x5c).map(Self::X509Chain);
        }
        if let Some(jku) = header.additional.get("jku") {
            let url = jku
                .as_str()
                .ok_or_else(|| KeyReferenceError::InvalidUrl {
                    parameter: "jku",
                    value: jku.to_string(),
                    reason: "not a string".to_owned(),
                })
                .and_then(|jku| parse_url("jku", jku))?;
            return Ok(Self::Jku {
                url,
                kid: header.kid.clone(),
            });
        }
        Err(kid_error.unwrap_or(KeyReferenceError::Missing))
    }

    /// Rules 1 to 3 of [`from_jws`](Self::from_jws): the reference `kid` makes with `iss`, or
    /// why `kid` is not a DID URL when it makes none.
    fn from_kid(kid: &str, iss: Option<&str>) -> Result<Result<Self, DidError>, KeyReferenceError> {
        let not_did_url = match DidUrl::parse(kid) {
            Ok(url) => return did_url(url).map(Ok),
            Err(error) => error,
        };
        if kid.starts_with('#') {
            let did = iss
                .and_then(|iss| Did::parse(iss).ok())
                .ok_or_else(|| KeyReferenceError::RelativeKidWithoutIssuer(kid.to_owned()))?;
            let url = did
                .join(kid)
                .map_err(|source| KeyReferenceError::InvalidKid {
                    kid: kid.to_owned(),
                    source,
                })?;
            return did_url(url).map(Ok);
        }
        if let Some(issuer) = iss
            .and_then(|iss| Url::parse(iss).ok())
            .filter(|issuer| issuer.scheme() == "https")
        {
            return Ok(Ok(Self::Jwks {
                issuer,
                kid: kid.to_owned(),
            }));
        }
        Ok(Err(not_did_url))
    }

    /// Whether `key`, which this reference resolved to and which verified the signature,
    /// belongs to `party`, the issuer or holder the token claims:
    ///
    /// | Reference | Binds when |
    /// |---|---|
    /// | [`DidUrl`](Self::DidUrl) | `party` is the DID of the URL |
    /// | [`Jwk`](Self::Jwk) | `party` is the `did:jwk` of `key`, or its RFC 7638 SHA-256 thumbprint, or absent (a SIOPv2 self-issued `sub`) |
    /// | [`Jwks`](Self::Jwks) | `party` is the issuer URL (compared as parsed URLs) |
    /// | [`X509Chain`](Self::X509Chain), [`Jku`](Self::Jku) | never, until the crate resolves them |
    ///
    /// Only a key by value can bind to no party; a validator that requires an issuer or holder
    /// passes it.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::DidUrl;
    /// use identity_kit::jose::Jwk;
    /// use identity_kit::resolver::KeyReference;
    ///
    /// // RFC 8037 Appendix A.2.
    /// let key: Jwk = serde_json::from_str(
    ///     r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    /// )?;
    /// let by_value = KeyReference::Jwk(Box::new(key.clone()));
    /// // RFC 8037 Appendix A.3.
    /// assert!(by_value.binds_to(Some("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"), &key));
    /// assert!(by_value.binds_to(None, &key));
    /// assert!(!by_value.binds_to(Some("did:example:123"), &key));
    ///
    /// let by_url = KeyReference::DidUrl(DidUrl::parse("did:example:123#key-1")?);
    /// assert!(by_url.binds_to(Some("did:example:123"), &key));
    /// assert!(!by_url.binds_to(Some("did:example:456"), &key));
    /// assert!(!by_url.binds_to(None, &key));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn binds_to(&self, party: Option<&str>, key: &Jwk) -> bool {
        match (self, party) {
            (Self::DidUrl(url), Some(party)) => {
                Did::parse(party).is_ok_and(|did| did == *url.did())
            }
            (Self::Jwk(_), None) => true,
            (Self::Jwk(_), Some(party)) => is_key_identifier(party, key),
            (Self::Jwks { issuer, .. }, Some(party)) => {
                Url::parse(party).is_ok_and(|party| party == *issuer)
            }
            _ => false,
        }
    }
}

impl fmt::Display for KeyReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DidUrl(url) => fmt::Display::fmt(url, f),
            Self::Jwk(jwk) => match jwk.thumbprint_sha256() {
                Ok(thumbprint) => write!(f, "JWK {thumbprint}"),
                Err(_) => f.write_str("JWK"),
            },
            Self::X509Chain(chain) => write!(f, "`x5c` chain of {} certificates", chain.len()),
            Self::Jwks { issuer, kid } => write!(f, "`{kid}` of issuer `{issuer}`"),
            Self::Jku {
                url,
                kid: Some(kid),
            } => write!(f, "`{kid}` of `{url}`"),
            Self::Jku { url, kid: None } => write!(f, "the key of `{url}`"),
        }
    }
}

/// `url`, refused when it carries a path or DID parameters.
fn did_url(url: DidUrl) -> Result<KeyReference, KeyReferenceError> {
    if url.path().is_some() || url.query().is_some() {
        return Err(KeyReferenceError::KidWithParameters(url));
    }
    Ok(KeyReference::DidUrl(url))
}

/// The certificates of an `x5c` header: an array of standard base64 DER (RFC 7515 §4.1.6).
fn x5c_chain(x5c: &serde_json::Value) -> Result<Vec<Vec<u8>>, KeyReferenceError> {
    let invalid = |reason: &str| KeyReferenceError::InvalidX5c(reason.to_owned());
    let certificates = x5c.as_array().ok_or_else(|| invalid("not an array"))?;
    if certificates.is_empty() {
        return Err(invalid("the chain is empty"));
    }
    certificates
        .iter()
        .map(|certificate| {
            let certificate = certificate
                .as_str()
                .ok_or_else(|| invalid("a certificate is not a string"))?;
            STANDARD
                .decode(certificate)
                .map_err(|_| invalid("a certificate is not base64"))
        })
        .collect()
}

/// `value` of `parameter` as an absolute URL.
fn parse_url(parameter: &'static str, value: &str) -> Result<Url, KeyReferenceError> {
    Url::parse(value).map_err(|e| KeyReferenceError::InvalidUrl {
        parameter,
        value: value.to_owned(),
        reason: e.to_string(),
    })
}

/// Whether `party` is the `did:jwk` or the RFC 7638 SHA-256 thumbprint of `key`.
fn is_key_identifier(party: &str, key: &Jwk) -> bool {
    let Ok(thumbprint) = key.thumbprint_sha256() else {
        return false;
    };
    if party == thumbprint {
        return true;
    }
    // A `did:jwk` names the key by value, in whatever member order its creator serialized it;
    // the thumbprint compares the required members only.
    Did::parse(party)
        .ok()
        .filter(|did| did.method() == "jwk")
        .and_then(|did| base64url::decode(did.method_specific_id()).ok())
        .and_then(|json| serde_json::from_slice::<Jwk>(&json).ok())
        .and_then(|jwk| jwk.thumbprint_sha256().ok())
        .is_some_and(|named| named == thumbprint)
}

/// Why a token names no key this crate can look for.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyReferenceError {
    /// The token names no key: no `kid`, `jwk`, `x5c` or `jku` (or, in `cnf`, no `jwk`, `kid`
    /// or `jku`).
    #[error("the token names no key: no `kid`, `jwk`, `x5c` or `jku`")]
    Missing,
    /// The `kid` is a `#fragment` and `iss` is not a DID to resolve it against.
    #[error("`kid` {0:?} is relative and `iss` is not a DID")]
    RelativeKidWithoutIssuer(String),
    /// The `kid` is neither a DID URL nor anything else the token resolves it with.
    #[error("`kid` {kid:?} is not a DID URL: {source}")]
    InvalidKid {
        /// The `kid`.
        kid: String,
        /// Why it is not a DID URL.
        #[source]
        source: DidError,
    },
    /// The `kid` carries a path or DID parameters. `versionId` and `versionTime` could select a
    /// document version that still lists a retired key, so only `did:…#fragment` keys are
    /// accepted.
    #[error("`kid` `{0}` carries a path or DID parameters")]
    KidWithParameters(DidUrl),
    /// The key by value is not usable: it holds private material, say.
    #[error("invalid `jwk`: {0}")]
    InvalidJwk(String),
    /// The `x5c` header is not an array of base64 certificates.
    #[error("invalid `x5c`: {0}")]
    InvalidX5c(String),
    /// A URL parameter (`jku`) is not an absolute URL.
    #[error("`{parameter}` {value:?} is not a URL: {reason}")]
    InvalidUrl {
        /// The parameter.
        parameter: &'static str,
        /// Its value.
        value: String,
        /// Why it did not parse.
        reason: String,
    },
    /// The confirmation names its key only by a method the crate does not resolve, such as
    /// `x5t#S256` or `jwe`.
    #[error("`cnf` names its key only by `{0}`, which is not supported")]
    UnsupportedConfirmation(String),
}

/// The role a key plays in a token, which decides what a DID document must say about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyRole {
    /// The key signs as the issuer of a credential or status list: `assertionMethod`.
    Issuer,
    /// The key proves possession by the subject or holder (a presentation, a key binding JWT,
    /// an ID token): `authentication`.
    Subject,
}

impl KeyRole {
    /// The verification relationship a DID document must list a key of this role under.
    pub fn relationship(self) -> VerificationRelationship {
        match self {
            Self::Issuer => VerificationRelationship::AssertionMethod,
            Self::Subject => VerificationRelationship::Authentication,
        }
    }
}

/// Finds the public key a [`KeyReference`] names.
///
/// [`Resolver`] implements it for DID URLs, [`JwkResolver`] for keys by value and, with the
/// `jwks` feature, `JwksResolver` for the key sets of HTTPS issuers;
/// [`CompositeKeyResolver`] combines them. An application can implement it over a cache, a
/// fixed set of trusted keys, or a reference the crate does not resolve.
#[async_trait::async_trait]
pub trait KeyResolver: Send + Sync {
    /// The public key `key` names, usable in `role`.
    ///
    /// # Errors
    ///
    /// [`KeyResolutionError::Unsupported`] for a kind of reference this resolver does not
    /// handle, which lets a [`CompositeKeyResolver`] try the next one; any other
    /// [`KeyResolutionError`] when the key cannot be found or used.
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError>;
}

macro_rules! forward_key_resolver {
    ($($ty:ty),* $(,)?) => {$(
        #[async_trait::async_trait]
        impl<T: KeyResolver + ?Sized> KeyResolver for $ty {
            async fn resolve_key(
                &self,
                key: &KeyReference,
                role: KeyRole,
            ) -> Result<Jwk, KeyResolutionError> {
                (**self).resolve_key(key, role).await
            }
        }
    )*};
}

forward_key_resolver!(&T, Box<T>, Arc<T>);

/// Resolves a [`KeyReference::DidUrl`] by dereferencing it to a verification method listed
/// under the relationship of the role; every other reference is
/// [`Unsupported`](KeyResolutionError::Unsupported).
#[async_trait::async_trait]
impl KeyResolver for Resolver {
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError> {
        match key {
            KeyReference::DidUrl(url) => self
                .resolve_public_key(url, Some(role.relationship()))
                .await
                .map_err(KeyResolutionError::from),
            other => Err(KeyResolutionError::unsupported(other)),
        }
    }
}

/// Resolves a [`KeyReference::Jwk`] to its public part; every other reference is
/// [`Unsupported`](KeyResolutionError::Unsupported).
///
/// Anybody can put a key in a `jwk` header, so the key says nothing about who signed: a
/// validator accepts it only when the claimed party is that key's `did:jwk` or thumbprint
/// ([`KeyReference::binds_to`]). Add it to a [`CompositeKeyResolver`] to accept such tokens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JwkResolver;

#[async_trait::async_trait]
impl KeyResolver for JwkResolver {
    async fn resolve_key(&self, key: &KeyReference, _: KeyRole) -> Result<Jwk, KeyResolutionError> {
        match key {
            KeyReference::Jwk(jwk) => Ok(jwk.public()),
            other => Err(KeyResolutionError::unsupported(other)),
        }
    }
}

/// Resolvers tried in order: the first answer other than
/// [`Unsupported`](KeyResolutionError::Unsupported) is the answer, an error included.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "did-key")]
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use identity_kit::jose::Jwk;
/// use identity_kit::methods::DidKey;
/// use identity_kit::resolver::{CompositeKeyResolver, JwkResolver, KeyReference, KeyResolver as _, KeyRole, Resolver};
///
/// let resolver = CompositeKeyResolver::new()
///     .with(Resolver::builder().with(DidKey::default()).build())
///     .with(JwkResolver);
///
/// // RFC 8037 Appendix A.2.
/// let key: Jwk = serde_json::from_str(
///     r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
/// )?;
/// let resolved = resolver.resolve_key(&KeyReference::Jwk(Box::new(key.clone())), KeyRole::Issuer).await?;
/// assert_eq!(resolved, key);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Default)]
pub struct CompositeKeyResolver {
    resolvers: Vec<Arc<dyn KeyResolver>>,
}

impl CompositeKeyResolver {
    /// A resolver with nothing to try: every reference is unsupported.
    pub fn new() -> Self {
        Self::default()
    }

    /// This resolver trying `resolver` after the ones added before.
    #[must_use]
    pub fn with(mut self, resolver: impl KeyResolver + 'static) -> Self {
        self.resolvers.push(Arc::new(resolver));
        self
    }

    /// This resolver trying the shared `resolver` after the ones added before.
    #[must_use]
    pub fn with_shared(mut self, resolver: Arc<dyn KeyResolver>) -> Self {
        self.resolvers.push(resolver);
        self
    }

    /// How many resolvers it tries.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether it has no resolver to try.
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl fmt::Debug for CompositeKeyResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeKeyResolver")
            .field("resolvers", &self.resolvers.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl KeyResolver for CompositeKeyResolver {
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError> {
        for resolver in &self.resolvers {
            match resolver.resolve_key(key, role).await {
                Err(KeyResolutionError::Unsupported(_)) => {}
                answer => return answer,
            }
        }
        Err(KeyResolutionError::unsupported(key))
    }
}

/// Why a [`KeyResolver`] found no key.
#[derive(Debug)]
#[non_exhaustive]
pub enum KeyResolutionError {
    /// The resolver does not handle this kind of reference.
    Unsupported(Box<KeyReference>),
    /// The resolver handles the reference and could not find or use the key.
    Failed(Box<dyn Error + Send + Sync + 'static>),
}

impl KeyResolutionError {
    /// The resolver does not handle `key`.
    pub fn unsupported(key: &KeyReference) -> Self {
        Self::Unsupported(Box::new(key.clone()))
    }

    /// A failure caused by `error`.
    pub fn new<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self::Failed(Box::new(error))
    }

    /// A failure described by `message` only.
    pub fn msg<M: fmt::Display>(message: M) -> Self {
        Self::Failed(message.to_string().into())
    }

    /// Whether the resolver does not handle the reference.
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported(_))
    }

    /// The error that caused a failure.
    pub fn inner(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
        match self {
            Self::Failed(error) => Some(&**error),
            Self::Unsupported(_) => None,
        }
    }
}

impl fmt::Display for KeyResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reference) => write!(f, "no resolver handles {reference}"),
            Self::Failed(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl Error for KeyResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Failed(error) => error.source(),
            Self::Unsupported(_) => None,
        }
    }
}

impl From<DereferenceError> for KeyResolutionError {
    fn from(error: DereferenceError) -> Self {
        Self::new(error)
    }
}
