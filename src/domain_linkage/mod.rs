//! DIF Well Known DID Configuration: proving that the controller of an origin and the
//! controller of a DID are the same entity.
//!
//! An origin publishes a [`DomainLinkageConfiguration`] at `/.well-known/did-configuration.json`
//! ([`configuration_url`]) holding one domain linkage credential per linked DID. This crate
//! handles the JSON Web Token proof format: [`DomainLinkageCredentialBuilder`] issues such a
//! credential (a VCDM 1.1 [`Credential`] of type `DomainLinkageCredential` whose subject is
//! the DID with the `origin`), and [`DomainLinkageValidator`] checks one, or a whole
//! configuration, against the origin it was fetched from, resolving the DID's key under
//! `assertionMethod`. Linked Data Proof entries are carried as data and not validated.
//!
//! The specification writes the origin with its scheme (`https://identity.foundation`), its
//! own JWT example without (`identity.foundation`); the validator normalizes both to the
//! `scheme://host[:port]` form, `https` when none is given, before comparing.

use core::fmt;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use url::Url;

use crate::did::{Did, DidUrl, Uri};
use crate::jose::{DefaultVerifier, JwsHeader, JwsVerifier, Signer};
use crate::vc::validation::{
    CredentialValidationOptions, DecodedCredential, JwtCredentialValidator, KeyResolver,
    ValidationError, decode_credential,
};
use crate::vc::{Credential, CredentialError, Jwt, JwtClaims, Subject};

/// The context of the DID configuration resource and of domain linkage credentials.
pub const CONTEXT: &str = "https://identity.foundation/.well-known/did-configuration/v1";

/// The credential type, `DomainLinkageCredential`.
pub const CREDENTIAL_TYPE: &str = "DomainLinkageCredential";

/// The path of the resource under an origin.
pub const WELL_KNOWN_PATH: &str = "/.well-known/did-configuration.json";

/// The URL of the DID configuration resource of `origin`.
///
/// # Errors
///
/// [`DomainLinkageError::InvalidOrigin`] when `origin` has no host.
///
/// # Examples
///
/// ```
/// use identity_kit::domain_linkage::configuration_url;
/// use url::Url;
///
/// let url = configuration_url(&Url::parse("https://identity.foundation")?)?;
/// assert_eq!(url.as_str(), "https://identity.foundation/.well-known/did-configuration.json");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn configuration_url(origin: &Url) -> Result<Url, DomainLinkageError> {
    let origin = normalize_origin(origin.as_str())?;
    Url::parse(&format!("{origin}{WELL_KNOWN_PATH}"))
        .map_err(|e| DomainLinkageError::InvalidOrigin(format!("{origin}: {e}")))
}

/// `origin` as `scheme://host[:port]`, lowercased, with `https` assumed when no scheme is
/// given and a path, query or fragment dropped.
///
/// # Errors
///
/// [`DomainLinkageError::InvalidOrigin`] when `origin` has no host.
pub fn normalize_origin(origin: &str) -> Result<String, DomainLinkageError> {
    let with_scheme = if has_scheme(origin) {
        origin.to_owned()
    } else {
        format!("https://{origin}")
    };
    let url = Url::parse(&with_scheme)
        .map_err(|e| DomainLinkageError::InvalidOrigin(format!("{origin:?}: {e}")))?;
    if url.host_str().is_none() {
        return Err(DomainLinkageError::InvalidOrigin(format!(
            "{origin:?} has no host"
        )));
    }
    let normalized = url.origin();
    if !normalized.is_tuple() {
        return Err(DomainLinkageError::InvalidOrigin(format!(
            "{origin:?} is not a domain origin"
        )));
    }
    Ok(normalized.ascii_serialization())
}

/// Whether `s` starts with a URI scheme (RFC 3986 §3.1) rather than a `host:port`.
fn has_scheme(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.starts_with(|c: char| c.is_ascii_digit())
}

/// One entry of `linked_dids`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum LinkedDid {
    /// A domain linkage credential in the JSON Web Token proof format.
    Jwt(Jwt),
    /// A domain linkage credential in the Linked Data Proof format, carried as data. An entry
    /// that is neither a compact JWT nor an object is a parse error, not a silently skipped
    /// credential.
    LinkedDataProof(serde_json::Map<String, Value>),
}

/// The DID configuration resource: `@context` and the domain linkage credentials.
///
/// # Examples
///
/// ```
/// use identity_kit::domain_linkage::{DomainLinkageConfiguration, LinkedDid};
/// use serde_json::json;
///
/// let configuration: DomainLinkageConfiguration = serde_json::from_value(json!({
///   "@context": "https://identity.foundation/.well-known/did-configuration/v1",
///   "linked_dids": [
///     "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
///   ]
/// }))?;
/// assert_eq!(configuration.jwts().count(), 1);
/// assert!(serde_json::from_value::<DomainLinkageConfiguration>(json!({
///   "@context": "https://example.com/other", "linked_dids": []
/// })).is_err());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct DomainLinkageConfiguration {
    /// `@context`, [`CONTEXT`].
    #[serde(rename = "@context")]
    pub context: String,
    /// The domain linkage credentials, one per linked DID.
    pub linked_dids: Vec<LinkedDid>,
}

impl Default for DomainLinkageConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainLinkageConfiguration {
    /// An empty configuration.
    pub fn new() -> Self {
        Self {
            context: CONTEXT.to_owned(),
            linked_dids: Vec::new(),
        }
    }

    /// This configuration with `credential` added.
    #[must_use]
    pub fn with_credential(mut self, credential: Jwt) -> Self {
        self.linked_dids.push(LinkedDid::Jwt(credential));
        self
    }

    /// The credentials in the JSON Web Token proof format, with their positions.
    pub fn jwts(&self) -> impl Iterator<Item = (usize, &Jwt)> {
        self.linked_dids
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| match entry {
                LinkedDid::Jwt(jwt) => Some((i, jwt)),
                _ => None,
            })
    }

    /// Checks that `@context` is [`CONTEXT`].
    ///
    /// # Errors
    ///
    /// [`DomainLinkageError::InvalidContext`].
    pub fn check(&self) -> Result<(), DomainLinkageError> {
        if self.context != CONTEXT {
            return Err(DomainLinkageError::InvalidContext(self.context.clone()));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for DomainLinkageConfiguration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(rename = "@context")]
            context: String,
            linked_dids: Vec<LinkedDid>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let configuration = Self {
            context: raw.context,
            linked_dids: raw.linked_dids,
        };
        configuration.check().map_err(serde::de::Error::custom)?;
        Ok(configuration)
    }
}

/// Builds a domain linkage credential in the JSON Web Token proof format: a VCDM 1.1
/// credential of type `DomainLinkageCredential` issued by `did` about `did` and `origin`,
/// carried in the `vc` claim with `iss`, `sub`, `nbf` and `exp` and nothing else.
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::did::Did;
/// use identity_kit::domain_linkage::DomainLinkageCredentialBuilder;
/// use url::Url;
///
/// let did = Did::parse("did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM")?;
/// let builder = DomainLinkageCredentialBuilder::new(
///     did.clone(),
///     &Url::parse("https://identity.foundation")?,
///     Utc.with_ymd_and_hms(2020, 12, 4, 20, 12, 19).unwrap(),
///     Utc.with_ymd_and_hms(2025, 12, 4, 20, 12, 19).unwrap(),
/// )?;
/// let claims = builder.jwt_claims();
/// assert_eq!(claims.iss.as_deref(), Some(did.as_str()));
/// assert_eq!(claims.sub, claims.iss);
/// assert_eq!(claims.nbf, Some(1607112739));
/// assert_eq!(claims.exp, Some(1764879139));
/// assert_eq!(claims.additional["vc"]["credentialSubject"]["origin"], "https://identity.foundation");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DomainLinkageCredentialBuilder {
    /// The DID: issuer and subject of the credential.
    pub did: Did,
    /// The origin, normalized.
    pub origin: String,
    /// `issuanceDate` and `nbf`.
    pub issuance_date: DateTime<Utc>,
    /// `expirationDate` and `exp`.
    pub expiration_date: DateTime<Utc>,
}

impl DomainLinkageCredentialBuilder {
    /// A credential linking `did` and `origin`, valid from `issuance_date` to
    /// `expiration_date`.
    ///
    /// # Errors
    ///
    /// [`DomainLinkageError::InvalidOrigin`] when `origin` has no host.
    pub fn new(
        did: Did,
        origin: &Url,
        issuance_date: DateTime<Utc>,
        expiration_date: DateTime<Utc>,
    ) -> Result<Self, DomainLinkageError> {
        Ok(Self {
            did,
            origin: normalize_origin(origin.as_str())?,
            issuance_date,
            expiration_date,
        })
    }

    /// The credential.
    pub fn credential(&self) -> Credential {
        let subject =
            Subject::new(Uri::from(self.did.clone())).with_property("origin", self.origin.clone());
        Credential::new(self.did.clone(), self.issuance_date, subject)
            .with_context(CONTEXT)
            .with_type(CREDENTIAL_TYPE)
            .with_expiration_date(self.expiration_date)
    }

    /// The JWT claims: `iss` and `sub` the DID, `nbf` and `exp` the validity period, `vc` the
    /// whole credential.
    pub fn jwt_claims(&self) -> JwtClaims {
        let mut claims = JwtClaims::new()
            .with_nbf(self.issuance_date)
            .with_exp(self.expiration_date);
        claims.iss = Some(self.did.as_str().to_owned());
        claims.sub = Some(self.did.as_str().to_owned());
        claims.additional.insert(
            "vc".to_owned(),
            serde_json::to_value(self.credential()).expect("a credential serializes"),
        );
        claims
    }

    /// The credential signed with `signer` under a header of `alg` and `kid` only, `kid`
    /// naming the verification method of the DID.
    ///
    /// # Errors
    ///
    /// [`DomainLinkageError::Validation`] with [`ValidationError::Jws`] when signing fails.
    pub async fn sign(&self, kid: &DidUrl, signer: &dyn Signer) -> Result<Jwt, DomainLinkageError> {
        let header = JwsHeader::new(signer.alg()).with_kid(kid.as_str());
        let jwt = Jwt::sign(&header, &self.jwt_claims(), signer)
            .await
            .map_err(ValidationError::from)?;
        Ok(jwt)
    }
}

/// Why a domain linkage credential or configuration did not validate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainLinkageError {
    /// An origin is not `scheme://host[:port]`.
    #[error("invalid origin: {0}")]
    InvalidOrigin(String),
    /// The configuration's `@context` is not [`CONTEXT`].
    #[error("`@context` is {0:?}, not `{CONTEXT}`")]
    InvalidContext(String),
    /// The JWT header has a `typ`, which the format forbids.
    #[error("header `typ` {0:?} must not be present")]
    TypPresent(String),
    /// The JWT header has a parameter other than `alg` and `kid`.
    #[error("header parameter `{0}` must not be present")]
    UnexpectedHeaderParameter(String),
    /// The JWT payload has a claim other than `iss`, `sub`, `nbf`, `exp` and `vc`.
    #[error("claim `{0}` must not be present")]
    UnexpectedClaim(String),
    /// A required claim is missing: `iss`, `sub`, `exp` or `nbf`.
    #[error("claim `{0}` is required")]
    MissingClaim(&'static str),
    /// The credential has an `id`, which the format forbids.
    #[error("the credential must not have an `id`")]
    IdPresent,
    /// The credential's context does not include [`CONTEXT`].
    #[error("the credential's `@context` does not include `{CONTEXT}`")]
    MissingContext,
    /// The credential's type does not include [`CREDENTIAL_TYPE`].
    #[error("the credential's `type` does not include `{CREDENTIAL_TYPE}`")]
    MissingType,
    /// The credential has no `expirationDate`.
    #[error("the credential must have an `expirationDate`")]
    MissingExpirationDate,
    /// `credentialSubject.id` is missing or not a DID.
    #[error("`credentialSubject.id` {0:?} is not a DID")]
    SubjectNotDid(Option<String>),
    /// The issuer, `iss` or `sub` differs from `credentialSubject.id`.
    #[error("{role} `{found}` is not the subject `{subject}`")]
    SubjectMismatch {
        /// `issuer`, `iss` or `sub`.
        role: &'static str,
        /// The value found.
        found: String,
        /// `credentialSubject.id`.
        subject: Did,
    },
    /// `credentialSubject.origin` is missing or not one string.
    #[error("`credentialSubject.origin` {0:?} is not one origin")]
    InvalidOriginProperty(Option<Value>),
    /// `credentialSubject.origin` is not the origin the resource was fetched from.
    #[error("origin {found:?} is not {expected:?}")]
    OriginMismatch {
        /// The normalized origin expected.
        expected: String,
        /// The credential's origin, normalized.
        found: String,
    },
    /// The credential did not decode or validate as a credential JWT.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The configuration holds no JWT credential for the DID.
    #[error("the configuration holds no JWT credential for `{0}`")]
    NoCredentialFor(Did),
    /// No credential of the configuration validated; the error of each JWT entry by its
    /// position.
    #[error("no domain linkage credential validated: {}", format_errors(.0))]
    NoValidCredential(BTreeMap<usize, DomainLinkageError>),
}

impl From<CredentialError> for DomainLinkageError {
    fn from(error: CredentialError) -> Self {
        Self::Validation(error.into())
    }
}

/// `errors` as `index: error; …`.
fn format_errors(errors: &BTreeMap<usize, DomainLinkageError>) -> String {
    errors
        .iter()
        .map(|(index, error)| format!("{index}: {error}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// A validated DID configuration resource: which entries linked which DIDs, and which failed.
#[derive(Debug)]
#[non_exhaustive]
pub struct DomainLinkageReport {
    /// The entries that validated, by position, with the DID each links.
    pub linked: Vec<(usize, Did, DecodedCredential)>,
    /// The JWT entries that failed, by position.
    pub failed: BTreeMap<usize, DomainLinkageError>,
}

impl DomainLinkageReport {
    /// The DIDs linked to the origin, in the order of the resource.
    pub fn dids(&self) -> impl Iterator<Item = &Did> {
        self.linked.iter().map(|(_, did, _)| did)
    }
}

/// Validates domain linkage credentials and DID configuration resources (DID Configuration
/// Resource Verification): the subject is a DID equal to the issuer, `iss` and `sub`, the
/// one `origin` is the requested origin, the credential has an expiration date, no `id`, no
/// extra claims or header parameters, and its signature verifies under a key of the DID
/// listed under `assertionMethod`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "did-key")]
/// # {
/// use identity_kit::domain_linkage::DomainLinkageValidator;
/// use identity_kit::jose::DefaultVerifier;
/// use identity_kit::methods::DidKey;
/// use identity_kit::resolver::Resolver;
///
/// let resolver = Resolver::builder().with(DidKey::default()).build();
/// let validator = DomainLinkageValidator::new(resolver, DefaultVerifier);
/// assert!(!validator.credential_validator().has_status_check());
/// # }
/// ```
#[derive(Debug)]
pub struct DomainLinkageValidator<R, V = DefaultVerifier> {
    credentials: JwtCredentialValidator<R, V>,
}

impl<R: KeyResolver, V: JwsVerifier> DomainLinkageValidator<R, V> {
    /// A validator resolving keys with `resolver` and verifying signatures with `verifier`.
    pub fn new(resolver: R, verifier: V) -> Self {
        Self {
            credentials: JwtCredentialValidator::new(resolver, verifier),
        }
    }

    /// A validator over `credentials`.
    pub fn from_credential_validator(credentials: JwtCredentialValidator<R, V>) -> Self {
        Self { credentials }
    }

    /// The credential validator.
    pub fn credential_validator(&self) -> &JwtCredentialValidator<R, V> {
        &self.credentials
    }

    /// Validates `jwt` as a domain linkage credential for `origin`.
    ///
    /// # Errors
    ///
    /// The first [`DomainLinkageError`] found: the format checks first, then the signature,
    /// issuer binding and validity period of [`JwtCredentialValidator::validate`].
    pub async fn validate_credential(
        &self,
        jwt: &Jwt,
        origin: &Url,
        options: &CredentialValidationOptions,
    ) -> Result<DecodedCredential, DomainLinkageError> {
        let expected = normalize_origin(origin.as_str())?;
        let decoded = decode_credential(jwt)?;
        check_format(&decoded, &expected)?;
        self.credentials.validate(jwt, options).await?;
        Ok(decoded)
    }

    /// Validates the credential of `configuration` linking `did` to `origin`: the first JWT
    /// entry issued by `did` that validates.
    ///
    /// # Errors
    ///
    /// [`DomainLinkageError::NoCredentialFor`] when no JWT entry names `did` as issuer,
    /// [`DomainLinkageError::NoValidCredential`] with the error of each such entry otherwise.
    pub async fn validate_linkage(
        &self,
        configuration: &DomainLinkageConfiguration,
        did: &Did,
        origin: &Url,
        options: &CredentialValidationOptions,
    ) -> Result<DecodedCredential, DomainLinkageError> {
        configuration.check()?;
        let mut errors = BTreeMap::new();
        for (index, jwt) in configuration.jwts() {
            if issuer_of(jwt).as_ref() != Some(did) {
                continue;
            }
            match self.validate_credential(jwt, origin, options).await {
                Ok(decoded) => return Ok(decoded),
                Err(error) => {
                    errors.insert(index, error);
                }
            }
        }
        if errors.is_empty() {
            return Err(DomainLinkageError::NoCredentialFor(did.clone()));
        }
        Err(DomainLinkageError::NoValidCredential(errors))
    }

    /// Validates every JWT entry of `configuration` for `origin`: succeeds when at least one
    /// does, reporting the rest as errors.
    ///
    /// # Errors
    ///
    /// [`DomainLinkageError::InvalidContext`], or [`DomainLinkageError::NoValidCredential`]
    /// with the error of every JWT entry.
    pub async fn validate_configuration(
        &self,
        configuration: &DomainLinkageConfiguration,
        origin: &Url,
        options: &CredentialValidationOptions,
    ) -> Result<DomainLinkageReport, DomainLinkageError> {
        configuration.check()?;
        let mut linked = Vec::new();
        let mut failed = BTreeMap::new();
        for (index, jwt) in configuration.jwts() {
            match self.validate_credential(jwt, origin, options).await {
                Ok(decoded) => {
                    let did = Did::parse(decoded.credential.issuer.id().as_str())
                        .expect("the format check accepted the issuer as a DID");
                    linked.push((index, did, decoded));
                }
                Err(error) => {
                    failed.insert(index, error);
                }
            }
        }
        if linked.is_empty() {
            return Err(DomainLinkageError::NoValidCredential(failed));
        }
        Ok(DomainLinkageReport { linked, failed })
    }
}

/// The issuer DID of `jwt`, read without verifying; `None` when it has none or it is not a
/// DID.
fn issuer_of(jwt: &Jwt) -> Option<Did> {
    crate::vc::validation::extract_issuer(jwt).ok()
}

/// The checks of the JSON Web Token proof format and of DID Configuration Resource
/// Verification that need no key.
fn check_format(
    decoded: &DecodedCredential,
    expected_origin: &str,
) -> Result<(), DomainLinkageError> {
    let header = &decoded.header;
    if let Some(typ) = &header.typ {
        return Err(DomainLinkageError::TypPresent(typ.clone()));
    }
    if header.kid.is_none() {
        return Err(ValidationError::MissingKid.into());
    }
    for (name, present) in [
        ("cty", header.cty.is_some()),
        ("jwk", header.jwk.is_some()),
        ("crit", header.crit.is_some()),
    ] {
        if present {
            return Err(DomainLinkageError::UnexpectedHeaderParameter(
                name.to_owned(),
            ));
        }
    }
    if let Some(name) = header.additional.keys().next() {
        return Err(DomainLinkageError::UnexpectedHeaderParameter(name.clone()));
    }

    let claims = &decoded.claims;
    for (name, present) in [
        ("aud", claims.aud.is_some()),
        ("iat", claims.iat.is_some()),
        ("jti", claims.jti.is_some()),
    ] {
        if present {
            return Err(DomainLinkageError::UnexpectedClaim(name.to_owned()));
        }
    }
    if let Some(name) = claims.additional.keys().find(|name| *name != "vc") {
        return Err(DomainLinkageError::UnexpectedClaim(name.clone()));
    }
    let iss = claims
        .iss
        .as_deref()
        .ok_or(DomainLinkageError::MissingClaim("iss"))?;
    let sub = claims
        .sub
        .as_deref()
        .ok_or(DomainLinkageError::MissingClaim("sub"))?;
    if claims.nbf.is_none() {
        return Err(DomainLinkageError::MissingClaim("nbf"));
    }
    if claims.exp.is_none() {
        return Err(DomainLinkageError::MissingClaim("exp"));
    }

    let credential = &decoded.credential;
    if credential.id.is_some() {
        return Err(DomainLinkageError::IdPresent);
    }
    if !credential.context.contains(CONTEXT) {
        return Err(DomainLinkageError::MissingContext);
    }
    if !credential.has_type(CREDENTIAL_TYPE) {
        return Err(DomainLinkageError::MissingType);
    }
    if credential.expiration_date.is_none() {
        return Err(DomainLinkageError::MissingExpirationDate);
    }
    // A JWT with `sub` and several subjects does not decode as a credential, so one subject
    // is all that gets here.
    let subject = credential
        .subject()
        .ok_or(DomainLinkageError::SubjectNotDid(None))?;
    let subject_id = subject.id.as_ref().map(Uri::as_str);
    let subject_did = subject_id
        .and_then(|id| Did::parse(id).ok())
        .ok_or_else(|| DomainLinkageError::SubjectNotDid(subject_id.map(str::to_owned)))?;
    for (role, found) in [
        ("issuer", credential.issuer.id().as_str()),
        ("iss", iss),
        ("sub", sub),
    ] {
        if found != subject_did.as_str() {
            return Err(DomainLinkageError::SubjectMismatch {
                role,
                found: found.to_owned(),
                subject: subject_did,
            });
        }
    }
    let origin = subject.properties.get("origin");
    let Some(Value::String(origin)) = origin else {
        return Err(DomainLinkageError::InvalidOriginProperty(origin.cloned()));
    };
    let found = normalize_origin(origin)?;
    if found != expected_origin {
        return Err(DomainLinkageError::OriginMismatch {
            expected: expected_origin.to_owned(),
            found,
        });
    }
    Ok(())
}

impl fmt::Display for DomainLinkageConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        f.write_str(&json)
    }
}
