//! DIF Linked Verifiable Presentation: verifiable presentations a DID controller publishes for
//! anyone to discover, through a `LinkedVerifiablePresentation` service in its DID document.
//!
//! The service entry is the normative part of the specification: `type` is
//! [`SERVICE_TYPE`] and `serviceEndpoint` one URL or a non-empty array of them. [`service`]
//! builds one, [`services`] reads them out of a document. Each URL serves one presentation;
//! this crate handles the JSON Web Token form (a VCDM 1.1 presentation in the `vp` claim, its
//! credentials as JWTs) and reports the JSON-LD form as unsupported.
//!
//! - [`LinkedPresentationBuilder`] signs a presentation for publishing: `iss`, `sub` and
//!   `holder` the DID, no `aud` and no `nonce`, which a presentation published for anyone
//!   cannot carry.
//! - [`LinkedVpValidator`] validates one presentation for the DID whose document lists it:
//!   holder and `iss` are that DID, the holder signed with a key of the DID under
//!   `authentication`, `exp` holds when present, and every credential validates with its
//!   subject the holder (the specification's SHOULD, configurable).
//! - [`LinkedVpClient`] fetches what a document's services point to through an
//!   [`HttpClient`] and validates each presentation, reporting per URL: every linked
//!   presentation stands on its own.
//!
//! # What fails alone
//!
//! A verifier reads what someone else published, so one malformed entry does not hide the
//! valid ones next to it:
//!
//! - An endpoint URI that is not a URL fails alone: [`services`] lists it in
//!   [`LinkedVpService::invalid_urls`] and keeps the service's other URLs, and
//!   [`LinkedVpClient::validate_document`] reports it on its own. A service fails as a whole
//!   only when its endpoint is a map or names no URL.
//! - An entry of the presentation's `verifiableCredential` that is not a credential JWT fails
//!   alone: [`decode`] returns one result per entry, and [`LinkedVpValidator::validate`]
//!   reports it in [`PresentationValidationError::credentials`] under its index, as any other
//!   credential that does not validate.
//! - Everything else is the presentation's: it does not decode, its holder or signer is not
//!   the linking DID, or its signature or time claims do not hold.
//!
//! # A linked presentation proves control at link time only
//!
//! Anyone can fetch a linked presentation and replay it, and it says nothing about who
//! controls the DID now. A verifier must not grant access on a linked presentation alone, but
//! ask the holder for an interactive proof of control, as the specification's security
//! considerations require. Hashlinks (`hl=` in a URL) are passed through and not verified.
//!
//! # `typ`
//!
//! The specification does not constrain `typ`. Its example presentation carries the literal
//! `'vp+ld+jwt'`, stray quotes included, and its credential `'vc+ld+jwt'`; the validator
//! accepts these ([`PRESENTATION_TYP`], [`CREDENTIAL_TYP`]) next to `JWT` and no `typ`. The
//! builder writes `JWT`.
//!
//! # Examples
//!
//! The specification's example document lists two presentations, one over HTTPS and one on
//! IPFS:
//!
//! ```
//! use identity_kit::did::DidDocument;
//! use identity_kit::linked_vp::services;
//! use serde_json::json;
//!
//! let document: DidDocument = serde_json::from_value(json!({
//!   "@context": ["https://www.w3.org/ns/did/v1", "https://identity.foundation/linked-vp/contexts/v1"],
//!   "id": "did:example:123",
//!   "service": [
//!     {
//!       "id": "did:example:123#foo",
//!       "type": "LinkedVerifiablePresentation",
//!       "serviceEndpoint": ["https://bar.example.com/verifiable-presentation.jsonld"]
//!     },
//!     {
//!       "id": "did:example:123#baz",
//!       "type": "LinkedVerifiablePresentation",
//!       "serviceEndpoint": "ipfs://bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly/verifiable-presentation.jwt"
//!     }
//!   ]
//! }))?;
//! let urls: Vec<String> = services(&document)
//!     .map(|service| service.map(|service| service.urls[0].to_string()))
//!     .collect::<Result<_, _>>()?;
//! assert_eq!(urls, [
//!     "https://bar.example.com/verifiable-presentation.jsonld",
//!     "ipfs://bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly/verifiable-presentation.jwt",
//! ]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::BTreeSet;
use std::error::Error;

use chrono::{DateTime, Utc};
use url::Url;

use crate::cause::cause;
use crate::did::{Did, DidDocument, DidUrl, ResolutionError, Service, ServiceEndpoint, Uri};
use crate::jose::{DefaultVerifier, JwsError, JwsHeader, JwsVerifier, Signer};
use crate::methods::web::{HttpClient, HttpError};
use crate::resolver::Resolver;
use crate::vc::validation::{
    CredentialValidationOptions, DecodedCredential, DecodedPresentation, FailFast,
    JwtPresentationValidator, KeyReference, KeyResolver, PresentationValidationError,
    PresentationValidationOptions, SubjectHolderRelationship, TimeOptions, ValidationError,
    decode_presentation_entries, extract_holder,
};
use crate::vc::{CredentialError, Jwt, JwtClaims, Party, Presentation};

/// The service type, `LinkedVerifiablePresentation`.
pub const SERVICE_TYPE: &str = "LinkedVerifiablePresentation";

/// The JSON-LD context defining [`SERVICE_TYPE`], for the `@context` of a DID document that
/// lists linked presentations.
pub const CONTEXT: &str = "https://identity.foundation/linked-vp/contexts/v1";

/// The header `typ` values a linked presentation may carry besides `JWT`: `vp+ld+jwt`, and the
/// literal `'vp+ld+jwt'` with the single quotes of the specification's example.
pub const PRESENTATION_TYP: [&str; 2] = ["vp+ld+jwt", "'vp+ld+jwt'"];

/// The header `typ` values a credential in a linked presentation may carry besides `JWT`:
/// `vc+ld+jwt`, and the literal `'vc+ld+jwt'` of the specification's example.
pub const CREDENTIAL_TYP: [&str; 2] = ["vc+ld+jwt", "'vc+ld+jwt'"];

/// A `LinkedVerifiablePresentation` service of `id` pointing to `urls`.
///
/// # Errors
///
/// [`LinkedVpError::InvalidService`] when `urls` is empty or a URL is not an RFC 3986 URI.
///
/// # Examples
///
/// ```
/// use identity_kit::did::{DidUrl, ServiceEndpoint};
/// use identity_kit::linked_vp::{SERVICE_TYPE, service};
/// use url::Url;
///
/// let service = service(
///     DidUrl::parse("did:example:123#foo")?,
///     [Url::parse("https://bar.example.com/verifiable-presentation.jwt")?],
/// )?;
/// assert!(service.has_type(SERVICE_TYPE));
/// assert!(matches!(service.service_endpoint, ServiceEndpoint::Uri(_)));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[expect(
    clippy::similar_names,
    reason = "the URLs given and the URIs of the service endpoint are both needed"
)]
pub fn service(id: DidUrl, urls: impl IntoIterator<Item = Url>) -> Result<Service, LinkedVpError> {
    let mut uris = Vec::new();
    for url in urls {
        let uri = Uri::parse(url.as_str()).map_err(|e| LinkedVpError::InvalidService {
            id: id.clone(),
            reason: format!("`{url}` is not a URI"),
            source: Some(Box::new(e)),
        })?;
        uris.push(uri);
    }
    let endpoint = match <[Uri; 1]>::try_from(uris) {
        Ok([uri]) => ServiceEndpoint::Uri(uri),
        Err(uris) if uris.is_empty() => {
            return Err(LinkedVpError::InvalidService {
                id,
                reason: "no URL".to_owned(),
                source: None,
            });
        }
        Err(uris) => ServiceEndpoint::Set(uris.into_iter().collect()),
    };
    Ok(Service::new(id, SERVICE_TYPE, endpoint))
}

/// A `LinkedVerifiablePresentation` service of a DID document, with its URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkedVpService<'a> {
    /// The service entry.
    pub service: &'a Service,
    /// Its URLs, in document order: the endpoint URIs that parse as URLs.
    pub urls: Vec<Url>,
    /// The endpoint URIs that do not parse as URLs, in document order, each with why. They
    /// do not hide the service's other URLs.
    pub invalid_urls: Vec<(Uri, url::ParseError)>,
}

impl LinkedVpService<'_> {
    /// The id of the service.
    pub fn id(&self) -> &DidUrl {
        &self.service.id
    }
}

/// The `LinkedVerifiablePresentation` services of `document`, in document order. A service of
/// that type whose endpoint is a map, or names no URL at all, is a
/// [`LinkedVpError::InvalidService`] rather than silently skipped. An endpoint URI that is not
/// a URL (`https://example.org:99999/vp`, whose port is out of range) is listed in
/// [`LinkedVpService::invalid_urls`] and leaves the service's other URLs in place.
pub fn services(
    document: &DidDocument,
) -> impl Iterator<Item = Result<LinkedVpService<'_>, LinkedVpError>> {
    document
        .service
        .iter()
        .filter(|service| service.has_type(SERVICE_TYPE))
        .map(linked_vp_service)
}

/// `service` with its URLs parsed.
fn linked_vp_service(service: &Service) -> Result<LinkedVpService<'_>, LinkedVpError> {
    let invalid = |reason: String, source: Option<Box<dyn Error + Send + Sync>>| {
        LinkedVpError::InvalidService {
            id: service.id.clone(),
            reason,
            source,
        }
    };
    if matches!(service.service_endpoint, ServiceEndpoint::Map(_)) {
        return Err(invalid(
            "`serviceEndpoint` is a map, not URLs".to_owned(),
            None,
        ));
    }
    let mut urls = Vec::new();
    let mut invalid_urls = Vec::new();
    for uri in service.service_endpoint.uris() {
        match Url::parse(uri.as_str()) {
            Ok(url) => urls.push(url),
            Err(e) => invalid_urls.push((uri.clone(), e)),
        }
    }
    if urls.is_empty() {
        return Err(match invalid_urls.into_iter().next() {
            Some((uri, e)) => invalid(format!("`{uri}` is not a URL"), Some(Box::new(e))),
            None => invalid("no URL".to_owned(), None),
        });
    }
    Ok(LinkedVpService {
        service,
        urls,
        invalid_urls,
    })
}

/// The report of `uri`, an endpoint URI of `service` that is not a URL.
fn invalid_url(service: &Service, uri: &Uri, error: url::ParseError) -> LinkedPresentationReport {
    LinkedPresentationReport {
        service: service.id.clone(),
        url: None,
        result: Err(LinkedVpError::InvalidService {
            id: service.id.clone(),
            reason: format!("`{uri}` is not a URL"),
            source: Some(Box::new(error)),
        }),
    }
}

/// Builds a linked presentation in the JSON Web Token form: a VCDM 1.1 presentation of
/// credential JWTs held by `holder`, with `iss`, `sub` and `holder` the holder, `jti` the
/// presentation's `id`, `iat` and `nbf` the issuance time, `exp` when an expiration is set,
/// and neither `aud` nor `nonce`.
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::did::{Did, Uri};
/// use identity_kit::linked_vp::LinkedPresentationBuilder;
///
/// let holder = Did::parse("did:example:123")?;
/// let claims = LinkedPresentationBuilder::new(holder)
///     .with_id(Uri::parse("https://bar.example.com/verifiable-presentation.jwt")?)
///     .with_issued_at(Utc.with_ymd_and_hms(2024, 2, 8, 17, 38, 46).unwrap())
///     .with_expiration(Utc.with_ymd_and_hms(2029, 2, 8, 17, 38, 46).unwrap())
///     .jwt_claims()?;
/// assert_eq!(claims.iss.as_deref(), Some("did:example:123"));
/// assert_eq!(claims.sub, claims.iss);
/// assert_eq!((claims.iat, claims.nbf, claims.exp), (Some(1707413926), Some(1707413926), Some(1865266726)));
/// assert_eq!(claims.jti.as_deref(), Some("https://bar.example.com/verifiable-presentation.jwt"));
/// assert!(claims.aud.is_none() && !claims.additional.contains_key("nonce"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkedPresentationBuilder {
    /// The holder: the DID whose document links the presentation.
    pub holder: Did,
    /// The presentation's `id`, usually the URL it is published at.
    pub id: Option<Uri>,
    /// The credential JWTs.
    pub credentials: Vec<Jwt>,
    /// `iat` and `nbf`.
    pub issued_at: DateTime<Utc>,
    /// `exp`, if the presentation expires.
    pub expiration: Option<DateTime<Utc>>,
}

impl LinkedPresentationBuilder {
    /// A presentation by `holder` of no credentials, issued now, without `id` or expiration.
    pub fn new(holder: Did) -> Self {
        Self {
            holder,
            id: None,
            credentials: Vec::new(),
            issued_at: Utc::now(),
            expiration: None,
        }
    }

    /// This presentation with its `id` set.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<Uri>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// This presentation with `credential` added.
    #[must_use]
    pub fn with_credential(mut self, credential: Jwt) -> Self {
        self.credentials.push(credential);
        self
    }

    /// This presentation issued at `issued_at`.
    #[must_use]
    pub fn with_issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.issued_at = issued_at;
        self
    }

    /// This presentation expiring at `expiration`, which the specification recommends to limit
    /// how long a published presentation stays valid.
    #[must_use]
    pub fn with_expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration = Some(expiration);
        self
    }

    /// The presentation.
    pub fn presentation(&self) -> Presentation {
        let mut presentation = Presentation::new().with_holder(self.holder.clone());
        if let Some(id) = &self.id {
            presentation = presentation.with_id(id.clone());
        }
        self.credentials
            .iter()
            .fold(presentation, |presentation, credential| {
                presentation.with_credential(credential.clone())
            })
    }

    /// The JWT claims: the presentation's (`iss`, `jti`, `vp`) with `sub`, `iat`, `nbf` and
    /// `exp`.
    ///
    /// # Errors
    ///
    /// A [`CredentialError`] when the presentation does not map to claims; one built here
    /// always does.
    pub fn jwt_claims(&self) -> Result<JwtClaims, CredentialError> {
        let mut claims = self
            .presentation()
            .to_jwt_claims()?
            .with_sub(self.holder.as_str())
            .with_iat(self.issued_at)
            .with_nbf(self.issued_at);
        if let Some(expiration) = self.expiration {
            claims = claims.with_exp(expiration);
        }
        Ok(claims)
    }

    /// The presentation signed with `signer` under a header of `alg`, `typ` `JWT` and `kid`,
    /// `kid` naming a verification method of the holder, which a verifier resolves under
    /// `authentication`.
    ///
    /// # Errors
    ///
    /// [`LinkedVpError::Validation`] with [`ValidationError::HolderMismatch`] when `kid` is not
    /// a key of the holder, or with [`ValidationError::Jws`] when signing fails.
    pub async fn sign(&self, kid: &DidUrl, signer: &dyn Signer) -> Result<Jwt, LinkedVpError> {
        if kid.did() != &self.holder {
            return Err(ValidationError::HolderMismatch {
                holder: self.holder.clone().into(),
                key: Box::new(KeyReference::DidUrl(kid.clone())),
            }
            .into());
        }
        let header = JwsHeader::new(signer.alg())
            .with_typ("JWT")
            .with_kid(kid.as_str());
        let claims = self.jwt_claims().map_err(ValidationError::from)?;
        let jwt = Jwt::sign(&header, &claims, signer)
            .await
            .map_err(ValidationError::from)?;
        Ok(jwt)
    }
}

/// Why a linked presentation could not be found, fetched or validated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinkedVpError {
    /// A `LinkedVerifiablePresentation` service does not name one or more URLs. The source
    /// is the URI or URL error, when there is one.
    #[error("service `{id}`: {reason}{}", cause(.source.as_ref()))]
    InvalidService {
        /// The id of the service.
        id: DidUrl,
        /// What is wrong with it.
        reason: String,
        /// The underlying error.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// A URL is not `https`: an `ipfs://` endpoint, say. Only HTTPS is fetched.
    #[error("`{0}` is not an HTTPS URL")]
    UnsupportedEndpoint(Url),
    /// The [`HttpClient`] got no response.
    #[error("fetching `{url}` failed: {source}")]
    Http {
        /// The URL fetched.
        url: Url,
        /// Why there was no response.
        #[source]
        source: HttpError,
    },
    /// The server answered with a status other than `2xx`.
    #[error("fetching `{url}` returned HTTP {status}")]
    HttpStatus {
        /// The URL fetched.
        url: Url,
        /// The status code.
        status: u16,
    },
    /// The body is a JSON object: a presentation in the JSON-LD form, which this crate does
    /// not process.
    #[error("`{0}` serves a JSON-LD presentation, which is not supported")]
    UnsupportedFormat(Url),
    /// The body is not a compact JWT. The source is the UTF-8 or [`JwsError`].
    #[error("`{url}` does not serve a compact JWT: {reason}{}", cause(.source.as_ref()))]
    InvalidBody {
        /// The URL fetched.
        url: Url,
        /// What is wrong with the body.
        reason: &'static str,
        /// The underlying error.
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    /// The presentation's holder is not the DID whose document links it.
    #[error("the holder `{holder}` is not `{did}`, the DID linking the presentation")]
    HolderMismatch {
        /// The DID linking the presentation.
        did: Did,
        /// The holder the presentation names.
        holder: Did,
    },
    /// The presentation or some of its credentials did not validate.
    #[error(transparent)]
    Presentation(#[from] PresentationValidationError),
    /// The presentation did not decode, or did not sign.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The DID did not resolve.
    #[error("resolving the DID failed: {0}")]
    Resolution(#[from] ResolutionError),
    /// The URL was not fetched: the DID document lists more URLs than the client's limit,
    /// given here.
    #[error("the DID document lists more than {0} presentation URLs")]
    TooManyUrls(usize),
}

/// Options of [`LinkedVpValidator`]. The audience and nonce are fixed: a linked presentation
/// has neither.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkedVpValidationOptions {
    /// The validation time and leeway of the presentation JWT; `exp` is honoured when present
    /// and not required.
    pub time: TimeOptions,
    /// The options every credential is validated with. [`CREDENTIAL_TYP`] is accepted on top
    /// of their `additional_typ`.
    pub credentials: CredentialValidationOptions,
    /// How credential subjects must relate to the holder;
    /// [`SubjectHolderRelationship::AlwaysSubject`] by default, as the specification
    /// recommends.
    pub subject_holder: SubjectHolderRelationship,
    /// Whether to stop at the first failing credential.
    pub fail_fast: FailFast,
}

impl LinkedVpValidationOptions {
    /// Default options: validate now without leeway, default credential options,
    /// [`SubjectHolderRelationship::AlwaysSubject`], [`FailFast::FirstError`].
    pub fn new() -> Self {
        Self::default()
    }

    /// These options with `time`, for the presentation JWT only.
    #[must_use]
    pub fn with_time(mut self, time: TimeOptions) -> Self {
        self.time = time;
        self
    }

    /// These options validating credentials with `credentials`.
    #[must_use]
    pub fn with_credentials(mut self, credentials: CredentialValidationOptions) -> Self {
        self.credentials = credentials;
        self
    }

    /// These options with `relationship`.
    #[must_use]
    pub fn with_subject_holder(mut self, relationship: SubjectHolderRelationship) -> Self {
        self.subject_holder = relationship;
        self
    }

    /// These options with `fail_fast`.
    #[must_use]
    pub fn with_fail_fast(mut self, fail_fast: FailFast) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// The options of the underlying [`JwtPresentationValidator`]: no audience, no nonce, and
    /// [`PRESENTATION_TYP`] and [`CREDENTIAL_TYP`] accepted.
    pub fn presentation_options(&self) -> PresentationValidationOptions {
        let mut credentials = self.credentials.clone();
        credentials
            .additional_typ
            .extend(CREDENTIAL_TYP.map(str::to_owned));
        let mut options = PresentationValidationOptions::new()
            .with_time(self.time)
            .with_subject_holder(self.subject_holder)
            .with_credentials(credentials)
            .with_fail_fast(self.fail_fast);
        options
            .additional_typ
            .extend(PRESENTATION_TYP.map(str::to_owned));
        options
    }
}

/// A linked presentation decoded without verification: the presentation, and each entry of
/// its `verifiableCredential` decoded on its own.
#[derive(Debug)]
#[non_exhaustive]
pub struct DecodedLinkedPresentation {
    /// The JWS header.
    pub header: JwsHeader,
    /// The claims set, `vp` included.
    pub claims: JwtClaims,
    /// The presentation, with `iss` and `jti` mapped back into it. Its
    /// `verifiable_credential` holds the entries that are compact JWTs.
    pub presentation: Presentation,
    /// One result per entry of `verifiableCredential`, in order: the credential decoded, or why
    /// that entry is not one.
    pub credentials: Vec<Result<DecodedCredential, ValidationError>>,
}

impl DecodedLinkedPresentation {
    /// The holder: `holder` of the presentation, which decoding set from `iss`.
    pub fn holder(&self) -> Option<&Uri> {
        self.presentation.holder.as_ref().map(Party::id)
    }
}

/// Decodes a linked presentation and its credentials without verifying or validating
/// anything, accepting [`PRESENTATION_TYP`] and [`CREDENTIAL_TYP`]. Each entry of
/// `verifiableCredential` decodes on its own: one that is not a credential JWT is an error in
/// [`DecodedLinkedPresentation::credentials`], next to the others.
///
/// # Errors
///
/// As [`decode_presentation`](crate::vc::validation::decode_presentation), for the
/// presentation alone.
pub fn decode(jwt: &Jwt) -> Result<DecodedLinkedPresentation, ValidationError> {
    let presentation_typ: BTreeSet<String> = PRESENTATION_TYP.map(str::to_owned).into();
    let credential_typ: BTreeSet<String> = CREDENTIAL_TYP.map(str::to_owned).into();
    let (decoded, credentials) =
        decode_presentation_entries(jwt, &presentation_typ, &credential_typ)?;
    Ok(DecodedLinkedPresentation {
        header: decoded.header,
        claims: decoded.claims,
        presentation: decoded.presentation,
        credentials,
    })
}

/// Validates linked presentations: [`JwtPresentationValidator`] with the options fixed to the
/// specification, plus the holder and the signer being the DID that links the presentation.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "did-key")]
/// # {
/// use identity_kit::jose::DefaultVerifier;
/// use identity_kit::linked_vp::LinkedVpValidator;
/// use identity_kit::methods::DidKey;
/// use identity_kit::resolver::Resolver;
///
/// let resolver = Resolver::builder().with(DidKey::default()).build();
/// let validator = LinkedVpValidator::new(resolver, DefaultVerifier);
/// assert!(!validator.presentation_validator().credential_validator().has_status_check());
/// # }
/// ```
#[derive(Debug)]
pub struct LinkedVpValidator<R, V = DefaultVerifier> {
    presentations: JwtPresentationValidator<R, V>,
}

impl<R: KeyResolver, V: JwsVerifier> LinkedVpValidator<R, V> {
    /// A validator resolving keys with `resolver` and verifying signatures with `verifier`.
    pub fn new(resolver: R, verifier: V) -> Self {
        Self {
            presentations: JwtPresentationValidator::new(resolver, verifier),
        }
    }

    /// A validator over `presentations`, with its status check.
    pub fn from_presentation_validator(presentations: JwtPresentationValidator<R, V>) -> Self {
        Self { presentations }
    }

    /// The presentation validator.
    pub fn presentation_validator(&self) -> &JwtPresentationValidator<R, V> {
        &self.presentations
    }

    /// Validates `jwt` as a presentation linked from the document of `did`.
    ///
    /// The holder, and the party the token's [`KeyReference`] names, are checked against
    /// `did` before any key is resolved, so a presentation naming another DID never makes the
    /// resolver fetch that DID's document: a DID URL must be of `did`, a key by value must be
    /// the `did:jwk` of `did`, and a key set of an HTTPS issuer never belongs to a DID.
    ///
    /// # Errors
    ///
    /// [`LinkedVpError::HolderMismatch`] when the holder is not `did`, otherwise
    /// [`LinkedVpError::Presentation`] with what [`JwtPresentationValidator::validate`]
    /// reports; a key of another DID is a [`ValidationError::HolderMismatch`] there.
    pub async fn validate(
        &self,
        jwt: &Jwt,
        did: &Did,
        options: &LinkedVpValidationOptions,
    ) -> Result<DecodedPresentation, LinkedVpError> {
        let holder = extract_holder(jwt).map_err(PresentationValidationError::presentation)?;
        if holder != *did {
            return Err(LinkedVpError::HolderMismatch {
                did: did.clone(),
                holder,
            });
        }
        let jws = jwt
            .decode()
            .map_err(|e| PresentationValidationError::presentation(e.into()))?;
        if let Ok(reference) = KeyReference::from_jws(&jws, Some(did.as_str())) {
            let of_did = match &reference {
                KeyReference::DidUrl(url) => url.did() == did,
                KeyReference::Jwk(jwk) => reference.binds_to(Some(did.as_str()), jwk),
                _ => false,
            };
            if !of_did {
                return Err(PresentationValidationError::presentation(
                    ValidationError::HolderMismatch {
                        holder: did.clone().into(),
                        key: Box::new(reference),
                    },
                )
                .into());
            }
        }
        let decoded = self
            .presentations
            .validate(jwt, &options.presentation_options())
            .await?;
        Ok(decoded)
    }
}

/// What became of one URL of a `LinkedVerifiablePresentation` service.
#[derive(Debug)]
#[non_exhaustive]
pub struct LinkedPresentationReport {
    /// The id of the service.
    pub service: DidUrl,
    /// The URL; `None` when the service entry itself is invalid.
    pub url: Option<Url>,
    /// The presentation, validated, or why it was not.
    pub result: Result<DecodedPresentation, LinkedVpError>,
}

/// Fetches the presentations a DID document links with an [`HttpClient`] and validates them
/// with a [`LinkedVpValidator`].
///
/// The URLs come from the document, so the client fetches whatever its controller names:
/// `http` must enforce the protections `ReqwestClient` (feature `reqwest`) does (HTTPS only,
/// no redirects, no non-public addresses after name resolution, a body limit and a timeout),
/// or fetching becomes a request forgery primitive. A DID document can also list any number of
/// URLs, so [`validate_document`](Self::validate_document) fetches at most
/// [`max_urls`](Self::max_urls) of them.
#[derive(Debug)]
pub struct LinkedVpClient<C, R, V = DefaultVerifier> {
    http: C,
    validator: LinkedVpValidator<R, V>,
    max_urls: usize,
}

impl<C, R, V> LinkedVpClient<C, R, V> {
    /// The most URLs [`new`](Self::new) fetches for one DID document: 32.
    pub const DEFAULT_MAX_URLS: usize = 32;
}

impl<C: HttpClient, R: KeyResolver, V: JwsVerifier> LinkedVpClient<C, R, V> {
    /// A client fetching with `http` and validating with `validator`, fetching at most
    /// [`DEFAULT_MAX_URLS`](Self::DEFAULT_MAX_URLS) URLs of a DID document.
    pub fn new(http: C, validator: LinkedVpValidator<R, V>) -> Self {
        Self {
            http,
            validator,
            max_urls: Self::DEFAULT_MAX_URLS,
        }
    }

    /// This client fetching at most `max_urls` URLs of a DID document.
    #[must_use]
    pub fn with_max_urls(mut self, max_urls: usize) -> Self {
        self.max_urls = max_urls;
        self
    }

    /// The most URLs [`validate_document`](Self::validate_document) fetches for one document.
    pub fn max_urls(&self) -> usize {
        self.max_urls
    }

    /// The HTTP client.
    pub fn http(&self) -> &C {
        &self.http
    }

    /// The validator.
    pub fn validator(&self) -> &LinkedVpValidator<R, V> {
        &self.validator
    }

    /// The presentation JWT at `url`, unverified: the body, trimmed, must be one compact JWT.
    ///
    /// # Errors
    ///
    /// [`LinkedVpError::UnsupportedEndpoint`] for a URL that is not `https`, without fetching;
    /// [`LinkedVpError::Http`] or [`LinkedVpError::HttpStatus`] when there is no `2xx`
    /// response; [`LinkedVpError::UnsupportedFormat`] for a JSON-LD presentation;
    /// [`LinkedVpError::InvalidBody`] for anything else that is not a compact JWT.
    pub async fn fetch(&self, url: &Url) -> Result<Jwt, LinkedVpError> {
        if url.scheme() != "https" {
            return Err(LinkedVpError::UnsupportedEndpoint(url.clone()));
        }
        let response = self
            .http
            .get(url)
            .await
            .map_err(|source| LinkedVpError::Http {
                url: url.clone(),
                source,
            })?;
        if !(200..300).contains(&response.status) {
            return Err(LinkedVpError::HttpStatus {
                url: url.clone(),
                status: response.status,
            });
        }
        let invalid = |reason: &'static str, source: Box<dyn Error + Send + Sync>| {
            LinkedVpError::InvalidBody {
                url: url.clone(),
                reason,
                source: Some(source),
            }
        };
        let body = core::str::from_utf8(&response.body)
            .map_err(|e| invalid("the body is not UTF-8", Box::new(e)))?
            .trim();
        if body.starts_with('{') {
            return Err(LinkedVpError::UnsupportedFormat(url.clone()));
        }
        Jwt::new(body).map_err(|e: JwsError| invalid("not a compact JWS", Box::new(e)))
    }

    /// Fetches and validates `url` as a presentation linked from the document of `did`.
    ///
    /// # Errors
    ///
    /// As [`fetch`](Self::fetch) and [`LinkedVpValidator::validate`].
    pub async fn validate_url(
        &self,
        url: &Url,
        did: &Did,
        options: &LinkedVpValidationOptions,
    ) -> Result<DecodedPresentation, LinkedVpError> {
        let jwt = self.fetch(url).await?;
        self.validator.validate(&jwt, did, options).await
    }

    /// Fetches and validates every presentation `document` links, one report per URL in
    /// document order, one for each endpoint URI that is not a URL, and one for each invalid
    /// service entry. URLs past the first [`max_urls`](Self::max_urls) are not fetched and
    /// report [`LinkedVpError::TooManyUrls`].
    pub async fn validate_document(
        &self,
        document: &DidDocument,
        options: &LinkedVpValidationOptions,
    ) -> Vec<LinkedPresentationReport> {
        let mut reports = Vec::new();
        let mut fetched = 0;
        for service in document
            .service
            .iter()
            .filter(|service| service.has_type(SERVICE_TYPE))
        {
            if let Err(error) = linked_vp_service(service) {
                reports.push(LinkedPresentationReport {
                    service: service.id.clone(),
                    url: None,
                    result: Err(error),
                });
                continue;
            }
            for uri in service.service_endpoint.uris() {
                let url = match Url::parse(uri.as_str()) {
                    Ok(url) => url,
                    Err(error) => {
                        reports.push(invalid_url(service, uri, error));
                        continue;
                    }
                };
                let result = if fetched < self.max_urls {
                    fetched += 1;
                    self.validate_url(&url, &document.id, options).await
                } else {
                    Err(LinkedVpError::TooManyUrls(self.max_urls))
                };
                reports.push(LinkedPresentationReport {
                    service: service.id.clone(),
                    url: Some(url),
                    result,
                });
            }
        }
        reports
    }
}

impl<C: HttpClient, V: JwsVerifier> LinkedVpClient<C, Resolver, V> {
    /// Resolves `did` with the validator's resolver, then validates every presentation its
    /// document links, as [`validate_document`](Self::validate_document).
    ///
    /// # Errors
    ///
    /// [`LinkedVpError::Resolution`] when `did` does not resolve to a document.
    pub async fn validate_did(
        &self,
        did: &Did,
        options: &LinkedVpValidationOptions,
    ) -> Result<Vec<LinkedPresentationReport>, LinkedVpError> {
        let document = self
            .validator
            .presentation_validator()
            .credential_validator()
            .resolver()
            .resolve_document(did)
            .await?;
        Ok(self.validate_document(&document, options).await)
    }
}
