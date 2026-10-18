//! DID URL dereferencing (DID Resolution "DID URL Dereferencing Algorithm").

use serde_json::Value;

use super::Resolver;
use crate::did::{
    Did, DidDocument, DidUrl, DocumentError, MethodType, ResolutionError, ResolutionOptions,
    Service, VerificationMethod, VerificationRelationship,
};
use crate::jose::Jwk;

/// The resource a DID URL names, as [`Resolver::dereference`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dereferenced {
    /// The DID document: the URL had no fragment.
    Document(Box<DidDocument>),
    /// The verification method with the id of the URL, listed under `verificationMethod` or
    /// embedded in a relationship.
    VerificationMethod(Box<VerificationMethod>),
    /// The service with the id of the URL.
    Service(Box<Service>),
}

impl Dereferenced {
    /// The document, when that is what was dereferenced.
    pub fn as_document(&self) -> Option<&DidDocument> {
        match self {
            Self::Document(document) => Some(document),
            _ => None,
        }
    }

    /// The verification method, when that is what was dereferenced.
    pub fn as_verification_method(&self) -> Option<&VerificationMethod> {
        match self {
            Self::VerificationMethod(method) => Some(method),
            _ => None,
        }
    }

    /// The service, when that is what was dereferenced.
    pub fn as_service(&self) -> Option<&Service> {
        match self {
            Self::Service(service) => Some(service),
            _ => None,
        }
    }
}

/// Why a DID URL could not be dereferenced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DereferenceError {
    /// Resolving the DID of the URL failed.
    #[error("resolving `{did}`: {error}")]
    Resolution {
        /// The DID that was resolved.
        did: Did,
        /// What went wrong.
        #[source]
        error: ResolutionError,
    },
    /// The URL is syntactically valid but not usable: a DID parameter is given twice.
    #[error("`{url}`: {reason}")]
    InvalidDidUrl {
        /// The URL.
        url: DidUrl,
        /// What is wrong with it.
        reason: String,
    },
    /// The URL has a path or query parameter whose meaning only its DID method defines; this
    /// crate dereferences none of them (the `service` and `relativeRef` parameters included).
    #[error("`{0}` has a path or query that only its DID method can dereference")]
    MethodSpecific(DidUrl),
    /// The DID has been deactivated, so none of its resources may be used.
    #[error("`{0}` is deactivated")]
    Deactivated(Did),
    /// No verification method or service of the document has the id of the URL.
    #[error("`{0}` names no verification method or service of the DID document")]
    NotFound(DidUrl),
    /// The URL names the document or a service, not a verification method.
    #[error("`{0}` is not a verification method")]
    NotVerificationMethod(DidUrl),
    /// The verification method exists but is not usable for the required relationship.
    #[error("verification method `{id}` is not listed under `{relationship}`")]
    NotInRelationship {
        /// The id of the verification method.
        id: DidUrl,
        /// The relationship that was required.
        relationship: VerificationRelationship,
    },
    /// The verification method has no `publicKeyJwk` and its `publicKeyMultibase` cannot be
    /// converted to one.
    #[error("verification method `{id}` of type `{method_type}` has no JWK")]
    NoJwk {
        /// The id of the verification method.
        id: DidUrl,
        /// Its `type`.
        method_type: MethodType,
    },
}

impl Resolver {
    /// Dereferences `url`: the DID document when the URL is a bare DID, else the verification
    /// method or service whose id is the URL. The fragment is looked up against the id of the
    /// resolved document, which is the canonical DID when `url` names an equivalent one.
    ///
    /// The `versionId` and `versionTime` DID parameters select the version of the document and
    /// are passed to the method's resolver as resolution options. A path, any other query
    /// parameter and the `service`/`relativeRef` parameters are method-specific and not
    /// dereferenced here.
    ///
    /// # Errors
    ///
    /// - [`DereferenceError::Resolution`] when resolving the DID fails.
    /// - [`DereferenceError::InvalidDidUrl`] when a DID parameter is given twice.
    /// - [`DereferenceError::MethodSpecific`] for a path or a query this crate does not handle.
    /// - [`DereferenceError::Deactivated`] when the DID has been deactivated.
    /// - [`DereferenceError::NotFound`] when nothing in the document has the id of the URL.
    pub async fn dereference(&self, url: &DidUrl) -> Result<Dereferenced, DereferenceError> {
        let document = self.resolve_for(url).await?;
        let Some(fragment) = url.fragment() else {
            return Ok(Dereferenced::Document(Box::new(document)));
        };
        let id = document.id.to_url().with_fragment(fragment);
        if let Some(method) = document.verification_method(&id) {
            return Ok(Dereferenced::VerificationMethod(Box::new(method.clone())));
        }
        if let Some(service) = document.service(&id) {
            return Ok(Dereferenced::Service(Box::new(service.clone())));
        }
        Err(DereferenceError::NotFound(id))
    }

    /// The verification method `url` names, which must be usable for `relationship` when one
    /// is given (the `verificationRelationship` dereferencing option of DID Resolution).
    ///
    /// # Errors
    ///
    /// As [`dereference`](Self::dereference), plus [`DereferenceError::NotVerificationMethod`]
    /// when the URL has no fragment or names a service, and
    /// [`DereferenceError::NotInRelationship`] when the method is not referenced or embedded
    /// under `relationship`.
    pub async fn resolve_verification_method(
        &self,
        url: &DidUrl,
        relationship: Option<VerificationRelationship>,
    ) -> Result<VerificationMethod, DereferenceError> {
        let document = self.resolve_for(url).await?;
        let Some(fragment) = url.fragment() else {
            return Err(DereferenceError::NotVerificationMethod(url.clone()));
        };
        let id = document.id.to_url().with_fragment(fragment);
        document
            .resolve_verification_method(&id, relationship)
            .cloned()
            .map_err(|error| match error {
                DocumentError::NotInRelationship { id, relationship } => {
                    DereferenceError::NotInRelationship { id, relationship }
                }
                _ if document.service(&id).is_some() => DereferenceError::NotVerificationMethod(id),
                _ => DereferenceError::NotFound(id),
            })
    }

    /// The public key of the verification method `url` names, as a JWK.
    ///
    /// # Errors
    ///
    /// As [`resolve_verification_method`](Self::resolve_verification_method) without a
    /// relationship, plus [`DereferenceError::NoJwk`] when the method carries
    /// `publicKeyMultibase` material.
    pub async fn resolve_public_key(&self, url: &DidUrl) -> Result<Jwk, DereferenceError> {
        let method = self.resolve_verification_method(url, None).await?;
        method
            .public_key_jwk()
            .map(Jwk::public)
            .ok_or(DereferenceError::NoJwk {
                id: method.id,
                method_type: method.method_type,
            })
    }

    /// Resolves the DID of `url` with the resolution options its DID parameters carry, and
    /// refuses a path, an unknown parameter and a deactivated DID.
    async fn resolve_for(&self, url: &DidUrl) -> Result<DidDocument, DereferenceError> {
        let options = resolution_options(url)?;
        let did = url.did();
        let result = self.resolve_with(did, &options).await.map_err(|error| {
            DereferenceError::Resolution {
                did: did.clone(),
                error,
            }
        })?;
        if result.document_metadata.is_deactivated() {
            return Err(DereferenceError::Deactivated(did.clone()));
        }
        // `resolve_with` returns a document whenever the DID is not deactivated.
        result
            .into_document()
            .map_err(|error| DereferenceError::Resolution {
                did: did.clone(),
                error,
            })
    }
}

/// The DID parameters this crate understands, which select a version of the document.
const VERSION_PARAMETERS: [&str; 2] = ["versionId", "versionTime"];

/// The resolution options for the DID parameters of `url`.
fn resolution_options(url: &DidUrl) -> Result<ResolutionOptions, DereferenceError> {
    if url.path().is_some() {
        return Err(DereferenceError::MethodSpecific(url.clone()));
    }
    let mut options = ResolutionOptions::default();
    let Some(query) = url.query() else {
        return Ok(options);
    };
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name);
        if !VERSION_PARAMETERS.contains(&name.as_str()) {
            return Err(DereferenceError::MethodSpecific(url.clone()));
        }
        let value = Value::String(percent_decode(value));
        if options.properties.insert(name.clone(), value).is_some() {
            return Err(DereferenceError::InvalidDidUrl {
                url: url.clone(),
                reason: format!("DID parameter `{name}` is given twice"),
            });
        }
    }
    Ok(options)
}

/// Decodes the percent-encoded octets of a query component, which `DidUrl` has already checked
/// to be complete; `+` is not a space in a DID URL.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| core::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
