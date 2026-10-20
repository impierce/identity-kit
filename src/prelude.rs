//! The commonly used types and traits of each layer, for glob import.
//!
//! The crate has two layers (see the [crate documentation](crate)). This module is the lower
//! layer's prelude: DIDs and DID documents, JOSE keys and signatures, key stores, DID
//! resolution and the methods the enabled features provide. [`credentials`] is the upper
//! layer's: verifiable credentials as JWTs, SD-JWT VCs and domain linkage.
//!
//! ```
//! use identity_kit::prelude::*;
//!
//! let did = Did::parse("did:example:123")?;
//! let url = did.join("#key-1")?;
//! assert_eq!(url.fragment(), Some("key-1"));
//! # Ok::<(), DidError>(())
//! ```

pub use crate::did::{
    Context, Did, DidDocument, DidDocumentBuilder, DidError, DidUrl, DidUrlReference,
    DocumentMetadata, MethodRef, MethodType, OneOrMany, ResolutionError, ResolutionErrorKind,
    ResolutionMetadata, ResolutionOptions, ResolutionResult, Service, ServiceEndpoint, Uri,
    VerificationMaterial, VerificationMethod, VerificationRelationship,
};
pub use crate::jose::{
    CompactJws, DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, JwsVerifier, KeyType, Signer,
    encode_compact,
};
#[cfg(feature = "in-memory")]
#[cfg_attr(docsrs, doc(cfg(feature = "in-memory")))]
pub use crate::keys::InMemoryKeyStore;
pub use crate::keys::{KeyId, KeySigner, KeySpec, KeyStore, KeyStoreCapabilities, KeyStoreError};
#[cfg(feature = "software")]
#[cfg_attr(docsrs, doc(cfg(feature = "software")))]
pub use crate::keys::{SoftwareKeyStore, SoftwareKeyStoreOptions};
#[cfg(feature = "did-jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-jwk")))]
pub use crate::methods::DidJwk;
#[cfg(feature = "did-key")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-key")))]
pub use crate::methods::DidKey;
#[cfg(feature = "did-web")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-web")))]
pub use crate::methods::DidWeb;
pub use crate::resolver::{
    DereferenceError, Dereferenced, DidProducer, DidResolver, DocumentCache, Hosting,
    MethodCapabilities, ProduceError, Resolver, ResolverBuilder,
};

/// The upper layer's prelude: credentials and presentations as JWTs (feature `vc`), SD-JWT
/// VCs (feature `sd-jwt`), domain linkage (feature `domain-linkage`) and linked presentations
/// (feature `linked-vp`).
///
/// It does not repeat the lower layer; import both.
///
/// ```
/// use identity_kit::prelude::*;
/// use identity_kit::prelude::credentials::*;
///
/// let holder = Did::parse("did:example:holder")?;
/// let subject = Subject::new(holder);
/// assert_eq!(subject.id.as_ref().map(Uri::as_str), Some("did:example:holder"));
/// # Ok::<(), DidError>(())
/// ```
#[cfg(feature = "vc")]
#[cfg_attr(docsrs, doc(cfg(feature = "vc")))]
pub mod credentials {
    #[cfg(feature = "domain-linkage")]
    #[cfg_attr(docsrs, doc(cfg(feature = "domain-linkage")))]
    pub use crate::domain_linkage::{
        DomainLinkageConfiguration, DomainLinkageCredentialBuilder, DomainLinkageError,
        DomainLinkageReport, DomainLinkageValidator, LinkedDid,
    };
    #[cfg(feature = "linked-vp")]
    #[cfg_attr(docsrs, doc(cfg(feature = "linked-vp")))]
    pub use crate::linked_vp::{
        LinkedPresentationBuilder, LinkedPresentationReport, LinkedVpClient, LinkedVpError,
        LinkedVpService, LinkedVpValidationOptions, LinkedVpValidator,
    };
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    pub use crate::sd_jwt_vc::{
        ClaimPath, Disclosure, HashAlgorithm, KeyBinding, KeyBindingOptions, Processed, SdJwt,
        SdJwtBuilder, SdJwtCredentialValidator, SdJwtError, SdJwtStatusCheck, SdJwtValidationError,
        SdJwtValidationOptions, SdJwtVc, SdJwtVcBuilder, SdJwtVcClaims, SdJwtVcError, Status,
        StatusList, StatusListToken, TypeMetadata, ValidatedSdJwtVc,
    };
    pub use crate::vc::validation::{
        CredentialValidationOptions, DecodedCredential, DecodedCredentialV2, DecodedPresentation,
        DecodedPresentationV2, FailFast, JwtCredentialValidator, JwtPresentationValidator,
        KeyResolver, PresentationValidationOptions, StatusCheck, StatusPolicy,
        SubjectHolderRelationship, TimeOptions, ValidationError,
    };
    pub use crate::vc::{
        Credential, CredentialError, CredentialV2, EnvelopedVc, EnvelopedVp, Jwt, JwtClaims, Party,
        Presentation, PresentationV2, Subject,
    };
}
