//! Selective disclosure for JWTs (SD-JWT, RFC 9901) and SD-JWT-based verifiable credentials
//! (SD-JWT VC), with the Token Status List and SD-JWT VC type metadata.
//!
//! - [`SdJwt`] is the data format: an issuer-signed JWT, its [`Disclosure`]s and an optional
//!   key binding JWT, parsed from and serialized to the `~`-separated compact form.
//!   [`SdJwt::process`] matches the disclosures to the digests (RFC 9901 §7.1) and yields the
//!   processed payload; [`SdJwt::disclose`] and [`SdJwt::select`] make a presentation;
//!   [`SdJwt::sign_key_binding`] turns it into an SD-JWT+KB.
//! - [`SdJwtBuilder`] issues: it conceals the claims at the given [`ClaimPath`]s, nested ones
//!   recursively, adds decoys and signs with any [`Signer`](crate::jose::Signer).
//! - [`SdJwtVc`] is an SD-JWT VC: `typ: dc+sd-jwt`, a `vct`, the registered claims that may
//!   not be selectively disclosed kept as such, [`SdJwtVcBuilder`] to issue one and
//!   [`SdJwtCredentialValidator`] to validate one, key binding included.
//! - [`Status`], [`StatusListRef`] and [`StatusList`] implement the Token Status List
//!   referenced from the `status` claim; [`TypeMetadata`] the SD-JWT VC type metadata with
//!   its claim paths, integrity metadata and `extends` processing.
//!
//! The SD-JWT layer is implemented here rather than taken from a dependency (ADR 0005).

mod builder;
mod credential;
mod disclosure;
mod error;
mod hash;
mod path;
mod sd_jwt;
mod status;
mod type_metadata;
pub mod validation;

pub use builder::{Encoded, SdJwtBuilder};
pub use credential::{
    Confirmation, LEGACY_TYP, MEDIA_TYPE, NON_DISCLOSABLE_CLAIMS, SdJwtVc, SdJwtVcBuilder,
    SdJwtVcClaims, SdJwtVcError, TYP,
};
pub use disclosure::Disclosure;
pub use error::SdJwtError;
pub use hash::HashAlgorithm;
pub use path::{ClaimPath, ClaimPathError, PathComponent};
pub use sd_jwt::{DisclosedClaim, ELLIPSIS_KEY, KB_JWT_TYP, KeyBinding, Processed, SD_KEY, SdJwt};
pub use status::{
    Status, StatusList, StatusListError, StatusListRef, StatusListToken, StatusMechanism,
    StatusType,
};
pub use type_metadata::{
    ClaimDisplay, ClaimMetadata, DisplayMetadata, Integrity, IntegrityAlgorithm, IntegrityError,
    SdPolicy, TypeMetadata, TypeMetadataError,
};
pub use validation::{
    KeyBindingOptions, SdJwtCredentialValidator, SdJwtStatusCheck, SdJwtValidationError,
    SdJwtValidationOptions, ValidatedSdJwtVc,
};
