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
//! - [`SdJwtCredentialV2`] is a VCDM 2.0 credential secured with SD-JWT (VC-JOSE-COSE
//!   §3.2.1): `typ: vc+sd-jwt`, the [`CredentialV2`](crate::vc::CredentialV2) itself as the
//!   payload, [`SdJwtCredentialV2Builder`] to issue one and
//!   [`SdJwtCredentialValidator::validate_v2`] to validate one.
//! - [`Status`], [`StatusListRef`] and [`StatusList`] implement the Token Status List
//!   referenced from the `status` claim; [`TypeMetadata`] the SD-JWT VC type metadata with
//!   its claim paths, integrity metadata and `extends` processing.
//!
//! The SD-JWT layer is implemented here rather than taken from a dependency (ADR 0005).
//!
//! # Two SD-JWT credential types
//!
//! An SD-JWT VC ([`SdJwtVc`]) carries a flat claims set typed by `vct`, with `typ:
//! dc+sd-jwt` (`vc+sd-jwt` in earlier drafts). A VCDM 2.0 credential secured with SD-JWT
//! ([`SdJwtCredentialV2`]) carries the credential's own `@context`, `type`, `issuer` and
//! `credentialSubject`, with `typ: vc+sd-jwt` and media type `application/vc+sd-jwt`. So
//! `vc+sd-jwt` alone does not say which one a token is; the payload does: an SD-JWT VC has
//! `vct`, a VCDM 2.0 credential has `@context` and no `vct`.
//!
//! A verifier that accepts both picks the parser by `typ` first and by the payload second.
//! [`SdJwtVc::from_sd_jwt`] accepts `vc+sd-jwt` only when the payload has `vct`, and reports a
//! `vc+sd-jwt` payload with `@context` and no `vct` as [`SdJwtVcError::VcdmPayload`], so that
//! a caller which tried the SD-JWT VC parser first can fall through:
//!
//! ```
//! use identity_kit::sd_jwt_vc::{SdJwt, SdJwtCredentialV2, SdJwtVc, SdJwtVcError};
//!
//! enum Parsed {
//!     SdJwtVc(SdJwtVc),
//!     Vcdm(SdJwtCredentialV2),
//! }
//!
//! fn parse(sd_jwt: SdJwt) -> Result<Parsed, Box<dyn std::error::Error>> {
//!     match SdJwtVc::from_sd_jwt(sd_jwt.clone()) {
//!         Ok(credential) => Ok(Parsed::SdJwtVc(credential)),
//!         Err(SdJwtVcError::VcdmPayload | SdJwtVcError::MissingTyp) => {
//!             Ok(Parsed::Vcdm(SdJwtCredentialV2::from_sd_jwt(sd_jwt)?))
//!         }
//!         Err(error) => Err(error.into()),
//!     }
//! }
//! # let _ = parse;
//! ```

mod builder;
mod credential;
mod credential_v2;
mod disclosure;
mod error;
mod hash;
mod sd_jwt;
mod status;
mod type_metadata;
pub mod validation;

pub use builder::{Encoded, SdJwtBuilder};
pub use credential::{
    Confirmation, LEGACY_TYP, MEDIA_TYPE, NON_DISCLOSABLE_CLAIMS, SdJwtVc, SdJwtVcBuilder,
    SdJwtVcClaims, SdJwtVcError, TYP,
};
pub use credential_v2::{SdJwtCredentialV2, SdJwtCredentialV2Builder, SdJwtCredentialV2Error};
pub use disclosure::Disclosure;
pub use error::SdJwtError;
pub use hash::HashAlgorithm;
pub use sd_jwt::{DisclosedClaim, ELLIPSIS_KEY, KB_JWT_TYP, KeyBinding, Processed, SD_KEY, SdJwt};
pub use status::{
    Status, StatusList, StatusListError, StatusListRef, StatusListToken, StatusMechanism,
    StatusType,
};

pub use crate::vc::{ClaimPath, ClaimPathError, PathComponent};
pub use type_metadata::{
    ClaimDisplay, ClaimMetadata, DisplayMetadata, Integrity, IntegrityAlgorithm, IntegrityError,
    SdPolicy, TypeMetadata, TypeMetadataError,
};
pub use validation::{
    KeyBindingOptions, SdJwtCredentialValidator, SdJwtValidationError, SdJwtValidationOptions,
    ValidatedSdJwtCredentialV2, ValidatedSdJwtVc,
};
