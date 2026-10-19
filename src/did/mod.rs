//! Decentralized identifiers (DIDs), DID URLs, DID documents and resolution types.
//!
//! Pure data: no I/O, no async, no crypto. The module has three parts:
//!
//! - **Identifiers.** [`Did`] and [`DidUrl`] implement the DID and DID URL syntax, described
//!   below; [`DidUrlReference`] is a DID URL or a relative reference such as `#key-1`; [`Uri`]
//!   is any RFC 3986 URI, kept as written.
//! - **Documents.** [`DidDocument`] with [`VerificationMethod`], [`MethodRef`], [`Service`] and
//!   the other types of DID Core §5, serialized deterministically with extension properties in
//!   insertion order, plus the operations to edit and query a document.
//! - **Resolution.** [`ResolutionResult`], [`DocumentMetadata`], [`ResolutionMetadata`],
//!   [`ResolutionOptions`] and [`ResolutionError`], whose [`ResolutionErrorKind`] is the error
//!   vocabulary of DID Core §7.1.
//!
//! # DID syntax
//!
//! [`Did`] and [`DidUrl`] are validated when constructed and otherwise keep the input unchanged.
//! They implement the syntax of [W3C DID Core 1.0] §3.1 and §3.2 together with the RFC 3986
//! productions it references:
//!
//! ```text
//! did                = "did:" method-name ":" method-specific-id
//! method-name        = 1*method-char
//! method-char        = %x61-7A / DIGIT                 ; lowercase a-z and 0-9 only
//! method-specific-id = *( *idchar ":" ) 1*idchar       ; colons allowed, last segment non-empty
//! idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
//! pct-encoded        = "%" HEXDIG HEXDIG
//!
//! did-url            = did path-abempty [ "?" query ] [ "#" fragment ]
//! ```
//!
//! Consequences worth knowing:
//!
//! - `did:` and the method name are lowercase and case-sensitive: `DID:example:123` and
//!   `did:Example:123` are invalid.
//! - The method-specific id may contain `:` and empty inner segments (`did:example:a::b` is valid)
//!   but must not end with `:` (`did:example:a:` is invalid).
//! - Percent-encoding is checked for completeness (`%3A` valid, `%3` and `%G1` invalid) but never
//!   decoded, and nothing is normalized. Two DIDs are equal exactly when their strings are equal.
//! - A space, `/`, `?`, `#` or non-ASCII character ends the DID. [`Did::parse`] rejects it;
//!   [`DidUrl::parse`] takes `/`, `?` and `#` as the start of the path, query or fragment.
//! - Parsing rejects input longer than [`DEFAULT_MAX_LEN`] bytes; use
//!   [`Did::parse_with_max_len`] or [`DidUrl::parse_with_max_len`] to change the limit.
//!
//! Both types implement `Display`, `FromStr`, `TryFrom<&str>`, `TryFrom<String>`, `AsRef<str>`,
//! `Clone`, `Eq`, `Ord`, `Hash`, and serde `Serialize`/`Deserialize` as a plain string, where
//! deserialization validates.
//!
//! # Examples
//!
//! ```
//! use identity_kit::did::{Did, DidUrl};
//!
//! let did: Did = "did:example:123".parse()?;
//! let key = did.join("#key-1")?;
//! assert_eq!(key.to_string(), "did:example:123#key-1");
//!
//! let url = DidUrl::parse("did:example:123/path?versionId=1#key-1")?;
//! assert_eq!(url.did(), &did);
//! assert_eq!(url.path(), Some("/path"));
//! assert_eq!(url.query(), Some("versionId=1"));
//! assert_eq!(url.fragment(), Some("key-1"));
//! # Ok::<(), identity_kit::did::DidError>(())
//! ```
//!
//! [W3C DID Core 1.0]: https://www.w3.org/TR/did-core/

mod document;
mod error;
mod reference;
mod resolution;
mod syntax;
mod uri;

pub use document::{
    Context, DidDocument, DidDocumentBuilder, DocumentError, MethodRef, MethodType, OneOrMany,
    Service, ServiceEndpoint, VerificationMaterial, VerificationMethod, VerificationRelationship,
};
pub use error::DidError;
pub use reference::DidUrlReference;
pub use resolution::{
    APPLICATION_DID_JSON, APPLICATION_DID_LD_JSON, DocumentMetadata, ResolutionError,
    ResolutionErrorKind, ResolutionMetadata, ResolutionOptions, ResolutionResult,
};
pub use syntax::{DEFAULT_MAX_LEN, Did, DidUrl};
pub use uri::Uri;
