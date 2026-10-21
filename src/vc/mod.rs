//! Verifiable credentials and presentations secured as JWTs.
//!
//! The module implements two profiles over the same JOSE layer:
//!
//! - **VCDM 1.1 JWT profile** (§6.3.1 of the Verifiable Credentials Data Model 1.1):
//!   [`Credential`] and [`Presentation`] map to and from a [`JwtClaims`] set whose `vc` or `vp`
//!   claim holds the data model object and whose registered claims (`iss`, `sub`, `jti`, `nbf`,
//!   `exp`, `aud`) carry the issuer, subject, id, validity period and audience.
//! - **VCDM 2.0 with VC-JOSE-COSE**: [`CredentialV2`] and [`PresentationV2`] are themselves the
//!   JWT payload (`typ: vc+jwt` or `vp+jwt`), and a secured credential travels inside a
//!   presentation as an [`EnvelopedVc`] holding a `data:application/vc+jwt,…` URL.
//!
//! Both are plain data with open extension properties; `@context` is carried, never processed.
//! [`ClaimPath`] points at a claim in any JSON credential: the claim path of SD-JWT VC §5.6.1 and
//! the claims path pointer of OID4VP §7, which DCQL applies to every JSON-based format.
//! [`Jwt`] is a compact JWS as a string, signed with any [`Signer`](crate::jose::Signer) through
//! [`Jwt::sign`]. The [`validation`] module verifies and validates the JWTs: signature through
//! a [`KeyResolver`](validation::KeyResolver) and a [`JwsVerifier`](crate::jose::JwsVerifier),
//! binding of the signing key to the issuer or holder, validity period, audience, nonce and
//! status.
//!
//! Timestamps are [`chrono::DateTime<Utc>`](chrono::DateTime) values, serialized as RFC 3339
//! in UTC (`2010-01-01T19:23:24Z`), the `dateTimeStamp` form the data model requires.
//!
//! # Examples
//!
//! The JWT claims of VCDM 1.1 Example 31, decoded to a credential and back.
//!
//! ```
//! use identity_kit::vc::{Credential, JwtClaims};
//! use serde_json::json;
//!
//! let claims: JwtClaims = serde_json::from_value(json!({
//!   "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
//!   "jti": "http://example.edu/credentials/3732",
//!   "iss": "https://example.com/keys/foo.jwk",
//!   "nbf": 1541493724,
//!   "exp": 1573029723,
//!   "nonce": "660!6345FSer",
//!   "vc": {
//!     "@context": [
//!       "https://www.w3.org/2018/credentials/v1",
//!       "https://www.w3.org/2018/credentials/examples/v1"
//!     ],
//!     "type": ["VerifiableCredential", "UniversityDegreeCredential"],
//!     "credentialSubject": {
//!       "degree": { "type": "BachelorDegree", "name": "Bachelor of Science and Arts" }
//!     }
//!   }
//! }))?;
//!
//! let credential = Credential::from_jwt_claims(&claims)?;
//! assert_eq!(credential.id.as_ref().map(|id| id.as_str()), Some("http://example.edu/credentials/3732"));
//! assert_eq!(credential.issuer.id().as_str(), "https://example.com/keys/foo.jwk");
//! assert_eq!(credential.issuance_date.to_rfc3339(), "2018-11-06T08:42:04+00:00");
//! assert_eq!(
//!     credential.subject().and_then(|s| s.id.as_ref()).map(|id| id.as_str()),
//!     Some("did:example:ebfeb1f712ebc6f1c276e12ec21")
//! );
//!
//! // The mapping is reversible; the custom `nonce` claim is the caller's to add back.
//! let encoded = credential.to_jwt_claims()?.with_claim("nonce", "660!6345FSer");
//! assert_eq!(encoded, claims);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod claims;
mod credential;
mod error;
mod jwt;
mod model;
mod path;
mod presentation;
mod v2;
pub mod validation;

pub use credential::Credential;
pub use error::CredentialError;
pub use jwt::{Jwt, JwtClaims};
#[cfg(feature = "sd-jwt")]
pub(crate) use jwt::{numeric_date, required_numeric_date};
pub use model::{CONTEXT_V1, CONTEXT_V2, Party, Subject, TypedObject};
pub use path::{ClaimPath, ClaimPathError, PathComponent};
pub use presentation::Presentation;
pub use v2::{CredentialV2, EnvelopedVc, EnvelopedVp, PresentationV2};
