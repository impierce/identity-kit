//! Errors of SD-JWT parsing, processing and building.

use super::ClaimPath;
use crate::jose::JwsError;

/// Why an SD-JWT could not be parsed, processed, selected from or built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtError {
    /// The issuer-signed JWT or the key binding JWT is not a compact JWS this crate decodes.
    #[error("invalid JWS: {0}")]
    Jws(#[from] JwsError),
    /// The compact serialization is malformed: no `~`, an empty disclosure.
    #[error("invalid SD-JWT: {0}")]
    Format(String),
    /// A disclosure is not base64url of a JSON array of the right shape.
    #[error("invalid disclosure {disclosure:?}: {reason}")]
    InvalidDisclosure {
        /// The encoded disclosure.
        disclosure: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The same disclosure is given twice.
    #[error("disclosure {0:?} is given twice")]
    DuplicateDisclosure(String),
    /// The issuer-signed JWT payload is not a JSON object, or `_sd`, `...` or `_sd_alg` is
    /// malformed.
    #[error("invalid SD-JWT payload: {0}")]
    Payload(String),
    /// The `_sd_alg` names a hash algorithm this crate does not implement.
    #[error("unsupported hash algorithm {0:?}")]
    UnsupportedHashAlgorithm(String),
    /// A digest appears more than once in the payload, directly or through disclosures.
    #[error("digest {0:?} appears more than once")]
    DuplicateDigest(String),
    /// A disclosure matches no digest in the payload or in another disclosure.
    #[error("disclosure {0:?} is referenced by no digest")]
    UnusedDisclosure(String),
    /// A disclosure of the wrong kind matches a digest: an array element disclosure in `_sd`,
    /// or an object property disclosure in an array.
    #[error("disclosure {disclosure:?} is not {expected}")]
    WrongDisclosureKind {
        /// The encoded disclosure.
        disclosure: String,
        /// `an object property disclosure` or `an array element disclosure`.
        expected: &'static str,
    },
    /// A disclosure names the reserved claim `_sd` or `...`.
    #[error("disclosure claim name {0:?} is reserved")]
    ReservedClaimName(String),
    /// A disclosure names a claim that already exists at the level of its `_sd`.
    #[error("claim {name:?} at {path} is both disclosed and present")]
    DuplicateClaim {
        /// The claim name.
        name: String,
        /// The object it is duplicated in.
        path: ClaimPath,
    },
    /// A disclosure was selected without the disclosure whose value references it.
    #[error("disclosure {disclosure:?} needs the disclosure {parent:?} it is nested in")]
    MissingParentDisclosure {
        /// The encoded disclosure selected.
        disclosure: String,
        /// The encoded disclosure it needs.
        parent: String,
    },
    /// A path to conceal or disclose selects no claim.
    #[error("no claim at {0}")]
    NoSuchClaim(ClaimPath),
    /// A claim cannot be made selectively disclosable: it is `_sd` or `...`, or a profile
    /// forbids it.
    #[error("claim at {path} cannot be selectively disclosable: {reason}")]
    NotConcealable {
        /// The claim.
        path: ClaimPath,
        /// Why.
        reason: String,
    },
    /// The claims nest deeper than [`SdJwtBuilder::MAX_DEPTH`](super::SdJwtBuilder::MAX_DEPTH)
    /// containers: claims to issue, which no parser of this crate would read back, or claims
    /// being processed, through the payload and the disclosures nested in it.
    #[error("the claims nest deeper than {max} containers")]
    TooDeep {
        /// The deepest nesting accepted.
        max: usize,
    },
    /// The key binding JWT is present where an SD-JWT without key binding was expected, or
    /// missing.
    #[error("{0}")]
    KeyBinding(String),
}
