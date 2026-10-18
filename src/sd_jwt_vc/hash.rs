//! The hash algorithm of an SD-JWT (`_sd_alg`).

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Digest as _;

use super::SdJwtError;
use crate::jose::base64url;

/// The hash algorithm an SD-JWT uses for its disclosure digests and its `sd_hash`, named as
/// in the IANA "Named Information Hash Algorithm" registry (`sha-256`, the default and the
/// one every implementation must support, `sha-384` or `sha-512`).
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::HashAlgorithm;
///
/// // RFC 9901 §4.2.3: the digest of the `family_name` disclosure.
/// let disclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
/// assert_eq!(
///     HashAlgorithm::Sha256.digest(disclosure.as_bytes()),
///     "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
/// );
/// assert_eq!("sha-256".parse::<HashAlgorithm>()?, HashAlgorithm::Sha256);
/// assert!("md5".parse::<HashAlgorithm>().is_err());
/// # Ok::<(), identity_kit::sd_jwt_vc::SdJwtError>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// `sha-256`, the default when `_sd_alg` is absent.
    #[default]
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

impl HashAlgorithm {
    /// The claim carrying the algorithm, `_sd_alg`.
    pub const CLAIM: &'static str = "_sd_alg";

    /// The IANA hash name string.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }

    /// The algorithm with the IANA hash name `name`.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::UnsupportedHashAlgorithm`] for any other name.
    pub fn parse(name: &str) -> Result<Self, SdJwtError> {
        match name {
            "sha-256" => Ok(Self::Sha256),
            "sha-384" => Ok(Self::Sha384),
            "sha-512" => Ok(Self::Sha512),
            _ => Err(SdJwtError::UnsupportedHashAlgorithm(name.to_owned())),
        }
    }

    /// The base64url-encoded digest of `data`.
    pub fn digest(self, data: &[u8]) -> String {
        let digest = match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        };
        base64url::encode(&digest)
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for HashAlgorithm {
    type Err = SdJwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for HashAlgorithm {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}
