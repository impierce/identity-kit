//! The SD-JWT and SD-JWT+KB data formats (RFC 9901 §4) and their processing (§7).

use core::fmt;
use core::str::FromStr;
use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::{ClaimPath, Disclosure, HashAlgorithm, SdJwtError};
use crate::jose::{JwsHeader, Signer};
use crate::vc::{Jwt, JwtClaims};

/// The `_sd` key: the digests of the disclosable properties of an object.
pub const SD_KEY: &str = "_sd";

/// The `...` key: the digest of a disclosable array element.
pub const ELLIPSIS_KEY: &str = "...";

/// The `typ` of a key binding JWT.
pub const KB_JWT_TYP: &str = "kb+jwt";

/// An SD-JWT: an issuer-signed JWT, its disclosures and, in an SD-JWT+KB, a key binding JWT,
/// as the compact serialization `<JWT>~<Disclosure 1>~…~<Disclosure N>~[<KB-JWT>]`.
///
/// Parsing checks the structure only. [`SdJwt::process`] matches the disclosures to the
/// digests and yields the processed payload; the signature is the validator's business
/// ([`SdJwtCredentialValidator`](super::SdJwtCredentialValidator) for an SD-JWT VC).
///
/// # Examples
///
/// The presentation of RFC 9901 §5.2, processed.
///
/// ```
/// use identity_kit::sd_jwt_vc::SdJwt;
/// use serde_json::json;
///
/// let presentation = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkNyUWU3UzVr\
///     cUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVa\
///     dTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFV\
///     QTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAi\
///     WFFfM2tQS3QxWHlYN0tBTmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242\
///     Q0pEYzZ2Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFrb2I5\
///     aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3\
///     TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAw\
///     MDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjogInVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7\
///     Ii4uLiI6ICJwRm5kamtaX1ZDem15VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4u\
///     IjogIjdDZjZKa1B1ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxn\
///     IjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAi\
///     eCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhq\
///     aVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.xJUoRLl1sVRxz57ralck\
///     9kBWbzbq0soK6dQ5liBXuge3IY8vVYq2xi1tywYwvlRTtPIM2A-XDzyta-SaJLhexQ~WyJlbHVWNU9nM\
///     2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJBSngtMDk1VlBycFR0TjRRTU9x\
///     Uk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5\
///     IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyIyR0xD\
///     NDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJsa2x4RjVqTVlsR1RQVW9\
///     2TU5JdkNBIiwgIlVTIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6IC\
///     IxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6ID\
///     E3NDg1MzY4NjUsICJzZF9oYXNoIjogImZNVjA1dnVNQVJzM3VHMERnMEJZZF83bVFSOUVHQmtSb2YwY1\
///     RaeXVxWEUifQ.76YniH11s4EDLnqNXKzYtIU1yXEBNzY8wfTd1QkpKzcJ0JY_KXbURL8qQBJA7xpZiA8\
///     vXYrlpPpd4yfHJTfhQA";
/// let sd_jwt: SdJwt = presentation.parse()?;
/// assert_eq!(sd_jwt.disclosures().len(), 4);
/// assert!(sd_jwt.key_binding_jwt().is_some());
///
/// let processed = sd_jwt.process()?;
/// assert_eq!(processed.payload["given_name"], "John");
/// assert_eq!(processed.payload["nationalities"], json!(["US"]));
/// assert!(!processed.payload.contains_key("email"));
/// # Ok::<(), identity_kit::sd_jwt_vc::SdJwtError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SdJwt {
    jwt: Jwt,
    disclosures: Vec<Disclosure>,
    key_binding: Option<Jwt>,
}

impl SdJwt {
    /// An SD-JWT of `jwt` and `disclosures`, without key binding.
    pub fn new(jwt: Jwt, disclosures: Vec<Disclosure>) -> Self {
        Self {
            jwt,
            disclosures,
            key_binding: None,
        }
    }

    /// Parses the compact serialization.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::Format`] without a `~` or with an empty disclosure, [`SdJwtError::Jws`]
    /// when the JWT or the key binding JWT does not decode,
    /// [`SdJwtError::InvalidDisclosure`] and [`SdJwtError::DuplicateDisclosure`].
    pub fn parse(s: &str) -> Result<Self, SdJwtError> {
        let parts: Vec<&str> = s.split('~').collect();
        let [jwt, middle @ .., last] = parts.as_slice() else {
            return Err(SdJwtError::Format(
                "no `~` after the issuer-signed JWT".into(),
            ));
        };
        let jwt = Jwt::new(*jwt)?;
        let key_binding = if last.is_empty() {
            None
        } else {
            Some(Jwt::new(*last)?)
        };
        let mut disclosures = Vec::with_capacity(middle.len());
        let mut seen = HashSet::new();
        for part in middle {
            if part.is_empty() {
                return Err(SdJwtError::Format("empty disclosure".into()));
            }
            if !seen.insert(*part) {
                return Err(SdJwtError::DuplicateDisclosure((*part).to_owned()));
            }
            disclosures.push(Disclosure::parse(part)?);
        }
        Ok(Self {
            jwt,
            disclosures,
            key_binding,
        })
    }

    /// The issuer-signed JWT.
    pub fn jwt(&self) -> &Jwt {
        &self.jwt
    }

    /// The disclosures, in order.
    pub fn disclosures(&self) -> &[Disclosure] {
        &self.disclosures
    }

    /// The key binding JWT, when this is an SD-JWT+KB.
    pub fn key_binding_jwt(&self) -> Option<&Jwt> {
        self.key_binding.as_ref()
    }

    /// This SD-JWT with `key_binding` as its key binding JWT.
    #[must_use]
    pub fn with_key_binding(mut self, key_binding: Jwt) -> Self {
        self.key_binding = Some(key_binding);
        self
    }

    /// This SD-JWT without its key binding JWT.
    #[must_use]
    pub fn without_key_binding(mut self) -> Self {
        self.key_binding = None;
        self
    }

    /// The issuer-signed JWT payload as issued: digests in place, nothing disclosed, nothing
    /// verified.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::Payload`] when the payload is not a JSON object.
    pub fn payload(&self) -> Result<Map<String, Value>, SdJwtError> {
        let jws = self.jwt.decode()?;
        serde_json::from_slice(jws.payload())
            .map_err(|e| SdJwtError::Payload(format!("not a JSON object: {e}")))
    }

    /// The hash algorithm, from `_sd_alg`; SHA-256 when absent.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::Payload`] when `_sd_alg` is not a string,
    /// [`SdJwtError::UnsupportedHashAlgorithm`] when it names an algorithm this crate does not
    /// implement.
    pub fn hash_algorithm(&self) -> Result<HashAlgorithm, SdJwtError> {
        hash_algorithm(&self.payload()?)
    }

    /// The compact serialization without the key binding JWT: the input of `sd_hash`.
    pub fn to_string_without_key_binding(&self) -> String {
        let mut s = String::from(self.jwt.as_str());
        s.push('~');
        for disclosure in &self.disclosures {
            s.push_str(disclosure.as_str());
            s.push('~');
        }
        s
    }

    /// The `sd_hash` a key binding JWT over this SD-JWT carries (RFC 9901 §4.3.1): the digest
    /// under `alg` of the serialization without the key binding JWT.
    pub fn sd_hash(&self, alg: HashAlgorithm) -> String {
        alg.digest(self.to_string_without_key_binding().as_bytes())
    }

    /// Processes the disclosures into the payload (RFC 9901 §7.1, steps 3 to 5): every
    /// disclosure must match a digest, no digest may appear twice, no disclosure may name a
    /// reserved or existing claim.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::Payload`], [`SdJwtError::UnsupportedHashAlgorithm`],
    /// [`SdJwtError::DuplicateDigest`], [`SdJwtError::UnusedDisclosure`],
    /// [`SdJwtError::WrongDisclosureKind`], [`SdJwtError::ReservedClaimName`] or
    /// [`SdJwtError::DuplicateClaim`].
    pub fn process(&self) -> Result<Processed, SdJwtError> {
        let mut payload = self.payload()?;
        let alg = hash_algorithm(&payload)?;
        payload.shift_remove(HashAlgorithm::CLAIM);
        let mut processor = Processor::new(alg, &self.disclosures);
        let issued = processor.object(payload, &ClaimPath::root(), None)?;
        if let Some(unused) = processor.used.iter().position(|used| !used) {
            return Err(SdJwtError::UnusedDisclosure(
                self.disclosures[unused].as_str().to_owned(),
            ));
        }
        let mut payload = Value::Object(issued.clone());
        strip_placeholders(&mut payload);
        let Value::Object(payload) = payload else {
            unreachable!("an object stays an object")
        };
        Ok(Processed {
            payload,
            disclosed: processor.disclosed,
            undisclosed: processor.undisclosed,
            issued,
            parents: processor.parents,
        })
    }

    /// This SD-JWT with only the disclosures `keep` selects and no key binding JWT, for
    /// presentation (RFC 9901 §7.2). A kept disclosure nested in another needs that one kept
    /// too.
    ///
    /// # Errors
    ///
    /// As [`process`](Self::process), plus [`SdJwtError::MissingParentDisclosure`].
    pub fn select(&self, mut keep: impl FnMut(&Disclosure) -> bool) -> Result<Self, SdJwtError> {
        let processed = self.process()?;
        let kept: Vec<bool> = self.disclosures.iter().map(&mut keep).collect();
        self.selected(&processed, &kept)
    }

    /// This SD-JWT with only the disclosures at `paths` and beneath them, plus the disclosures
    /// they are nested in, and no key binding JWT. A path may use `null` for every element.
    ///
    /// # Errors
    ///
    /// As [`process`](Self::process), plus [`SdJwtError::NoSuchClaim`] for a path selecting
    /// no disclosure.
    pub fn disclose<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a ClaimPath>,
    ) -> Result<Self, SdJwtError> {
        let processed = self.process()?;
        let mut kept = vec![false; self.disclosures.len()];
        for path in paths {
            let mut found = false;
            for claim in &processed.disclosed {
                if path.is_prefix_of(&claim.path) {
                    found = true;
                    let mut index = Some(claim.disclosure);
                    while let Some(i) = index {
                        kept[i] = true;
                        index = processed.parents[i];
                    }
                }
            }
            if !found {
                return Err(SdJwtError::NoSuchClaim(path.clone()));
            }
        }
        self.selected(&processed, &kept)
    }

    /// The SD-JWT with the disclosures flagged in `kept`, checking their parents are kept.
    fn selected(&self, processed: &Processed, kept: &[bool]) -> Result<Self, SdJwtError> {
        for (i, disclosure) in self.disclosures.iter().enumerate() {
            if !kept[i] {
                continue;
            }
            if let Some(parent) = processed.parents[i] {
                if !kept[parent] {
                    return Err(SdJwtError::MissingParentDisclosure {
                        disclosure: disclosure.as_str().to_owned(),
                        parent: self.disclosures[parent].as_str().to_owned(),
                    });
                }
            }
        }
        let disclosures = self
            .disclosures
            .iter()
            .zip(kept)
            .filter(|(_, kept)| **kept)
            .map(|(d, _)| d.clone())
            .collect();
        Ok(Self::new(self.jwt.clone(), disclosures))
    }

    /// This SD-JWT as an SD-JWT+KB: `binding` signed by the holder with `signer` over the
    /// `sd_hash` of this SD-JWT (RFC 9901 §4.3), replacing any key binding JWT present.
    ///
    /// # Errors
    ///
    /// As [`hash_algorithm`](Self::hash_algorithm), or [`SdJwtError::Jws`] when signing
    /// fails.
    pub async fn sign_key_binding(
        self,
        binding: &KeyBinding,
        signer: &dyn Signer,
    ) -> Result<Self, SdJwtError> {
        let sd_jwt = self.without_key_binding();
        let alg = sd_jwt.hash_algorithm()?;
        let claims = binding.claims(sd_jwt.sd_hash(alg));
        let header = JwsHeader::new(signer.alg()).with_typ(KB_JWT_TYP);
        let key_binding = Jwt::sign(&header, &claims, signer).await?;
        Ok(sd_jwt.with_key_binding(key_binding))
    }
}

/// The `_sd_alg` of `payload`.
fn hash_algorithm(payload: &Map<String, Value>) -> Result<HashAlgorithm, SdJwtError> {
    match payload.get(HashAlgorithm::CLAIM) {
        None => Ok(HashAlgorithm::default()),
        Some(Value::String(name)) => HashAlgorithm::parse(name),
        Some(_) => Err(SdJwtError::Payload("`_sd_alg` is not a string".into())),
    }
}

impl fmt::Debug for SdJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwt")
            .field("jwt", &self.jwt)
            .field("disclosures", &self.disclosures)
            .field("key_binding", &self.key_binding)
            .finish()
    }
}

impl fmt::Display for SdJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_without_key_binding())?;
        if let Some(key_binding) = &self.key_binding {
            f.write_str(key_binding.as_str())?;
        }
        Ok(())
    }
}

impl FromStr for SdJwt {
    type Err = SdJwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SdJwt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SdJwt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The outcome of [`SdJwt::process`]: the processed payload and where the disclosures went.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Processed {
    /// The processed SD-JWT payload: disclosed claims in place, `_sd`, `...` and `_sd_alg`
    /// gone, undisclosed array elements removed.
    pub payload: Map<String, Value>,
    /// Every disclosure that was matched, with the path of the claim it disclosed.
    pub disclosed: Vec<DisclosedClaim>,
    /// The paths of array elements whose digest matched no disclosure, in the coordinates of
    /// the payload as issued.
    pub undisclosed: Vec<ClaimPath>,
    issued: Map<String, Value>,
    parents: Vec<Option<usize>>,
}

impl Processed {
    /// The payload in the coordinates of the issued credential: as [`payload`](Self::payload),
    /// except that an undisclosed array element stays in place as the `{"...": "<digest>"}`
    /// object that referenced it. Claim paths of type metadata are evaluated against this.
    pub fn as_issued(&self) -> &Map<String, Value> {
        &self.issued
    }

    /// The disclosed claim paths, in the coordinates of the issued credential.
    pub fn disclosed_paths(&self) -> impl Iterator<Item = &ClaimPath> {
        self.disclosed.iter().map(|claim| &claim.path)
    }

    /// Whether the claim at the concrete `path` was disclosed by a disclosure of its own.
    pub fn is_disclosed(&self, path: &ClaimPath) -> bool {
        self.disclosed.iter().any(|claim| claim.path == *path)
    }
}

/// A disclosure matched to its place in the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DisclosedClaim {
    /// The path of the claim, in the coordinates of the issued credential.
    pub path: ClaimPath,
    /// The index of the disclosure in [`SdJwt::disclosures`].
    pub disclosure: usize,
}

/// Whether `value` is an object with one key `...` referring to a string: the form a digest
/// takes in an array.
fn digest_placeholder(value: &Value) -> Option<&str> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    object.get(ELLIPSIS_KEY)?.as_str()
}

/// Removes every undisclosed array element placeholder from `value`.
fn strip_placeholders(value: &mut Value) {
    match value {
        Value::Object(object) => object.values_mut().for_each(strip_placeholders),
        Value::Array(array) => {
            array.retain(|element| digest_placeholder(element).is_none());
            array.iter_mut().for_each(strip_placeholders);
        }
        _ => {}
    }
}

/// The state of one [`SdJwt::process`] run.
struct Processor<'a> {
    disclosures: &'a [Disclosure],
    digests: HashMap<String, usize>,
    used: Vec<bool>,
    parents: Vec<Option<usize>>,
    seen: HashSet<String>,
    disclosed: Vec<DisclosedClaim>,
    undisclosed: Vec<ClaimPath>,
}

impl<'a> Processor<'a> {
    fn new(alg: HashAlgorithm, disclosures: &'a [Disclosure]) -> Self {
        let digests = disclosures
            .iter()
            .enumerate()
            .map(|(i, d)| (d.digest(alg), i))
            .collect();
        Self {
            disclosures,
            digests,
            used: vec![false; disclosures.len()],
            parents: vec![None; disclosures.len()],
            seen: HashSet::new(),
            disclosed: Vec::new(),
            undisclosed: Vec::new(),
        }
    }

    /// The disclosure `digest` references, if any; rejects a digest seen before.
    fn lookup(&mut self, digest: &str, owner: Option<usize>) -> Result<Option<usize>, SdJwtError> {
        if !self.seen.insert(digest.to_owned()) {
            return Err(SdJwtError::DuplicateDigest(digest.to_owned()));
        }
        let Some(&index) = self.digests.get(digest) else {
            return Ok(None);
        };
        self.used[index] = true;
        self.parents[index] = owner;
        Ok(Some(index))
    }

    fn value(
        &mut self,
        value: Value,
        path: &ClaimPath,
        owner: Option<usize>,
    ) -> Result<Value, SdJwtError> {
        match value {
            Value::Object(object) => self.object(object, path, owner).map(Value::Object),
            Value::Array(array) => self.array(array, path, owner).map(Value::Array),
            other => Ok(other),
        }
    }

    fn object(
        &mut self,
        object: Map<String, Value>,
        path: &ClaimPath,
        owner: Option<usize>,
    ) -> Result<Map<String, Value>, SdJwtError> {
        let mut out = Map::new();
        let mut digests = None;
        for (name, value) in object {
            if name == SD_KEY {
                let Value::Array(array) = value else {
                    return Err(SdJwtError::Payload(format!(
                        "`_sd` at {path} is not an array"
                    )));
                };
                digests = Some(array);
                continue;
            }
            let value = self.value(value, &path.join(name.as_str()), owner)?;
            out.insert(name, value);
        }
        for digest in digests.unwrap_or_default() {
            let Value::String(digest) = digest else {
                return Err(SdJwtError::Payload(format!(
                    "`_sd` at {path} holds a non-string"
                )));
            };
            let Some(index) = self.lookup(&digest, owner)? else {
                continue;
            };
            let disclosure = &self.disclosures[index];
            let Some(name) = disclosure.name() else {
                return Err(SdJwtError::WrongDisclosureKind {
                    disclosure: disclosure.as_str().to_owned(),
                    expected: "an object property disclosure",
                });
            };
            if name == SD_KEY || name == ELLIPSIS_KEY {
                return Err(SdJwtError::ReservedClaimName(name.to_owned()));
            }
            if out.contains_key(name) {
                return Err(SdJwtError::DuplicateClaim {
                    name: name.to_owned(),
                    path: path.clone(),
                });
            }
            let name = name.to_owned();
            let claim_path = path.join(name.as_str());
            let value = self.value(disclosure.value().clone(), &claim_path, Some(index))?;
            out.insert(name, value);
            self.disclosed.push(DisclosedClaim {
                path: claim_path,
                disclosure: index,
            });
        }
        Ok(out)
    }

    fn array(
        &mut self,
        array: Vec<Value>,
        path: &ClaimPath,
        owner: Option<usize>,
    ) -> Result<Vec<Value>, SdJwtError> {
        let mut out = Vec::with_capacity(array.len());
        for (i, element) in array.into_iter().enumerate() {
            let element_path = path.join(i);
            let Some(digest) = digest_placeholder(&element).map(str::to_owned) else {
                out.push(self.value(element, &element_path, owner)?);
                continue;
            };
            let Some(index) = self.lookup(&digest, owner)? else {
                self.undisclosed.push(element_path);
                out.push(element);
                continue;
            };
            let disclosure = &self.disclosures[index];
            if !disclosure.is_element() {
                return Err(SdJwtError::WrongDisclosureKind {
                    disclosure: disclosure.as_str().to_owned(),
                    expected: "an array element disclosure",
                });
            }
            let value = self.value(disclosure.value().clone(), &element_path, Some(index))?;
            out.push(value);
            self.disclosed.push(DisclosedClaim {
                path: element_path,
                disclosure: index,
            });
        }
        Ok(out)
    }
}

/// What a key binding JWT asserts (RFC 9901 §4.3): the verifier it is for, the nonce of the
/// transaction and when it was made; `sd_hash` is computed when the SD-JWT is signed.
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::sd_jwt_vc::KeyBinding;
///
/// let binding = KeyBinding::new(
///     "https://verifier.example.org",
///     "1234567890",
///     Utc.timestamp_opt(1748536865, 0).unwrap(),
/// );
/// let claims = binding.claims("fMV05vuMARs3uG0Dg0BYd_7mQR9EGBkRof0cTZyuqXE".to_owned());
/// assert_eq!(claims.iat, Some(1748536865));
/// assert_eq!(claims.additional["nonce"], "1234567890");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyBinding {
    /// `aud`: the verifier the presentation is for.
    pub audience: String,
    /// `nonce`: the value binding the presentation to the transaction.
    pub nonce: String,
    /// `iat`: when the key binding JWT is issued.
    pub issued_at: i64,
    /// Further claims.
    pub additional: IndexMap<String, Value>,
}

impl KeyBinding {
    /// A key binding for `audience` with `nonce`, issued at `issued_at`.
    pub fn new(
        audience: impl Into<String>,
        nonce: impl Into<String>,
        issued_at: DateTime<Utc>,
    ) -> Self {
        Self {
            audience: audience.into(),
            nonce: nonce.into(),
            issued_at: JwtClaims::numeric_date(issued_at),
            additional: IndexMap::new(),
        }
    }

    /// This binding with the claim `name` set to `value`.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.additional.insert(name.into(), value.into());
        self
    }

    /// The claims set of the key binding JWT, with `sd_hash`.
    pub fn claims(&self, sd_hash: String) -> JwtClaims {
        let mut claims = JwtClaims::new().with_aud(self.audience.clone());
        claims.iat = Some(self.issued_at);
        claims
            .additional
            .insert("nonce".to_owned(), Value::String(self.nonce.clone()));
        claims
            .additional
            .insert("sd_hash".to_owned(), Value::String(sd_hash));
        claims.additional.extend(self.additional.clone());
        claims
    }
}
