//! Issuing an SD-JWT: choosing which claims are selectively disclosable (RFC 9901 §4.2).

use core::fmt;

use serde_json::{Map, Value};

use super::sd_jwt::{ELLIPSIS_KEY, SD_KEY};
use super::{ClaimPath, Disclosure, HashAlgorithm, SdJwt, SdJwtError};
use crate::jose::{JwsHeader, Signer, base64url, encode_compact};

/// Turns a claims set into an SD-JWT payload and its disclosures: the claims at the paths
/// given to [`conceal`](Self::conceal) are replaced by digests, children before parents, so
/// that concealing a claim and a claim inside it yields recursive disclosures.
///
/// Salts are 128 bits from the operating system's random number generator unless
/// [`with_salt_generator`](Self::with_salt_generator) substitutes a source; decoy digests,
/// when asked for, are added to every `_sd` array, which is then sorted.
///
/// # Examples
///
/// The structure of RFC 9901 §6.3: `address` is selectively disclosable, and so is each of its
/// members.
///
/// ```
/// use identity_kit::sd_jwt_vc::SdJwtBuilder;
/// use serde_json::json;
///
/// let claims = json!({
///   "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
///   "address": {
///     "street_address": "Schulstr. 12",
///     "locality": "Schulpforta",
///     "region": "Sachsen-Anhalt",
///     "country": "DE"
///   }
/// });
/// let encoded = SdJwtBuilder::new(claims.as_object().unwrap().clone())
///     .conceal(["address"])
///     .conceal(["address", "street_address"])
///     .conceal(["address", "locality"])
///     .conceal(["address", "region"])
///     .conceal(["address", "country"])
///     .encode()?;
/// assert_eq!(encoded.disclosures.len(), 5);
/// assert_eq!(encoded.payload["_sd"].as_array().unwrap().len(), 1);
/// assert_eq!(encoded.payload["_sd_alg"], "sha-256");
/// assert!(!encoded.payload.contains_key("address"));
/// let address = encoded.disclosures.iter().find(|d| d.name() == Some("address")).unwrap();
/// assert_eq!(address.value()["_sd"].as_array().unwrap().len(), 4);
/// # Ok::<(), identity_kit::sd_jwt_vc::SdJwtError>(())
/// ```
pub struct SdJwtBuilder {
    claims: Map<String, Value>,
    concealed: Vec<ClaimPath>,
    decoys: usize,
    alg: HashAlgorithm,
    salts: Box<dyn FnMut() -> String + Send>,
}

impl SdJwtBuilder {
    /// The deepest nesting of objects and arrays [`encode`](Self::encode) accepts, counting the
    /// claims set itself: a claim value may sit inside 63 more containers.
    ///
    /// The parsers of this crate read at most 128 nested containers (serde_json's default),
    /// and concealment, disclosures and the payload add a few around a claim value, so a
    /// claims set within this limit always processes back; one beyond it might not.
    /// [`SdJwt::process`](super::SdJwt::process) enforces the same limit on the claims it
    /// reassembles from the payload and the disclosures.
    pub const MAX_DEPTH: usize = 64;

    /// A builder over `claims`, nothing concealed yet.
    pub fn new(claims: Map<String, Value>) -> Self {
        Self {
            claims,
            concealed: Vec::new(),
            decoys: 0,
            alg: HashAlgorithm::default(),
            salts: Box::new(random_salt),
        }
    }

    /// This builder concealing the claim at `path`: an object property or an array element,
    /// with `()` in the path standing for every element of an array.
    #[must_use]
    pub fn conceal(mut self, path: impl Into<ClaimPath>) -> Self {
        self.concealed.push(path.into());
        self
    }

    /// This builder adding `count` decoy digests to every `_sd` array.
    #[must_use]
    pub fn with_decoys(mut self, count: usize) -> Self {
        self.decoys = count;
        self
    }

    /// This builder hashing with `alg`.
    #[must_use]
    pub fn with_hash_algorithm(mut self, alg: HashAlgorithm) -> Self {
        self.alg = alg;
        self
    }

    /// This builder taking its salts from `salts`, one call per disclosure and decoy, in
    /// document order with the members of an object or array before the object or array
    /// itself.
    #[must_use]
    pub fn with_salt_generator(mut self, salts: impl FnMut() -> String + Send + 'static) -> Self {
        self.salts = Box::new(salts);
        self
    }

    /// The claims.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The paths to conceal.
    pub fn concealed(&self) -> &[ClaimPath] {
        &self.concealed
    }

    /// The payload and the disclosures, unsigned.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::NoSuchClaim`] when a path selects nothing, [`SdJwtError::NotConcealable`]
    /// for `_sd` or `...`, [`SdJwtError::Payload`] when the claims already use `_sd` or
    /// `_sd_alg`, [`SdJwtError::TooDeep`] when they nest deeper than
    /// [`MAX_DEPTH`](Self::MAX_DEPTH).
    pub fn encode(mut self) -> Result<Encoded, SdJwtError> {
        if self.claims.contains_key(HashAlgorithm::CLAIM) {
            return Err(SdJwtError::payload("the claims already carry `_sd_alg`"));
        }
        if self
            .claims
            .values()
            .any(|value| nests_deeper_than(value, Self::MAX_DEPTH - 1))
        {
            return Err(SdJwtError::TooDeep {
                max: Self::MAX_DEPTH,
            });
        }
        let mut matched = vec![false; self.concealed.len()];
        let mut disclosures = Vec::new();
        let mut payload = self.object(
            self.claims.clone(),
            &ClaimPath::root(),
            &mut matched,
            &mut disclosures,
        )?;
        if let Some(unmatched) = matched.iter().position(|m| !m) {
            return Err(SdJwtError::NoSuchClaim(self.concealed[unmatched].clone()));
        }
        if !disclosures.is_empty() || payload.contains_key(SD_KEY) {
            payload.insert(
                HashAlgorithm::CLAIM.to_owned(),
                Value::String(self.alg.name().to_owned()),
            );
        }
        Ok(Encoded {
            payload,
            disclosures,
        })
    }

    /// The SD-JWT: the payload signed under `header` with `signer`, with every disclosure.
    ///
    /// # Errors
    ///
    /// As [`encode`](Self::encode), or [`SdJwtError::Jws`] when signing fails.
    pub async fn sign(self, header: &JwsHeader, signer: &dyn Signer) -> Result<SdJwt, SdJwtError> {
        let encoded = self.encode()?;
        let payload = serde_json::to_vec(&encoded.payload).expect("a JSON object serializes");
        let jwt = encode_compact(header, &payload, signer).await?;
        Ok(SdJwt::new(
            crate::vc::Jwt::new(jwt).expect("a freshly encoded JWS decodes"),
            encoded.disclosures,
        ))
    }

    /// Whether `path` is to be concealed, marking the pattern that matched it.
    fn is_concealed(&self, path: &ClaimPath, matched: &mut [bool]) -> bool {
        let mut concealed = false;
        for (i, pattern) in self.concealed.iter().enumerate() {
            if pattern.matches(path) {
                matched[i] = true;
                concealed = true;
            }
        }
        concealed
    }

    fn value(
        &mut self,
        value: Value,
        path: &ClaimPath,
        matched: &mut [bool],
        disclosures: &mut Vec<Disclosure>,
    ) -> Result<Value, SdJwtError> {
        match value {
            Value::Object(object) => self
                .object(object, path, matched, disclosures)
                .map(Value::Object),
            Value::Array(array) => self
                .array(array, path, matched, disclosures)
                .map(Value::Array),
            other => Ok(other),
        }
    }

    fn object(
        &mut self,
        object: Map<String, Value>,
        path: &ClaimPath,
        matched: &mut [bool],
        disclosures: &mut Vec<Disclosure>,
    ) -> Result<Map<String, Value>, SdJwtError> {
        if object.contains_key(SD_KEY) {
            return Err(SdJwtError::payload(format!(
                "the object at {path} already carries `_sd`"
            )));
        }
        let mut out = Map::new();
        let mut digests = Vec::new();
        for (name, value) in object {
            let child = path.join(name.as_str());
            let value = self.value(value, &child, matched, disclosures)?;
            if !self.is_concealed(&child, matched) {
                out.insert(name, value);
                continue;
            }
            if name == SD_KEY || name == ELLIPSIS_KEY {
                return Err(SdJwtError::NotConcealable {
                    path: child,
                    reason: format!("`{name}` is reserved"),
                });
            }
            let disclosure = Disclosure::property((self.salts)(), name, value);
            digests.push(disclosure.digest(self.alg));
            disclosures.push(disclosure);
        }
        if !digests.is_empty() {
            for _ in 0..self.decoys {
                digests.push(self.alg.digest((self.salts)().as_bytes()));
            }
            digests.sort_unstable();
            out.insert(
                SD_KEY.to_owned(),
                Value::Array(digests.into_iter().map(Value::String).collect()),
            );
        }
        Ok(out)
    }

    fn array(
        &mut self,
        array: Vec<Value>,
        path: &ClaimPath,
        matched: &mut [bool],
        disclosures: &mut Vec<Disclosure>,
    ) -> Result<Vec<Value>, SdJwtError> {
        let mut out = Vec::with_capacity(array.len());
        for (i, element) in array.into_iter().enumerate() {
            let child = path.join(i);
            let element = self.value(element, &child, matched, disclosures)?;
            if !self.is_concealed(&child, matched) {
                out.push(element);
                continue;
            }
            let disclosure = Disclosure::element((self.salts)(), element);
            let mut placeholder = Map::new();
            placeholder.insert(
                ELLIPSIS_KEY.to_owned(),
                Value::String(disclosure.digest(self.alg)),
            );
            disclosures.push(disclosure);
            out.push(Value::Object(placeholder));
        }
        Ok(out)
    }
}

impl fmt::Debug for SdJwtBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtBuilder")
            .field("claims", &self.claims)
            .field("concealed", &self.concealed)
            .field("decoys", &self.decoys)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

/// 128 bits of operating system randomness, base64url-encoded.
pub(super) fn random_salt() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    base64url::encode(&bytes)
}

/// The output of [`SdJwtBuilder::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Encoded {
    /// The issuer-signed JWT payload, digests in place, with `_sd_alg` when anything is
    /// concealed.
    pub payload: Map<String, Value>,
    /// The disclosures, in the order their claims were concealed.
    pub disclosures: Vec<Disclosure>,
}

/// Whether `value` nests more than `limit` containers deep, descending no further than that:
/// a value built in memory may nest far deeper than any parser of this crate reads, and the
/// walk must not be what overflows the stack on it.
fn nests_deeper_than(value: &Value, limit: usize) -> bool {
    match value {
        Value::Array(items) => {
            limit == 0 || items.iter().any(|item| nests_deeper_than(item, limit - 1))
        }
        Value::Object(members) => {
            limit == 0
                || members
                    .values()
                    .any(|member| nests_deeper_than(member, limit - 1))
        }
        _ => false,
    }
}
