//! `JwksResolver`: the keys of an HTTPS issuer, from its JWT VC issuer metadata.

use core::fmt;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::{KeyReference, KeyResolutionError, KeyResolver, KeyRole};
use crate::jose::Jwk;
use crate::methods::web::{HttpClient, HttpError};

/// Resolves a [`KeyReference::Jwks`] through the JWT VC issuer metadata of the issuer (SD-JWT VC
/// §3.5); every other reference is [`Unsupported`](KeyResolutionError::Unsupported).
///
/// For an issuer `https://host[:port][/path]` it fetches
/// `https://host[:port]/.well-known/jwt-vc-issuer[/path]` (a trailing `/` of the path dropped),
/// requires the metadata's `issuer` to be the issuer, takes its `jwks`, or fetches its
/// `jwks_uri`, and returns the one key whose `kid` is the reference's. Issuer and `jwks_uri`
/// must be `https`, and the issuer has no query, fragment or credentials. The key set of an
/// issuer is cached for a time to live ([`DEFAULT_TTL`](Self::DEFAULT_TTL) unless set with
/// [`with_ttl`](Self::with_ttl)), so a rotated key is found once its entry expires.
///
/// The issuer comes from the token, so the client fetches whatever a token names: `client` must
/// enforce the protections `ReqwestClient` (feature `reqwest`) does (HTTPS only, no redirects,
/// no non-public addresses after name resolution, a body limit and a timeout), or resolution
/// becomes a request forgery primitive. Resolving says nothing about whether the issuer is
/// trusted; that stays the application's policy.
///
/// # Examples
///
/// ```
/// use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
/// use identity_kit::resolver::{JwksResolver, KeyReference, KeyResolver as _, KeyRole};
/// use url::Url;
///
/// /// Serves the metadata of `https://example.com/issuer`.
/// struct Served;
///
/// #[async_trait::async_trait]
/// impl HttpClient for Served {
///     async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
///         assert_eq!(url.as_str(), "https://example.com/.well-known/jwt-vc-issuer/issuer");
///         Ok(HttpResponse::new(200, r#"{
///           "issuer": "https://example.com/issuer",
///           "jwks": { "keys": [{
///             "kid": "key-1", "kty": "OKP", "crv": "Ed25519",
///             "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
///           }]}
///         }"#))
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let resolver = JwksResolver::new(Served);
/// let reference = KeyReference::Jwks {
///     issuer: Url::parse("https://example.com/issuer")?,
///     kid: "key-1".to_owned(),
/// };
/// let key = resolver.resolve_key(&reference, KeyRole::Issuer).await?;
/// assert_eq!(key.crv(), Some("Ed25519"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct JwksResolver<C> {
    client: C,
    ttl: Duration,
    capacity: usize,
    cache: RwLock<HashMap<Url, Entry>>,
}

/// The key set of one issuer and when it expires.
struct Entry {
    keys: Arc<[Value]>,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

/// The members of JWT VC issuer metadata this resolver reads.
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    #[serde(default)]
    jwks: Option<KeySet>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

/// A JWK set (RFC 7517 §5), its keys left as JSON so that a key of a type this crate does not
/// read does not spoil the others.
#[derive(Deserialize)]
struct KeySet {
    keys: Vec<Value>,
}

impl<C> JwksResolver<C> {
    /// How long [`new`](Self::new) keeps an issuer's key set: five minutes.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

    /// How many issuers [`new`](Self::new) keeps key sets of.
    pub const DEFAULT_CAPACITY: usize = 256;

    /// A resolver fetching with `client`, keeping key sets for
    /// [`DEFAULT_TTL`](Self::DEFAULT_TTL).
    pub fn new(client: C) -> Self {
        Self {
            client,
            ttl: Self::DEFAULT_TTL,
            capacity: Self::DEFAULT_CAPACITY,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// This resolver keeping key sets for `ttl`; zero keeps none.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// This resolver keeping the key sets of at most `capacity` issuers (at least one).
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// How long a key set is kept.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The HTTP client.
    pub fn client(&self) -> &C {
        &self.client
    }

    /// The cached key set of `issuer`, if live.
    fn cached(&self, issuer: &Url) -> Option<Arc<[Value]>> {
        let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(issuer)
            .filter(|entry| entry.is_live(Instant::now()))
            .map(|entry| Arc::clone(&entry.keys))
    }

    /// Keeps `keys` as the key set of `issuer`, evicting expired entries and then the one that
    /// expires soonest when full.
    fn store(&self, issuer: &Url, keys: Arc<[Value]>) {
        if self.ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        if !cache.contains_key(issuer) && cache.len() >= self.capacity {
            cache.retain(|_, entry| entry.is_live(now));
            if cache.len() >= self.capacity
                && let Some(soonest) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires_at)
                    .map(|(issuer, _)| issuer.clone())
            {
                cache.remove(&soonest);
            }
        }
        cache.insert(
            issuer.clone(),
            Entry {
                keys,
                expires_at: now.checked_add(self.ttl),
            },
        );
    }
}

impl<C: HttpClient> JwksResolver<C> {
    /// The key set of `issuer`, from the cache or fetched.
    async fn key_set(&self, issuer: &Url) -> Result<Arc<[Value]>, JwksError> {
        if let Some(keys) = self.cached(issuer) {
            return Ok(keys);
        }
        let url = metadata_url(issuer)?;
        let metadata: Metadata = self.fetch_json(&url).await?;
        if Url::parse(&metadata.issuer).ok().as_ref() != Some(issuer) {
            return Err(JwksError::IssuerMismatch {
                expected: issuer.clone(),
                found: metadata.issuer,
            });
        }
        let keys = match (metadata.jwks, metadata.jwks_uri) {
            (Some(jwks), None) => jwks.keys,
            (None, Some(jwks_uri)) => {
                let jwks_uri = Url::parse(&jwks_uri).map_err(|e| JwksError::InvalidMetadata {
                    url: url.clone(),
                    reason: format!("`jwks_uri` {jwks_uri:?}: {e}"),
                })?;
                if jwks_uri.scheme() != "https" {
                    return Err(JwksError::NotHttps(jwks_uri));
                }
                self.fetch_json::<KeySet>(&jwks_uri).await?.keys
            }
            (Some(_), Some(_)) => {
                return Err(JwksError::InvalidMetadata {
                    url,
                    reason: "both `jwks` and `jwks_uri` are present".to_owned(),
                });
            }
            (None, None) => {
                return Err(JwksError::InvalidMetadata {
                    url,
                    reason: "neither `jwks` nor `jwks_uri` is present".to_owned(),
                });
            }
        };
        let keys: Arc<[Value]> = keys.into();
        self.store(issuer, Arc::clone(&keys));
        Ok(keys)
    }

    /// The JSON body at `url`, parsed.
    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &Url) -> Result<T, JwksError> {
        let response = self
            .client
            .get(url)
            .await
            .map_err(|source| JwksError::Http {
                url: url.clone(),
                source,
            })?;
        if !(200..300).contains(&response.status) {
            return Err(JwksError::HttpStatus {
                url: url.clone(),
                status: response.status,
            });
        }
        serde_json::from_slice(&response.body).map_err(|e| JwksError::InvalidMetadata {
            url: url.clone(),
            reason: e.to_string(),
        })
    }
}

/// `https://host[:port]/.well-known/jwt-vc-issuer[/path]` for `issuer`.
fn metadata_url(issuer: &Url) -> Result<Url, JwksError> {
    if issuer.scheme() != "https" {
        return Err(JwksError::NotHttps(issuer.clone()));
    }
    if issuer.query().is_some()
        || issuer.fragment().is_some()
        || issuer.host().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
    {
        return Err(JwksError::InvalidIssuer(issuer.clone()));
    }
    let path = issuer.path().trim_end_matches('/');
    let mut url = issuer.clone();
    url.set_path(&format!("/.well-known/jwt-vc-issuer{path}"));
    Ok(url)
}

/// The one key of `keys` whose `kid` is `kid`, as a public JWK.
fn select(keys: &[Value], issuer: &Url, kid: &str) -> Result<Jwk, JwksError> {
    let mut matching = keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid));
    let key = matching.next().ok_or_else(|| JwksError::UnknownKid {
        issuer: issuer.clone(),
        kid: kid.to_owned(),
    })?;
    if matching.next().is_some() {
        return Err(JwksError::DuplicateKid {
            issuer: issuer.clone(),
            kid: kid.to_owned(),
        });
    }
    let jwk: Jwk = serde_json::from_value(key.clone()).map_err(|e| JwksError::InvalidKey {
        kid: kid.to_owned(),
        reason: e.to_string(),
    })?;
    if jwk.is_private() {
        return Err(JwksError::InvalidKey {
            kid: kid.to_owned(),
            reason: "the key set publishes private material".to_owned(),
        });
    }
    Ok(jwk)
}

impl<C> fmt::Debug for JwksResolver<C>
where
    C: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwksResolver")
            .field("client", &self.client)
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl<C: HttpClient> KeyResolver for JwksResolver<C> {
    async fn resolve_key(&self, key: &KeyReference, _: KeyRole) -> Result<Jwk, KeyResolutionError> {
        let KeyReference::Jwks { issuer, kid } = key else {
            return Err(KeyResolutionError::unsupported(key));
        };
        let keys = self.key_set(issuer).await?;
        Ok(select(&keys, issuer, kid)?)
    }
}

/// Why a [`JwksResolver`] found no key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// The issuer or `jwks_uri` is not an `https` URL.
    #[error("`{0}` is not an HTTPS URL")]
    NotHttps(Url),
    /// The issuer has a query, a fragment or credentials, or no host.
    #[error(
        "`{0}` is not an issuer identifier: it has a query, a fragment or credentials, or no host"
    )]
    InvalidIssuer(Url),
    /// The [`HttpClient`] got no response.
    #[error("fetching `{url}` failed: {source}")]
    Http {
        /// The URL fetched.
        url: Url,
        /// Why there was no response.
        #[source]
        source: HttpError,
    },
    /// The server answered with a status other than `2xx`.
    #[error("fetching `{url}` returned HTTP {status}")]
    HttpStatus {
        /// The URL fetched.
        url: Url,
        /// The status code.
        status: u16,
    },
    /// The metadata or key set is not what SD-JWT VC §3.5 and RFC 7517 §5 describe.
    #[error("`{url}`: {reason}")]
    InvalidMetadata {
        /// The URL fetched.
        url: Url,
        /// What is wrong with the body.
        reason: String,
    },
    /// The metadata names another issuer.
    #[error("the metadata of `{expected}` names the issuer {found:?}")]
    IssuerMismatch {
        /// The issuer whose metadata was fetched.
        expected: Url,
        /// The `issuer` the metadata names.
        found: String,
    },
    /// No key of the issuer has the `kid`.
    #[error("issuer `{issuer}` has no key `{kid}`")]
    UnknownKid {
        /// The issuer.
        issuer: Url,
        /// The `kid`.
        kid: String,
    },
    /// Several keys of the issuer have the `kid`, so it names none of them.
    #[error("issuer `{issuer}` has several keys `{kid}`")]
    DuplicateKid {
        /// The issuer.
        issuer: Url,
        /// The `kid`.
        kid: String,
    },
    /// The key is not a public JWK this crate reads.
    #[error("key `{kid}`: {reason}")]
    InvalidKey {
        /// The `kid`.
        kid: String,
        /// What is wrong with it.
        reason: String,
    },
}

impl From<JwksError> for KeyResolutionError {
    fn from(error: JwksError) -> Self {
        Self::new(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_expires_at_its_instant() {
        let now = Instant::now();
        let entry = Entry {
            keys: Arc::from([]),
            expires_at: Some(now),
        };
        assert!(entry.is_live(now - Duration::from_nanos(1)));
        assert!(!entry.is_live(now));
    }
}
