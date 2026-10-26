//! [`StatusListCheck`]: the Token Status List as a [`StatusCheck`], over an [`HttpClient`].

use chrono::{DateTime, Utc};
use url::Url;

use crate::jose::{DefaultVerifier, JwsVerifier};
use crate::methods::web::{HttpClient, HttpResponse};
use crate::resolver::{KeyReference, KeyResolver, KeyRole};
use crate::vc::Jwt;
use crate::vc::validation::{CredentialStatus, StatusCheck, StatusError};

use super::{StatusListError, StatusListToken, StatusMechanism};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A [`StatusCheck`] for the Token Status List: for the `status` claim of an SD-JWT
/// credential or of a JWT credential ([`CredentialStatus::StatusClaim`]), fetches the status
/// list token from the referenced URI with an [`HttpClient`], verifies it was signed by
/// the key its header names ([`KeyReference::from_jws`] with the token's `iss`), resolved
/// for [`KeyRole::Issuer`], and reads the status at the referenced index (Token Status
/// List §8).
///
/// When the token has an `iss`, the key must belong to it ([`KeyReference::binds_to`]);
/// without one, only a key named by a DID URL is accepted, since a key by value or a key
/// set could be anybody's. Beyond that the check trusts the key the reference resolves
/// to; whether that key may speak for the list is the application's policy to enforce
/// around it, by restricting the resolver, say.
///
/// # Fetching
///
/// Every request asks for `application/statuslist+jwt` ([`StatusListToken::MEDIA_TYPE`])
/// through [`HttpClient::get_accepting`]. `ReqwestClient` (feature `reqwest`) also
/// negotiates gzip, which the draft recommends Status Providers use.
///
/// A 301, 302, 303, 307 or 308 response is followed, as the draft recommends: its
/// [`location`](HttpResponse::location) is resolved against the URL
/// that returned it and fetched with a new request through the same client, so that every
/// hop passes the client's checks. The check refuses a target that is not `https`, a URL
/// already visited (a loop), a redirect without a `Location`, and more than
/// [`MAX_REDIRECTS`](Self::MAX_REDIRECTS) redirects.
///
/// The status list URI comes from the credential, and a redirect target from whoever serves
/// it, so the client fetches whatever an issuer names: `client` must enforce the protections
/// `ReqwestClient` does (HTTPS only, no redirects of its own, no non-public addresses after
/// name resolution, a body limit and a timeout), or the status check becomes a request
/// forgery primitive.
pub struct StatusListCheck<C, R, V = DefaultVerifier> {
    client: C,
    resolver: R,
    verifier: V,
}

impl<C, R, V> StatusListCheck<C, R, V> {
    /// The most redirects one status list fetch follows.
    pub const MAX_REDIRECTS: usize = 3;
}

impl<C: HttpClient, R: KeyResolver, V: JwsVerifier> StatusListCheck<C, R, V> {
    /// A check fetching with `client`, resolving the status issuer's key with `resolver`
    /// and verifying with `verifier`.
    pub fn new(client: C, resolver: R, verifier: V) -> Self {
        Self {
            client,
            resolver,
            verifier,
        }
    }

    /// The response for `uri`, following redirects as the type documentation describes.
    async fn get(&self, uri: &str) -> Result<HttpResponse, StatusError> {
        let unavailable = |reason: String, source: Option<BoxError>| StatusError::Unavailable {
            uri: uri.to_owned(),
            reason,
            source,
        };
        let mut url = Url::parse(uri).map_err(|e| StatusError::InvalidList {
            uri: uri.to_owned(),
            reason: "the URI is not a URL".to_owned(),
            source: Some(Box::new(e)),
        })?;
        let mut visited = vec![url.clone()];
        loop {
            let response = self
                .client
                .get_accepting(&url, StatusListToken::MEDIA_TYPE)
                .await
                .map_err(|e| unavailable(format!("fetching {url}"), Some(Box::new(e))))?;
            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            if visited.len() > Self::MAX_REDIRECTS {
                return Err(unavailable(
                    format!("more than {} redirects", Self::MAX_REDIRECTS),
                    None,
                ));
            }
            let location = response.location.ok_or_else(|| {
                unavailable(
                    format!(
                        "{url} answered HTTP {} without a `Location`",
                        response.status
                    ),
                    None,
                )
            })?;
            let next = url.join(&location).map_err(|e| {
                unavailable(
                    format!("redirect from {url} to {location:?}"),
                    Some(Box::new(e)),
                )
            })?;
            if next.scheme() != "https" {
                return Err(unavailable(
                    format!("redirect from {url} to {next}, which is not HTTPS"),
                    None,
                ));
            }
            if visited.contains(&next) {
                return Err(unavailable(format!("redirect loop at {next}"), None));
            }
            visited.push(next.clone());
            url = next;
        }
    }

    /// The status list token at `uri`, fetched and verified.
    async fn fetch(&self, uri: &str) -> Result<StatusListToken, StatusError> {
        let invalid = |reason: &str, source: Option<BoxError>| StatusError::InvalidList {
            uri: uri.to_owned(),
            reason: reason.to_owned(),
            source,
        };
        let response = self.get(uri).await?;
        if !(200..300).contains(&response.status) {
            return Err(StatusError::Unavailable {
                uri: uri.to_owned(),
                reason: format!("HTTP {}", response.status),
                source: None,
            });
        }
        let body = String::from_utf8(response.body)
            .map_err(|e| invalid("the body is not UTF-8", Some(Box::new(e))))?;
        let not_a_token = |e: BoxError| invalid("not a status list token", Some(e));
        let jwt = Jwt::new(body.trim()).map_err(|e| not_a_token(Box::new(e)))?;
        let (_, token) = StatusListToken::decode(&jwt).map_err(|e| not_a_token(Box::new(e)))?;
        let jws = jwt.decode().map_err(|e| not_a_token(Box::new(e)))?;
        let iss = token.additional.get("iss").and_then(|iss| iss.as_str());
        let reference = KeyReference::from_jws(&jws, iss)
            .map_err(|e| invalid("no key to verify it with", Some(Box::new(e))))?;
        let key = self
            .resolver
            .resolve_key(&reference, KeyRole::Issuer)
            .await
            .map_err(|e| StatusError::UnresolvedKey {
                uri: uri.to_owned(),
                key: reference.to_string(),
                source: e,
            })?;
        jws.verify(&self.verifier, &key)
            .map_err(|e| invalid("the signature does not verify", Some(Box::new(e))))?;
        let bound = match iss {
            Some(iss) => reference.binds_to(Some(iss), &key),
            None => matches!(reference, KeyReference::DidUrl(_)),
        };
        if !bound {
            return Err(invalid(
                &format!("key {reference} does not belong to the issuer {iss:?}"),
                None,
            ));
        }
        Ok(token)
    }
}

#[async_trait::async_trait]
impl<C: HttpClient, R: KeyResolver, V: JwsVerifier> StatusCheck for StatusListCheck<C, R, V> {
    /// Checks the Token Status List reference of a `status` claim; a `credentialStatus`
    /// entry, or a `status` claim without one, is [`StatusError::Unsupported`].
    async fn check(
        &self,
        status: CredentialStatus<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), StatusError> {
        let CredentialStatus::StatusClaim(status) = status else {
            return Err(StatusError::Unsupported(status.mechanism()));
        };
        let Some(reference) = &status.status_list else {
            let names: Vec<&str> = status
                .mechanisms()
                .filter_map(|m| match m {
                    StatusMechanism::Other { name, .. } => Some(name),
                    _ => None,
                })
                .collect();
            return Err(StatusError::Unsupported(names.join(", ")));
        };
        let uri = &reference.uri;
        let token = self.fetch(uri).await?;
        let status_type = token.status_of(reference, now).map_err(|e| match e {
            StatusListError::Expired { expired_at, now } => StatusError::Expired {
                uri: uri.clone(),
                expired_at,
                now,
            },
            StatusListError::IndexOutOfRange { idx, len } => StatusError::IndexOutOfRange {
                uri: uri.clone(),
                idx,
                len,
            },
            other => StatusError::InvalidList {
                uri: uri.clone(),
                reason: "it does not cover the reference".to_owned(),
                source: Some(Box::new(other)),
            },
        })?;
        if status_type.is_valid() {
            Ok(())
        } else {
            Err(StatusError::Invalid(status_type.to_string()))
        }
    }
}

impl<C: core::fmt::Debug, R: core::fmt::Debug, V: core::fmt::Debug> core::fmt::Debug
    for StatusListCheck<C, R, V>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatusListCheck")
            .field("client", &self.client)
            .field("resolver", &self.resolver)
            .field("verifier", &self.verifier)
            .finish()
    }
}
