//! `ReqwestClient`: the hardened default `HttpClient`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use url::{Host, Url};

use super::{HttpClient, HttpError, HttpResponse};

/// An [`HttpClient`] over [`reqwest`] hardened for fetching DID documents from the public web.
///
/// [`ReqwestClient::new`] builds a client that:
///
/// - speaks HTTPS only, with the platform's root certificates and `rustls`;
/// - follows no redirect, so a document is fetched from the URL its DID maps to and nowhere
///   else;
/// - resolves host names itself and refuses loopback, private, link-local and other
///   non-public addresses, so a DID cannot point the resolver at internal services;
/// - stops reading a body over [`DEFAULT_MAX_BODY`](Self::DEFAULT_MAX_BODY) bytes;
/// - times out after [`DEFAULT_TIMEOUT`](Self::DEFAULT_TIMEOUT).
///
/// [`ReqwestClient::from_client`] wraps a client the application configured itself, keeping
/// only the HTTPS-only rule, the refusal of non-public IP literals and the body limit; the
/// other protections are then the application's.
#[derive(Debug, Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
    max_body: usize,
}

impl ReqwestClient {
    /// The largest body [`new`](Self::new) reads: 1 MiB, far above any DID document.
    pub const DEFAULT_MAX_BODY: usize = 1 << 20;

    /// The request timeout of [`new`](Self::new).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// A hardened client with the defaults above.
    ///
    /// # Errors
    ///
    /// [`HttpError`] when the TLS backend cannot be initialized.
    pub fn new() -> Result<Self, HttpError> {
        // Make `ring` the process default when nothing chose a provider yet; a provider another
        // part of the application installed is kept.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::new(PublicAddresses))
            .timeout(Self::DEFAULT_TIMEOUT)
            .user_agent(concat!("identity-kit/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(HttpError::new)?;
        Ok(Self {
            client,
            max_body: Self::DEFAULT_MAX_BODY,
        })
    }

    /// A client over `client` as the application configured it, still HTTPS-only, refusing
    /// non-public IP literals, and reading at most [`DEFAULT_MAX_BODY`](Self::DEFAULT_MAX_BODY)
    /// bytes of body.
    pub const fn from_client(client: reqwest::Client) -> Self {
        Self {
            client,
            max_body: Self::DEFAULT_MAX_BODY,
        }
    }

    /// This client reading at most `max_body` bytes of body.
    #[must_use]
    pub const fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// The body limit.
    pub const fn max_body(&self) -> usize {
        self.max_body
    }

    /// The underlying client.
    pub const fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
        if url.scheme() != "https" {
            return Err(HttpError::msg(format!("`{url}` is not an HTTPS URL")));
        }
        // An IP literal never reaches the DNS resolver, so it is checked here.
        let literal = match url.host() {
            Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        };
        if literal.is_some_and(|ip| !is_public(ip)) {
            return Err(HttpError::msg(format!("`{url}` is not a public address")));
        }
        let mut response = self
            .client
            .get(url.as_str())
            .send()
            .await
            .map_err(HttpError::new)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|len| len > self.max_body as u64)
        {
            return Err(HttpError::msg(format!(
                "response body exceeds {} bytes",
                self.max_body
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(HttpError::new)? {
            if body.len() + chunk.len() > self.max_body {
                return Err(HttpError::msg(format!(
                    "response body exceeds {} bytes",
                    self.max_body
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse::new(status, body))
    }
}

/// A DNS resolver that keeps only public addresses.
struct PublicAddresses;

impl reqwest::dns::Resolve for PublicAddresses {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|address| is_public(address.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(format!("`{host}` resolves to no public address").into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Whether `ip` is a globally routable unicast address: not loopback, private, link-local,
/// unspecified, multicast, broadcast, documentation or otherwise reserved.
pub(crate) fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || (a == 100 && (64..=127).contains(&b)) // shared address space, RFC 6598
                || (a == 192 && b == 0 && v4.octets()[2] == 0) // IETF protocol assignments
                || (a == 198 && (18..=19).contains(&b)) // benchmarking, RFC 2544
                || a >= 240) // reserved and broadcast
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || segments[0] == 0x2001 && segments[1] == 0x0db8 // documentation
                || segments[0] == 0x0064 && segments[1] == 0xff9b) // NAT64 well-known prefix
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses() {
        for public in [
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
            "1.1.1.1",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
        for private in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "198.51.100.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b::7f00:1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
    }
}
