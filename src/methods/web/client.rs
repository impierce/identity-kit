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
///   else: a 3xx response is returned with its `Location` in [`HttpResponse::location`], for a
///   caller that follows redirects to fetch each target through this client again;
/// - sends `Accept` when asked through [`HttpClient::get_accepting`], and
///   `Accept-Encoding: gzip`, decoding a gzip-encoded body;
/// - resolves host names itself and refuses loopback, private, link-local and other
///   non-public addresses, so a DID cannot point the resolver at internal services;
/// - uses no proxy, whatever `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` or the platform's
///   settings say: a proxy resolves the host itself, so it would reach the addresses refused
///   above;
/// - stops reading a body over [`DEFAULT_MAX_BODY`](Self::DEFAULT_MAX_BODY) bytes, counted
///   after decoding, so a small compressed body cannot expand past the limit;
/// - times out after [`DEFAULT_TIMEOUT`](Self::DEFAULT_TIMEOUT).
///
/// [`ReqwestClient::from_client`] wraps a client the application configured itself, keeping
/// only the HTTPS-only rule, the refusal of non-public IP literals and the body limit; the
/// other protections are then the application's. That is also how to fetch through an egress
/// proxy: configure it on that client, and have the proxy refuse non-public targets, since it
/// resolves the host names.
///
/// # Local development and tests
///
/// With the feature `local-network`, [`ReqwestClient::builder`] can let a client reach
/// a `did:web` served from the local machine or a private network, such as a test server on
/// `127.0.0.1` or a development deployment in a docker-compose network. It is for
/// development and tests only; enable the feature under `[dev-dependencies]`, or behind a
/// feature of the application's own, so that a release build does not contain it.
///
/// - [`dangerous_allow_loopback`](ReqwestClientBuilder::dangerous_allow_loopback) allows
///   `127.0.0.0/8` and `::1`, and
///   [`dangerous_allow_private_network`](ReqwestClientBuilder::dangerous_allow_private_network)
///   allows RFC 1918 and `fc00::/7`. Neither takes a `bool`: the choice is made in code.
/// - The client resolves the host first. When every address is in an allowed range, it fetches
///   the URL over plain `http`, on the port the URL names (443 when it names none), connecting
///   to exactly the addresses it checked. Otherwise the rules above apply unchanged: a host with
///   public and local addresses is held to them.
/// - Link-local addresses (including cloud metadata endpoints such as `169.254.169.254`) and
///   every other non-public range stay refused; redirects, the timeout and the body limit are
///   unchanged.
#[derive(Debug, Clone)]
pub struct ReqwestClient {
    client: reqwest::Client,
    max_body: usize,
    #[cfg(feature = "local-network")]
    local: LocalNetwork,
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
            .no_proxy()
            .timeout(Self::DEFAULT_TIMEOUT)
            .user_agent(concat!("identity-kit/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(HttpError::new)?;
        Ok(Self {
            client,
            max_body: Self::DEFAULT_MAX_BODY,
            #[cfg(feature = "local-network")]
            local: LocalNetwork::NONE,
        })
    }

    /// A client over `client` as the application configured it, still HTTPS-only, refusing
    /// non-public IP literals, and reading at most [`DEFAULT_MAX_BODY`](Self::DEFAULT_MAX_BODY)
    /// bytes of body.
    ///
    /// Host names are resolved as `client` resolves them, so refusing the non-public
    /// addresses they resolve to is the application's: with a DNS resolver like the one
    /// [`new`](Self::new) installs, and, when `client` uses a proxy, by the proxy itself,
    /// which resolves the host names it is asked to reach.
    pub const fn from_client(client: reqwest::Client) -> Self {
        Self {
            client,
            max_body: Self::DEFAULT_MAX_BODY,
            #[cfg(feature = "local-network")]
            local: LocalNetwork::NONE,
        }
    }

    /// A builder for a client that may also reach the local network, for development and
    /// tests; see [Local development and tests](Self#local-development-and-tests).
    #[cfg(feature = "local-network")]
    #[cfg_attr(docsrs, doc(cfg(feature = "local-network")))]
    pub const fn builder() -> ReqwestClientBuilder {
        ReqwestClientBuilder {
            local: LocalNetwork::NONE,
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
        self.fetch(url, None).await
    }

    async fn get_accepting(&self, url: &Url, media_type: &str) -> Result<HttpResponse, HttpError> {
        self.fetch(url, Some(media_type)).await
    }
}

impl ReqwestClient {
    /// Fetches `url`, sending `accept` as the `Accept` header when given.
    async fn fetch(&self, url: &Url, accept: Option<&str>) -> Result<HttpResponse, HttpError> {
        #[cfg(feature = "local-network")]
        if let Some(response) = self.get_local(url, accept).await? {
            return Ok(response);
        }
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
        let response = request(&self.client, url, accept)
            .send()
            .await
            .map_err(HttpError::new)?;
        read(response, self.max_body).await
    }
}

/// A `GET` of `url` with `accept` as the `Accept` header, when given.
fn request(client: &reqwest::Client, url: &Url, accept: Option<&str>) -> reqwest::RequestBuilder {
    let request = client.get(url.as_str());
    match accept {
        Some(media_type) => request.header(reqwest::header::ACCEPT, media_type),
        None => request,
    }
}

/// The status, the `Location` of a redirect and at most `max_body` bytes of decoded body of
/// `response`.
async fn read(mut response: reqwest::Response, max_body: usize) -> Result<HttpResponse, HttpError> {
    let status = response.status().as_u16();
    let location = if response.status().is_redirection() {
        response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|location| location.to_str().ok())
            .map(str::to_owned)
    } else {
        None
    };
    if response
        .content_length()
        .is_some_and(|len| len > max_body as u64)
    {
        return Err(HttpError::msg(format!(
            "response body exceeds {max_body} bytes"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(HttpError::new)? {
        if body.len() + chunk.len() > max_body {
            return Err(HttpError::msg(format!(
                "response body exceeds {max_body} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    let response = HttpResponse::new(status, body);
    Ok(match location {
        Some(location) => response.with_location(location),
        None => response,
    })
}

#[cfg(feature = "local-network")]
pub use local::{LocalNetwork, ReqwestClientBuilder};

#[cfg(feature = "local-network")]
mod local {
    use std::net::{IpAddr, SocketAddr};

    use url::{Host, Url};

    use super::{HttpError, HttpResponse, ReqwestClient, is_public, read, request};

    /// The local address ranges a [`ReqwestClient`] may reach besides the public internet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct LocalNetwork {
        /// `127.0.0.0/8` and `::1`.
        pub loopback: bool,
        /// RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and `fc00::/7`.
        pub private: bool,
    }

    impl LocalNetwork {
        /// No local range: the public rules only.
        pub const NONE: Self = Self {
            loopback: false,
            private: false,
        };

        /// Whether `ip` is in one of the allowed local ranges. Link-local and every other
        /// non-public range never are.
        pub fn allows(&self, ip: IpAddr) -> bool {
            let ip = match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
                IpAddr::V4(_) => ip,
            };
            let loopback = ip.is_loopback();
            let private = match ip {
                IpAddr::V4(v4) => v4.is_private(),
                IpAddr::V6(v6) => v6.is_unique_local(),
            };
            (self.loopback && loopback) || (self.private && private)
        }

        /// Whether every one of `addresses`, of which there is at least one, is in an allowed
        /// local range: the host is fetched over plain `http`. Otherwise the public rules
        /// apply.
        pub fn all_local(&self, addresses: &[IpAddr]) -> bool {
            !addresses.is_empty() && addresses.iter().all(|ip| self.allows(*ip))
        }
    }

    /// Builds a [`ReqwestClient`] that may also reach the local network, for development and
    /// tests; see [Local development and tests](ReqwestClient#local-development-and-tests).
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::methods::web::ReqwestClient;
    ///
    /// let client = ReqwestClient::builder().dangerous_allow_loopback().build()?;
    /// assert!(client.local_network().loopback && !client.local_network().private);
    /// # Ok::<(), identity_kit::methods::web::HttpError>(())
    /// ```
    #[derive(Debug, Clone)]
    #[must_use]
    pub struct ReqwestClientBuilder {
        pub(super) local: LocalNetwork,
    }

    impl ReqwestClientBuilder {
        /// Lets the client reach `127.0.0.0/8` and `::1` over plain `http`. For development
        /// and tests only.
        pub const fn dangerous_allow_loopback(mut self) -> Self {
            self.local.loopback = true;
            self
        }

        /// Lets the client reach RFC 1918 addresses and `fc00::/7` over plain `http`. For
        /// development and tests only.
        pub const fn dangerous_allow_private_network(mut self) -> Self {
            self.local.private = true;
            self
        }

        /// The client: [`ReqwestClient::new`] plus the local ranges allowed here.
        ///
        /// # Errors
        ///
        /// [`HttpError`] when the TLS backend cannot be initialized.
        pub fn build(self) -> Result<ReqwestClient, HttpError> {
            let mut client = ReqwestClient::new()?;
            client.local = self.local;
            Ok(client)
        }
    }

    impl ReqwestClient {
        /// The local ranges this client may reach; [`LocalNetwork::NONE`] unless built with
        /// [`ReqwestClient::builder`].
        pub const fn local_network(&self) -> LocalNetwork {
            self.local
        }

        /// Fetches `url` over plain `http` when every address of its host is in an allowed
        /// local range; `None` when the public rules apply.
        pub(super) async fn get_local(
            &self,
            url: &Url,
            accept: Option<&str>,
        ) -> Result<Option<HttpResponse>, HttpError> {
            if self.local == LocalNetwork::NONE || !matches!(url.scheme(), "https" | "http") {
                return Ok(None);
            }
            // An `http` or `https` URL always has a host and a port.
            let port = url.port_or_known_default().unwrap_or(443);
            let host = url.host().expect("an `http` or `https` URL has a host");
            let (name, addresses): (Option<&str>, Vec<IpAddr>) = match host {
                Host::Ipv4(ip) => (None, vec![IpAddr::V4(ip)]),
                Host::Ipv6(ip) => (None, vec![IpAddr::V6(ip)]),
                Host::Domain(name) => {
                    let addresses = tokio::net::lookup_host((name, port))
                        .await
                        .map_err(HttpError::new)?
                        .map(|address| address.ip())
                        .collect();
                    (Some(name), addresses)
                }
            };
            if !self.local.all_local(&addresses) {
                return Ok(None);
            }
            debug_assert!(addresses.iter().all(|ip| !is_public(*ip)));
            let target = plain_http(url, port);
            let mut builder = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(ReqwestClient::DEFAULT_TIMEOUT)
                .user_agent(concat!("identity-kit/", env!("CARGO_PKG_VERSION")));
            if let Some(name) = name {
                let pinned: Vec<SocketAddr> = addresses
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, port))
                    .collect();
                builder = builder.resolve_to_addrs(name, &pinned);
            }
            let client = builder.build().map_err(HttpError::new)?;
            let response = request(&client, &target, accept)
                .send()
                .await
                .map_err(HttpError::new)?;
            read(response, self.max_body).await.map(Some)
        }
    }

    /// `url` with the `http` scheme on `port`, the port the URL names or the `https` default it
    /// implies.
    pub(super) fn plain_http(url: &Url, port: u16) -> Url {
        let mut target = url.clone();
        // Scheme first: `set_port` drops a port equal to the current scheme's default, so 443
        // set while the URL is still `https` would leave `http` on port 80.
        target
            .set_scheme("http")
            .expect("an `http` or `https` URL can be `http`");
        target
            .set_port(Some(port))
            .expect("a URL with a host takes a port");
        target
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

    #[cfg(feature = "local-network")]
    #[test]
    fn plain_http_keeps_the_port() {
        for (url, port, expected) in [
            // No port: the `https` default, 443, which `http` must name explicitly.
            (
                "https://localhost/.well-known/did.json",
                443,
                "http://localhost:443/.well-known/did.json",
            ),
            (
                "https://issuer/user/alice/did.json",
                443,
                "http://issuer:443/user/alice/did.json",
            ),
            (
                "https://127.0.0.1/did.json",
                443,
                "http://127.0.0.1:443/did.json",
            ),
            ("https://[::1]/did.json", 443, "http://[::1]:443/did.json"),
            // An explicit port is kept, including 80.
            (
                "https://localhost:8443/did.json",
                8443,
                "http://localhost:8443/did.json",
            ),
            (
                "https://localhost:80/did.json",
                80,
                "http://localhost/did.json",
            ),
            // A plain `http` URL is unchanged.
            (
                "http://localhost:8080/did.json",
                8080,
                "http://localhost:8080/did.json",
            ),
            ("http://localhost/did.json", 80, "http://localhost/did.json"),
        ] {
            let url = url::Url::parse(url).unwrap();
            let rewritten = local::plain_http(&url, port);
            assert_eq!(rewritten.as_str(), expected, "{url}");
            assert_eq!(rewritten.port_or_known_default(), Some(port), "{url}");
        }
    }

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
