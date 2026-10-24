//! Specification vectors for `did:web`: the DID to URL mapping examples of the did:web method
//! specification, its Read operation over an in-file `HttpClient`, and the hardened default
//! client's refusals.
#![cfg(feature = "did-web")]

use std::collections::HashMap;
use std::error::Error as _;
use std::sync::Mutex;

use identity_kit::did::{Did, DidUrl, ResolutionErrorKind, ResolutionOptions};
use identity_kit::jose::Jwk;
use identity_kit::methods::DidWeb;
use identity_kit::methods::web::{
    HttpClient, HttpError, HttpResponse, WebError, did_from_origin, did_from_url, document_url,
};
use identity_kit::resolver::{DidProducer, DidResolver, Hosting, ProduceError, Resolver};
use serde_json::{Value, json};
use url::Url;

/// did:web specification, first example. (The specification's JSON has a trailing comma after
/// the last verification method, removed here.)
const EXAMPLE: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "id": "did:web:example.com#key-0",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU"
      }
    },
    {
      "id": "did:web:example.com#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k"
      }
    },
    {
      "id": "did:web:example.com#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
        "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
      }
    }
  ],
  "authentication": [
    "did:web:example.com#key-0",
    "did:web:example.com#key-2"
  ],
  "assertionMethod": [
    "did:web:example.com#key-0",
    "did:web:example.com#key-2"
  ],
  "keyAgreement": [
    "did:web:example.com#key-1",
    "did:web:example.com#key-2"
  ]
}"#;

fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

/// Serves canned responses and records the URLs asked for.
#[derive(Default)]
struct Mock {
    responses: HashMap<String, Result<HttpResponse, String>>,
    calls: Mutex<Vec<String>>,
}

impl Mock {
    fn serving(url: &str, status: u16, body: &str) -> Self {
        let mut mock = Self::default();
        mock.responses.insert(
            url.to_owned(),
            Ok(HttpResponse::new(status, body.as_bytes())),
        );
        mock
    }

    fn failing(url: &str, message: &str) -> Self {
        let mut mock = Self::default();
        mock.responses
            .insert(url.to_owned(), Err(message.to_owned()));
        mock
    }
}

#[async_trait::async_trait]
impl HttpClient for Mock {
    async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
        self.calls.lock().unwrap().push(url.to_string());
        match self.responses.get(url.as_str()) {
            Some(Ok(response)) => Ok(response.clone()),
            Some(Err(message)) => Err(HttpError::msg(message)),
            None => Ok(HttpResponse::new(404, Vec::new())),
        }
    }
}

/// A client that answers with the media type it was asked for.
struct Echo;

#[async_trait::async_trait]
impl HttpClient for Echo {
    async fn get(&self, _: &Url) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse::new(200, "no media type"))
    }

    async fn get_accepting(&self, _: &Url, media_type: &str) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse::new(200, media_type))
    }
}

#[tokio::test]
async fn get_accepting_is_forwarded_and_defaults_to_get() {
    let target = url("https://example.com/statuslists/1");
    let accept = "application/statuslist+jwt";
    // `&T`, `Box<T>` and `Arc<T>` pass the media type on, rather than falling back to `get`.
    async fn ask<C: HttpClient>(client: C, url: &Url, accept: &str) -> String {
        let response = client.get_accepting(url, accept).await.unwrap();
        String::from_utf8(response.body).unwrap()
    }
    assert_eq!(ask(Echo, &target, accept).await, accept);
    assert_eq!(ask(&Echo, &target, accept).await, accept);
    assert_eq!(ask(Box::new(Echo), &target, accept).await, accept);
    let boxed: Box<dyn HttpClient> = Box::new(Echo);
    assert_eq!(ask(boxed, &target, accept).await, accept);
    assert_eq!(
        ask(std::sync::Arc::new(Echo), &target, accept).await,
        accept
    );

    // A client implementing `get` only answers `get_accepting` with it.
    let mock = Mock::serving(target.as_str(), 200, "{}");
    assert_eq!(
        mock.get_accepting(&target, accept).await.unwrap(),
        mock.get(&target).await.unwrap()
    );
    assert_eq!(mock.calls.lock().unwrap().len(), 2);

    // A redirect carries its target; nothing else does.
    let moved = HttpResponse::new(302, Vec::new()).with_location("/statuslists/2");
    assert_eq!(moved.location.as_deref(), Some("/statuslists/2"));
    assert_eq!(HttpResponse::new(200, Vec::new()).location, None);
}

#[test]
fn did_to_url_mapping_examples() {
    // did:web specification, "Create" and "Optional Path Considerations".
    for (did_str, url_str) in [
        (
            "did:web:w3c-ccg.github.io",
            "https://w3c-ccg.github.io/.well-known/did.json",
        ),
        (
            "did:web:w3c-ccg.github.io:user:alice",
            "https://w3c-ccg.github.io/user/alice/did.json",
        ),
        (
            "did:web:example.com%3A3000:user:alice",
            "https://example.com:3000/user/alice/did.json",
        ),
        (
            "did:web:example.com:u:bob",
            "https://example.com/u/bob/did.json",
        ),
        (
            "did:web:example.com",
            "https://example.com/.well-known/did.json",
        ),
    ] {
        assert_eq!(document_url(&did(did_str)).unwrap().as_str(), url_str);
        // The document URL maps back to the DID, and so does the location it was built from.
        assert_eq!(
            did_from_url(&url(url_str)).unwrap(),
            did(did_str),
            "{url_str}"
        );
        let location = url_str.strip_suffix("/did.json").unwrap();
        let location = location.strip_suffix("/.well-known").unwrap_or(location);
        assert_eq!(
            did_from_url(&url(location)).unwrap(),
            did(did_str),
            "{url_str}"
        );
    }
    // Percent-decoding other than the port colon is harmless.
    assert_eq!(
        document_url(&did("did:web:example%2Ecom%3a443:a"))
            .unwrap()
            .as_str(),
        "https://example.com/a/did.json"
    );
}

#[test]
fn url_to_did() {
    assert_eq!(
        did_from_url(&url("https://example.com:443/")).unwrap(),
        did("did:web:example.com")
    );
    assert_eq!(
        did_from_url(&url("https://example.com/user/alice/")).unwrap(),
        did("did:web:example.com:user:alice")
    );
    assert_eq!(
        did_from_url(&url("https://EXAMPLE.com")).unwrap(),
        did("did:web:example.com")
    );
    assert_eq!(
        did_from_url(&url("https://example.com/a%20b/c~d/e!f/g%zz")).unwrap(),
        did("did:web:example.com:a%20b:c%7Ed:e%21f:g%25zz")
    );
    // Only the file name at the end is dropped: `.well-known` elsewhere is a path segment.
    assert_eq!(
        did_from_url(&url("https://example.com/.well-known/x/did.json")).unwrap(),
        did("did:web:example.com:.well-known:x")
    );
    assert_eq!(
        did_from_url(&url("https://example.com/did.json/x")).unwrap(),
        did("did:web:example.com:did.json:x")
    );
    assert_eq!(
        did_from_origin(&url("https://example.com")).unwrap(),
        did("did:web:example.com")
    );
    for (bad, reason) in [
        ("http://example.com", "the scheme must be `https`"),
        (
            "https://192.0.2.1/",
            "the host must be a domain name, not an IP address",
        ),
        (
            "https://[::1]/",
            "the host must be a domain name, not an IP address",
        ),
        (
            "https://user:pw@example.com/",
            "the URL must not carry credentials",
        ),
        (
            "https://user@example.com/",
            "the URL must not carry credentials",
        ),
        (
            "https://example.com/?q",
            "the URL must not have a query or a fragment",
        ),
        (
            "https://example.com/#f",
            "the URL must not have a query or a fragment",
        ),
        ("https://example.com/a//b", "the path has an empty segment"),
        (
            "https://ex_ample.com/",
            "the host has characters a DID cannot carry",
        ),
    ] {
        assert_eq!(
            did_from_url(&url(bad)),
            Err(WebError::InvalidUrl {
                url: url(bad),
                reason,
            }),
            "{bad}"
        );
    }
    assert_eq!(
        did_from_origin(&url("https://example.com/path")),
        Err(WebError::InvalidUrl {
            url: url("https://example.com/path"),
            reason: "an origin has no path",
        })
    );
    assert_eq!(
        did_from_url(&url("http://example.com"))
            .unwrap_err()
            .to_string(),
        "`http://example.com/` cannot be a did:web: the scheme must be `https`"
    );
}

#[test]
fn did_to_url_rejections() {
    for (bad, reason) in [
        (
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "the method is not `web`",
        ),
        ("did:web:192.0.2.1", "the host is an IP address"),
        ("did:web:1.2.3", "the host is an IP address"),
        ("did:web:%5B%3A%3A1%5D", "the host is not a domain name"),
        (
            "did:web:example.com%2Fadmin",
            "the host is not a domain name",
        ),
        (
            "did:web:example.com%3A443%40evil.com",
            "the port is not a number",
        ),
        (
            "did:web:example.com%40evil.com",
            "the host is not a domain name",
        ),
        ("did:web:example.com%3Fx", "the host is not a domain name"),
        ("did:web:example.com%3A", "the port is not a number"),
        ("did:web:example.com%3Aabc", "the port is not a number"),
        ("did:web:example.com%3A123456", "the port is not a number"),
        (
            "did:web:example.com::x",
            "a path segment is empty, `.` or `..`",
        ),
        (
            "did:web:example.com:..:x",
            "a path segment is empty, `.` or `..`",
        ),
        (
            "did:web:example.com:.",
            "a path segment is empty, `.` or `..`",
        ),
        // The URL parser reads `%2E` as `.` in a path segment and collapses the dot segments,
        // so these would name a document outside the path the DID spells.
        (
            "did:web:example.com:a:%2E%2E:b",
            "a path segment is empty, `.` or `..`",
        ),
        (
            "did:web:example.com:a:.%2e:b",
            "a path segment is empty, `.` or `..`",
        ),
        (
            "did:web:example.com:a:%2E.:b",
            "a path segment is empty, `.` or `..`",
        ),
        (
            "did:web:example.com:%2E",
            "a path segment is empty, `.` or `..`",
        ),
        (
            "did:web:%2E%2E-2Edid:web:%2E%2E",
            "a path segment is empty, `.` or `..`",
        ),
    ] {
        assert_eq!(
            document_url(&did(bad)),
            Err(WebError::InvalidDid {
                did: did(bad),
                reason,
            }),
            "{bad}"
        );
    }
    assert_eq!(
        document_url(&did("did:web:192.0.2.1"))
            .unwrap_err()
            .to_string(),
        "`did:web:192.0.2.1` is not a valid did:web: the host is an IP address"
    );
}

#[tokio::test]
async fn read_operation() {
    let mock = Mock::serving("https://example.com/.well-known/did.json", 200, EXAMPLE);
    let method = DidWeb::new(mock);
    assert_eq!(DidResolver::method(&method), "web");
    let resolver = Resolver::builder().with(method).build();
    let did = did("did:web:example.com");
    let document = resolver.resolve_document(&did).await.unwrap();
    let expected: Value = serde_json::from_str(EXAMPLE).unwrap();
    assert_eq!(serde_json::to_value(&document).unwrap(), expected);

    let key = DidUrl::parse("did:web:example.com#key-0").unwrap();
    let jwk = resolver.resolve_public_key(&key, None).await.unwrap();
    assert_eq!(jwk.crv(), Some("Ed25519"));
    let key_agreement = DidUrl::parse("did:web:example.com#key-1").unwrap();
    assert_eq!(
        resolver
            .resolve_public_key(&key_agreement, None)
            .await
            .unwrap()
            .crv(),
        Some("X25519")
    );

    let web = resolver.resolver("web").unwrap();
    assert_eq!(
        web.resolve(&did, &ResolutionOptions::accept("application/did+cbor"))
            .await,
        Err(ResolutionErrorKind::RepresentationNotSupported.into())
    );
}

/// What a failed `did:web` resolution says about its cause, besides its keyword.
enum Cause {
    /// The detail is exactly this text, and there is no source.
    Detail(&'static str),
    /// The source is the client's `HttpError`, with this message.
    Http(&'static str),
    /// The source is the `serde_json::Error` of the body.
    Json,
}

#[tokio::test]
async fn read_operation_failures() {
    let url = "https://example.com/.well-known/did.json";
    let example = did("did:web:example.com");
    let other = r#"{"id": "did:web:example.org"}"#;
    let status = |code: u16| match code {
        404 => "`https://example.com/.well-known/did.json` responded with HTTP status 404",
        410 => "`https://example.com/.well-known/did.json` responded with HTTP status 410",
        500 => "`https://example.com/.well-known/did.json` responded with HTTP status 500",
        301 => "`https://example.com/.well-known/did.json` responded with HTTP status 301",
        _ => unreachable!(),
    };
    for (mock, kind, cause) in [
        (
            Mock::serving(url, 404, ""),
            ResolutionErrorKind::NotFound,
            Cause::Detail(status(404)),
        ),
        (
            Mock::serving(url, 410, ""),
            ResolutionErrorKind::NotFound,
            Cause::Detail(status(410)),
        ),
        (
            Mock::serving(url, 500, ""),
            ResolutionErrorKind::InternalError,
            Cause::Detail(status(500)),
        ),
        (
            Mock::serving(url, 301, ""),
            ResolutionErrorKind::InternalError,
            Cause::Detail(status(301)),
        ),
        (
            Mock::failing(url, "connection refused"),
            ResolutionErrorKind::InternalError,
            Cause::Http("connection refused"),
        ),
        (
            Mock::failing(url, "`https://example.com/` is not a public address"),
            ResolutionErrorKind::InternalError,
            Cause::Http("`https://example.com/` is not a public address"),
        ),
        (
            Mock::serving(url, 200, "<html>"),
            ResolutionErrorKind::InvalidDidDocument,
            Cause::Json,
        ),
        (
            Mock::serving(url, 200, "{}"),
            ResolutionErrorKind::InvalidDidDocument,
            Cause::Json,
        ),
        (
            Mock::serving(url, 200, other),
            ResolutionErrorKind::InvalidDidDocument,
            Cause::Detail(
                "`https://example.com/.well-known/did.json` holds the document of \
                 `did:web:example.org`, not `did:web:example.com`",
            ),
        ),
        (
            Mock::serving("https://example.com/did.json", 200, EXAMPLE),
            ResolutionErrorKind::NotFound,
            Cause::Detail(status(404)),
        ),
    ] {
        let method = DidWeb::new(mock);
        let error = method
            .resolve(&example, &ResolutionOptions::default())
            .await
            .unwrap_err();
        assert_eq!(error, kind);
        assert_eq!(method.client().calls.lock().unwrap().len(), 1);
        match cause {
            Cause::Detail(detail) => {
                assert_eq!(error.detail(), Some(detail));
                assert!(error.source().is_none(), "{error}");
                assert_eq!(error.to_string(), format!("{kind}: {detail}"));
            }
            Cause::Http(message) => {
                let source = error.source().unwrap().downcast_ref::<HttpError>();
                assert_eq!(source.unwrap().to_string(), message);
                assert_eq!(
                    error.to_string(),
                    format!("internal resolver error: fetching `{url}` failed: {message}")
                );
            }
            Cause::Json => {
                let source = error.source().unwrap();
                assert!(source.is::<serde_json::Error>(), "{error}");
                assert_eq!(
                    error.detail(),
                    Some(
                        "the body of `https://example.com/.well-known/did.json` is not a DID document"
                    )
                );
            }
        }
    }
    // A DID without a document URL never reaches the client.
    let method = DidWeb::new(Mock::default());
    let error = method
        .resolve(&did("did:web:192.0.2.1"), &ResolutionOptions::default())
        .await
        .unwrap_err();
    assert_eq!(error, ResolutionErrorKind::InvalidDid);
    assert!(error.source().unwrap().is::<WebError>(), "{error}");
    assert!(method.client().calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn produce_the_document_to_publish() {
    let method = DidWeb::new(Mock::default());
    assert_eq!(DidProducer::method(&method), "web");
    let capabilities = method.capabilities();
    assert_eq!(capabilities.hosting, Hosting::Web);
    assert!(capabilities.updatable && !capabilities.single_key);
    assert_eq!(capabilities.fixed_fragment, None);

    let keys: Vec<Jwk> = [
        json!({"kty": "OKP", "crv": "Ed25519", "x": "0-e2i2_Ua1S5HbTYnVB0lj2Z2ytXu2-tYmDFf8f5NjU"}),
        json!({"kty": "OKP", "crv": "X25519", "x": "9GXjPGGvmRq9F6Ng5dQQ_s31mfhxrcNZxRGONrmH30k"}),
        json!({"kty": "EC", "crv": "P-256", "use": "enc", "kid": "agreement",
               "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
               "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"}),
    ]
    .into_iter()
    .map(|value| serde_json::from_value(value).unwrap())
    .collect();
    let document = method
        .produce(&keys, url("https://example.com/user/alice"))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&document).unwrap(),
        json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            "id": "did:web:example.com:user:alice",
            "verificationMethod": [
                {
                    "id": "did:web:example.com:user:alice#key-0",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:example.com:user:alice",
                    "publicKeyJwk": keys[0]
                },
                {
                    "id": "did:web:example.com:user:alice#key-1",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:example.com:user:alice",
                    "publicKeyJwk": keys[1]
                },
                {
                    "id": "did:web:example.com:user:alice#agreement",
                    "type": "JsonWebKey2020",
                    "controller": "did:web:example.com:user:alice",
                    "publicKeyJwk": keys[2]
                }
            ],
            "authentication": ["did:web:example.com:user:alice#key-0"],
            "assertionMethod": ["did:web:example.com:user:alice#key-0"],
            "keyAgreement": ["did:web:example.com:user:alice#key-1", "did:web:example.com:user:alice#agreement"],
            "capabilityInvocation": ["did:web:example.com:user:alice#key-0"],
            "capabilityDelegation": ["did:web:example.com:user:alice#key-0"]
        })
    );
    // The produced document resolves through the method it was made for.
    let served = serde_json::to_string(&document).unwrap();
    let resolver = Resolver::builder()
        .with(DidWeb::new(Mock::serving(
            "https://example.com/user/alice/did.json",
            200,
            &served,
        )))
        .build();
    assert_eq!(
        resolver.resolve_document(&document.id).await.unwrap(),
        document
    );

    // Private parameters are stripped.
    let private: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "kid": "k",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }))
    .unwrap();
    let document = method
        .produce(std::slice::from_ref(&private), url("https://example.com"))
        .await
        .unwrap();
    assert_eq!(
        document.verification_method[0].public_key_jwk(),
        Some(&private.public())
    );
    assert_eq!(document.verification_method[0].id.fragment(), Some("k"));

    assert!(matches!(
        method.produce(&[], url("https://example.com")).await,
        Err(ProduceError::NoKeys)
    ));
    assert!(matches!(
        method.produce(&keys, url("http://example.com")).await,
        Err(ProduceError::InvalidParams(_))
    ));
    assert!(matches!(
        method
            .produce(
                &[private.clone(), private.clone()],
                url("https://example.com")
            )
            .await,
        Err(ProduceError::Document(_))
    ));
    let bad_kid = private.clone().with_kid("a b");
    assert!(matches!(
        method.produce(&[bad_kid], url("https://example.com")).await,
        Err(ProduceError::UnsupportedKey { index: 0, .. })
    ));
}

#[test]
fn http_error_wraps_any_error() {
    let error = HttpError::new(std::io::Error::other("boom"));
    assert_eq!(error.to_string(), "boom");
    assert_eq!(error.inner().to_string(), "boom");
    let boxed: Box<dyn std::error::Error + Send + Sync> = "nope".into();
    assert_eq!(HttpError::from(boxed).to_string(), "nope");
    assert_eq!(
        HttpResponse::new(200, "body"),
        HttpResponse::new(200, b"body".to_vec())
    );
}

#[cfg(feature = "reqwest")]
mod reqwest_client {
    use identity_kit::methods::web::ReqwestClient;

    use super::*;

    #[tokio::test]
    async fn refuses_what_a_did_must_not_reach() {
        let client = ReqwestClient::new().unwrap();
        assert_eq!(client.max_body(), ReqwestClient::DEFAULT_MAX_BODY);
        let client = client.with_max_body(1024);
        assert_eq!(client.max_body(), 1024);
        for (refused, reason) in [
            (
                "http://example.com/.well-known/did.json",
                "not an HTTPS URL",
            ),
            (
                "https://127.0.0.1/.well-known/did.json",
                "not a public address",
            ),
            ("https://[::1]/.well-known/did.json", "not a public address"),
            (
                "https://10.0.0.1/.well-known/did.json",
                "not a public address",
            ),
            (
                "https://169.254.169.254/latest/meta-data",
                "not a public address",
            ),
            (
                "https://localhost/.well-known/did.json",
                "no public address",
            ),
        ] {
            let error = client.get(&url(refused)).await.unwrap_err();
            let message = format!("{error}: {:?}", std::error::Error::source(&error));
            assert!(message.contains(reason), "{refused}: {message}");
        }
    }

    /// `new` uses no proxy, whatever the environment says: a proxy resolves the host itself,
    /// so it would reach the addresses the client refuses. Setting this process's environment
    /// would need `unsafe` and race with the other tests, so the test runs itself again as a
    /// child process whose proxy variables all point at a listener here.
    #[tokio::test]
    async fn ignores_proxies_from_the_environment() {
        const CHILD: &str = "IDENTITY_KIT_TEST_PROXY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // `localhost` has no public address, so a direct fetch fails before connecting;
            // through the proxy, the proxy would be asked for `localhost:443` instead.
            let error = ReqwestClient::new()
                .unwrap()
                .get(&url("https://localhost/.well-known/did.json"))
                .await
                .unwrap_err();
            let message = format!("{error}: {:?}", std::error::Error::source(&error));
            assert!(message.contains("no public address"), "{message}");
            return;
        }

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        // The test's path inside this test binary, without the binary's own name.
        let (_, module) = module_path!().split_once("::").unwrap();
        let name = format!("{module}::ignores_proxies_from_the_environment");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args([name.as_str(), "--exact", "--nocapture"]);
        command.env(CHILD, "1");
        for variable in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
            command.env(variable, &proxy);
            command.env(variable.to_lowercase(), &proxy);
        }
        command.env_remove("NO_PROXY").env_remove("no_proxy");
        let output = command.output().unwrap();
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // The child must have run the test, not filtered it out.
        assert!(
            output.status.success() && report.contains("1 passed"),
            "{report}"
        );
        assert!(
            listener
                .accept()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
            "the client connected to the proxy"
        );
    }

    #[tokio::test]
    async fn default_methods_register_everything() {
        let resolver =
            identity_kit::methods::default_methods(ReqwestClient::new().unwrap()).build();
        let mut methods = vec!["web"];
        if cfg!(feature = "did-key") {
            methods.push("key");
        }
        if cfg!(feature = "did-jwk") {
            methods.push("jwk");
        }
        methods.sort_unstable();
        assert_eq!(resolver.methods(), methods);
        let wrapped = ReqwestClient::from_client(reqwest::Client::new());
        assert_eq!(wrapped.max_body(), ReqwestClient::DEFAULT_MAX_BODY);
        let _ = wrapped.client();
    }
}

/// The local-network opt-in exists for development and tests only, so no other feature may
/// switch it on.
#[test]
fn local_network_is_never_enabled_by_another_feature() {
    let manifest = include_str!("../Cargo.toml");
    let features = manifest
        .split("[features]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .unwrap();
    for line in features.lines() {
        if line.starts_with('#') || line.starts_with("local-network =") {
            continue;
        }
        assert!(!line.contains("local-network"), "{line}");
    }
}

#[cfg(feature = "local-network")]
mod local_network {
    use std::net::IpAddr;

    use identity_kit::methods::web::{LocalNetwork, ReqwestClient};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn sends_the_media_type_and_decodes_gzip() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/statuslists/1"))
            .and(header("accept", "application/statuslist+jwt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(gzip(b"a compressed body")),
            )
            .mount(&server)
            .await;
        let target = url(&format!(
            "https://127.0.0.1:{}/statuslists/1",
            server.address().port()
        ));
        let client = loopback();
        let response = client
            .get_accepting(&target, "application/statuslist+jwt")
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"a compressed body");
        let requests = server.received_requests().await.unwrap();
        let headers = &requests[0].headers;
        assert_eq!(headers["accept"], "application/statuslist+jwt");
        assert!(
            headers["accept-encoding"]
                .to_str()
                .unwrap()
                .contains("gzip")
        );
        // `get` asks for no media type in particular, so the server's mock does not match.
        assert_eq!(client.get(&target).await.unwrap().status, 404);
        assert_eq!(
            server.received_requests().await.unwrap()[1].headers["accept"],
            "*/*"
        );
    }

    #[tokio::test]
    async fn the_body_limit_counts_decoded_bytes() {
        let server = MockServer::start().await;
        let expanding = gzip(&[b'a'; 4096]);
        assert!(expanding.len() < 100, "{}", expanding.len());
        Mock::given(method("GET"))
            .and(path("/expanding"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(expanding),
            )
            .mount(&server)
            .await;
        let target = url(&format!(
            "https://127.0.0.1:{}/expanding",
            server.address().port()
        ));
        // A hundred bytes on the wire, four thousand once decoded.
        let error = loopback()
            .with_max_body(1000)
            .get(&target)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 1000 bytes"), "{error}");
        let response = loopback().with_max_body(4096).get(&target).await.unwrap();
        assert_eq!(response.body, [b'a'; 4096]);
    }

    #[tokio::test]
    async fn a_redirect_is_returned_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/moved"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/statuslists/1"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/created"))
            .respond_with(ResponseTemplate::new(201).insert_header("location", "/statuslists/1"))
            .mount(&server)
            .await;
        let port = server.address().port();
        let client = loopback();
        let response = client
            .get(&url(&format!("https://127.0.0.1:{port}/moved")))
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        assert_eq!(response.location.as_deref(), Some("/statuslists/1"));
        let response = client
            .get(&url(&format!("https://127.0.0.1:{port}/created")))
            .await
            .unwrap();
        assert_eq!((response.status, response.location), (201, None));
        // Two requests: the redirect target was not fetched.
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.url.path() != "/statuslists/1"));
    }

    fn loopback() -> ReqwestClient {
        ReqwestClient::builder()
            .dangerous_allow_loopback()
            .build()
            .unwrap()
    }

    fn everything_local() -> ReqwestClient {
        ReqwestClient::builder()
            .dangerous_allow_loopback()
            .dangerous_allow_private_network()
            .build()
            .unwrap()
    }

    /// A server on `127.0.0.1` serving the document of `did:web:localhost%3A<port>`.
    async fn serving_a_document() -> (MockServer, Did) {
        let server = MockServer::start().await;
        let did = did(&format!("did:web:localhost%3A{}", server.address().port()));
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": did.as_str() })))
            .mount(&server)
            .await;
        (server, did)
    }

    #[tokio::test]
    async fn did_web_on_localhost() {
        let (server, did) = serving_a_document().await;

        let refusing = Resolver::builder()
            .with(DidWeb::new(ReqwestClient::new().unwrap()))
            .build();
        assert!(refusing.resolve_document(&did).await.is_err());
        assert!(server.received_requests().await.unwrap().is_empty());

        let client = loopback();
        assert_eq!(
            client.local_network(),
            ReqwestClient::builder()
                .dangerous_allow_loopback()
                .build()
                .unwrap()
                .local_network()
        );
        let resolver = Resolver::builder()
            .with(DidWeb::new(client.clone()))
            .build();
        assert_eq!(resolver.resolve_document(&did).await.unwrap().id, did);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.scheme(), "http");

        // An IP literal is fetched the same way, and the body limit still holds.
        let literal = url(&format!(
            "https://127.0.0.1:{}/.well-known/did.json",
            server.address().port()
        ));
        assert_eq!(client.get(&literal).await.unwrap().status, 200);
        let error = client.with_max_body(4).get(&literal).await.unwrap_err();
        assert!(error.to_string().contains("exceeds 4 bytes"), "{error}");
    }

    #[tokio::test]
    async fn a_streamed_body_is_limited_too() {
        // A body without `Content-Length`, sent in chunks, is counted as it arrives.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                      5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let error = loopback()
            .with_max_body(6)
            .get(&url(&format!(
                "https://127.0.0.1:{port}/.well-known/did.json"
            )))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 6 bytes"), "{error}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/did.json"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere"))
            .mount(&server)
            .await;
        let response = loopback()
            .get(&url(&format!(
                "https://localhost:{}/.well-known/did.json",
                server.address().port()
            )))
            .await
            .unwrap();
        assert_eq!(response.status, 302);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "the redirect target is never requested");
    }

    #[tokio::test]
    async fn what_stays_refused() {
        // Each of these is decided before any connection is attempted.
        for (client, refused, reason) in [
            // A private address needs its own opt-in.
            (
                loopback(),
                "https://10.0.0.1/.well-known/did.json",
                "not a public address",
            ),
            (
                loopback(),
                "http://192.168.1.1/.well-known/did.json",
                "not an HTTPS URL",
            ),
            // Link-local, including cloud metadata endpoints, in every mode.
            (
                everything_local(),
                "https://169.254.169.254/latest/meta-data",
                "not a public address",
            ),
            (
                everything_local(),
                "http://169.254.169.254/latest/meta-data",
                "not an HTTPS URL",
            ),
            (
                everything_local(),
                "https://[fe80::1]/.well-known/did.json",
                "not a public address",
            ),
            // The other non-public ranges.
            (
                everything_local(),
                "https://100.64.0.1/.well-known/did.json",
                "not a public address",
            ),
            (
                everything_local(),
                "https://0.0.0.0/.well-known/did.json",
                "not a public address",
            ),
            // A public host over `http`.
            (
                everything_local(),
                "http://93.184.216.34/.well-known/did.json",
                "not an HTTPS URL",
            ),
        ] {
            let error = client.get(&url(refused)).await.unwrap_err();
            assert!(error.to_string().contains(reason), "{refused}: {error}");
        }
    }

    #[test]
    fn local_ranges() {
        let none = LocalNetwork::NONE;
        let loopback = loopback().local_network();
        let both = everything_local().local_network();
        assert_eq!(ReqwestClient::new().unwrap().local_network(), none);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();

        for address in ["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1"] {
            assert!(!none.allows(ip(address)), "{address}");
            assert!(loopback.allows(ip(address)), "{address}");
            assert!(both.allows(ip(address)), "{address}");
        }
        for address in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "fc00::1",
            "fd12::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!loopback.allows(ip(address)), "{address}");
            assert!(both.allows(ip(address)), "{address}");
        }
        for address in [
            "169.254.169.254",
            "fe80::1",
            "::ffff:169.254.169.254",
            "0.0.0.0",
            "::",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "2001:db8::1",
            "93.184.216.34",
        ] {
            assert!(!both.allows(ip(address)), "{address}");
        }

        // Plain `http` only when every address is local; a mixed host keeps the public rules.
        assert!(both.all_local(&[ip("127.0.0.1"), ip("::1"), ip("10.0.0.1")]));
        assert!(!both.all_local(&[ip("127.0.0.1"), ip("93.184.216.34")]));
        assert!(!both.all_local(&[ip("127.0.0.1"), ip("169.254.169.254")]));
        assert!(!loopback.all_local(&[ip("127.0.0.1"), ip("10.0.0.1")]));
        assert!(!both.all_local(&[]));
    }
}
