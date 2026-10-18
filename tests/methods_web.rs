//! Specification vectors for `did:web`: the DID to URL mapping examples of the did:web method
//! specification, its Read operation over an in-file `HttpClient`, and the hardened default
//! client's refusals.
#![cfg(feature = "did-web")]

use std::collections::HashMap;
use std::sync::Mutex;

use identity_kit::did::{Did, DidUrl, ResolutionError, ResolutionOptions};
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
        Err(ResolutionError::RepresentationNotSupported)
    );
}

#[tokio::test]
async fn read_operation_failures() {
    let url = "https://example.com/.well-known/did.json";
    let example = did("did:web:example.com");
    let other = r#"{"id": "did:web:example.org"}"#;
    for (mock, error) in [
        (Mock::serving(url, 404, ""), ResolutionError::NotFound),
        (Mock::serving(url, 410, ""), ResolutionError::NotFound),
        (Mock::serving(url, 500, ""), ResolutionError::InternalError),
        (Mock::serving(url, 301, ""), ResolutionError::InternalError),
        (
            Mock::failing(url, "connection refused"),
            ResolutionError::InternalError,
        ),
        (
            Mock::serving(url, 200, "<html>"),
            ResolutionError::InvalidDidDocument,
        ),
        (
            Mock::serving(url, 200, "{}"),
            ResolutionError::InvalidDidDocument,
        ),
        (
            Mock::serving(url, 200, other),
            ResolutionError::InvalidDidDocument,
        ),
        (
            Mock::serving("https://example.com/did.json", 200, EXAMPLE),
            ResolutionError::NotFound,
        ),
    ] {
        let method = DidWeb::new(mock);
        assert_eq!(
            method
                .resolve(&example, &ResolutionOptions::default())
                .await,
            Err(error)
        );
        assert_eq!(method.client().calls.lock().unwrap().len(), 1);
    }
    // A DID without a document URL never reaches the client.
    let method = DidWeb::new(Mock::default());
    assert_eq!(
        method
            .resolve(&did("did:web:192.0.2.1"), &ResolutionOptions::default())
            .await,
        Err(ResolutionError::InvalidDid)
    );
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
