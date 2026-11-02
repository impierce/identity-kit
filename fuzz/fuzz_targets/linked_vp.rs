//! DIF Linked Verifiable Presentation: arbitrary DID documents yield only well-formed linked
//! presentation services and one report per endpoint URI, no more fetched than the limit, arbitrary
//! response bodies and tokens never panic the fetcher, decoder or validator, and a built
//! presentation maps to JWT claims and back unchanged.
#![no_main]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use arbitrary::{Arbitrary, Unstructured};
use chrono::DateTime;
use identity_kit::did::{Did, DidDocument, ServiceEndpoint, Uri};
use identity_kit::jose::{DefaultVerifier, Jwk};
use identity_kit::linked_vp::{
    LinkedPresentationBuilder, LinkedVpClient, LinkedVpError, LinkedVpValidationOptions,
    LinkedVpValidator, SERVICE_TYPE, decode, service, services,
};
use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
use identity_kit::resolver::{KeyReference, KeyResolutionError, KeyResolver, KeyRole};
use identity_kit::vc::{Jwt, Presentation};
use libfuzzer_sys::fuzz_target;
use url::Url;

/// Runs a future that never waits: every stub here answers at once.
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a stub future is never pending"),
    }
}

/// Serves the fuzz input at every URL.
struct Body(Vec<u8>);

#[async_trait::async_trait]
impl HttpClient for Body {
    async fn get(&self, _: &Url) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse::new(200, self.0.clone()))
    }
}

/// Knows no key, so validation stops at the signature after every check that needs none.
#[derive(Debug)]
struct NoKeys;

#[async_trait::async_trait]
impl KeyResolver for NoKeys {
    async fn resolve_key(&self, _: &KeyReference, _: KeyRole) -> Result<Jwk, KeyResolutionError> {
        Err(KeyResolutionError::msg("no keys"))
    }
}

#[derive(Debug, Arbitrary)]
struct Built<'a> {
    holder: &'a str,
    id: Option<&'a str>,
    credentials: Vec<&'a str>,
    issued_at: i64,
    expiration: Option<i64>,
}

fn exercise_document(document: &DidDocument, body: &[u8]) {
    let mut expected_reports = 0;
    for linked in services(document) {
        match linked {
            Ok(linked) => {
                assert!(linked.service.has_type(SERVICE_TYPE));
                assert!(!matches!(
                    linked.service.service_endpoint,
                    ServiceEndpoint::Map(_)
                ));
                // Every endpoint URI is a URL or listed as invalid, in order; one report each.
                let uris: Vec<&Uri> = linked.service.service_endpoint.uris().collect();
                expected_reports += uris.len();
                assert_eq!(linked.urls.len() + linked.invalid_urls.len(), uris.len());
                assert!(!linked.urls.is_empty());
                let (valid, invalid): (Vec<&Uri>, Vec<&Uri>) = uris
                    .into_iter()
                    .partition(|uri| Url::parse(uri.as_str()).is_ok());
                for (url, uri) in linked.urls.iter().zip(valid) {
                    assert_eq!(Url::parse(uri.as_str()).as_ref(), Ok(url));
                }
                for ((uri, error), expected) in linked.invalid_urls.iter().zip(invalid) {
                    assert_eq!(uri, expected);
                    assert_eq!(Url::parse(uri.as_str()).err(), Some(*error));
                }
                if let Ok(rebuilt) = service(linked.id().clone(), linked.urls.clone()) {
                    assert!(rebuilt.has_type(SERVICE_TYPE));
                    assert_eq!(&rebuilt.id, linked.id());
                }
            }
            Err(LinkedVpError::InvalidService { id, .. }) => {
                assert!(document.service.iter().any(|service| service.id == id));
                expected_reports += 1;
            }
            Err(other) => panic!("services reports only invalid services, not {other:?}"),
        }
    }
    // One report per URL and per invalid entry, the limit included; nothing validates without
    // a key.
    let client = LinkedVpClient::new(
        Body(body.to_vec()),
        LinkedVpValidator::new(NoKeys, DefaultVerifier),
    )
    .with_max_urls(2);
    let reports = ready(client.validate_document(document, &LinkedVpValidationOptions::new()));
    assert_eq!(reports.len(), expected_reports);
    assert!(reports.iter().all(|report| report.result.is_err()));
    assert!(
        reports
            .iter()
            .filter(|report| !matches!(
                report.result,
                Err(LinkedVpError::InvalidService { .. } | LinkedVpError::TooManyUrls(2))
            ))
            .count()
            <= 2
    );
}

fn exercise_body(data: &[u8]) {
    let client = LinkedVpClient::new(
        Body(data.to_vec()),
        LinkedVpValidator::new(NoKeys, DefaultVerifier),
    );
    let url = Url::parse("https://holder.example/vp.jwt").expect("a URL");
    match ready(client.fetch(&url)) {
        Ok(jwt) => {
            let body = std::str::from_utf8(data).expect("a fetched token is UTF-8");
            assert_eq!(jwt.as_str(), body.trim());
            exercise_token(&jwt);
        }
        Err(LinkedVpError::UnsupportedFormat(_) | LinkedVpError::InvalidBody { .. }) => {}
        Err(other) => panic!("a served body is a token or a body error, not {other:?}"),
    }
}

fn exercise_token(jwt: &Jwt) {
    if let Ok(decoded) = decode(jwt) {
        // One result per entry; the presentation keeps the entries that are JWTs.
        assert!(decoded.credentials.len() >= decoded.presentation.verifiable_credential.len());
    }
    let validator = LinkedVpValidator::new(NoKeys, DefaultVerifier);
    let did = Did::parse("did:example:123").expect("a DID");
    let result = ready(validator.validate(jwt, &did, &LinkedVpValidationOptions::new()));
    assert!(result.is_err(), "nothing validates without a key");
}

fn exercise_builder(built: &Built<'_>) {
    let Ok(holder) = Did::parse(built.holder) else {
        return;
    };
    let Some(issued_at) = DateTime::from_timestamp(built.issued_at, 0) else {
        return;
    };
    let mut builder = LinkedPresentationBuilder::new(holder.clone()).with_issued_at(issued_at);
    if let Some(id) = built.id {
        let Ok(id) = Uri::parse(id) else { return };
        builder = builder.with_id(id);
    }
    if let Some(expiration) = built.expiration {
        let Some(expiration) = DateTime::from_timestamp(expiration, 0) else {
            return;
        };
        builder = builder.with_expiration(expiration);
    }
    for credential in &built.credentials {
        let Ok(credential) = Jwt::new(*credential) else {
            return;
        };
        builder = builder.with_credential(credential);
    }
    let claims = builder
        .jwt_claims()
        .expect("a built presentation maps to claims");
    assert_eq!(claims.iss.as_deref(), Some(holder.as_str()));
    assert_eq!(claims.sub, claims.iss);
    assert_eq!(claims.iat, Some(built.issued_at));
    assert_eq!(claims.nbf, claims.iat);
    assert_eq!(claims.exp, built.expiration);
    assert!(claims.aud.is_none());
    assert_eq!(
        Presentation::from_jwt_claims(&claims).as_ref(),
        Ok(&builder.presentation())
    );
}

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = serde_json::from_slice::<DidDocument>(data) {
        exercise_document(&document, data);
    }
    exercise_body(data);
    if let Ok(built) = Built::arbitrary(&mut Unstructured::new(data)) {
        exercise_builder(&built);
    }
});
