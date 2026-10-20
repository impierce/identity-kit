//! DIF Well Known DID Configuration: arbitrary DID documents yield only well-formed
//! `LinkedDomains` services whose origins rebuild into the same service, arbitrary response
//! bodies and statuses are classified without panicking, and nothing validates without a key.
#![no_main]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use identity_kit::did::{DidDocument, DidUrl, VerificationRelationship};
use identity_kit::domain_linkage::{
    DomainLinkageClient, DomainLinkageConfiguration, DomainLinkageError, DomainLinkageValidator,
    SERVICE_TYPE, fetch_configuration, normalize_origin, service, services,
};
use identity_kit::jose::{DefaultVerifier, Jwk};
use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
use identity_kit::vc::validation::{CredentialValidationOptions, KeyResolutionError, KeyResolver};
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

/// Serves one response at every URL.
struct Serve {
    status: u16,
    body: Vec<u8>,
}

#[async_trait::async_trait]
impl HttpClient for Serve {
    async fn get(&self, _: &Url) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse::new(self.status, self.body.clone()))
    }
}

/// Knows no key, so validation stops at the signature after every check that needs none.
#[derive(Debug)]
struct NoKeys;

#[async_trait::async_trait]
impl KeyResolver for NoKeys {
    async fn resolve_key(
        &self,
        _: &DidUrl,
        _: VerificationRelationship,
    ) -> Result<Jwk, KeyResolutionError> {
        Err(KeyResolutionError::msg("no keys"))
    }
}

fn serve(status: u16, body: &[u8]) -> Serve {
    Serve {
        status,
        body: body.to_vec(),
    }
}

fn client(status: u16, body: &[u8]) -> DomainLinkageClient<Serve, NoKeys> {
    DomainLinkageClient::new(
        serve(status, body),
        DomainLinkageValidator::new(NoKeys, DefaultVerifier),
    )
}

fn exercise_document(document: &DidDocument, body: &[u8]) {
    let mut expected_reports = 0;
    for linked in services(document) {
        match linked {
            Ok(linked) => {
                assert!(linked.service.has_type(SERVICE_TYPE));
                assert!(!linked.origins.is_empty());
                for origin in &linked.origins {
                    let serialized = origin.origin().ascii_serialization();
                    assert_eq!(
                        normalize_origin(&serialized).ok().as_deref(),
                        Some(serialized.as_str())
                    );
                }
                let rebuilt = service(linked.id().clone(), linked.origins.clone())
                    .expect("normalized origins rebuild a service");
                let mut rebuilt_document = DidDocument::new(document.id.clone());
                rebuilt_document.service.push(rebuilt);
                let reread: Vec<_> = services(&rebuilt_document)
                    .map(|reread| reread.expect("a built service reads back").origins)
                    .collect();
                assert_eq!(reread, std::slice::from_ref(&linked.origins));
                expected_reports += linked.origins.len();
            }
            Err(DomainLinkageError::InvalidService { id, .. }) => {
                assert!(document.service.iter().any(|service| service.id == id));
                expected_reports += 1;
            }
            Err(other) => panic!("services reports only invalid services, not {other:?}"),
        }
    }
    let reports =
        ready(client(200, body).validate_document(document, &CredentialValidationOptions::new()));
    assert_eq!(reports.len(), expected_reports);
    assert!(
        reports.iter().all(|report| report.result.is_err()),
        "nothing validates without a key"
    );
}

fn exercise_body(data: &[u8]) {
    let origin = Url::parse("https://example.com").expect("a URL");
    match ready(fetch_configuration(&serve(200, data), &origin)) {
        Ok(configuration) => {
            assert!(configuration.check().is_ok());
            let reparsed: DomainLinkageConfiguration =
                serde_json::from_str(&configuration.to_string()).expect("a configuration reparses");
            assert_eq!(reparsed, configuration);
            let result = ready(
                client(200, data).validate_origin(&origin, &CredentialValidationOptions::new()),
            );
            assert!(result.is_err(), "nothing validates without a key");
        }
        Err(DomainLinkageError::InvalidConfiguration { .. }) => {}
        Err(other) => panic!("a served body is a configuration or invalid, not {other:?}"),
    }
}

fn exercise_status(data: &[u8]) {
    let Some(&[high, low]) = data.first_chunk::<2>() else {
        return;
    };
    let status = u16::from_be_bytes([high, low]);
    let origin = Url::parse("https://example.com").expect("a URL");
    let result = ready(fetch_configuration(&serve(status, &data[2..]), &origin));
    match status {
        200..=299 => assert!(matches!(
            result,
            Ok(_) | Err(DomainLinkageError::InvalidConfiguration { .. })
        )),
        404 | 410 => assert!(result.is_err_and(|error| error.is_not_published())),
        _ => assert!(matches!(
            result,
            Err(DomainLinkageError::HttpStatus { status: found, .. }) if found == status
        )),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(document) = serde_json::from_slice::<DidDocument>(data) {
        exercise_document(&document, data);
    }
    exercise_body(data);
    exercise_status(data);
});
