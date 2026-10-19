//! DIF Linked Verifiable Presentation v1.0.0 vectors: the example DID documents, the example
//! presentation JWT (verified with the key of the specification repository that signed it) and
//! the JSON-LD and top-level-payload variants; then presentations built, published, fetched and
//! validated over the RFC 8037 `did:key`, and every way one can fail.
#![cfg(all(feature = "linked-vp", feature = "did-key"))]

mod common;

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::did::{
    Context, Did, DidDocument, DidUrl, ResolutionError, ResolutionErrorKind, ResolutionOptions,
    ResolutionResult, Service, ServiceEndpoint, Uri,
};
use identity_kit::jose::{DefaultVerifier, JwsAlgorithm, JwsHeader};
use identity_kit::linked_vp::{
    CONTEXT, CREDENTIAL_TYP, LinkedPresentationBuilder, LinkedVpClient, LinkedVpError,
    LinkedVpValidationOptions, LinkedVpValidator, PRESENTATION_TYP, SERVICE_TYPE, decode, service,
    services,
};
use identity_kit::methods::DidKey;
use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
use identity_kit::resolver::{DidResolver, Resolver};
use identity_kit::vc::validation::{
    CredentialValidationOptions, FailFast, JwtCredentialValidator, JwtPresentationValidator,
    PresentationValidationError, PresentationValidationOptions, SubjectHolderRelationship,
    TimeOptions, ValidationError, decode_presentation,
};
use identity_kit::vc::{Credential, CredentialError, Jwt, JwtClaims, Presentation, Subject};
use serde_json::{Value, json};
use url::Url;

use common::Ed25519Signer;

const EXAMPLE_DID: &str = "did:example:123";
const EXAMPLE_KID: &str = "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A";
const EXAMPLE_URL: &str = "https://bar.example.com/verifiable-presentation.jsonld";
const IPFS_URL: &str = "ipfs://bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly/verifiable-presentation.jwt";
const PUBLISHED_URL: &str = "https://holder.example/linked-vp.jwt";

fn vector(name: &str) -> &'static str {
    match name {
        "did_document" => include_str!("vectors/linked_vp/did_document.json"),
        "did_document_hashlinks" => include_str!("vectors/linked_vp/did_document_hashlinks.json"),
        "jwt" => include_str!("vectors/linked_vp/jwt.txt"),
        "header" => include_str!("vectors/linked_vp/header.json"),
        "credential_header" => include_str!("vectors/linked_vp/credential_header.json"),
        "json_ld" => include_str!("vectors/linked_vp/presentation.jsonld"),
        "flat_jwt" => include_str!("vectors/linked_vp/flat_jwt.txt"),
        "verification_method" => include_str!("vectors/linked_vp/verification_method.json"),
        _ => unreachable!(),
    }
}

fn json(name: &str) -> Value {
    serde_json::from_str(vector(name)).unwrap()
}

fn example_jwt() -> Jwt {
    vector("jwt").trim().parse().unwrap()
}

fn example_did() -> Did {
    Did::parse(EXAMPLE_DID).unwrap()
}

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

/// Inside the validity of the example (2024-02-08 to 2029-02-08) and of the presentations built
/// here (2024-01-01 to 2026-01-01).
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
}

fn options() -> LinkedVpValidationOptions {
    LinkedVpValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_credentials(CredentialValidationOptions::new().with_time(TimeOptions::at(now())))
}

/// The example DID document as published, with its verification method replaced by
/// `verification_method` and listed under `relationships`. The published document lists its key
/// under no relationship, and the key it shows did not sign the example JWT (see
/// `published_example_key_does_not_verify`).
fn example_document(verification_method: Value, relationships: &[&str]) -> DidDocument {
    let mut document = json("did_document");
    document["verificationMethod"] = json!([verification_method]);
    for relationship in relationships {
        document[*relationship] = json!([EXAMPLE_KID]);
    }
    serde_json::from_value(document).unwrap()
}

/// The example document able to verify the example JWT.
fn verifiable_example_document() -> DidDocument {
    example_document(
        json("verification_method"),
        &["authentication", "assertionMethod"],
    )
}

/// A `did:example` resolver serving fixed documents, counting its calls.
struct Documents {
    documents: Vec<DidDocument>,
    calls: AtomicUsize,
}

impl Documents {
    fn new(documents: impl IntoIterator<Item = DidDocument>) -> Self {
        Self {
            documents: documents.into_iter().collect(),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl DidResolver for Documents {
    fn method(&self) -> &'static str {
        "example"
    }

    async fn resolve(
        &self,
        did: &Did,
        _: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.documents
            .iter()
            .find(|document| document.id == *did)
            .cloned()
            .map(ResolutionResult::new)
            .ok_or(ResolutionErrorKind::NotFound.into())
    }
}

/// A web serving fixed responses, recording what was fetched.
#[derive(Default)]
struct Web {
    pages: HashMap<String, Result<(u16, Vec<u8>), String>>,
    fetched: Mutex<Vec<String>>,
}

impl Web {
    fn serving(mut self, url: &str, status: u16, body: impl Into<Vec<u8>>) -> Self {
        self.pages.insert(url.to_owned(), Ok((status, body.into())));
        self
    }

    fn failing(mut self, url: &str, message: &str) -> Self {
        self.pages.insert(url.to_owned(), Err(message.to_owned()));
        self
    }

    fn fetched(&self) -> Vec<String> {
        self.fetched.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for Web {
    async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
        self.fetched.lock().unwrap().push(url.to_string());
        match self.pages.get(url.as_str()) {
            Some(Ok((status, body))) => Ok(HttpResponse::new(*status, body.clone())),
            Some(Err(message)) => Err(HttpError::msg(message)),
            None => Ok(HttpResponse::new(404, Vec::new())),
        }
    }
}

fn resolver(documents: impl IntoIterator<Item = DidDocument>) -> Resolver {
    Resolver::builder()
        .with(DidKey::default())
        .with(Documents::new(documents))
        .build()
}

fn example_validator() -> LinkedVpValidator<Resolver> {
    LinkedVpValidator::from_presentation_validator(JwtPresentationValidator::new(
        resolver([verifiable_example_document()]),
        DefaultVerifier,
    ))
}

fn client(web: Web, validator: LinkedVpValidator<Resolver>) -> LinkedVpClient<Web, Resolver> {
    LinkedVpClient::new(web, validator)
}

fn presentation_error(error: LinkedVpError) -> ValidationError {
    match error {
        LinkedVpError::Presentation(PresentationValidationError {
            presentation: Some(error),
            ..
        }) => *error,
        other => panic!("expected an error of the presentation, got {other:?}"),
    }
}

fn credential_errors(error: LinkedVpError) -> Vec<(usize, ValidationError)> {
    match error {
        LinkedVpError::Presentation(PresentationValidationError {
            presentation: None,
            credentials,
            ..
        }) => credentials.into_iter().collect(),
        other => panic!("expected errors of credentials, got {other:?}"),
    }
}

// The specification's examples.

#[test]
fn example_did_document() {
    let document: DidDocument = serde_json::from_str(vector("did_document")).unwrap();
    assert_eq!(
        serde_json::to_value(&document).unwrap(),
        json("did_document")
    );
    assert!(document.context.as_ref().unwrap().contains(CONTEXT));
    let linked: Vec<_> = services(&document).map(Result::unwrap).collect();
    assert_eq!(linked.len(), 2);
    assert_eq!(linked[0].id().as_str(), "did:example:123#foo");
    assert!(matches!(
        &linked[0].service.service_endpoint,
        ServiceEndpoint::Set(set) if set.len() == 1
    ));
    assert_eq!(linked[0].urls, [url(EXAMPLE_URL)]);
    assert_eq!(linked[1].id().as_str(), "did:example:123#baz");
    assert!(matches!(
        &linked[1].service.service_endpoint,
        ServiceEndpoint::Uri(_)
    ));
    assert_eq!(linked[1].urls, [url(IPFS_URL)]);
}

#[test]
fn example_did_document_with_hashlinks() {
    let document: DidDocument = serde_json::from_str(vector("did_document_hashlinks")).unwrap();
    let urls: Vec<String> = services(&document)
        .flat_map(|service| service.unwrap().urls)
        .map(String::from)
        .collect();
    assert_eq!(
        urls,
        [
            "https://bar.example.com/verifiable-presentation.jsonld?hl=z3aq31uzgnZBuWNzUB",
            "ipfs://bafybeihkoviema7g3gxyt6la7vd5ho32ictqbilu3wnlo3rs7ewhnp7lly/verifiable-presentation.jwt?hl=z8guWNzUBnZBu3aq31",
        ]
    );
}

#[test]
fn example_jwt_decodes() {
    let decoded = decode(&example_jwt()).unwrap();
    assert_eq!(
        serde_json::to_value(&decoded.header).unwrap(),
        json("header")
    );
    assert_eq!(decoded.header.typ.as_deref(), Some(PRESENTATION_TYP[1]));
    assert_eq!(decoded.claims.iss.as_deref(), Some(EXAMPLE_DID));
    assert_eq!(decoded.claims.sub.as_deref(), Some(EXAMPLE_DID));
    assert_eq!(
        (decoded.claims.nbf, decoded.claims.iat, decoded.claims.exp),
        (Some(1707413926), Some(1707413926), Some(1865266726))
    );
    assert_eq!(decoded.holder().map(Uri::as_str), Some(EXAMPLE_DID));
    assert_eq!(
        decoded.presentation.id.as_ref().map(Uri::as_str),
        Some(EXAMPLE_URL)
    );
    assert!(decoded.claims.aud.is_none());
    assert!(!decoded.claims.additional.contains_key("nonce"));

    let [credential] = decoded.credentials.as_slice() else {
        panic!("one credential");
    };
    assert_eq!(
        serde_json::to_value(&credential.header).unwrap(),
        json("credential_header")
    );
    assert_eq!(credential.header.typ.as_deref(), Some(CREDENTIAL_TYP[1]));
    assert_eq!(credential.credential.issuer.id().as_str(), EXAMPLE_DID);
    assert!(credential.credential.has_type("schema:Organization"));
    let subject = credential.credential.subject().unwrap();
    assert_eq!(subject.id.as_ref().map(Uri::as_str), Some(EXAMPLE_DID));
    assert_eq!(subject.properties["schema:legalName"], "Example LLC");

    // The plain VCDM 1.1 decoder holds the presentation to `typ: JWT`.
    assert!(matches!(
        decode_presentation(&example_jwt()),
        Err(ValidationError::UnexpectedTyp { expected: "JWT", found }) if found == PRESENTATION_TYP[1]
    ));
}

#[tokio::test]
async fn example_jwt_validates() {
    let decoded = example_validator()
        .validate(&example_jwt(), &example_did(), &options())
        .await
        .unwrap();
    assert_eq!(decoded.credentials.len(), 1);
    assert_eq!(decoded.holder().map(Uri::as_str), Some(EXAMPLE_DID));

    // Expired on 2029-02-08, not valid before 2024-02-08.
    let late = options().with_time(TimeOptions::at(
        Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap(),
    ));
    let error = example_validator()
        .validate(&example_jwt(), &example_did(), &late)
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::Expired { .. }
    ));
    let early = options().with_time(TimeOptions::at(
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
    ));
    let error = example_validator()
        .validate(&example_jwt(), &example_did(), &early)
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::NotYetValid { .. }
    ));
}

#[tokio::test]
async fn published_example_key_does_not_verify() {
    // The key the example document shows, under `authentication` and `assertionMethod`.
    let mut document = json("did_document");
    let shown = document["verificationMethod"][0].clone();
    assert_eq!(
        shown["publicKeyJwk"]["x"],
        "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
    );
    document["authentication"] = json!([EXAMPLE_KID]);
    let document: DidDocument = serde_json::from_value(document).unwrap();
    let validator = LinkedVpValidator::new(resolver([document]), DefaultVerifier);
    let error = validator
        .validate(&example_jwt(), &example_did(), &options())
        .await
        .unwrap_err();
    let error = presentation_error(error);
    assert!(matches!(error, ValidationError::Signature(_)), "{error:?}");
}

#[tokio::test]
async fn example_key_must_be_under_authentication() {
    let only_assertion = example_document(json("verification_method"), &["assertionMethod"]);
    let validator = LinkedVpValidator::new(resolver([only_assertion]), DefaultVerifier);
    let error = validator
        .validate(&example_jwt(), &example_did(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::KeyResolution { .. }
    ));

    // Under `authentication` only, the presentation verifies and its credential, which needs
    // `assertionMethod`, does not.
    let only_authentication = example_document(json("verification_method"), &["authentication"]);
    let validator = LinkedVpValidator::new(resolver([only_authentication]), DefaultVerifier);
    let error = validator
        .validate(&example_jwt(), &example_did(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        credential_errors(error).as_slice(),
        [(0, ValidationError::KeyResolution { .. })]
    ));
}

#[tokio::test]
async fn example_fetched_from_the_example_document() {
    let web = Web::default().serving(EXAMPLE_URL, 200, vector("jwt"));
    let client = client(web, example_validator());
    let reports = client
        .validate_document(&verifiable_example_document(), &options())
        .await;
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].service.as_str(), "did:example:123#foo");
    assert_eq!(reports[0].url.as_ref(), Some(&url(EXAMPLE_URL)));
    assert_eq!(reports[0].result.as_ref().unwrap().credentials.len(), 1);
    assert_eq!(reports[1].service.as_str(), "did:example:123#baz");
    assert!(matches!(
        &reports[1].result,
        Err(LinkedVpError::UnsupportedEndpoint(found)) if *found == url(IPFS_URL)
    ));
    // The IPFS endpoint is never handed to the HTTP client.
    assert_eq!(client.http().fetched(), [EXAMPLE_URL]);
}

#[tokio::test]
async fn example_fetched_by_did() {
    let web = Web::default().serving(EXAMPLE_URL, 200, vector("jwt"));
    let client = client(web, example_validator());
    let reports = client
        .validate_did(&example_did(), &options())
        .await
        .unwrap();
    assert!(reports[0].result.is_ok());
    assert_eq!(
        client
            .validator()
            .presentation_validator()
            .credential_validator()
            .resolver()
            .methods(),
        ["example", "key"]
    );

    let error = client
        .validate_did(&Did::parse("did:example:unknown").unwrap(), &options())
        .await
        .unwrap_err();
    assert!(
        matches!(error, LinkedVpError::Resolution(error) if error == ResolutionErrorKind::NotFound)
    );
}

#[tokio::test]
async fn hashlinked_urls_are_fetched_as_written() {
    let mut document = json("did_document_hashlinks");
    document["verificationMethod"] = json!([json("verification_method")]);
    document["authentication"] = json!([EXAMPLE_KID]);
    document["assertionMethod"] = json!([EXAMPLE_KID]);
    let document: DidDocument = serde_json::from_value(document).unwrap();
    let hashlinked = "https://bar.example.com/verifiable-presentation.jsonld?hl=z3aq31uzgnZBuWNzUB";
    let web = Web::default().serving(hashlinked, 200, vector("jwt"));
    let client = client(web, example_validator());
    let reports = client.validate_document(&document, &options()).await;
    assert!(reports[0].result.is_ok());
    assert_eq!(client.http().fetched(), [hashlinked]);
}

#[tokio::test]
async fn json_ld_example_is_unsupported() {
    let web = Web::default().serving(EXAMPLE_URL, 200, vector("json_ld"));
    let client = client(web, example_validator());
    assert!(matches!(
        client.fetch(&url(EXAMPLE_URL)).await,
        Err(LinkedVpError::UnsupportedFormat(found)) if found == url(EXAMPLE_URL)
    ));
}

#[tokio::test]
async fn top_level_payload_is_not_a_vcdm_jwt() {
    // The specification's "decoded JWT payload" example has the presentation members at the top
    // level; VCDM 1.1 puts them in `vp`. The token is signed by the same key and still refused.
    let flat: Jwt = vector("flat_jwt").trim().parse().unwrap();
    assert!(matches!(
        decode(&flat),
        Err(ValidationError::Credential(CredentialError::MissingClaim(
            "vp"
        )))
    ));
    let error = example_validator()
        .validate(&flat, &example_did(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::Credential(CredentialError::MissingClaim("vp"))
    ));
}

// Presentations built here, by the RFC 8037 key behind a `did:key`.

struct Holder {
    signer: Ed25519Signer,
    did: Did,
    kid: DidUrl,
}

fn holder() -> Holder {
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    Holder { signer, did, kid }
}

fn did_key_validator() -> LinkedVpValidator<Resolver> {
    LinkedVpValidator::new(resolver([]), DefaultVerifier)
}

/// A credential `holder` issued about `subject`, signed with `typ` `JWT`.
async fn credential(holder: &Holder, subject: &Did) -> Jwt {
    let credential = Credential::new(
        &holder.did,
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        Subject::new(subject.clone()).with_property("name", "Example LLC"),
    )
    .with_type("OrganizationCredential");
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("JWT")
        .with_kid(holder.kid.as_str());
    Jwt::sign(
        &header,
        &credential.to_jwt_claims().unwrap(),
        &holder.signer,
    )
    .await
    .unwrap()
}

fn builder(holder: &Holder) -> LinkedPresentationBuilder {
    LinkedPresentationBuilder::new(holder.did.clone())
        .with_id(Uri::parse(PUBLISHED_URL).unwrap())
        .with_issued_at(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .with_expiration(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
}

/// `claims` signed by the holder, with `typ` when given.
async fn sign(holder: &Holder, claims: &JwtClaims, typ: Option<&str>) -> Jwt {
    let mut header = JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(holder.kid.as_str());
    if let Some(typ) = typ {
        header = header.with_typ(typ);
    }
    Jwt::sign(&header, claims, &holder.signer).await.unwrap()
}

#[tokio::test]
async fn round_trip_over_did_key() {
    let holder = holder();
    let builder = builder(&holder).with_credential(credential(&holder, &holder.did).await);
    let jwt = builder.sign(&holder.kid, &holder.signer).await.unwrap();

    let mut document = resolver([]).resolve_document(&holder.did).await.unwrap();
    document.context = Some(Context::uris([Context::DID_V1, CONTEXT]));
    document
        .insert_service(
            service(holder.did.join("#linked-vp").unwrap(), [url(PUBLISHED_URL)]).unwrap(),
        )
        .unwrap();
    // A service of another type is not fetched.
    document
        .insert_service(Service::new(
            holder.did.join("#other").unwrap(),
            "LinkedDomains",
            Uri::parse("https://holder.example").unwrap(),
        ))
        .unwrap();

    let web = Web::default().serving(PUBLISHED_URL, 200, format!("\n{jwt}\n"));
    let client = client(web, did_key_validator());
    let reports = client.validate_document(&document, &options()).await;
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].service, holder.did.join("#linked-vp").unwrap());
    let decoded = reports[0].result.as_ref().unwrap();
    assert_eq!(decoded.presentation, builder.presentation());
    assert_eq!(decoded.header.typ.as_deref(), Some("JWT"));
    assert_eq!(decoded.claims, builder.jwt_claims().unwrap());
    assert_eq!(decoded.claims.sub.as_deref(), Some(holder.did.as_str()));
    assert!(decoded.claims.aud.is_none());
    assert!(!decoded.claims.additional.contains_key("nonce"));
    assert_eq!(decoded.credentials.len(), 1);
    assert_eq!(client.http().fetched(), [PUBLISHED_URL]);

    // An ordinary VCDM 1.1 presentation, so the plain validator accepts it too.
    let plain = JwtPresentationValidator::new(resolver([]), DefaultVerifier)
        .validate(&jwt, &options().presentation_options())
        .await
        .unwrap();
    assert_eq!(plain.presentation, builder.presentation());
}

#[tokio::test]
async fn built_presentation_is_deterministic() {
    let holder = holder();
    let builder = builder(&holder).with_credential(credential(&holder, &holder.did).await);
    let first = builder.sign(&holder.kid, &holder.signer).await.unwrap();
    let second = builder
        .clone()
        .sign(&holder.kid, &holder.signer)
        .await
        .unwrap();
    assert_eq!(first, second);
    let claims = builder.jwt_claims().unwrap();
    assert_eq!(claims.iss.as_deref(), Some(holder.did.as_str()));
    assert_eq!(claims.jti.as_deref(), Some(PUBLISHED_URL));
    assert_eq!(
        (claims.iat, claims.nbf, claims.exp),
        (Some(1704067200), Some(1704067200), Some(1767225600))
    );
    assert_eq!(
        Presentation::from_jwt_claims(&claims).unwrap(),
        builder.presentation()
    );
    // Without an expiration there is no `exp`, and without an id no `jti`.
    let bare = LinkedPresentationBuilder::new(holder.did.clone())
        .jwt_claims()
        .unwrap();
    assert!(bare.exp.is_none() && bare.jti.is_none());
    assert_eq!(bare.iat, bare.nbf);
}

#[tokio::test]
async fn builder_refuses_a_key_of_another_did() {
    let holder = holder();
    let other = DidUrl::parse("did:example:other#key-1").unwrap();
    assert!(matches!(
        builder(&holder).sign(&other, &holder.signer).await,
        Err(LinkedVpError::Validation(ValidationError::HolderMismatch { kid, .. })) if kid == other
    ));
}

#[tokio::test]
async fn presentation_without_expiration_validates() {
    let holder = holder();
    let mut builder = builder(&holder);
    builder.expiration = None;
    let jwt = builder.sign(&holder.kid, &holder.signer).await.unwrap();
    let far = options().with_time(TimeOptions::at(
        Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
    ));
    did_key_validator()
        .validate(&jwt, &holder.did, &far)
        .await
        .unwrap();
}

#[tokio::test]
async fn expired_presentation_fails() {
    let holder = holder();
    let jwt = builder(&holder)
        .sign(&holder.kid, &holder.signer)
        .await
        .unwrap();
    let late = options().with_time(TimeOptions::at(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ));
    let error = did_key_validator()
        .validate(&jwt, &holder.did, &late)
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::Expired { .. }
    ));
}

#[tokio::test]
async fn holder_must_be_the_linking_did() {
    let holder = holder();
    let jwt = builder(&holder)
        .sign(&holder.kid, &holder.signer)
        .await
        .unwrap();
    let error = did_key_validator()
        .validate(&jwt, &example_did(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        LinkedVpError::HolderMismatch { did, holder: found } if did == example_did() && found == holder.did
    ));
}

#[tokio::test]
async fn key_of_another_did_is_refused_before_resolving_it() {
    let holder = holder();
    let claims = builder(&holder).jwt_claims().unwrap();
    let foreign = DidUrl::parse("did:example:attacker#key-1").unwrap();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("JWT")
        .with_kid(foreign.as_str());
    let jwt = Jwt::sign(&header, &claims, &holder.signer).await.unwrap();

    let documents = std::sync::Arc::new(Documents::new([]));
    let resolver = Resolver::builder()
        .with(DidKey::default())
        .with_arc(documents.clone())
        .build();
    let error = LinkedVpValidator::new(resolver, DefaultVerifier)
        .validate(&jwt, &holder.did, &options())
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::HolderMismatch { kid, .. } if kid == foreign
    ));
    assert_eq!(documents.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn iss_must_agree_with_holder() {
    let holder = holder();
    let mut claims = builder(&holder).jwt_claims().unwrap();
    claims.additional["vp"]["holder"] = json!("did:example:other");
    let jwt = sign(&holder, &claims, Some("JWT")).await;
    let error = did_key_validator()
        .validate(&jwt, &holder.did, &options())
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::Credential(_)
    ));
}

#[tokio::test]
async fn audience_and_nonce_are_ignored() {
    let holder = holder();
    let claims = builder(&holder)
        .jwt_claims()
        .unwrap()
        .with_aud("did:example:verifier")
        .with_claim("nonce", "n-0S6_WzA2Mj");
    let jwt = sign(&holder, &claims, Some("JWT")).await;
    did_key_validator()
        .validate(&jwt, &holder.did, &options())
        .await
        .unwrap();
}

#[tokio::test]
async fn typ_values() {
    let holder = holder();
    let claims = builder(&holder).jwt_claims().unwrap();
    for typ in [
        None,
        Some("JWT"),
        Some(PRESENTATION_TYP[0]),
        Some(PRESENTATION_TYP[1]),
    ] {
        let jwt = sign(&holder, &claims, typ).await;
        assert!(
            did_key_validator()
                .validate(&jwt, &holder.did, &options())
                .await
                .is_ok(),
            "{typ:?}"
        );
        assert!(decode(&jwt).is_ok(), "{typ:?}");
    }
    for typ in ["vp+jwt", "vp+ld+json", "jwt"] {
        let jwt = sign(&holder, &claims, Some(typ)).await;
        let error = did_key_validator()
            .validate(&jwt, &holder.did, &options())
            .await
            .unwrap_err();
        assert!(
            matches!(presentation_error(error), ValidationError::UnexpectedTyp { found, .. } if found == typ)
        );
    }
}

#[tokio::test]
async fn credential_typ_values() {
    let holder = holder();
    let mut issued = Vec::new();
    for typ in ["JWT", CREDENTIAL_TYP[0], CREDENTIAL_TYP[1], "vc+jwt"] {
        let credential = Credential::new(
            &holder.did,
            Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            Subject::new(holder.did.clone()),
        );
        let header = JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_typ(typ)
            .with_kid(holder.kid.as_str());
        issued.push(
            Jwt::sign(
                &header,
                &credential.to_jwt_claims().unwrap(),
                &holder.signer,
            )
            .await
            .unwrap(),
        );
    }
    let builder = issued
        .into_iter()
        .fold(builder(&holder), LinkedPresentationBuilder::with_credential);
    let jwt = builder.sign(&holder.kid, &holder.signer).await.unwrap();
    let error = did_key_validator()
        .validate(
            &jwt,
            &holder.did,
            &options().with_fail_fast(FailFast::AllErrors),
        )
        .await
        .unwrap_err();
    // `vc+jwt` is the VCDM 2.0 credential profile, not one a linked VCDM 1.1 presentation takes.
    assert!(matches!(
        credential_errors(error).as_slice(),
        [(3, ValidationError::UnexpectedTyp { found, .. })] if found == "vc+jwt"
    ));
}

#[tokio::test]
async fn credential_subjects_must_be_the_holder() {
    let holder = holder();
    let stranger = Did::parse("did:example:stranger").unwrap();
    let jwt = builder(&holder)
        .with_credential(credential(&holder, &stranger).await)
        .with_credential(credential(&holder, &holder.did).await)
        .with_credential(credential(&holder, &stranger).await)
        .sign(&holder.kid, &holder.signer)
        .await
        .unwrap();

    let error = did_key_validator()
        .validate(&jwt, &holder.did, &options())
        .await
        .unwrap_err();
    assert!(matches!(
        credential_errors(error).as_slice(),
        [(0, ValidationError::SubjectHolderMismatch { .. })]
    ));
    let all = options().with_fail_fast(FailFast::AllErrors);
    let error = did_key_validator()
        .validate(&jwt, &holder.did, &all)
        .await
        .unwrap_err();
    let indices: Vec<usize> = credential_errors(error)
        .into_iter()
        .map(|(i, _)| i)
        .collect();
    assert_eq!(indices, [0, 2]);

    let any = options().with_subject_holder(SubjectHolderRelationship::Any);
    let decoded = did_key_validator()
        .validate(&jwt, &holder.did, &any)
        .await
        .unwrap();
    assert_eq!(decoded.credentials.len(), 3);
}

// Services.

#[test]
fn service_entries() {
    let id = DidUrl::parse("did:example:123#vp").unwrap();
    let one = service(id.clone(), [url(EXAMPLE_URL)]).unwrap();
    assert!(one.has_type(SERVICE_TYPE));
    assert_eq!(
        serde_json::to_value(&one).unwrap(),
        json!({ "id": "did:example:123#vp", "type": SERVICE_TYPE, "serviceEndpoint": EXAMPLE_URL })
    );
    let two = service(id.clone(), [url(EXAMPLE_URL), url(PUBLISHED_URL)]).unwrap();
    assert_eq!(
        serde_json::to_value(&two).unwrap()["serviceEndpoint"],
        json!([EXAMPLE_URL, PUBLISHED_URL])
    );
    assert!(matches!(
        service(id.clone(), []),
        Err(LinkedVpError::InvalidService { id: found, .. }) if found == id
    ));
    // WHATWG leaves `|` unescaped in a path, which RFC 3986 does not allow in a URI.
    let piped = url("https://holder.example/a|b");
    assert_eq!(piped.as_str(), "https://holder.example/a|b");
    assert!(matches!(
        service(id.clone(), [piped]),
        Err(LinkedVpError::InvalidService { reason, .. }) if reason.contains("is not a URI")
    ));

    let mut document = DidDocument::new(Did::parse(EXAMPLE_DID).unwrap());
    document.insert_service(two).unwrap();
    let linked: Vec<_> = services(&document).map(Result::unwrap).collect();
    assert_eq!(linked[0].urls, [url(EXAMPLE_URL), url(PUBLISHED_URL)]);
}

#[tokio::test]
async fn invalid_service_entries_are_reported() {
    let document: DidDocument = serde_json::from_value(json!({
        "id": EXAMPLE_DID,
        "service": [
            { "id": "did:example:123#map", "type": SERVICE_TYPE, "serviceEndpoint": { "origins": [EXAMPLE_URL] } },
            { "id": "did:example:123#bad", "type": SERVICE_TYPE, "serviceEndpoint": ["https://[bad"] },
            { "id": "did:example:123#several-types", "type": ["Other", SERVICE_TYPE], "serviceEndpoint": EXAMPLE_URL },
            { "id": "did:example:123#other", "type": "LinkedDomains", "serviceEndpoint": "https://example.com" }
        ]
    }))
    .unwrap();
    let linked: Vec<_> = services(&document).collect();
    assert_eq!(linked.len(), 3);
    assert!(
        matches!(&linked[0], Err(LinkedVpError::InvalidService { id, .. }) if id.as_str() == "did:example:123#map")
    );
    assert!(
        matches!(&linked[1], Err(LinkedVpError::InvalidService { id, .. }) if id.as_str() == "did:example:123#bad")
    );
    assert!(linked[2].is_ok());

    let web = Web::default().serving(EXAMPLE_URL, 200, vector("jwt"));
    let client = client(web, example_validator());
    let reports = client.validate_document(&document, &options()).await;
    assert_eq!(reports.len(), 3);
    assert!(reports[0].url.is_none() && reports[1].url.is_none());
    assert!(matches!(
        reports[0].result,
        Err(LinkedVpError::InvalidService { .. })
    ));
    assert!(reports[2].result.is_ok());
    assert_eq!(client.http().fetched(), [EXAMPLE_URL]);
}

// Fetching.

#[tokio::test]
async fn fetch_failures() {
    let web = Web::default()
        .serving("https://holder.example/gone", 410, vector("jwt"))
        .failing("https://holder.example/refused", "connection refused")
        .serving("https://holder.example/binary", 200, vec![0xff, 0xfe])
        .serving("https://holder.example/text", 200, "not a token")
        .serving("https://holder.example/empty", 200, "  \n");
    let client = client(web, example_validator());
    assert!(matches!(
        client.fetch(&url("https://holder.example/gone")).await,
        Err(LinkedVpError::HttpStatus { status: 410, .. })
    ));
    assert!(matches!(
        client.fetch(&url("https://holder.example/missing")).await,
        Err(LinkedVpError::HttpStatus { status: 404, .. })
    ));
    let error = client
        .fetch(&url("https://holder.example/refused"))
        .await
        .unwrap_err();
    assert!(matches!(&error, LinkedVpError::Http { .. }));
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("connection refused".to_owned())
    );
    for path in ["binary", "text", "empty"] {
        let target = url(&format!("https://holder.example/{path}"));
        assert!(
            matches!(client.fetch(&target).await, Err(LinkedVpError::InvalidBody { url, .. }) if url == target),
            "{path}"
        );
    }
    // Plain HTTP and other schemes are refused without a request.
    for refused in ["http://holder.example/vp.jwt", IPFS_URL] {
        assert!(matches!(
            client.fetch(&url(refused)).await,
            Err(LinkedVpError::UnsupportedEndpoint(_))
        ));
    }
    assert!(
        !client
            .http()
            .fetched()
            .iter()
            .any(|fetched| fetched.starts_with("http:") || fetched.starts_with("ipfs:"))
    );
}

// The accepted `typ` set of the general validators, which the linked presentation validator
// builds on.

#[tokio::test]
async fn validators_accept_additional_typ_only_when_asked() {
    let holder = holder();
    let credential = {
        let credential = Credential::new(
            &holder.did,
            Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            Subject::new(holder.did.clone()),
        );
        sign(
            &holder,
            &credential.to_jwt_claims().unwrap(),
            Some("vc+ld+jwt"),
        )
        .await
    };
    let credentials = JwtCredentialValidator::new(resolver([]), DefaultVerifier);
    let strict = CredentialValidationOptions::new().with_time(TimeOptions::at(now()));
    assert!(matches!(
        credentials.validate(&credential, &strict).await,
        Err(ValidationError::UnexpectedTyp { expected: "JWT", found }) if found == "vc+ld+jwt"
    ));
    let lenient = strict.clone().with_additional_typ("vc+ld+jwt");
    credentials.validate(&credential, &lenient).await.unwrap();

    let claims = builder(&holder)
        .with_credential(credential)
        .jwt_claims()
        .unwrap();
    let presentation = sign(&holder, &claims, Some("vp+ld+jwt")).await;
    let presentations = JwtPresentationValidator::new(resolver([]), DefaultVerifier);
    let strict = PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_credentials(lenient.clone());
    assert!(matches!(
        presentations.validate(&presentation, &strict).await,
        Err(PresentationValidationError { presentation: Some(error), .. })
            if matches!(*error, ValidationError::UnexpectedTyp { .. })
    ));
    let lenient_presentation = strict.clone().with_additional_typ("vp+ld+jwt");
    presentations
        .validate(&presentation, &lenient_presentation)
        .await
        .unwrap();
    // The credentials keep their own set.
    let strict_credentials = lenient_presentation
        .with_credentials(CredentialValidationOptions::new().with_time(TimeOptions::at(now())));
    assert!(matches!(
        presentations.validate(&presentation, &strict_credentials).await,
        Err(PresentationValidationError { presentation: None, credentials, .. })
            if matches!(credentials.get(&0), Some(ValidationError::UnexpectedTyp { .. }))
    ));
}
