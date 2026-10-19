//! DIF Well Known DID Configuration vectors: the example DID configuration resource with its
//! Linked Data Proof and JSON Web Token entries, the latter signed by a `did:key` and so
//! verifiable here, and the example DID document with its `LinkedDomains` services; then a
//! configuration issued and validated over the RFC 8037 `did:key`, and fetched over a stub
//! `HttpClient` for an origin and for every origin of a `did:web` document.
#![cfg(all(feature = "domain-linkage", feature = "did-key"))]

mod common;

use std::collections::HashMap;
use std::error::Error as _;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::did::{Did, DidDocument, DidUrl, ResolutionErrorKind, ServiceEndpoint, Uri};
use identity_kit::domain_linkage::{
    CONTEXT, CREDENTIAL_TYPE, DomainLinkageClient, DomainLinkageConfiguration,
    DomainLinkageCredentialBuilder, DomainLinkageError, DomainLinkageValidator, LinkedDid,
    SERVICE_TYPE, configuration_url, fetch_configuration, normalize_origin, service, services,
};
use identity_kit::jose::{DefaultVerifier, JwsAlgorithm, JwsHeader};
use identity_kit::methods::DidKey;
use identity_kit::methods::web::{DidWeb, HttpClient, HttpError, HttpResponse};
use identity_kit::resolver::Resolver;
use identity_kit::vc::validation::{
    CredentialValidationOptions, TimeOptions, ValidationError, decode_credential,
};
use identity_kit::vc::{Credential, Jwt, JwtClaims, Subject};
use serde_json::{Value, json};
use url::Url;

use common::Ed25519Signer;

const DID: &str = "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM";
const ORIGIN: &str = "https://identity.foundation";

fn resource() -> &'static str {
    include_str!("vectors/did_configuration/resource.json")
}

fn example_jwt() -> Jwt {
    include_str!("vectors/did_configuration/jwt.txt")
        .trim()
        .parse()
        .unwrap()
}

fn origin() -> Url {
    Url::parse(ORIGIN).unwrap()
}

/// The example credential is valid from 2020-12-04 to 2025-12-04.
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap()
}

fn at(now: DateTime<Utc>) -> CredentialValidationOptions {
    CredentialValidationOptions::new().with_time(TimeOptions::at(now))
}

fn validator() -> DomainLinkageValidator<Resolver> {
    let resolver = Resolver::builder().with(DidKey::default()).build();
    DomainLinkageValidator::new(resolver, DefaultVerifier)
}

#[test]
fn well_known_location() {
    assert_eq!(
        configuration_url(&origin()).unwrap().as_str(),
        "https://identity.foundation/.well-known/did-configuration.json"
    );
    assert_eq!(
        configuration_url(&Url::parse("https://Example.com:8443/some/path?q#f").unwrap())
            .unwrap()
            .as_str(),
        "https://example.com:8443/.well-known/did-configuration.json"
    );
    assert_eq!(normalize_origin("identity.foundation").unwrap(), ORIGIN);
    assert_eq!(
        normalize_origin("https://identity.foundation/").unwrap(),
        ORIGIN
    );
    assert_eq!(
        normalize_origin("HTTPS://IDENTITY.FOUNDATION").unwrap(),
        ORIGIN
    );
    assert_eq!(
        normalize_origin("http://localhost:3000").unwrap(),
        "http://localhost:3000"
    );
    assert_eq!(
        normalize_origin("localhost:3000").unwrap(),
        "https://localhost:3000"
    );
    assert!(matches!(
        normalize_origin("mailto:someone@example.com"),
        Err(DomainLinkageError::InvalidOrigin(_))
    ));
    assert!(matches!(
        normalize_origin(""),
        Err(DomainLinkageError::InvalidOrigin(_))
    ));
}

#[test]
fn example_resource() {
    let configuration: DomainLinkageConfiguration = serde_json::from_str(resource()).unwrap();
    assert_eq!(configuration.context, CONTEXT);
    assert_eq!(configuration.linked_dids.len(), 2);
    assert!(
        matches!(&configuration.linked_dids[0], LinkedDid::LinkedDataProof(ld) if ld["proof"]["type"] == "Ed25519Signature2018")
    );
    assert!(matches!(&configuration.linked_dids[1], LinkedDid::Jwt(jwt) if *jwt == example_jwt()));
    let jwts: Vec<_> = configuration.jwts().collect();
    assert_eq!(jwts, [(1, &example_jwt())]);
    assert!(configuration.check().is_ok());
    assert_eq!(
        serde_json::to_value(&configuration).unwrap(),
        serde_json::from_str::<Value>(resource()).unwrap()
    );
    assert_eq!(
        serde_json::from_str::<DomainLinkageConfiguration>(&configuration.to_string()).unwrap(),
        configuration
    );
    // An entry that is neither a compact JWT nor a Linked Data Proof object is a parse error,
    // never a credential that quietly drops out of validation.
    for entry in [json!("not.a.jwt"), json!(42), json!(["x"])] {
        assert!(
            serde_json::from_value::<DomainLinkageConfiguration>(json!({
                "@context": CONTEXT,
                "linked_dids": [entry]
            }))
            .is_err(),
            "{entry}"
        );
    }

    // `@context` and `linked_dids` only, with that context.
    assert!(
        serde_json::from_value::<DomainLinkageConfiguration>(json!({
            "@context": "https://example.com/other", "linked_dids": []
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DomainLinkageConfiguration>(json!({
            "@context": CONTEXT, "linked_dids": [], "extra": 1
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<DomainLinkageConfiguration>(json!({"linked_dids": []})).is_err()
    );
    let mut wrong = DomainLinkageConfiguration::new();
    wrong.context = "https://example.com/other".to_owned();
    assert!(matches!(
        wrong.check(),
        Err(DomainLinkageError::InvalidContext(_))
    ));
}

#[test]
fn example_jwt_decodes_to_the_published_header_and_payload() {
    let decoded = decode_credential(&example_jwt()).unwrap();
    let header: Value =
        serde_json::from_str(include_str!("vectors/did_configuration/header.json")).unwrap();
    assert_eq!(serde_json::to_value(&decoded.header).unwrap(), header);
    assert_eq!(decoded.header.alg, JwsAlgorithm::EdDSA);
    assert!(decoded.header.typ.is_none());

    let payload: Value =
        serde_json::from_str(include_str!("vectors/did_configuration/payload.json")).unwrap();
    assert_eq!(serde_json::to_value(&decoded.claims).unwrap(), payload);
    assert_eq!(decoded.claims.iss.as_deref(), Some(DID));
    assert_eq!(decoded.claims.sub.as_deref(), Some(DID));
    assert_eq!(decoded.claims.nbf, Some(1607112739));
    assert_eq!(decoded.claims.exp, Some(1764879139));

    let credential = &decoded.credential;
    assert!(credential.context.contains(CONTEXT));
    assert!(credential.has_type(CREDENTIAL_TYPE));
    assert_eq!(credential.issuer.id().as_str(), DID);
    assert_eq!(credential.id, None);
    assert_eq!(
        credential.issuance_date.to_rfc3339(),
        "2020-12-04T20:12:19+00:00"
    );
    assert_eq!(
        credential.expiration_date.map(|t| t.to_rfc3339()),
        Some("2025-12-04T20:12:19+00:00".to_owned())
    );
    let subject = credential.subject().unwrap();
    assert_eq!(subject.id.as_ref().map(Uri::as_str), Some(DID));
    assert_eq!(subject.properties["origin"], "identity.foundation");
}

#[tokio::test]
async fn example_jwt_validates_against_its_did_key() {
    let validator = validator();
    let decoded = validator
        .validate_credential(&example_jwt(), &origin(), &at(now()))
        .await
        .unwrap();
    assert_eq!(decoded.credential.issuer.id().as_str(), DID);

    // The origin must match, with or without scheme.
    let trailing = Url::parse("https://identity.foundation/").unwrap();
    assert!(
        validator
            .validate_credential(&example_jwt(), &trailing, &at(now()))
            .await
            .is_ok()
    );
    assert!(matches!(
        validator.validate_credential(&example_jwt(), &Url::parse("https://example.com").unwrap(), &at(now())).await,
        Err(DomainLinkageError::OriginMismatch { expected, found })
            if expected == "https://example.com" && found == ORIGIN
    ));
    assert!(matches!(
        validator
            .validate_credential(
                &example_jwt(),
                &Url::parse("http://identity.foundation").unwrap(),
                &at(now())
            )
            .await,
        Err(DomainLinkageError::OriginMismatch { .. })
    ));

    // The validity period.
    assert!(matches!(
        validator
            .validate_credential(
                &example_jwt(),
                &origin(),
                &at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
            )
            .await,
        Err(DomainLinkageError::Validation(
            ValidationError::Expired { .. }
        ))
    ));
    assert!(matches!(
        validator
            .validate_credential(
                &example_jwt(),
                &origin(),
                &at(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap())
            )
            .await,
        Err(DomainLinkageError::Validation(
            ValidationError::NotYetValid { .. }
        ))
    ));

    // The whole resource: the JWT entry links the DID, the Linked Data Proof entry is data.
    let configuration: DomainLinkageConfiguration = serde_json::from_str(resource()).unwrap();
    let report = validator
        .validate_configuration(&configuration, &origin(), &at(now()))
        .await
        .unwrap();
    assert_eq!(
        report.dids().collect::<Vec<_>>(),
        [&Did::parse(DID).unwrap()]
    );
    assert_eq!(report.linked[0].0, 1);
    assert!(report.failed.is_empty());
    let decoded = validator
        .validate_linkage(
            &configuration,
            &Did::parse(DID).unwrap(),
            &origin(),
            &at(now()),
        )
        .await
        .unwrap();
    assert_eq!(decoded.credential.issuer.id().as_str(), DID);
    let other = Did::parse("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp").unwrap();
    assert!(matches!(
        validator.validate_linkage(&configuration, &other, &origin(), &at(now())).await,
        Err(DomainLinkageError::NoCredentialFor(did)) if did == other
    ));
    // Expired: the one JWT entry fails, so the resource does.
    let expired = at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    assert!(matches!(
        validator.validate_configuration(&configuration, &origin(), &expired).await,
        Err(DomainLinkageError::NoValidCredential(errors)) if errors.len() == 1 && errors.contains_key(&1)
    ));
    assert!(matches!(
        validator
            .validate_linkage(
                &configuration,
                &Did::parse(DID).unwrap(),
                &origin(),
                &expired
            )
            .await,
        Err(DomainLinkageError::NoValidCredential(_))
    ));
    // No JWT entries at all.
    let mut ld_only = configuration.clone();
    ld_only.linked_dids.truncate(1);
    assert!(matches!(
        validator.validate_configuration(&ld_only, &origin(), &at(now())).await,
        Err(DomainLinkageError::NoValidCredential(errors)) if errors.is_empty()
    ));
}

#[test]
fn builder_reproduces_the_example_payload() {
    let did = Did::parse(DID).unwrap();
    let builder = DomainLinkageCredentialBuilder::new(
        did.clone(),
        &origin(),
        Utc.timestamp_opt(1607112739, 0).unwrap(),
        Utc.timestamp_opt(1764879139, 0).unwrap(),
    )
    .unwrap();
    assert_eq!(builder.origin, ORIGIN);
    let mut claims = serde_json::to_value(builder.jwt_claims()).unwrap();
    // The example writes the origin without its scheme; the timestamps are the same instants
    // in a different zone.
    claims["vc"]["credentialSubject"]["origin"] = json!("identity.foundation");
    let mut expected: Value =
        serde_json::from_str(include_str!("vectors/did_configuration/payload.json")).unwrap();
    expected["vc"]["issuanceDate"] = json!("2020-12-04T20:12:19Z");
    expected["vc"]["expirationDate"] = json!("2025-12-04T20:12:19Z");
    assert_eq!(claims, expected);

    let credential = builder.credential();
    assert!(credential.check().is_ok());
    assert_eq!(credential.issuer.id().as_str(), DID);
    assert_eq!(credential.subject().unwrap().properties["origin"], ORIGIN);
    assert!(matches!(
        DomainLinkageCredentialBuilder::new(
            did,
            &Url::parse("mailto:a@example.com").unwrap(),
            now(),
            now()
        ),
        Err(DomainLinkageError::InvalidOrigin(_))
    ));
}

/// The RFC 8037 `did:key`, issuing for `https://example.com`.
struct Controller {
    did: Did,
    kid: DidUrl,
    signer: Ed25519Signer,
}

fn controller() -> Controller {
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    Controller { did, kid, signer }
}

fn example_com() -> Url {
    Url::parse("https://example.com").unwrap()
}

fn builder_for(controller: &Controller) -> DomainLinkageCredentialBuilder {
    DomainLinkageCredentialBuilder::new(
        controller.did.clone(),
        &example_com(),
        now() - chrono::TimeDelta::days(1),
        now() + chrono::TimeDelta::days(365),
    )
    .unwrap()
}

#[tokio::test]
async fn issued_configuration_validates() {
    let controller = controller();
    let jwt = builder_for(&controller)
        .sign(&controller.kid, &controller.signer)
        .await
        .unwrap();
    let header = jwt.decode().unwrap().header().clone();
    assert_eq!(header.kid.as_deref(), Some(controller.kid.as_str()));
    assert!(header.typ.is_none());

    let validator = validator();
    let decoded = validator
        .validate_credential(&jwt, &example_com(), &at(now()))
        .await
        .unwrap();
    assert_eq!(
        decoded.credential.subject().unwrap().properties["origin"],
        "https://example.com"
    );

    let configuration = DomainLinkageConfiguration::new()
        .with_credential(jwt.clone())
        .with_credential(example_jwt());
    let report = validator
        .validate_configuration(&configuration, &example_com(), &at(now()))
        .await
        .unwrap();
    assert_eq!(report.dids().collect::<Vec<_>>(), [&controller.did]);
    assert!(matches!(
        report.failed.get(&1),
        Some(DomainLinkageError::OriginMismatch { .. })
    ));
    assert!(
        validator
            .validate_linkage(&configuration, &controller.did, &example_com(), &at(now()))
            .await
            .is_ok()
    );
    assert!(matches!(
        validator.validate_linkage(&configuration, &Did::parse(DID).unwrap(), &example_com(), &at(now())).await,
        Err(DomainLinkageError::NoValidCredential(errors)) if errors.len() == 1
    ));
}

/// Signs `claims` under `header` and validates the result for `https://example.com`.
async fn validate_custom(
    controller: &Controller,
    header: JwsHeader,
    claims: &JwtClaims,
) -> Result<(), DomainLinkageError> {
    let jwt = Jwt::sign(&header, claims, &controller.signer)
        .await
        .unwrap();
    validator()
        .validate_credential(&jwt, &example_com(), &at(now()))
        .await
        .map(|_| ())
}

#[tokio::test]
async fn format_rules() {
    let controller = controller();
    let builder = builder_for(&controller);
    let header = || JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(controller.kid.as_str());
    let claims = builder.jwt_claims();
    assert!(
        validate_custom(&controller, header(), &claims)
            .await
            .is_ok()
    );

    // The header: `alg` and `kid` only.
    assert!(matches!(
        validate_custom(&controller, header().with_typ("JWT"), &claims).await,
        Err(DomainLinkageError::TypPresent(typ)) if typ == "JWT"
    ));
    assert!(matches!(
        validate_custom(&controller, JwsHeader::new(JwsAlgorithm::EdDSA), &claims).await,
        Err(DomainLinkageError::Validation(ValidationError::MissingKid))
    ));
    let mut extra = header();
    extra
        .additional
        .insert("x5u".to_owned(), json!("https://example.com/cert"));
    assert!(matches!(
        validate_custom(&controller, extra, &claims).await,
        Err(DomainLinkageError::UnexpectedHeaderParameter(name)) if name == "x5u"
    ));
    let mut cty = header();
    cty.cty = Some("json".to_owned());
    assert!(matches!(
        validate_custom(&controller, cty, &claims).await,
        Err(DomainLinkageError::UnexpectedHeaderParameter(name)) if name == "cty"
    ));

    // The payload: `iss`, `sub`, `nbf`, `exp` and `vc` only.
    for (name, modify) in [
        (
            "iat",
            Box::new(|c: &mut JwtClaims| c.iat = Some(1)) as Box<dyn Fn(&mut JwtClaims)>,
        ),
        (
            "jti",
            Box::new(|c: &mut JwtClaims| c.jti = Some("urn:uuid:1".into())),
        ),
        (
            "aud",
            Box::new(|c: &mut JwtClaims| c.aud = Some("x".to_owned().into())),
        ),
        (
            "nonce",
            Box::new(|c: &mut JwtClaims| {
                c.additional.insert("nonce".into(), json!("x"));
            }),
        ),
    ] {
        let mut modified = claims.clone();
        modify(&mut modified);
        assert!(
            matches!(
                validate_custom(&controller, header(), &modified).await,
                Err(DomainLinkageError::UnexpectedClaim(found)) if found == name
            ),
            "{name}"
        );
    }
    for (name, modify) in [
        (
            "iss",
            Box::new(|c: &mut JwtClaims| c.iss = None) as Box<dyn Fn(&mut JwtClaims)>,
        ),
        ("sub", Box::new(|c: &mut JwtClaims| c.sub = None)),
        ("nbf", Box::new(|c: &mut JwtClaims| c.nbf = None)),
        ("exp", Box::new(|c: &mut JwtClaims| c.exp = None)),
    ] {
        let mut modified = claims.clone();
        modify(&mut modified);
        let result = validate_custom(&controller, header(), &modified).await;
        assert!(
            matches!(&result, Err(DomainLinkageError::MissingClaim(missing)) if *missing == name),
            "{name}: {result:?}"
        );
    }

    // `iss` and `sub` equal to `credentialSubject.id`.
    let other = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
    let mut iss = claims.clone();
    iss.iss = Some(other.to_owned());
    iss.additional["vc"]["issuer"] = json!(other);
    assert!(matches!(
        validate_custom(&controller, header(), &iss).await,
        Err(DomainLinkageError::SubjectMismatch { role: "issuer", .. })
    ));
    let mut sub = claims.clone();
    sub.sub = Some(other.to_owned());
    sub.additional["vc"]["credentialSubject"]["id"] = json!(other);
    assert!(matches!(
        validate_custom(&controller, header(), &sub).await,
        Err(DomainLinkageError::SubjectMismatch { role: "issuer", .. })
    ));
    // A registered claim and its property must agree, as for any credential JWT.
    let mut disagreeing = claims.clone();
    disagreeing.sub = Some(other.to_owned());
    assert!(matches!(
        validate_custom(&controller, header(), &disagreeing).await,
        Err(DomainLinkageError::Validation(ValidationError::Credential(
            _
        )))
    ));

    // The credential: no `id`, the context and type, an expiration date, one DID subject with
    // one origin.
    let with_vc = |modify: &dyn Fn(&mut Value)| {
        let mut modified = claims.clone();
        modify(&mut modified.additional["vc"]);
        modified
    };
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["id"] = json!("urn:uuid:1"))
        )
        .await,
        Err(DomainLinkageError::IdPresent)
    ));
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["@context"] = json!(["https://www.w3.org/2018/credentials/v1"]))
        )
        .await,
        Err(DomainLinkageError::MissingContext)
    ));
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["type"] = json!(["VerifiableCredential"]))
        )
        .await,
        Err(DomainLinkageError::MissingType)
    ));
    let mut no_expiry = with_vc(&|vc| {
        vc.as_object_mut().unwrap().remove("expirationDate");
    });
    no_expiry.exp = None;
    assert!(matches!(
        validate_custom(&controller, header(), &no_expiry).await,
        Err(DomainLinkageError::MissingClaim("exp"))
    ));
    // Several subjects cannot carry a `sub`: the credential decoder rejects them first.
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["credentialSubject"] =
                json!([vc["credentialSubject"], vc["credentialSubject"]]))
        )
        .await,
        Err(DomainLinkageError::Validation(ValidationError::Credential(
            _
        )))
    ));
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| {
                vc["credentialSubject"]
                    .as_object_mut()
                    .unwrap()
                    .remove("origin");
            })
        )
        .await,
        Err(DomainLinkageError::InvalidOriginProperty(None))
    ));
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["credentialSubject"]["origin"] = json!(["https://example.com"]))
        )
        .await,
        Err(DomainLinkageError::InvalidOriginProperty(Some(_)))
    ));
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["credentialSubject"]["origin"] = json!("https://other.example"))
        )
        .await,
        Err(DomainLinkageError::OriginMismatch { .. })
    ));
    assert!(matches!(
        validate_custom(
            &controller,
            header(),
            &with_vc(&|vc| vc["credentialSubject"]["origin"] = json!("not a url"))
        )
        .await,
        Err(DomainLinkageError::InvalidOrigin(_))
    ));

    // A subject that is not a DID.
    let mut subject = JwtClaims::new()
        .with_nbf(now())
        .with_exp(now() + chrono::TimeDelta::days(1));
    subject.iss = Some(controller.did.as_str().to_owned());
    subject.sub = Some("https://example.com/me".to_owned());
    let credential = Credential::new(
        controller.did.clone(),
        now(),
        Subject::new(Uri::parse("https://example.com/me").unwrap())
            .with_property("origin", "https://example.com"),
    )
    .with_context(CONTEXT)
    .with_type(CREDENTIAL_TYPE)
    .with_expiration_date(now() + chrono::TimeDelta::days(1));
    subject
        .additional
        .insert("vc".to_owned(), serde_json::to_value(&credential).unwrap());
    assert!(matches!(
        validate_custom(&controller, header(), &subject).await,
        Err(DomainLinkageError::SubjectNotDid(Some(id))) if id == "https://example.com/me"
    ));

    // The signature must be the DID's.
    let impostor = Controller {
        did: controller.did.clone(),
        kid: controller.kid.clone(),
        signer: Ed25519Signer {
            key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
            kid: None,
        },
    };
    assert!(matches!(
        validate_custom(&impostor, header(), &claims).await,
        Err(DomainLinkageError::Validation(ValidationError::Signature(
            _
        )))
    ));
}

// ---------------------------------------------------------------------------------------------
// `LinkedDomains` services
// ---------------------------------------------------------------------------------------------

fn did_document() -> DidDocument {
    serde_json::from_str(include_str!("vectors/did_configuration/did_document.json")).unwrap()
}

fn url(s: &str) -> Url {
    Url::parse(s).unwrap()
}

/// The origins of each `LinkedDomains` service of `document`, as strings.
fn origins_of(document: &DidDocument) -> Vec<Result<(String, Vec<String>), DomainLinkageError>> {
    services(document)
        .map(|linked| {
            linked.map(|linked| {
                let origins = linked
                    .origins
                    .iter()
                    .map(|origin| origin.origin().ascii_serialization())
                    .collect();
                (linked.id().to_string(), origins)
            })
        })
        .collect()
}

#[test]
fn example_did_document_services() {
    let document = did_document();
    let found: Vec<_> = origins_of(&document)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        found,
        [
            (
                "did:example:123#foo".to_owned(),
                vec![
                    "https://foo.example.com".to_owned(),
                    "https://identity.foundation".to_owned()
                ]
            ),
            (
                "did:example:123#bar".to_owned(),
                vec!["https://bar.example.com".to_owned()]
            ),
        ]
    );
    // `service` writes the two forms the example uses.
    for linked in services(&document) {
        let linked = linked.unwrap();
        let rebuilt = service(linked.id().clone(), linked.origins.clone()).unwrap();
        assert_eq!(&rebuilt, linked.service);
    }
}

#[test]
fn service_endpoint_forms() {
    let document: DidDocument = serde_json::from_value(json!({
      "id": "did:example:123",
      "service": [
        { "id": "did:example:123#set", "type": "LinkedDomains",
          "serviceEndpoint": ["https://Example.com/", "https://example.org:8443/path"] },
        { "id": "did:example:123#host", "type": ["LinkedDomains", "Other"],
          "serviceEndpoint": { "origins": ["identity.foundation"], "other": true } },
        { "id": "did:example:123#vp", "type": "LinkedVerifiablePresentation",
          "serviceEndpoint": "https://example.com/vp.jwt" },
        { "id": "did:example:123#map", "type": "LinkedDomains",
          "serviceEndpoint": { "origin": "https://example.com" } },
        { "id": "did:example:123#empty", "type": "LinkedDomains",
          "serviceEndpoint": { "origins": [] } },
        { "id": "did:example:123#number", "type": "LinkedDomains",
          "serviceEndpoint": { "origins": ["https://example.com", 42] } },
        { "id": "did:example:123#mailto", "type": "LinkedDomains",
          "serviceEndpoint": "mailto:someone@example.com" }
      ]
    }))
    .unwrap();
    let found = origins_of(&document);
    assert_eq!(found.len(), 6, "the other service type is ignored");
    assert_eq!(
        found[0].as_ref().unwrap(),
        &(
            "did:example:123#set".to_owned(),
            vec![
                "https://example.com".to_owned(),
                "https://example.org:8443".to_owned()
            ]
        )
    );
    assert_eq!(
        found[1].as_ref().unwrap(),
        &(
            "did:example:123#host".to_owned(),
            vec!["https://identity.foundation".to_owned()]
        )
    );
    for (result, id) in found[2..]
        .iter()
        .zip(["#map", "#empty", "#number", "#mailto"])
    {
        assert!(
            matches!(result, Err(DomainLinkageError::InvalidService { id: found, .. }) if found.as_str().ends_with(id)),
            "{id}: {result:?}"
        );
    }
}

#[test]
fn service_builder() {
    let id = DidUrl::parse("did:example:123#domains").unwrap();
    let one = service(id.clone(), [url("https://Example.com/some/path")]).unwrap();
    assert!(one.has_type(SERVICE_TYPE));
    assert_eq!(
        serde_json::to_value(&one.service_endpoint).unwrap(),
        json!("https://example.com")
    );
    let two = service(
        id.clone(),
        [url("https://example.com"), url("https://example.org")],
    )
    .unwrap();
    assert!(matches!(two.service_endpoint, ServiceEndpoint::Map(_)));
    assert!(matches!(
        service(id.clone(), []),
        Err(DomainLinkageError::InvalidService { .. })
    ));
    assert!(matches!(
        service(id, [url("mailto:someone@example.com")]),
        Err(DomainLinkageError::InvalidService { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------------------------

/// A web serving fixed responses, recording what was fetched; `404` for anything else.
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

const EXAMPLE_RESOURCE_URL: &str = "https://identity.foundation/.well-known/did-configuration.json";

#[tokio::test]
async fn example_resource_fetched_and_validated() {
    let web = Web::default().serving(EXAMPLE_RESOURCE_URL, 200, resource());
    let configuration = fetch_configuration(&web, &origin()).await.unwrap();
    assert_eq!(
        configuration,
        serde_json::from_str::<DomainLinkageConfiguration>(resource()).unwrap()
    );
    // Any URL of the origin names the same resource.
    fetch_configuration(&web, &url("https://identity.foundation/about?x#y"))
        .await
        .unwrap();
    assert_eq!(web.fetched(), [EXAMPLE_RESOURCE_URL, EXAMPLE_RESOURCE_URL]);

    let client = DomainLinkageClient::new(web, validator());
    assert_eq!(client.http().fetched().len(), 2);
    assert!(!client.validator().credential_validator().has_status_check());
    let report = client.validate_origin(&origin(), &at(now())).await.unwrap();
    assert_eq!(report.dids().map(Did::as_str).collect::<Vec<_>>(), [DID]);
    assert!(
        report.failed.is_empty(),
        "the Linked Data Proof entry is data"
    );
    let decoded = client
        .validate_linkage(&Did::parse(DID).unwrap(), &origin(), &at(now()))
        .await
        .unwrap();
    assert_eq!(decoded.credential.issuer.id().as_str(), DID);
    // The example credential expired on 2025-12-04.
    let late = at(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    let error = client.validate_origin(&origin(), &late).await.unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("no domain linkage credential validated: 1: ")
    );
    assert!(matches!(
        error,
        DomainLinkageError::NoValidCredential(errors)
            if matches!(errors.get(&1), Some(DomainLinkageError::Validation(ValidationError::Expired { .. })))
    ));
}

#[tokio::test]
async fn fetch_outcomes() {
    let resource_of = |host: &str| format!("https://{host}/.well-known/did-configuration.json");
    let other_context = json!({ "@context": "https://example.com/other", "linked_dids": [] });
    let web = Web::default()
        .serving(&resource_of("gone.example"), 410, "gone")
        .serving(&resource_of("broken.example"), 500, "oops")
        .serving(&resource_of("moved.example"), 301, Vec::new())
        .failing(&resource_of("down.example"), "connection refused")
        .serving(&resource_of("html.example"), 200, "<html></html>")
        .serving(&resource_of("binary.example"), 200, [0xff, 0xfe])
        .serving(
            &resource_of("other.example"),
            200,
            other_context.to_string(),
        )
        .serving(&resource_of("empty.example"), 200, CONTEXT_ONLY);

    // Not published: `404` (here: anything not served) and `410`.
    for (host, expected) in [("missing.example", 404), ("gone.example", 410)] {
        let error = fetch(&web, host).await.unwrap_err();
        assert!(error.is_not_published(), "{host}");
        assert!(
            matches!(&error, DomainLinkageError::NotPublished { url, status } if *status == expected && url.as_str() == resource_of(host))
        );
    }

    // Other statuses, and no response at all, are failures with their cause.
    for (host, expected) in [("broken.example", 500), ("moved.example", 301)] {
        let error = fetch(&web, host).await.unwrap_err();
        assert!(!error.is_not_published());
        assert!(
            matches!(error, DomainLinkageError::HttpStatus { status, .. } if status == expected),
            "{host}"
        );
    }
    let error = fetch(&web, "down.example").await.unwrap_err();
    assert!(matches!(error, DomainLinkageError::Http { .. }));
    assert_eq!(
        error.source().unwrap().to_string(),
        "connection refused",
        "the `HttpError` is the source"
    );

    // A body that is not a configuration keeps the JSON error as its source.
    for host in ["html.example", "binary.example", "other.example"] {
        let error = fetch(&web, host).await.unwrap_err();
        assert!(
            matches!(&error, DomainLinkageError::InvalidConfiguration { url, .. } if url.as_str() == resource_of(host)),
            "{host}: {error:?}"
        );
        assert!(
            error
                .source()
                .unwrap()
                .downcast_ref::<serde_json::Error>()
                .is_some()
        );
    }
    assert!(
        fetch(&web, "other.example")
            .await
            .unwrap_err()
            .to_string()
            .contains("https://example.com/other")
    );

    // A configuration without credentials fetches, and validates to nothing.
    let empty = fetch(&web, "empty.example").await.unwrap();
    assert!(empty.linked_dids.is_empty());

    // Only HTTPS origins are fetched; nothing reaches the client for the others.
    let before = web.fetched().len();
    assert!(matches!(
        fetch_configuration(&web, &url("http://identity.foundation")).await,
        Err(DomainLinkageError::InsecureOrigin(origin)) if origin == "http://identity.foundation"
    ));
    assert!(matches!(
        fetch_configuration(&web, &url("data:text/plain,x")).await,
        Err(DomainLinkageError::InvalidOrigin(_))
    ));
    assert_eq!(web.fetched().len(), before);

    // The client reports the same outcomes from its validating calls.
    let client = DomainLinkageClient::new(web, validator());
    assert!(
        client
            .validate_origin(&url("https://gone.example"), &at(now()))
            .await
            .unwrap_err()
            .is_not_published()
    );
    assert!(matches!(
        client
            .validate_linkage(
                &Did::parse(DID).unwrap(),
                &url("https://broken.example"),
                &at(now())
            )
            .await,
        Err(DomainLinkageError::HttpStatus { status: 500, .. })
    ));
    assert!(matches!(
        client
            .validate_origin(&url("https://empty.example"), &at(now()))
            .await,
        Err(DomainLinkageError::NoValidCredential(errors)) if errors.is_empty()
    ));
}

/// The configuration of `https://{host}`.
async fn fetch(web: &Web, host: &str) -> Result<DomainLinkageConfiguration, DomainLinkageError> {
    fetch_configuration(web, &url(&format!("https://{host}"))).await
}

const CONTEXT_ONLY: &str = r#"{"@context":"https://identity.foundation/.well-known/did-configuration/v1","linked_dids":[]}"#;

// ---------------------------------------------------------------------------------------------
// A `did:web` and its origins
// ---------------------------------------------------------------------------------------------

const WEB_DID: &str = "did:web:example.com";

/// The document of `did:web:example.com`: the RFC 8037 key under `assertionMethod`, its own
/// origin, one that publishes nothing and one that does not link it, then an invalid entry.
fn web_document(controller: &Controller) -> Value {
    json!({
      "@context": ["https://www.w3.org/ns/did/v1", CONTEXT],
      "id": WEB_DID,
      "verificationMethod": [{
        "id": "did:web:example.com#key-1",
        "type": "JsonWebKey2020",
        "controller": WEB_DID,
        "publicKeyJwk": controller.signer.public_jwk()
      }],
      "assertionMethod": ["did:web:example.com#key-1"],
      "service": [
        { "id": "did:web:example.com#domains", "type": "LinkedDomains",
          "serviceEndpoint": { "origins": ["https://example.com", "https://example.org"] } },
        { "id": "did:web:example.com#identity", "type": "LinkedDomains",
          "serviceEndpoint": "https://identity.foundation" },
        { "id": "did:web:example.com#broken", "type": "LinkedDomains",
          "serviceEndpoint": { "origin": "https://example.com" } }
      ]
    })
}

#[tokio::test]
async fn origins_of_a_did_web_are_reported_one_by_one() {
    let controller = controller();
    let did = Did::parse(WEB_DID).unwrap();
    let kid = DidUrl::parse("did:web:example.com#key-1").unwrap();
    let credential = DomainLinkageCredentialBuilder::new(
        did.clone(),
        &example_com(),
        now() - chrono::TimeDelta::days(1),
        now() + chrono::TimeDelta::days(365),
    )
    .unwrap()
    .sign(&kid, &controller.signer)
    .await
    .unwrap();
    let configuration = DomainLinkageConfiguration::new().with_credential(credential);
    let web = Arc::new(
        Web::default()
            .serving(
                "https://example.com/.well-known/did.json",
                200,
                web_document(&controller).to_string(),
            )
            .serving(
                "https://example.com/.well-known/did-configuration.json",
                200,
                configuration.to_string(),
            )
            .serving(EXAMPLE_RESOURCE_URL, 200, resource()),
    );
    let resolver = Resolver::builder()
        .with(DidKey::default())
        .with(DidWeb::new(Arc::clone(&web)))
        .build();
    let client = DomainLinkageClient::new(
        Arc::clone(&web),
        DomainLinkageValidator::new(resolver, DefaultVerifier),
    );

    let reports = client.validate_did(&did, &at(now())).await.unwrap();
    let summary: Vec<_> = reports
        .iter()
        .map(|report| {
            (
                report.service.fragment().unwrap_or_default().to_owned(),
                report
                    .origin
                    .as_ref()
                    .map(|origin| origin.origin().ascii_serialization()),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("domains".to_owned(), Some("https://example.com".to_owned())),
            ("domains".to_owned(), Some("https://example.org".to_owned())),
            (
                "identity".to_owned(),
                Some("https://identity.foundation".to_owned())
            ),
            ("broken".to_owned(), None),
        ]
    );
    let decoded = reports[0].result.as_ref().unwrap();
    assert_eq!(decoded.credential.issuer.id().as_str(), WEB_DID);
    assert!(reports[1].result.as_ref().unwrap_err().is_not_published());
    assert!(matches!(
        &reports[2].result,
        Err(DomainLinkageError::NoCredentialFor(found)) if *found == did
    ));
    assert!(matches!(
        &reports[3].result,
        Err(DomainLinkageError::InvalidService { .. })
    ));
    // The DID document, then each origin's resource, the DID document again for the key of the
    // one credential the DID issued; the `did:key` of the example resource is never resolved,
    // as its entry is not the DID's.
    assert_eq!(
        web.fetched(),
        [
            "https://example.com/.well-known/did.json",
            "https://example.com/.well-known/did-configuration.json",
            "https://example.com/.well-known/did.json",
            "https://example.org/.well-known/did-configuration.json",
            EXAMPLE_RESOURCE_URL,
        ]
    );

    // A DID document read elsewhere gives the same reports without resolving.
    let document: DidDocument = serde_json::from_value(web_document(&controller)).unwrap();
    assert_eq!(
        client.validate_document(&document, &at(now())).await.len(),
        4
    );

    // A DID that does not resolve is an error of its own.
    assert!(matches!(
        client
            .validate_did(&Did::parse("did:web:example.net").unwrap(), &at(now()))
            .await,
        Err(DomainLinkageError::Resolution(error)) if *error.kind() == ResolutionErrorKind::NotFound
    ));
}
