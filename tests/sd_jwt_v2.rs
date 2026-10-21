//! VCDM 2.0 credentials secured with SD-JWT (VC-JOSE-COSE §3.2.1) and presented in `vp+jwt`
//! presentations (§3.2.2): the SD-JWT credential inputs of the W3C VC-JOSE-COSE test suite,
//! then a credential issued, presented and validated end to end. A `did:key` issuer (the
//! Ed25519 key of RFC 8037 Appendix A.1) signs for a `did:jwk` holder (the P-256 key of RFC
//! 7515 Appendix A.3), who presents with key binding and envelopes the credential in a
//! `vp+jwt` presentation.
#![cfg(all(feature = "sd-jwt", feature = "did-key", feature = "did-jwk"))]

mod common;

use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::claim_path;
use identity_kit::did::{Did, DidUrl, Uri};
use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::Resolver;
use identity_kit::sd_jwt_vc::{
    Disclosure, HashAlgorithm, KeyBinding, KeyBindingOptions, SdJwt, SdJwtBuilder,
    SdJwtCredentialV2, SdJwtCredentialV2Builder, SdJwtCredentialV2Error, SdJwtCredentialValidator,
    SdJwtError, SdJwtStatusCheck, SdJwtValidationError, SdJwtValidationOptions, SdJwtVc,
    SdJwtVcBuilder, SdJwtVcError, Status, StatusListRef,
};
use identity_kit::vc::validation::{
    CredentialValidationOptions, FailFast, JwtPresentationValidator, KeyReference,
    KeyReferenceError, KeyResolutionError, KeyResolver, KeyRole, PresentationValidationError,
    PresentationValidationOptions, PresentedCredentialV2, StatusCheck, StatusError, StatusPolicy,
    TimeOptions, ValidationError, decode_presentation_v2,
};
use identity_kit::vc::{
    CredentialError, CredentialV2, EnvelopedVc, Jwt, JwtClaims, PresentationV2, Subject,
    TypedObject,
};
use serde_json::{Value, json};

use common::{Ed25519Signer, Es256Signer};

// The W3C VC-JOSE-COSE test suite's SD-JWT credential inputs.

fn vector(name: &str) -> &'static str {
    match name {
        "selective" => include_str!("vectors/vc_jose_cose/suite-credential-sdjwt-selective.txt"),
        "selective_json" => include_str!("vectors/vc_jose_cose/suite-credential-selective.json"),
        "nested" => include_str!("vectors/vc_jose_cose/suite-credential-sdjwt-nested.txt"),
        "bad_signature" => {
            include_str!("vectors/vc_jose_cose/suite-credential-sdjwt-bad-signature.txt")
        }
        "bad_media_type" => {
            include_str!("vectors/vc_jose_cose/suite-credential-sdjwt-bad-media-type.txt")
        }
        "vm_p384" => include_str!("vectors/vc_jose_cose/suite-vm-p384.json"),
        "vm_ed25519" => include_str!("vectors/vc_jose_cose/suite-vm-ed25519.json"),
        _ => unreachable!(),
    }
}

fn suite_key(name: &str) -> Jwk {
    let method: Value = serde_json::from_str(vector(name)).unwrap();
    serde_json::from_value(method["publicKeyJwk"].clone()).unwrap()
}

#[test]
fn suite_basic_credential() {
    // Test 20 "SD-JWT Basic Credential Verification": `credential-selective.json` secured with
    // ES384, `credentialSubject.firstName` and `lastName` selectively disclosable, both
    // disclosed.
    let sd_jwt: SdJwt = vector("selective").trim().parse().unwrap();
    let jws = sd_jwt.jwt().decode().unwrap();
    assert_eq!(jws.header().alg, JwsAlgorithm::ES384);
    assert_eq!(jws.header().typ.as_deref(), Some(SdJwtCredentialV2::TYP));
    assert_eq!(jws.header().cty.as_deref(), Some("vc"));
    assert_eq!(
        jws.header().kid.as_deref(),
        Some("96qBnDpvS6x8YSCH_xmnLlXZMkDhHBr8lj99u5aog7s")
    );
    // ES384 is in the algorithm vocabulary but not implemented by the default verifier.
    assert!(jws.verify(&DefaultVerifier, &suite_key("vm_p384")).is_err());

    assert_eq!(sd_jwt.disclosures().len(), 2);
    let processed = sd_jwt.process().unwrap();
    assert!(processed.is_disclosed(&claim_path!["credentialSubject", "firstName"]));
    assert!(processed.is_disclosed(&claim_path!["credentialSubject", "lastName"]));
    assert_eq!(processed.disclosed.len(), 2);
    assert_eq!(processed.undisclosed.len(), 0);

    // The processed payload is the suite's source credential, plus `iss` and an `iat`
    // written as an RFC 3339 string where RFC 7519 wants a NumericDate.
    let mut payload = processed.payload.clone();
    assert_eq!(
        payload.remove("iss"),
        Some(json!("https://example.issuer/vc-jose-cose"))
    );
    assert_eq!(payload.remove("iat"), Some(json!("2024-01-01T00:00:00Z")));
    let source: Value = serde_json::from_str(vector("selective_json")).unwrap();
    assert_eq!(Value::Object(payload), source);

    // So it is not a claims set this crate reads, and not an SD-JWT VC either: `vc+sd-jwt`
    // with `@context` and no `vct` is the VCDM 2.0 type.
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt(sd_jwt.clone()),
        Err(SdJwtCredentialV2Error::Payload(_))
    ));
    assert!(matches!(
        SdJwtVc::from_sd_jwt(sd_jwt.clone()),
        Err(SdJwtVcError::VcdmPayload)
    ));

    // With `iat` as a NumericDate, the payload maps to the suite's credential.
    let mut repaired = processed.payload.clone();
    repaired.insert("iat".to_owned(), json!(1_704_067_200));
    let claims: JwtClaims = serde_json::from_value(Value::Object(repaired)).unwrap();
    let credential = CredentialV2::from_jwt_claims(&claims).unwrap();
    let expected: CredentialV2 = serde_json::from_str(vector("selective_json")).unwrap();
    assert_eq!(credential, expected);
    assert_eq!(
        credential
            .subject()
            .map(|s| s.properties["firstName"].clone()),
        Some(json!("Jane"))
    );
}

#[test]
fn suite_complex_credential() {
    // Test 21 "SD-JWT Complex Credential Verification" is signed with ES512, which is outside
    // the crate's algorithm vocabulary, so the issuer-signed JWT does not decode.
    let text = vector("nested").trim();
    assert!(matches!(SdJwt::parse(text), Err(SdJwtError::Jws(_))));
    // Its disclosures parse on their own: `street`, `city` and the first phone number.
    let parts: Vec<&str> = text.split('~').collect();
    let disclosures: Vec<Disclosure> = parts[1..parts.len() - 1]
        .iter()
        .map(|part| Disclosure::parse(part).unwrap())
        .collect();
    assert_eq!(
        disclosures.iter().map(Disclosure::name).collect::<Vec<_>>(),
        [Some("street"), Some("city"), None]
    );
    assert_eq!(disclosures[2].value()["type"], "work");
}

#[test]
fn suite_bad_signature() {
    // Test 23 "SD-JWT Credential With an Invalid Signature": test 20's credential with its
    // signature bytes rearranged; everything else is the same token.
    let good: SdJwt = vector("selective").trim().parse().unwrap();
    let bad: SdJwt = vector("bad_signature").trim().parse().unwrap();
    let (good_jws, bad_jws) = (good.jwt().decode().unwrap(), bad.jwt().decode().unwrap());
    assert_eq!(good_jws.payload(), bad_jws.payload());
    assert_eq!(good_jws.header(), bad_jws.header());
    assert_ne!(good_jws.signature(), bad_jws.signature());
    assert_eq!(good.disclosures(), bad.disclosures());
    assert_eq!(good.process().unwrap(), bad.process().unwrap());
    assert!(
        bad_jws
            .verify(&DefaultVerifier, &suite_key("vm_p384"))
            .is_err()
    );
}

#[test]
fn suite_bad_media_type() {
    // Test 24 "SD-JWT Credential with an Invalid Media Type": `typ` is `bad+typ`, signed with
    // EdDSA under the suite's Ed25519 key.
    let sd_jwt: SdJwt = vector("bad_media_type").trim().parse().unwrap();
    sd_jwt
        .jwt()
        .decode()
        .unwrap()
        .verify(&DefaultVerifier, &suite_key("vm_ed25519"))
        .unwrap();
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt(sd_jwt.clone()),
        Err(SdJwtCredentialV2Error::UnexpectedTyp(typ)) if typ == "bad+typ"
    ));
    assert!(matches!(
        SdJwtVc::from_sd_jwt(sd_jwt.clone()),
        Err(SdJwtVcError::UnexpectedTyp(typ)) if typ == "bad+typ"
    ));
    // Accepting its `typ` gets as far as the disclosures: the input conceals `issuer`, which a
    // verifier needs before anything else and this crate keeps disclosed.
    let accepted = BTreeSet::from(["bad+typ".to_owned()]);
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt_with(sd_jwt, &accepted),
        Err(SdJwtCredentialV2Error::DisclosedRegisteredClaim(claim)) if claim == "issuer"
    ));
}

// A credential issued, presented and validated end to end.

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
}

const AUDIENCE: &str = "did:example:verifier";
const NONCE: &str = "n-0S6_WzA2Mj";

struct Party {
    did: Did,
    kid: DidUrl,
}

/// The issuer: `did:key` of the RFC 8037 key.
fn issuer() -> (Party, Ed25519Signer) {
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    (Party { did, kid }, signer)
}

/// The holder: `did:jwk` of the RFC 7515 A.3 key, whose verification method is `#0`.
fn holder() -> (Party, Es256Signer) {
    let signer = Es256Signer::rfc7515_a3();
    let did = DidJwk::did(&signer.public_jwk()).unwrap();
    let kid = did.join("#0").unwrap();
    (Party { did, kid }, signer)
}

fn resolver() -> Resolver {
    Resolver::builder()
        .with(DidKey::default())
        .with(DidJwk)
        .build()
}

fn validator() -> SdJwtCredentialValidator<Resolver> {
    SdJwtCredentialValidator::new(resolver(), DefaultVerifier)
}

fn options() -> SdJwtValidationOptions {
    SdJwtValidationOptions::new().with_time(TimeOptions::at(now()))
}

fn key_binding_options() -> KeyBindingOptions {
    KeyBindingOptions::new(AUDIENCE, NONCE).with_time(TimeOptions::at(now()))
}

fn with_key_binding() -> SdJwtValidationOptions {
    options().with_key_binding(key_binding_options())
}

/// The VC-JOSE-COSE credential example's shape, issued about `subject`.
fn credential(issuer: &Did, subject: &Did) -> CredentialV2 {
    CredentialV2::new(
        issuer,
        Subject::new(subject)
            .with_property(
                "degree",
                json!({ "type": "ExampleBachelorDegree", "name": "Bachelor of Science and Arts" }),
            )
            .with_property("alumniOf", json!({ "name": "Example University" })),
    )
    .with_context("https://www.w3.org/ns/credentials/examples/v2")
    .with_id(Uri::parse("http://university.example/credentials/3732").unwrap())
    .with_type("ExampleDegreeCredential")
    .with_valid_from(Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap())
    .with_valid_until(Utc.with_ymd_and_hms(2030, 1, 1, 19, 23, 24).unwrap())
}

/// A builder over the credential, bound to the holder's key: `degree`, `degree.name` and
/// `alumniOf` selectively disclosable, two decoys.
fn builder(credential: CredentialV2) -> SdJwtCredentialV2Builder {
    let (issuer, _) = issuer();
    let (_, holder_signer) = holder();
    SdJwtCredentialV2Builder::new(credential)
        .with_kid(issuer.kid.as_str())
        .with_issued_at(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .with_expires_at(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap())
        .with_holder_key(&holder_signer.public_jwk())
        .conceal(["credentialSubject", "degree"])
        .conceal(["credentialSubject", "degree", "name"])
        .conceal(["credentialSubject", "alumniOf"])
        .with_decoys(2)
}

async fn issue() -> SdJwtCredentialV2 {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();
    builder(credential(&issuer.did, &holder.did))
        .sign(&signer)
        .await
        .unwrap()
}

/// The holder presents `degree` without its name (`select` keeps exactly the chosen
/// disclosures, where `disclose` would keep the ones beneath a path too), with key binding.
async fn present(credential: &SdJwtCredentialV2) -> SdJwtCredentialV2 {
    let (_, signer) = holder();
    credential
        .select(|disclosure| disclosure.name() == Some("degree"))
        .unwrap()
        .sign_key_binding(&KeyBinding::new(AUDIENCE, NONCE, now()), &signer)
        .await
        .unwrap()
}

#[tokio::test]
async fn issued_credential_round_trips() {
    let (issuer, _) = issuer();
    let (holder, holder_signer) = holder();
    let original = credential(&issuer.did, &holder.did);
    let issued = issue().await;

    assert_eq!(issued.header().typ.as_deref(), Some(SdJwtCredentialV2::TYP));
    assert_eq!(issued.header().kid.as_deref(), Some(issuer.kid.as_str()));
    assert_eq!(issued.header().alg, JwsAlgorithm::EdDSA);
    assert_eq!(*issued.credential(), original);
    assert_eq!(issued.claims().iss.as_deref(), Some(issuer.did.as_str()));
    assert_eq!(issued.claims().iat, Some(1_704_067_200));
    assert_eq!(issued.claims().exp, Some(1_893_456_000));
    assert_eq!(issued.holder_key(), Some(&holder_signer.public_jwk()));
    assert!(issued.status().is_none());
    assert_eq!(issued.sd_jwt().disclosures().len(), 3);
    assert!(issued.sd_jwt().key_binding_jwt().is_none());

    // Every disclosure is applied; the issued payload carries the digests and the decoys.
    assert_eq!(issued.processed().disclosed.len(), 3);
    assert!(!issued.payload().contains_key("_sd_alg"));
    let raw = issued.sd_jwt().payload().unwrap();
    assert_eq!(raw["_sd_alg"], "sha-256");
    assert_eq!(raw["credentialSubject"]["_sd"].as_array().unwrap().len(), 4);
    assert_eq!(raw["iss"], issuer.did.as_str());
    assert_eq!(raw["issuer"], issuer.did.as_str());
    assert!(!raw.contains_key("vc"));

    // Compact serialization, `FromStr` and serde agree.
    let text = issued.to_string();
    assert_eq!(SdJwtCredentialV2::parse(&text).unwrap(), issued);
    assert_eq!(text.parse::<SdJwtCredentialV2>().unwrap(), issued);
    assert_eq!(serde_json::to_value(&issued).unwrap(), json!(text));
    assert_eq!(
        serde_json::from_value::<SdJwtCredentialV2>(json!(text)).unwrap(),
        issued
    );
    assert_eq!(issued.clone().into_sd_jwt().to_string(), text);

    // It validates as issued, without key binding.
    let validated = validator()
        .validate_v2(issued.sd_jwt(), &options())
        .await
        .unwrap();
    assert_eq!(validated.credential, issued);
    assert_eq!(
        validated.issuer_key,
        KeyReference::DidUrl(issuer.kid.clone())
    );
    assert!(validated.key_binding.is_none());
    assert!(validated.holder_key.is_none());
    let validated = validator()
        .validate_credential_v2(issued.clone(), &options())
        .await
        .unwrap();
    assert_eq!(validated.credential, issued);
}

#[tokio::test]
async fn presentation_with_key_binding_validates() {
    let issued = issue().await;
    let presented = present(&issued).await;

    // `degree` is disclosed without its `name`; `alumniOf` is not disclosed.
    let subject = presented.credential().subject().unwrap();
    let properties = &subject.properties;
    assert_eq!(
        properties["degree"],
        json!({ "type": "ExampleBachelorDegree" })
    );
    assert!(!properties.contains_key("alumniOf"));
    assert!(
        presented
            .processed()
            .is_disclosed(&claim_path!["credentialSubject", "degree"])
    );
    assert!(!presented.processed().is_disclosed(&claim_path![
        "credentialSubject",
        "degree",
        "name"
    ]));
    assert_eq!(presented.sd_jwt().disclosures().len(), 1);
    assert!(presented.sd_jwt().key_binding_jwt().is_some());
    assert_eq!(presented.credential().issuer, issued.credential().issuer);

    let validated = validator()
        .validate_v2(presented.sd_jwt(), &with_key_binding())
        .await
        .unwrap();
    assert_eq!(validated.credential, presented);
    let key_binding = validated.key_binding.unwrap();
    assert_eq!(key_binding.audiences().collect::<Vec<_>>(), [AUDIENCE]);
    assert_eq!(key_binding.additional["nonce"], NONCE);
    assert_eq!(
        key_binding.additional["sd_hash"],
        presented
            .sd_jwt()
            .sd_hash(presented.sd_jwt().hash_algorithm().unwrap())
    );

    // Without requiring key binding, the key binding JWT is simply not checked.
    let validated = validator()
        .validate_v2(presented.sd_jwt(), &options())
        .await
        .unwrap();
    assert!(validated.key_binding.is_none());

    // `disclose` keeps the disclosures beneath a path too, and drops the key binding.
    let disclosed = presented
        .disclose(&[claim_path!["credentialSubject", "degree"]])
        .unwrap();
    assert_eq!(disclosed.sd_jwt().disclosures().len(), 1);
    assert!(disclosed.sd_jwt().key_binding_jwt().is_none());
    let disclosed = issued
        .disclose(&[claim_path!["credentialSubject", "degree"]])
        .unwrap();
    assert_eq!(disclosed.sd_jwt().disclosures().len(), 2);
    assert_eq!(
        disclosed.credential().subject().unwrap().properties["degree"]["name"],
        "Bachelor of Science and Arts"
    );
    let selected = issued.select(|d| d.name() == Some("alumniOf")).unwrap();
    assert_eq!(selected.sd_jwt().disclosures().len(), 1);
    assert_eq!(
        selected.credential().subject().unwrap().properties["alumniOf"],
        json!({ "name": "Example University" })
    );
}

#[tokio::test]
async fn registered_claims_cannot_be_concealed() {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();
    for claim in [
        "@context",
        "type",
        "issuer",
        "validFrom",
        "validUntil",
        "credentialStatus",
        "credentialSchema",
        "relatedResource",
        "_sd_alg",
        "iss",
        "nbf",
        "exp",
        "cnf",
        "status",
    ] {
        let builder = builder(credential(&issuer.did, &holder.did)).conceal([claim]);
        assert!(
            matches!(
                builder.check_concealed(),
                Err(SdJwtCredentialV2Error::SdJwt(SdJwtError::NotConcealable { path, .. }))
                    if path == claim_path![claim]
            ),
            "{claim}"
        );
        assert!(builder.sign(&signer).await.is_err(), "{claim}");
    }
    // A property inside the subject may be concealed; `credentialSubject` itself may too.
    let builder = builder(credential(&issuer.did, &holder.did)).conceal(["credentialSubject"]);
    assert!(builder.check_concealed().is_ok());
    let signed = builder.sign(&signer).await.unwrap();
    assert_eq!(signed.sd_jwt().disclosures().len(), 4);

    // An SD-JWT built by hand with `issuer` concealed is refused when parsed, whether or not
    // the disclosure is presented: the digest alone hides the issuer.
    let mut claims = credential(&issuer.did, &holder.did).to_jwt_claims();
    claims.iss = Some(issuer.did.to_string());
    let claims = serde_json::to_value(&claims).unwrap();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(SdJwtCredentialV2::TYP)
        .with_kid(issuer.kid.as_str());
    let sd_jwt = SdJwtBuilder::new(claims.as_object().unwrap().clone())
        .conceal(["issuer"])
        .sign(&header, &signer)
        .await
        .unwrap();
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt(sd_jwt.clone()),
        Err(SdJwtCredentialV2Error::DisclosedRegisteredClaim(claim)) if claim == "issuer"
    ));
    // Withheld, the digest hides nothing the verifier needs: `iss`, which cannot be
    // concealed and is bound to the signing key, fills `issuer`.
    let hidden = sd_jwt.select(|_| false).unwrap();
    let credential = SdJwtCredentialV2::from_sd_jwt(hidden).unwrap();
    assert_eq!(
        credential.credential().issuer.id().as_str(),
        issuer.did.as_str()
    );
    assert!(credential.payload().get("issuer").is_none());
}

/// A VCDM 2.0 payload secured by hand under `typ`.
async fn vcdm_sd_jwt(typ: Option<&str>) -> SdJwt {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();
    let mut claims = credential(&issuer.did, &holder.did).to_jwt_claims();
    claims.iss = Some(issuer.did.to_string());
    let claims = serde_json::to_value(&claims).unwrap();
    let mut header = JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(issuer.kid.as_str());
    header.typ = typ.map(str::to_owned);
    SdJwtBuilder::new(claims.as_object().unwrap().clone())
        .conceal(["credentialSubject", "alumniOf"])
        .sign(&header, &signer)
        .await
        .unwrap()
}

#[tokio::test]
async fn typ_routes_between_the_two_credential_types() {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();

    // A VCDM 2.0 payload under `dc+sd-jwt` is neither: not this type by `typ`, not an
    // SD-JWT VC by its claims.
    let wrong_typ = vcdm_sd_jwt(Some("dc+sd-jwt")).await;
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt(wrong_typ.clone()),
        Err(SdJwtCredentialV2Error::UnexpectedTyp(typ)) if typ == "dc+sd-jwt"
    ));
    assert!(matches!(
        SdJwtVc::from_sd_jwt(wrong_typ.clone()),
        Err(SdJwtVcError::Claims(reason)) if reason.contains("vct")
    ));
    // Unless the caller accepts that `typ`.
    let accepted = BTreeSet::from(["dc+sd-jwt".to_owned()]);
    assert!(SdJwtCredentialV2::from_sd_jwt_with(wrong_typ.clone(), &accepted).is_ok());
    let error = validator()
        .validate_v2(&wrong_typ, &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::CredentialV2(SdJwtCredentialV2Error::UnexpectedTyp(_))
    ));
    validator()
        .validate_v2(&wrong_typ, &options().with_additional_typ("dc+sd-jwt"))
        .await
        .unwrap();

    // An SD-JWT VC under the pre-standard `vc+sd-jwt` stays an SD-JWT VC: it has `vct`. Read
    // as a VCDM 2.0 credential, it lacks `@context`.
    let standard = SdJwtVcBuilder::new("https://credentials.example.com/identity_credential")
        .with_issuer(issuer.did.as_str())
        .with_kid(issuer.kid.as_str())
        .with_claim("given_name", "Erika")
        .conceal(["given_name"])
        .sign(&signer)
        .await
        .unwrap();
    assert!(!standard.has_legacy_typ());
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("vc+sd-jwt")
        .with_kid(issuer.kid.as_str());
    let legacy = SdJwtBuilder::new(
        json!({
            "vct": "https://credentials.example.com/identity_credential",
            "iss": issuer.did.as_str(),
            "given_name": "Erika"
        })
        .as_object()
        .unwrap()
        .clone(),
    )
    .conceal(["given_name"])
    .sign(&header, &signer)
    .await
    .unwrap();
    let parsed = SdJwtVc::from_sd_jwt(legacy.clone()).unwrap();
    assert!(parsed.has_legacy_typ());
    assert_eq!(parsed.claims().claims["given_name"], "Erika");
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt(legacy),
        Err(SdJwtCredentialV2Error::Credential(CredentialError::InvalidClaim { claim, .. }))
            if claim == "@context"
    ));

    // Without `typ`, a VCDM 2.0 payload is accepted here (VC-JOSE-COSE: `typ` SHOULD be
    // `vc+sd-jwt`) and refused as an SD-JWT VC, which requires one.
    let untyped = vcdm_sd_jwt(None).await;
    let credential = SdJwtCredentialV2::from_sd_jwt(untyped.clone()).unwrap();
    assert!(credential.header().typ.is_none());
    assert_eq!(
        *credential.credential(),
        self::credential(&issuer.did, &holder.did)
    );
    assert!(matches!(
        SdJwtVc::from_sd_jwt(untyped.clone()),
        Err(SdJwtVcError::MissingTyp)
    ));
    validator().validate_v2(&untyped, &options()).await.unwrap();

    // Disclosing from a credential accepted under another `typ` keeps accepting it.
    let custom = SdJwt::parse(&vcdm_sd_jwt(Some("custom+sd-jwt")).await.to_string()).unwrap();
    let accepted = BTreeSet::from(["custom+sd-jwt".to_owned()]);
    let credential = SdJwtCredentialV2::from_sd_jwt_with(custom, &accepted).unwrap();
    let disclosed = credential
        .disclose(&[claim_path!["credentialSubject", "alumniOf"]])
        .unwrap();
    assert_eq!(disclosed.header().typ.as_deref(), Some("custom+sd-jwt"));
    assert!(credential.select(|_| false).is_ok());
}

/// A resolver that finds no key under `assertionMethod`.
struct AuthenticationOnly(Resolver);

#[async_trait::async_trait]
impl KeyResolver for AuthenticationOnly {
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError> {
        if role == KeyRole::Issuer {
            return Err(KeyResolutionError::msg("not an assertion method"));
        }
        self.0.resolve_key(key, role).await
    }
}

#[tokio::test]
async fn issuer_binding_and_time_errors() {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();

    // The credential's `issuer` is not the DID of `kid`.
    let other = Did::parse("did:example:other").unwrap();
    let mismatched = builder(credential(&other, &holder.did))
        .sign(&signer)
        .await
        .unwrap();
    assert_eq!(
        mismatched.claims().iss.as_deref(),
        Some("did:example:other")
    );
    let error = validator()
        .validate_v2(mismatched.sd_jwt(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::IssuerMismatch { issuer, key })
            if issuer.as_str() == "did:example:other" && *key == KeyReference::DidUrl(issuer_kid())
    ));

    // An HTTPS issuer does not control the key of a DID, whatever the DID URL in `kid`.
    let mut https_credential = credential(&issuer.did, &holder.did);
    https_credential.issuer = Uri::parse("https://university.example/issuers/14")
        .unwrap()
        .into();
    let https = builder(https_credential).sign(&signer).await.unwrap();
    assert!(matches!(
        validator().validate_v2(https.sd_jwt(), &options()).await.unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::IssuerMismatch { issuer, key })
            if issuer.as_str() == "https://university.example/issuers/14"
                && *key == KeyReference::DidUrl(issuer_kid())
    ));

    // `iss` disagreeing with `issuer` is caught when parsing.
    let mut claims = credential(&issuer.did, &holder.did).to_jwt_claims();
    claims.iss = Some("did:example:other".to_owned());
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(SdJwtCredentialV2::TYP)
        .with_kid(issuer.kid.as_str());
    let disagreeing = SdJwtBuilder::new(
        serde_json::to_value(&claims)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
    )
    .sign(&header, &signer)
    .await
    .unwrap();
    assert!(matches!(
        SdJwtCredentialV2::from_sd_jwt(disagreeing),
        Err(SdJwtCredentialV2Error::Credential(
            CredentialError::ClaimMismatch { claim: "iss", .. }
        ))
    ));

    // The signing key is found only under `authentication`.
    let issued = issue().await;
    let strict = SdJwtCredentialValidator::new(AuthenticationOnly(resolver()), DefaultVerifier);
    assert!(matches!(
        strict.validate_v2(issued.sd_jwt(), &options()).await.unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::KeyResolution { key, .. })
            if *key == KeyReference::DidUrl(issuer_kid())
    ));

    // A tampered payload does not verify.
    let text = issued.to_string();
    let (jwt, rest) = text.split_once('~').unwrap();
    let mut parts: Vec<&str> = jwt.split('.').collect();
    let payload = common::encode(
        serde_json::to_vec(&json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": "VerifiableCredential",
            "issuer": issuer.did.as_str(),
            "credentialSubject": { "id": holder.did.as_str() }
        }))
        .unwrap()
        .as_slice(),
    );
    parts[1] = &payload;
    // Without the disclosures, which the new payload references nowhere.
    let _ = rest;
    let tampered = SdJwt::parse(&format!("{}~", parts.join("."))).unwrap();
    assert!(matches!(
        validator()
            .validate_v2(&tampered, &options())
            .await
            .unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::Signature(_))
    ));

    // The validity period and the time claims hold at the validation time.
    let at = |time: DateTime<Utc>| options().with_time(TimeOptions::at(time));
    assert!(matches!(
        validator()
            .validate_v2(issued.sd_jwt(), &at(Utc.with_ymd_and_hms(2031, 1, 1, 0, 0, 0).unwrap()))
            .await
            .unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::Expired { expired_at, .. })
            if expired_at == Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()
    ));
    assert!(matches!(
        validator()
            .validate_v2(
                issued.sd_jwt(),
                &at(Utc.with_ymd_and_hms(2009, 1, 1, 0, 0, 0).unwrap())
            )
            .await
            .unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::IssuedInFuture { .. })
    ));
    let not_yet = builder(
        credential(&issuer.did, &holder.did)
            .with_valid_from(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
    )
    .sign(&signer)
    .await
    .unwrap();
    assert!(matches!(
        validator().validate_v2(not_yet.sd_jwt(), &options()).await.unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::NotYetValid { not_before, .. })
            if not_before == Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    ));
    let expired = builder(
        credential(&issuer.did, &holder.did)
            .with_valid_until(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
    )
    .sign(&signer)
    .await
    .unwrap();
    assert!(matches!(
        validator().validate_v2(expired.sd_jwt(), &options()).await.unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::Expired { expired_at, .. })
            if expired_at == Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
    ));
}

fn issuer_kid() -> DidUrl {
    issuer().0.kid
}

#[tokio::test]
async fn key_binding_errors() {
    let (issuer, issuer_signer) = issuer();
    let (holder, holder_signer) = holder();
    let issued = issue().await;
    let presented = present(&issued).await;

    // Required but absent.
    assert!(matches!(
        validator()
            .validate_v2(issued.sd_jwt(), &with_key_binding())
            .await
            .unwrap_err(),
        SdJwtValidationError::KeyBindingRequired
    ));

    // No holder key in the credential.
    let unbound = SdJwtCredentialV2Builder::new(credential(&issuer.did, &holder.did))
        .with_kid(issuer.kid.as_str())
        .sign(&issuer_signer)
        .await
        .unwrap()
        .sign_key_binding(&KeyBinding::new(AUDIENCE, NONCE, now()), &holder_signer)
        .await
        .unwrap();
    assert!(unbound.confirmation().is_none());
    assert!(matches!(
        validator()
            .validate_v2(unbound.sd_jwt(), &with_key_binding())
            .await
            .unwrap_err(),
        SdJwtValidationError::NoHolderKey(KeyReferenceError::Missing)
    ));

    // The key binding JWT covers another set of disclosures.
    let kb_jwt = presented.sd_jwt().key_binding_jwt().unwrap().clone();
    let swapped = SdJwt::new(
        issued.sd_jwt().jwt().clone(),
        issued.sd_jwt().disclosures().to_vec(),
    )
    .with_key_binding(kb_jwt);
    assert!(matches!(
        validator()
            .validate_v2(&swapped, &with_key_binding())
            .await
            .unwrap_err(),
        SdJwtValidationError::SdHashMismatch { .. }
    ));

    // Signed by a key other than the one in `cnf`.
    let foreign = issued
        .disclose(&[claim_path!["credentialSubject", "degree"]])
        .unwrap()
        .sign_key_binding(&KeyBinding::new(AUDIENCE, NONCE, now()), &issuer_signer)
        .await
        .unwrap();
    assert!(matches!(
        validator()
            .validate_v2(foreign.sd_jwt(), &with_key_binding())
            .await
            .unwrap_err(),
        SdJwtValidationError::Validation(ValidationError::Signature(_))
    ));

    // For another verifier, or another transaction.
    for (audience, nonce) in [("did:example:other", NONCE), (AUDIENCE, "other")] {
        let required = KeyBindingOptions::new(audience, nonce).with_time(TimeOptions::at(now()));
        let error = validator()
            .validate_v2(presented.sd_jwt(), &options().with_key_binding(required))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                SdJwtValidationError::Validation(
                    ValidationError::AudienceMismatch { .. }
                        | ValidationError::NonceMismatch { .. }
                )
            ),
            "{audience} {nonce}: {error}"
        );
    }
}

/// A status check that finds every credential revoked.
struct Revoked;

#[async_trait::async_trait]
impl StatusCheck for Revoked {
    async fn check(&self, status: &TypedObject) -> Result<(), StatusError> {
        assert_eq!(status.object_type(), "BitstringStatusListEntry");
        Err(StatusError::Invalid("revoked".to_owned()))
    }
}

#[async_trait::async_trait]
impl SdJwtStatusCheck for Revoked {
    async fn check(&self, status: &Status, _now: DateTime<Utc>) -> Result<(), StatusError> {
        assert_eq!(status.status_list.as_ref().unwrap().idx, 7);
        Err(StatusError::Invalid("revoked".to_owned()))
    }
}

/// A status check that finds every credential valid.
struct Valid;

#[async_trait::async_trait]
impl StatusCheck for Valid {
    async fn check(&self, _status: &TypedObject) -> Result<(), StatusError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl SdJwtStatusCheck for Valid {
    async fn check(&self, _status: &Status, _now: DateTime<Utc>) -> Result<(), StatusError> {
        Ok(())
    }
}

/// A credential with a `credentialStatus` entry and a `status` claim.
async fn with_statuses() -> SdJwtCredentialV2 {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();
    builder(
        credential(&issuer.did, &holder.did).with_status(
            TypedObject::new("BitstringStatusListEntry")
                .with_id(Uri::parse("https://university.example/status/3#94567").unwrap()),
        ),
    )
    .with_status(Status::status_list(StatusListRef::new(
        "https://university.example/status/sd-jwt",
        7,
    )))
    .sign(&signer)
    .await
    .unwrap()
}

#[tokio::test]
async fn status_policies() {
    let credential = with_statuses().await;
    assert_eq!(
        credential
            .status()
            .unwrap()
            .status_list
            .as_ref()
            .unwrap()
            .idx,
        7
    );
    assert_eq!(credential.credential().statuses().count(), 1);
    assert_eq!(
        credential.claims().additional["status"]["status_list"]["idx"],
        7
    );

    // Under `Strict`, both must be checked; `credentialStatus` comes first.
    let error = validator()
        .validate_v2(credential.sd_jwt(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::StatusUnchecked(kind))
            if kind == "BitstringStatusListEntry"
    ));
    let error = validator()
        .with_credential_status_check(Valid)
        .validate_v2(credential.sd_jwt(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::StatusUnchecked(kind))
            if kind == "status_list"
    ));
    validator()
        .with_credential_status_check(Valid)
        .with_status_check(Valid)
        .validate_v2(credential.sd_jwt(), &options())
        .await
        .unwrap();

    // Either check finding the credential revoked fails it.
    let error = validator()
        .with_credential_status_check(Revoked)
        .with_status_check(Valid)
        .validate_v2(credential.sd_jwt(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::Status(StatusError::Invalid(status)))
            if status == "revoked"
    ));
    let error = validator()
        .with_credential_status_check(Valid)
        .with_status_check(Revoked)
        .validate_v2(credential.sd_jwt(), &options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::Status(StatusError::Invalid(_)))
    ));

    // `SkipUnsupported` passes without checks, `SkipAll` even past a revocation.
    validator()
        .validate_v2(
            credential.sd_jwt(),
            &options().with_status(StatusPolicy::SkipUnsupported),
        )
        .await
        .unwrap();
    validator()
        .with_credential_status_check(Revoked)
        .with_status_check(Revoked)
        .validate_v2(
            credential.sd_jwt(),
            &options().with_status(StatusPolicy::SkipAll),
        )
        .await
        .unwrap();
    let validator = validator()
        .with_credential_status_check(Valid)
        .with_status_check(Valid);
    assert!(validator.has_status_check());
    assert!(validator.has_credential_status_check());
    assert!(format!("{validator:?}").contains("StatusCheck"));
}

// Presentations.

fn presentation_validator() -> JwtPresentationValidator<Resolver> {
    JwtPresentationValidator::new(resolver(), DefaultVerifier)
}

fn presentation_options() -> PresentationValidationOptions {
    PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_audience(AUDIENCE)
        .with_nonce(NONCE)
        .with_credentials(CredentialValidationOptions::new().with_time(TimeOptions::at(now())))
}

/// `credential` signed by the issuer as a `vc+jwt`.
async fn issue_jwt(credential: &CredentialV2) -> Jwt {
    let (issuer, signer) = issuer();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(CredentialV2::JWT_TYP)
        .with_kid(issuer.kid.as_str());
    Jwt::sign(&header, &credential.to_jwt_claims(), &signer)
        .await
        .unwrap()
}

/// A `vp+jwt` by the holder enveloping `credentials`, for the verifier's audience and nonce.
async fn present_vp(credentials: impl IntoIterator<Item = EnvelopedVc>) -> (PresentationV2, Jwt) {
    let (holder, signer) = holder();
    let presentation = credentials.into_iter().fold(
        PresentationV2::new()
            .with_id(Uri::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").unwrap())
            .with_holder(&holder.did),
        PresentationV2::with_credential,
    );
    let claims = presentation
        .to_jwt_claims()
        .with_aud(AUDIENCE)
        .with_claim("nonce", NONCE)
        .with_iat(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .with_exp(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    let header = JwsHeader::new(JwsAlgorithm::ES256)
        .with_typ(PresentationV2::JWT_TYP)
        .with_kid(holder.kid.as_str());
    (
        presentation,
        Jwt::sign(&header, &claims, &signer).await.unwrap(),
    )
}

fn credential_errors(error: PresentationValidationError) -> Vec<(usize, ValidationError)> {
    assert!(error.presentation.is_none(), "{error:?}");
    error.credentials.into_iter().collect()
}

#[tokio::test]
async fn enveloped_sd_jwt_round_trips() {
    let issued = issue().await;
    let presented = present(&issued).await;
    let enveloped = EnvelopedVc::from_sd_jwt(presented.sd_jwt());
    assert_eq!(enveloped.media_type(), EnvelopedVc::SD_JWT_MEDIA_TYPE);
    assert_eq!(enveloped.media_type(), "application/vc+sd-jwt");
    assert_eq!(enveloped.data(), presented.to_string());
    assert!(enveloped.is_sd_jwt());
    assert_eq!(enveloped.to_sd_jwt().unwrap(), *presented.sd_jwt());
    assert!(matches!(
        enveloped.to_jwt(),
        Err(CredentialError::UnsupportedMediaType { media_type, expected: "application/vc+jwt", .. })
            if media_type == "application/vc+sd-jwt"
    ));
    let json = serde_json::to_value(&enveloped).unwrap();
    assert_eq!(json["type"], "EnvelopedVerifiableCredential");
    assert!(
        json["id"]
            .as_str()
            .unwrap()
            .starts_with("data:application/vc+sd-jwt,ey")
    );
    assert_eq!(
        serde_json::from_value::<EnvelopedVc>(json).unwrap(),
        enveloped
    );

    // A JWT envelope is not an SD-JWT one.
    let jwt = EnvelopedVc::from_jwt(&issue_jwt(issued.credential()).await);
    assert!(!jwt.is_sd_jwt());
    assert!(matches!(
        jwt.to_sd_jwt(),
        Err(CredentialError::UnsupportedMediaType {
            expected: "application/vc+sd-jwt",
            ..
        })
    ));
    // Nor is a base64 one, or one whose data is not an SD-JWT.
    let base64 = EnvelopedVc::new("application/vc+sd-jwt;base64", "AAAA").unwrap();
    assert!(!base64.is_sd_jwt());
    assert!(matches!(
        base64.to_sd_jwt(),
        Err(CredentialError::UnsupportedMediaType { media_type, .. })
            if media_type == "application/vc+sd-jwt;base64"
    ));
    let garbage = EnvelopedVc::new("application/vc+sd-jwt", "not-an-sd-jwt").unwrap();
    assert!(garbage.is_sd_jwt());
    assert!(matches!(
        garbage.to_sd_jwt(),
        Err(CredentialError::InvalidClaim { claim: "id", .. })
    ));
}

#[tokio::test]
async fn presentation_with_sd_jwt_and_jwt_credentials_validates() {
    let (issuer, _) = issuer();
    let (holder, _) = holder();
    let issued = issue().await;
    let presented = present(&issued).await;
    let plain = credential(&issuer.did, &holder.did)
        .with_id(Uri::parse("http://university.example/credentials/1872").unwrap());
    let (presentation, vp) = present_vp([
        EnvelopedVc::from_sd_jwt(presented.sd_jwt()),
        EnvelopedVc::from_jwt(&issue_jwt(&plain).await),
    ])
    .await;

    let decoded = presentation_validator()
        .validate_v2(&vp, &presentation_options())
        .await
        .unwrap();
    assert_eq!(
        decoded.presentation,
        presentation.clone().with_property("nonce", NONCE)
    );
    assert_eq!(decoded.holder(), Some(&Uri::from(holder.did.clone())));
    let [first, second] = decoded.credentials.as_slice() else {
        panic!("two credentials in order");
    };
    assert_eq!(first.as_sd_jwt(), Some(&presented));
    assert!(first.as_jwt().is_none());
    assert_eq!(first.credential(), presented.credential());
    assert_eq!(first.header().typ.as_deref(), Some("vc+sd-jwt"));
    assert!(matches!(first, PresentedCredentialV2::SdJwt(_)));
    assert_eq!(second.as_jwt().map(|d| &d.credential), Some(&plain));
    assert!(second.as_sd_jwt().is_none());
    assert_eq!(second.credential(), &plain);
    assert_eq!(second.header().typ.as_deref(), Some("vc+jwt"));

    // Requiring key binding of enveloped SD-JWTs: the presented one carries it.
    presentation_validator()
        .validate_v2(
            &vp,
            &presentation_options().with_key_binding(key_binding_options()),
        )
        .await
        .unwrap();

    // Decoding without validating gives the same credentials.
    let unverified = decode_presentation_v2(&vp).unwrap();
    assert_eq!(unverified.presentation, decoded.presentation);
    assert_eq!(unverified.credentials[0].as_sd_jwt(), Some(&presented));
    assert_eq!(unverified.credentials[1].credential(), &plain);
}

#[tokio::test]
async fn presentation_credential_errors_are_reported_by_index() {
    let (issuer, signer) = issuer();

    let issued = issue().await;
    let all_errors = || presentation_options().with_fail_fast(FailFast::AllErrors);

    // Key binding required of the enveloped SD-JWT, which has none; a COSE envelope; a JWT
    // credential whose subject is not the holder; an SD-JWT credential whose subject is not
    // the holder.
    let stranger = credential(&issuer.did, &Did::parse("did:example:stranger").unwrap());
    let stranger_sd_jwt = builder(stranger.clone()).sign(&signer).await.unwrap();
    let (_, vp) = present_vp([
        EnvelopedVc::from_sd_jwt(issued.sd_jwt()),
        EnvelopedVc::new("application/vc+cose;base64", "AAAA").unwrap(),
        EnvelopedVc::from_jwt(&issue_jwt(&stranger).await),
        EnvelopedVc::from_sd_jwt(stranger_sd_jwt.sd_jwt()),
    ])
    .await;
    let errors = credential_errors(
        presentation_validator()
            .validate_v2(&vp, &all_errors().with_key_binding(key_binding_options()))
            .await
            .unwrap_err(),
    );
    assert_eq!(errors.len(), 4);
    assert!(matches!(
        &errors[0],
        (0, ValidationError::SdJwt(error))
            if matches!(**error, SdJwtValidationError::KeyBindingRequired)
    ));
    assert!(matches!(
        &errors[1],
        (1, ValidationError::Credential(CredentialError::UnsupportedMediaType { media_type, .. }))
            if media_type == "application/vc+cose;base64"
    ));
    assert!(matches!(
        &errors[2],
        (2, ValidationError::SubjectHolderMismatch { subject: Some(subject), .. })
            if subject.as_str() == "did:example:stranger"
    ));
    // Key binding is checked before the subject is compared with the holder.
    assert!(matches!(
        &errors[3],
        (3, ValidationError::SdJwt(error))
            if matches!(**error, SdJwtValidationError::KeyBindingRequired)
    ));

    // Without requiring key binding, the first passes and the last fails on its subject.
    let errors = credential_errors(
        presentation_validator()
            .validate_v2(&vp, &all_errors())
            .await
            .unwrap_err(),
    );
    assert_eq!(
        errors.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(matches!(
        &errors[2],
        (3, ValidationError::SubjectHolderMismatch { subject: Some(subject), .. })
            if subject.as_str() == "did:example:stranger"
    ));
    // `FirstError` stops at the COSE one.
    let errors = credential_errors(
        presentation_validator()
            .validate_v2(&vp, &presentation_options())
            .await
            .unwrap_err(),
    );
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, 1);

    // Decoding stops at the COSE envelope too.
    assert!(matches!(
        decode_presentation_v2(&vp),
        Err(ValidationError::Credential(
            CredentialError::UnsupportedMediaType { .. }
        ))
    ));

    // An SD-JWT credential that does not parse is reported for its index: here the issuer's
    // signature is checked only after the credential is read.
    let (_, vp) = present_vp([EnvelopedVc::new(
        "application/vc+sd-jwt",
        &vcdm_sd_jwt(Some("dc+sd-jwt")).await.to_string(),
    )
    .unwrap()])
    .await;
    let errors = credential_errors(
        presentation_validator()
            .validate_v2(&vp, &presentation_options())
            .await
            .unwrap_err(),
    );
    assert!(matches!(
        &errors[0],
        (0, ValidationError::SdJwt(error))
            if matches!(
                &**error,
                SdJwtValidationError::CredentialV2(SdJwtCredentialV2Error::UnexpectedTyp(typ))
                    if typ == "dc+sd-jwt"
            )
    ));
    assert!(matches!(
        decode_presentation_v2(&vp),
        Err(ValidationError::SdJwt(_))
    ));
    // The credential options' `additional_typ` applies to enveloped SD-JWTs too.
    presentation_validator()
        .validate_v2(
            &vp,
            &presentation_options().with_credentials(
                CredentialValidationOptions::new()
                    .with_time(TimeOptions::at(now()))
                    .with_additional_typ("dc+sd-jwt"),
            ),
        )
        .await
        .unwrap();

    // A tampered SD-JWT credential fails its signature check, for its index.
    let text = issued.to_string();
    let (jwt, rest) = text.split_once('~').unwrap();
    let mut parts: Vec<&str> = jwt.split('.').collect();
    let signature = common::encode(&[0u8; 64]);
    parts[2] = &signature;
    let (_, vp) = present_vp([EnvelopedVc::new(
        "application/vc+sd-jwt",
        &format!("{}~{rest}", parts.join(".")),
    )
    .unwrap()])
    .await;
    let errors = credential_errors(
        presentation_validator()
            .validate_v2(&vp, &presentation_options())
            .await
            .unwrap_err(),
    );
    assert!(matches!(&errors[0], (0, ValidationError::Signature(_))));
}

#[tokio::test]
async fn presentation_status_checks() {
    let credential = with_statuses().await;
    let (_, vp) = present_vp([EnvelopedVc::from_sd_jwt(credential.sd_jwt())]).await;

    // `credentialStatus` goes through the presentation validator's check, per the policy.
    let errors = credential_errors(
        presentation_validator()
            .validate_v2(&vp, &presentation_options())
            .await
            .unwrap_err(),
    );
    assert!(matches!(
        &errors[0],
        (0, ValidationError::StatusUnchecked(kind)) if kind == "BitstringStatusListEntry"
    ));
    let errors = credential_errors(
        presentation_validator()
            .with_status_check(Revoked)
            .validate_v2(&vp, &presentation_options())
            .await
            .unwrap_err(),
    );
    assert!(matches!(
        &errors[0],
        (0, ValidationError::Status(StatusError::Invalid(_)))
    ));
    // The `status` claim is not checked inside a presentation: with `credentialStatus`
    // passing, the credential passes, and the claim is there for the application to check.
    let decoded = presentation_validator()
        .with_status_check(Valid)
        .validate_v2(&vp, &presentation_options())
        .await
        .unwrap();
    assert_eq!(
        decoded.credentials[0]
            .as_sd_jwt()
            .unwrap()
            .status()
            .unwrap()
            .status_list
            .as_ref()
            .unwrap()
            .idx,
        7
    );
    presentation_validator()
        .validate_v2(
            &vp,
            &presentation_options().with_credentials(
                CredentialValidationOptions::new()
                    .with_time(TimeOptions::at(now()))
                    .with_status(StatusPolicy::SkipUnsupported),
            ),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn issuance_is_deterministic_with_fixed_salts() {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();
    let salts = || {
        let mut counter = 0u32;
        move || {
            counter += 1;
            format!("salt-{counter:04}")
        }
    };
    let issue = || async {
        builder(credential(&issuer.did, &holder.did))
            .with_salt_generator(salts())
            .sign(&signer)
            .await
            .unwrap()
    };
    let (first, second) = (issue().await, issue().await);
    assert_eq!(first, second);
    assert_eq!(first.to_string(), second.to_string());
    // The three disclosures and the decoys each took a salt from the sequence.
    let salts: BTreeSet<&str> = first
        .sd_jwt()
        .disclosures()
        .iter()
        .map(Disclosure::salt)
        .collect();
    assert_eq!(salts.len(), 3);
    assert!(salts.iter().all(|salt| salt.starts_with("salt-000")));
    // Another salt sequence changes the digests and the disclosures but not the credential.
    let mut counter = 0u32;
    let other = builder(credential(&issuer.did, &holder.did))
        .with_salt_generator(move || {
            counter += 1;
            format!("other-{counter:04}")
        })
        .sign(&signer)
        .await
        .unwrap();
    assert_ne!(other.to_string(), first.to_string());
    assert_eq!(other.credential(), first.credential());
}

#[tokio::test]
async fn builder_setters_and_debug_output() {
    let (issuer, signer) = issuer();
    let (holder, _) = holder();
    let original = credential(&issuer.did, &holder.did);
    let builder = builder(original.clone())
        .with_not_before(Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap())
        .with_hash_algorithm(HashAlgorithm::Sha384);
    assert_eq!(*builder.credential(), original);
    let debug = format!("{builder:?}");
    assert!(debug.starts_with("SdJwtCredentialV2Builder {"));
    assert!(debug.contains("alg: Sha384"));
    assert!(debug.contains("concealed: ["));
    assert!(debug.ends_with(", .. }"));

    // A copy of the credential alone: nothing concealed, nothing else set.
    let bare = builder.clone_credential().sign(&signer).await.unwrap();
    assert!(bare.sd_jwt().disclosures().is_empty());
    assert!(bare.confirmation().is_none());
    assert_eq!(bare.claims().nbf, None);
    assert_eq!(bare.header().kid.as_deref(), None);

    let signed = builder.sign(&signer).await.unwrap();
    assert_eq!(signed.claims().nbf, Some(1_717_200_000));
    assert_eq!(
        signed.sd_jwt().hash_algorithm().unwrap(),
        HashAlgorithm::Sha384
    );
    let debug = format!("{signed:?}");
    assert!(debug.starts_with("SdJwtCredentialV2 {"));
    assert!(debug.contains("cnf: Some("));
    assert!(debug.contains("status: None"));
    assert!(debug.ends_with(", .. }"));
    validator()
        .validate_v2(signed.sd_jwt(), &options())
        .await
        .unwrap();

    // `cnf` and `status` must be what the claims hold.
    for (claim, value) in [("cnf", json!("not an object")), ("status", json!(5))] {
        let mut claims = original.to_jwt_claims();
        claims.iss = Some(issuer.did.to_string());
        claims.additional.insert(claim.to_owned(), value);
        let header = JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_typ(SdJwtCredentialV2::TYP)
            .with_kid(issuer.kid.as_str());
        let sd_jwt = SdJwtBuilder::new(
            serde_json::to_value(&claims)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
        )
        .sign(&header, &signer)
        .await
        .unwrap();
        assert!(
            matches!(
                SdJwtCredentialV2::from_sd_jwt(sd_jwt),
                Err(SdJwtCredentialV2Error::InvalidClaim { claim: found, .. }) if found == claim
            ),
            "{claim}"
        );
    }
}
