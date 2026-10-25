//! Specification vectors for `Presentation`: VCDM 1.1 Example 33 (a presentation as JWT
//! claims and as a JWT) and the presentation examples of §4.10.
#![cfg(feature = "vc")]

use identity_kit::did::{Did, OneOrMany, Uri};
use identity_kit::vc::validation::{decode_presentation, extract_holder, extract_issuer};
use identity_kit::vc::{CredentialError, Jwt, JwtClaims, Party, Presentation};
use serde_json::{Value, json};

/// VCDM 1.1 Example 31 as a JWT (the credential inside Example 33).
const EXAMPLE_31: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiZmUxM2Y3MTIxMjA0MzFjMjc2ZTEyZWNhYiNr\
    ZXlzLTEifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJodHRwOi8vZXhhb\
    XBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb20va2V5cy9mb28uandrIiwibmJmIjoxN\
    TQxNDkzNzI0LCJpYXQiOjE1NDE0OTM3MjQsImV4cCI6MTU3MzAyOTcyMywibm9uY2UiOiI2NjAhNjM0NUZTZXIiLCJ2YyI6eyJAY\
    29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L\
    2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ\
    3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6I\
    jxzcGFuIGxhbmc9J2ZyLUNBJz5CYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzPC9zcGFuPiJ9fX19.KLJo5GAy\
    BND3LDTn9H7FQokEsUEi8jKwXhGvoN3JtRa51xrNDgXDb0cq1UTYB-rK4Ft9YVmR1NI_ZOF8oGc_7wAp8PHbF2HaWodQIoOBxxT-\
    4WNqAxft7ET6lkH-4S6Ux3rSGAmczMohEEf8eCeN-jC8WekdPl6zKZQj0YPB1rx6X0-xlFBs7cl6Wt8rfBP_tZ9YgVWrQmUWypSi\
    oc0MUyiphmyEbLZagTyPlUyflGlEdqrZAv6eSe6RtxJy6M1-lD7a5HTzanYTWBPAUHDZGyGKXdJw-W_x0IWChBzI8t3kpG253fg6\
    V3tPgHeKXE94fz_QpYfg--7kLsyBAfQGbg";

/// VCDM 1.1 Example 33: the JWT claims of a presentation, with the credential JWT in place of
/// the `"..."` placeholder, as the signed example carries it.
fn example_33_claims() -> JwtClaims {
    serde_json::from_value(json!({
        "iss": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "jti": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        "aud": "did:example:4a57546973436f6f6c4a4a57573",
        "nbf": 1541493724,
        "iat": 1541493724,
        "exp": 1573029723,
        "nonce": "343s$FSFDa-",
        "vp": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": ["VerifiablePresentation", "CredentialManagerPresentation"],
            "verifiableCredential": [EXAMPLE_31]
        }
    }))
    .unwrap()
}

/// VCDM 1.1 Example 33 as a JWT (RS256, key not published: decoding only).
const EXAMPLE_33: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOjB4YWJjI2tleTEifQ.eyJpc3MiOiJkaWQ6ZXhhb\
    XBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJ1cm46dXVpZDozOTc4MzQ0Zi04NTk2LTRjM2EtYTk3OC04Z\
    mNhYmEzOTAzYzUiLCJhdWQiOiJkaWQ6ZXhhbXBsZTo0YTU3NTQ2OTczNDM2ZjZmNmM0YTRhNTc1NzMiLCJuYmYiOjE1NDE0OTM3M\
    jQsImlhdCI6MTU0MTQ5MzcyNCwiZXhwIjoxNTczMDI5NzIzLCJub25jZSI6IjM0M3MkRlNGRGEtIiwidnAiOnsiQGNvbnRleHQiO\
    lsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50a\
    WFscy9leGFtcGxlcy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJDcmVkZW50aWFsTWFuYWdlclByZXNlb\
    nRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6WyJleUpoYkdjaU9pSlNVekkxTmlJc0luUjVjQ0k2SWtwWFZDSXNJbXRwW\
    kNJNkltUnBaRHBsZUdGdGNHeGxPbUZpWm1VeE0yWTNNVEl4TWpBME16RmpNamMyWlRFeVpXTmhZaU5yWlhsekxURWlmUS5leUp6Z\
    FdJaU9pSmthV1E2WlhoaGJYQnNaVHBsWW1abFlqRm1OekV5WldKak5tWXhZekkzTm1VeE1tVmpNakVpTENKcWRHa2lPaUpvZEhSd\
    09pOHZaWGhoYlhCc1pTNWxaSFV2WTNKbFpHVnVkR2xoYkhNdk16Y3pNaUlzSW1semN5STZJbWgwZEhCek9pOHZaWGhoYlhCc1pTN\
    WpiMjB2YTJWNWN5OW1iMjh1YW5kcklpd2libUptSWpveE5UUXhORGt6TnpJMExDSnBZWFFpT2pFMU5ERTBPVE0zTWpRc0ltVjRjQ\
    0k2TVRVM016QXlPVGN5TXl3aWJtOXVZMlVpT2lJMk5qQWhOak0wTlVaVFpYSWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZ\
    EhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05e\
    Vp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXU\
    mxiblJwWVd3aUxDSlZibWwyWlhKemFYUjVSR1ZuY21WbFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ\
    0k2ZXlKa1pXZHlaV1VpT25zaWRIbHdaU0k2SWtKaFkyaGxiRzl5UkdWbmNtVmxJaXdpYm1GdFpTSTZJanh6Y0dGdUlHeGhibWM5S\
    jJaeUxVTkJKejVDWVdOallXeGhkWExEcVdGMElHVnVJRzExYzJseGRXVnpJRzUxYmNPcGNtbHhkV1Z6UEM5emNHRnVQaUo5ZlgxO\
    S5LTEpvNUdBeUJORDNMRFRuOUg3RlFva0VzVUVpOGpLd1hoR3ZvTjNKdFJhNTF4ck5EZ1hEYjBjcTFVVFlCLXJLNEZ0OVlWbVIxT\
    klfWk9GOG9HY183d0FwOFBIYkYySGFXb2RRSW9PQnh4VC00V05xQXhmdDdFVDZsa0gtNFM2VXgzclNHQW1jek1vaEVFZjhlQ2VOL\
    WpDOFdla2RQbDZ6S1pRajBZUEIxcng2WDAteGxGQnM3Y2w2V3Q4cmZCUF90WjlZZ1ZXclFtVVd5cFNpb2MwTVV5aXBobXlFYkxaY\
    WdUeVBsVXlmbEdsRWRxclpBdjZlU2U2UnR4Snk2TTEtbEQ3YTVIVHphbllUV0JQQVVIRFpHeUdLWGRKdy1XX3gwSVdDaEJ6STh0M\
    2twRzI1M2ZnNlYzdFBnSGVLWEU5NGZ6X1FwWWZnLS03a0xzeUJBZlFHYmciXX19.ft_Eq4IniBrr7gtzRfrYj8Vy1aPXuFZU-6_a\
    i0wvaKcsrzI4JkQEKTvbJwdvIeuGuTqy7ipO-EYi7V4TvonPuTRdpB7ZHOlYlbZ4wA9WJ6mSVSqDACvYRiFvrOFmie8rgm6GacWa\
    tgO4m4NqiFKFko3r58LueFfGw47NK9RcfOkVQeHCq4btaDqksDKeoTrNysF4YS89INa-prWomrLRAhnwLOo1Etp3E4ESAxg73CR2\
    kA5AoMbf5KtFueWnMcSbQkMRdWcGC1VssC0tB0JffVjq7ZV6OTyV4kl1-UVgiPLXUTpupFfLRhf9QpqMBjYgP62KvhIvW8BbkGUe\
    lYMetA";

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

#[test]
fn example_33_claims_decode_to_the_presentation_and_back() {
    let claims = example_33_claims();
    let presentation = Presentation::from_jwt_claims(&claims).unwrap();

    // §6.3.1 "JWT Decoding": iss → holder, jti → id; the credential is the Example 31 JWT.
    assert_eq!(
        presentation.holder,
        Some(Party::Uri(uri("did:example:ebfeb1f712ebc6f1c276e12ec21")))
    );
    assert_eq!(
        presentation.id,
        Some(uri("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5"))
    );
    assert!(presentation.has_type("CredentialManagerPresentation"));
    assert_eq!(
        presentation.verifiable_credential,
        [EXAMPLE_31.parse::<Jwt>().unwrap()]
    );
    assert_eq!(
        serde_json::to_value(&presentation).unwrap(),
        json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
            "type": ["VerifiablePresentation", "CredentialManagerPresentation"],
            "verifiableCredential": [EXAMPLE_31],
            "holder": "did:example:ebfeb1f712ebc6f1c276e12ec21"
        })
    );

    // §6.3.1 "JWT Encoding" gives the example back once the holder adds `aud`, the times and
    // the nonce.
    let encoded = presentation.to_jwt_claims().unwrap();
    assert_eq!(encoded.additional["vp"], claims.additional["vp"]);
    assert_eq!(encoded.iss, claims.iss);
    assert_eq!(encoded.jti, claims.jti);
    assert_eq!(
        (encoded.aud, encoded.nbf, encoded.exp, encoded.iat),
        (None, None, None, None)
    );
    let encoded = presentation
        .to_jwt_claims()
        .unwrap()
        .with_aud("did:example:4a57546973436f6f6c4a4a57573")
        .with_nbf(JwtClaims::timestamp(1541493724).unwrap())
        .with_iat(JwtClaims::timestamp(1541493724).unwrap())
        .with_exp(JwtClaims::timestamp(1573029723).unwrap())
        .with_claim("nonce", "343s$FSFDa-");
    assert_eq!(encoded, claims);
}

#[test]
fn example_33_token_decodes_with_its_credential() {
    let jwt: Jwt = EXAMPLE_33.parse().unwrap();
    let decoded = decode_presentation(&jwt).unwrap();
    assert_eq!(
        decoded.header.kid.as_deref(),
        Some("did:example:0xabc#key1")
    );
    assert_eq!(decoded.claims, example_33_claims());
    assert_eq!(
        decoded.holder(),
        Some(&uri("did:example:ebfeb1f712ebc6f1c276e12ec21"))
    );
    assert_eq!(decoded.credentials.len(), 1);
    let credential = &decoded.credentials[0].credential;
    assert_eq!(
        credential.id,
        Some(uri("http://example.edu/credentials/3732"))
    );
    assert_eq!(
        credential.subject().unwrap().id,
        Some(uri("did:example:ebfeb1f712ebc6f1c276e12ec21"))
    );
    assert_eq!(
        decoded.credentials[0].claims.additional["nonce"],
        "660!6345FSer"
    );

    // The signer's DID is readable without any verification.
    assert_eq!(
        extract_holder(&jwt).unwrap(),
        Did::parse("did:example:ebfeb1f712ebc6f1c276e12ec21").unwrap()
    );
    // Example 31's issuer is a URL, not a DID.
    let credential: Jwt = EXAMPLE_31.parse().unwrap();
    assert!(matches!(
        extract_issuer(&credential),
        Err(identity_kit::vc::validation::ValidationError::NotDid { role: "issuer", id })
            if id == "https://example.com/keys/foo.jwk"
    ));
}

#[test]
fn holder_and_iss_must_agree() {
    let mut claims = example_33_claims();
    claims.additional["vp"]["holder"] = json!("did:example:other");
    assert_eq!(
        Presentation::from_jwt_claims(&claims),
        Err(CredentialError::ClaimMismatch {
            claim: "iss",
            property: "holder"
        })
    );
    claims.additional["vp"]["holder"] = json!({
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "name": "Jayden Doe"
    });
    let presentation = Presentation::from_jwt_claims(&claims).unwrap();
    assert_eq!(
        presentation.holder.as_ref().unwrap().properties().unwrap()["name"],
        "Jayden Doe"
    );
    // An object holder stays in `vp`.
    let encoded = presentation.to_jwt_claims().unwrap();
    assert_eq!(
        encoded.iss.as_deref(),
        Some("did:example:ebfeb1f712ebc6f1c276e12ec21")
    );
    assert_eq!(encoded.additional["vp"]["holder"]["name"], "Jayden Doe");

    let mut without = example_33_claims();
    without.additional.shift_remove("vp");
    assert_eq!(
        Presentation::from_jwt_claims(&without),
        Err(CredentialError::MissingClaim("vp"))
    );
}

#[test]
fn structural_requirements_and_builder() {
    // VCDM 1.1 §4.10: a presentation needs the base context and the VerifiablePresentation
    // type; `verifiableCredential` and `holder` are optional.
    let minimal: Presentation = serde_json::from_value(json!({
        "@context": "https://www.w3.org/2018/credentials/v1",
        "type": "VerifiablePresentation"
    }))
    .unwrap();
    assert_eq!(minimal, Presentation::new());
    assert!(minimal.verifiable_credential.is_empty());
    assert_eq!(
        serde_json::to_value(&minimal).unwrap(),
        json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiablePresentation"
        })
    );
    let error = |value: Value| {
        serde_json::from_value::<Presentation>(value)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        error(json!({
            "@context": "https://www.w3.org/ns/credentials/v2",
            "type": "VerifiablePresentation"
        })),
        "the first `@context` must be `https://www.w3.org/2018/credentials/v1`"
    );
    assert_eq!(
        error(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": ["CredentialManagerPresentation"]
        })),
        "`type` must include `VerifiablePresentation`"
    );
    // A credential that is not a JWT string is rejected.
    assert!(
        error(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiablePresentation",
            "verifiableCredential": [{ "id": "http://example.edu/credentials/3732" }]
        }))
        .contains("expected a string")
    );

    let presentation = Presentation::new()
        .with_context("https://www.w3.org/2018/credentials/examples/v1")
        .with_type("CredentialManagerPresentation")
        .with_id(uri("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5"))
        .with_holder(Did::parse("did:example:ebfeb1f712ebc6f1c276e12ec21").unwrap())
        .with_credential(EXAMPLE_31.parse().unwrap())
        .with_property("nonce", "343s$FSFDa-");
    assert_eq!(
        presentation.types,
        OneOrMany::Many(vec![
            "VerifiablePresentation".to_owned(),
            "CredentialManagerPresentation".to_owned()
        ])
    );
    assert_eq!(presentation.properties["nonce"], "343s$FSFDa-");
    assert_eq!(
        serde_json::to_value(&presentation.context).unwrap(),
        json!([
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ])
    );
    assert!(presentation.has_type("CredentialManagerPresentation"));
    assert!(!presentation.has_type("OtherPresentation"));
    let jwt: Jwt = EXAMPLE_31.parse().unwrap();
    assert_eq!(jwt.into_string(), EXAMPLE_31);
    let roundtrip: Presentation =
        serde_json::from_value(serde_json::to_value(&presentation).unwrap()).unwrap();
    assert_eq!(roundtrip, presentation);
}
