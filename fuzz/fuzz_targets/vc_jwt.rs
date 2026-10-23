//! JWT verifiable credentials (VCDM 1.1 §6.3.1, VCDM 2.0 enveloped): arbitrary tokens, claims
//! sets and credential JSON never panic, what the models accept maps to JWT claims and back
//! unchanged, a presentation that decodes, in either profile, decodes every credential, and no
//! token that decodes is the issuer-signed JWT of an SD-JWT.
#![no_main]

use chrono::Timelike as _;
use identity_kit::vc::validation::{
    decode_credential, decode_credential_v2, decode_presentation, decode_presentation_v2,
};
use identity_kit::vc::{
    Credential, CredentialV2, EnvelopedVc, EnvelopedVp, Jwt, JwtClaims, Presentation,
    PresentationV2,
};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Whether a date of `credential` has what a `NumericDate` cannot carry: a fraction of a second,
/// or a leap second (`:60`, RFC 3339 §5.6), which chrono keeps as a nanosecond count of a second
/// or more. The JWT mapping floors both to whole seconds, so such a credential does not map back
/// unchanged.
fn has_subsecond_precision(credential: &Credential) -> bool {
    [Some(credential.issuance_date), credential.expiration_date]
        .into_iter()
        .flatten()
        .any(|time| time.nanosecond() != 0)
}

fn json_roundtrip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
    let json = serde_json::to_string(value).expect("serializes");
    let again: T = serde_json::from_str(&json).expect("a serialized value parses");
    assert_eq!(&again, value);
}

/// Whether `value` has what RFC 9901 §4.2 reserves for an SD-JWT: a member `_sd` or `_sd_alg`,
/// or an array element `{"...": "<digest>"}`.
fn has_sd_jwt_names(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(name, value)| name == "_sd" || name == "_sd_alg" || has_sd_jwt_names(value)),
        Value::Array(array) => array.iter().any(|element| {
            let placeholder = element.as_object().is_some_and(|object| {
                object.len() == 1 && object.get("...").is_some_and(Value::is_string)
            });
            placeholder || has_sd_jwt_names(element)
        }),
        _ => false,
    }
}

/// Asserts that the payload of `jwt`, which a decode function accepted, is not an SD-JWT's.
fn assert_plain(jwt: &Jwt) {
    let payload: Value = serde_json::from_slice(jwt.decode().unwrap().payload()).unwrap();
    assert!(
        !has_sd_jwt_names(&payload),
        "an SD-JWT payload decoded as a plain JWT"
    );
}

fn exercise_claims(claims: &JwtClaims) {
    json_roundtrip(claims);
    if let Ok(credential) = Credential::from_jwt_claims(claims) {
        json_roundtrip(&credential);
        if let Ok(back) = credential.to_jwt_claims()
            && !has_subsecond_precision(&credential)
        {
            assert_eq!(Credential::from_jwt_claims(&back).as_ref(), Ok(&credential));
        }
    }
    if let Ok(credential) = CredentialV2::from_jwt_claims(claims) {
        json_roundtrip(&credential);
        let back = credential.to_jwt_claims();
        assert_eq!(
            CredentialV2::from_jwt_claims(&back).as_ref(),
            Ok(&credential)
        );
    }
    if let Ok(presentation) = Presentation::from_jwt_claims(claims) {
        json_roundtrip(&presentation);
        if let Ok(back) = presentation.to_jwt_claims() {
            assert_eq!(
                Presentation::from_jwt_claims(&back).as_ref(),
                Ok(&presentation)
            );
        }
    }
    if let Ok(presentation) = PresentationV2::from_jwt_claims(claims) {
        json_roundtrip(&presentation);
        let back = presentation.to_jwt_claims();
        assert_eq!(
            PresentationV2::from_jwt_claims(&back).as_ref(),
            Ok(&presentation)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        if let Ok(jwt) = Jwt::new(input) {
            assert_eq!(jwt.as_str(), input);
            let jws = jwt.decode().expect("a wrapped token decodes");
            if let Ok(claims) = serde_json::from_slice::<JwtClaims>(jws.payload()) {
                exercise_claims(&claims);
            }
            if decode_credential(&jwt).is_ok() || decode_credential_v2(&jwt).is_ok() {
                assert_plain(&jwt);
            }
            if let Ok(decoded) = decode_presentation(&jwt) {
                assert_plain(&jwt);
                for credential in &decoded.presentation.verifiable_credential {
                    assert_plain(credential);
                }
                assert_eq!(
                    decoded.credentials.len(),
                    decoded.presentation.verifiable_credential.len()
                );
                // `iss` is the holder.
                if let Some(iss) = decoded.claims.iss.as_deref() {
                    assert_eq!(decoded.holder().map(|holder| holder.as_str()), Some(iss));
                }
            }
            if let Ok(decoded) = decode_presentation_v2(&jwt) {
                assert_plain(&jwt);
                assert_eq!(
                    decoded.credentials.len(),
                    decoded.presentation.verifiable_credential.len()
                );
                // `iss`, when present, agrees with `holder`, or stands in for it.
                if let Some(iss) = decoded.claims.iss.as_deref() {
                    assert_eq!(decoded.holder().map(|holder| holder.as_str()), Some(iss));
                }
            }
            let enveloped = EnvelopedVc::from_jwt(&jwt);
            assert_eq!(enveloped.data(), input);
            assert!(enveloped.check().is_ok());
            assert_eq!(enveloped.to_jwt().as_ref(), Ok(&jwt));
            json_roundtrip(&enveloped);
            let enveloped = EnvelopedVp::from_jwt(&jwt);
            assert_eq!(enveloped.to_jwt().as_ref(), Ok(&jwt));
            json_roundtrip(&enveloped);
        }
        for media_type in ["application/vc+jwt", "application/vp+jwt", "text/plain"] {
            if let Ok(enveloped) = EnvelopedVc::new(media_type, input) {
                assert_eq!(enveloped.media_type(), media_type);
                assert_eq!(enveloped.data(), input);
                let _ = enveloped.check();
                let _ = enveloped.to_jwt();
                json_roundtrip(&enveloped);
            }
            if let Ok(enveloped) = EnvelopedVp::new(media_type, input) {
                let _ = enveloped.check();
                let _ = enveloped.to_jwt();
                json_roundtrip(&enveloped);
            }
        }
    }
    if let Ok(claims) = serde_json::from_slice::<JwtClaims>(data) {
        exercise_claims(&claims);
    }
    if let Ok(credential) = serde_json::from_slice::<Credential>(data) {
        json_roundtrip(&credential);
        if let Ok(claims) = credential.to_jwt_claims()
            && !has_subsecond_precision(&credential)
        {
            assert_eq!(
                Credential::from_jwt_claims(&claims).as_ref(),
                Ok(&credential)
            );
        }
    }
    if let Ok(credential) = serde_json::from_slice::<CredentialV2>(data) {
        json_roundtrip(&credential);
        let claims = credential.to_jwt_claims();
        assert_eq!(
            CredentialV2::from_jwt_claims(&claims).as_ref(),
            Ok(&credential)
        );
    }
    if let Ok(presentation) = serde_json::from_slice::<Presentation>(data) {
        json_roundtrip(&presentation);
        if let Ok(claims) = presentation.to_jwt_claims() {
            assert_eq!(
                Presentation::from_jwt_claims(&claims).as_ref(),
                Ok(&presentation)
            );
        }
    }
    if let Ok(presentation) = serde_json::from_slice::<PresentationV2>(data) {
        json_roundtrip(&presentation);
        let claims = presentation.to_jwt_claims();
        assert_eq!(
            PresentationV2::from_jwt_claims(&claims).as_ref(),
            Ok(&presentation)
        );
    }
});
