//! SD-JWT issuance and processing (RFC 9901 §4 to §7): any claims set the builder accepts,
//! concealed along any paths with any number of decoys, processes back to the same claims after
//! a trip through the serialization, and selective disclosure processes to a subset of it.
#![no_main]

use arbitrary::Arbitrary;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_kit::sd_jwt_vc::{
    ClaimPath, HashAlgorithm, PathComponent, SdJwt, SdJwtBuilder, SdJwtError,
};
use identity_kit::vc::Jwt;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

/// A JSON value with the fuzzer's structure: no floats, whose text form is not stable.
#[derive(Arbitrary, Debug)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl From<Json> for Value {
    fn from(json: Json) -> Self {
        match json {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(b),
            Json::Int(i) => Value::from(i),
            Json::String(s) => Value::String(s),
            Json::Array(items) => Value::Array(items.into_iter().map(Value::from).collect()),
            Json::Object(members) => Value::Object(
                members
                    .into_iter()
                    .map(|(name, value)| (name, Value::from(value)))
                    .collect(),
            ),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Component {
    Name(String),
    Index(u8),
    All,
}

impl From<Component> for PathComponent {
    fn from(component: Component) -> Self {
        match component {
            Component::Name(name) => PathComponent::from(name),
            Component::Index(index) => PathComponent::from(usize::from(index)),
            Component::All => PathComponent::from(()),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Input {
    claims: Vec<(String, Json)>,
    conceal: Vec<Vec<Component>>,
    decoys: u8,
    sha512: bool,
}

/// An unsigned-looking JWT over `payload`: the structure is what SD-JWT processing reads, and
/// nothing here verifies signatures.
fn jwt_over(payload: &Map<String, Value>) -> Jwt {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("JSON"));
    let signature = URL_SAFE_NO_PAD.encode([0u8; 64]);
    Jwt::new(format!("{header}.{payload}.{signature}")).expect("a compact JWS")
}

fuzz_target!(|input: Input| {
    let claims: Map<String, Value> = input
        .claims
        .into_iter()
        .map(|(name, value)| (name, Value::from(value)))
        .collect();
    let paths: Vec<ClaimPath> = input
        .conceal
        .into_iter()
        .map(|components| components.into_iter().collect())
        .collect();
    let mut builder = SdJwtBuilder::new(claims.clone())
        .with_decoys(usize::from(input.decoys))
        .with_hash_algorithm(if input.sha512 {
            HashAlgorithm::Sha512
        } else {
            HashAlgorithm::Sha256
        });
    let mut counter = 0u64;
    builder = builder.with_salt_generator(move || {
        counter += 1;
        URL_SAFE_NO_PAD.encode(counter.to_be_bytes())
    });
    for path in &paths {
        builder = builder.conceal(path.clone());
    }
    assert_eq!(builder.claims(), &claims);
    assert_eq!(builder.concealed(), paths.as_slice());
    let Ok(encoded) = builder.encode() else {
        return;
    };

    let sd_jwt = SdJwt::new(jwt_over(&encoded.payload), encoded.disclosures);
    let processed = sd_jwt.process().expect("a freshly issued SD-JWT processes");
    assert_eq!(processed.as_issued(), &claims);
    let parsed = SdJwt::parse(&sd_jwt.to_string()).expect("a printed SD-JWT parses");
    assert_eq!(parsed, sd_jwt);
    assert_eq!(parsed.process().ok().as_ref(), Some(&processed));

    let disclosed: Vec<ClaimPath> = processed.disclosed_paths().cloned().collect();
    assert_eq!(disclosed.len(), sd_jwt.disclosures().len());
    for (keep, path) in disclosed.iter().enumerate() {
        assert!(processed.is_disclosed(path));
        let partial = sd_jwt.disclose([path]).expect("disclosing one path");
        let shown = partial.process().expect("a partial disclosure processes");
        assert!(shown.is_disclosed(path));
        assert!(shown.disclosed_paths().count() <= disclosed.len());
        // One disclosure on its own is a valid selection unless it is nested in another.
        match sd_jwt.select(|disclosure| disclosure == &sd_jwt.disclosures()[keep]) {
            Ok(selected) => {
                selected.process().expect("a selection processes");
            }
            Err(SdJwtError::MissingParentDisclosure { .. }) => {}
            Err(error) => panic!("selecting one disclosure: {error}"),
        }
    }
    let none = sd_jwt.select(|_| false).expect("selecting nothing");
    let hidden = none.process().expect("a token without disclosures processes");
    assert_eq!(hidden.disclosed_paths().count(), 0);
    if paths.is_empty() {
        assert_eq!(hidden.as_issued(), &claims);
    }
});
