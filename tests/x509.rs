//! `X509Resolver` and `X509Certificate` (feature `x509`): path validation against the C2SP
//! x509-limbo vectors (`tests/x509-limbo`), the rules HAIP 1.0 adds for an `x5c` header, what a
//! certificate says about its subject, and tokens signed with a certificate chain, validated
//! end to end: an SD-JWT VC (HAIP §6.1.1), a Status List Token (HAIP §6.1) and a plain JWT.
#![cfg(feature = "x509")]

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use identity_kit::jose::{CertifiedSigner, Jwk, JwsHeader, Signer as _};
use identity_kit::resolver::{
    CompositeKeyResolver, JwkResolver, KeyReference, KeyResolutionError, KeyResolver, KeyRole,
    X509Certificate, X509Error, X509Resolver,
};
use serde::Deserialize;
use serde_json::json;

use common::Es256Signer;

// ---------------------------------------------------------------------------------------------
// x509-limbo
// ---------------------------------------------------------------------------------------------

/// One x509-limbo testcase, with the fields this crate's resolver has a use for.
#[derive(Debug, Deserialize)]
struct Testcase {
    id: String,
    trusted_certs: Vec<String>,
    untrusted_intermediates: Vec<String>,
    peer_certificate: String,
    validation_time: Option<String>,
    expected_result: String,
}

#[derive(Debug, Deserialize)]
struct Limbo {
    testcases: Vec<Testcase>,
}

/// The DER of one PEM block.
fn der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).unwrap()
}

/// Seconds since the Unix epoch of `YYYY-MM-DDTHH:MM:SS`, in UTC; a fraction is dropped.
fn unix_seconds(time: &str) -> i64 {
    let number = |range: core::ops::Range<usize>| time[range].parse::<i64>().unwrap();
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second) = (number(11..13), number(14..16), number(17..19));
    assert!(time.ends_with("+00:00"), "{time}");
    // Days from the civil date (Howard Hinnant's `days_from_civil`).
    let year = if month <= 2 { year - 1 } else { year };
    let (era, year_of_era) = (year.div_euclid(400), year.rem_euclid(400));
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) * 86_400 + hour * 3600 + minute * 60 + second
}

/// The time the testcases without one are validated at: 2023-11-14, inside the validity of the
/// suite's certificates.
const DEFAULT_TIME: i64 = 1_700_000_000;

impl Testcase {
    /// What the resolver says of this testcase's chain, at its validation time.
    fn validate(&self) -> Result<Jwk, X509Error> {
        let resolver = X509Resolver::new(self.trusted_certs.iter().map(|pem| der(pem)))?;
        let chain: Vec<Vec<u8>> = core::iter::once(&self.peer_certificate)
            .chain(&self.untrusted_intermediates)
            .map(|pem| der(pem))
            .collect();
        let now = self
            .validation_time
            .as_deref()
            .map_or(DEFAULT_TIME, unix_seconds);
        resolver.validate(&chain, now)
    }

    fn expects_success(&self) -> bool {
        match self.expected_result.as_str() {
            "SUCCESS" => true,
            "FAILURE" => false,
            other => panic!("{}: {other}", self.id),
        }
    }
}

/// Why the resolver's verdict differs from the suite's. The suite expects what a validator of
/// TLS server certificates does; a token signed with `x5c` has no host name, and its
/// certificates follow no Web PKI profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Difference {
    /// Accepted. The suite refuses the certificate for the host name it validates for, or
    /// for how the certificate writes names; the resolver validates for no name.
    PeerName,
    /// Accepted. The suite requires the `serverAuth` extended key usage; the specifications
    /// that use `x5c` define none, so the resolver accepts any.
    ExtendedKeyUsage,
    /// Accepted. The suite enforces a rule of RFC 5280 or of the CA/Browser Forum on how a
    /// certificate is issued (key identifiers, a serial number, an RSA modulus) that
    /// `rustls-webpki` does not check.
    IssuanceProfile,
    /// Accepted. The suite refuses the trust anchor for its own certificate's extensions;
    /// the resolver requires an anchor to be a CA certificate within its validity period and
    /// leaves the rest to the application that chose it.
    TrustAnchorProfile,
    /// Accepted. Name constraints that are empty, misplaced or badly formed, which
    /// `rustls-webpki` reads leniently.
    NameConstraintsForm,
    /// Accepted. Certificate policies are not processed.
    Policy,
    /// Accepted. The suite configures a maximum chain depth; the resolver has one fixed
    /// limit, which the chain is within.
    ChainDepth,
    /// Refused. The leaf is a CA certificate, which `rustls-webpki` does not accept as the
    /// end of a path.
    CaAsLeaf,
    /// Refused. A CA certificate issued to itself in the middle of the path, which
    /// `rustls-webpki` does not build through.
    SelfIssuedIntermediate,
    /// Refused. Name constraints of a kind `rustls-webpki` does not evaluate (email
    /// addresses, directory names), which it refuses rather than ignore.
    UnsupportedNameConstraint,
}

impl Difference {
    /// Whether the resolver accepts where the suite expects a failure.
    fn accepts(self) -> bool {
        !matches!(
            self,
            Self::CaAsLeaf | Self::SelfIssuedIntermediate | Self::UnsupportedNameConstraint
        )
    }
}

/// Every testcase of the vendored suite whose verdict differs, by reason.
const KNOWN_DIFFERENCES: &[(Difference, &[&str])] = &[
    (
        Difference::PeerName,
        &[
            "rfc5280::san::ip-in-dns",
            "rfc5280::san::underscore-dns",
            "webpki::cn::case-mismatch",
            "webpki::cn::ipv4-hex-mismatch",
            "webpki::cn::ipv4-leading-zeros-mismatch",
            "webpki::cn::ipv6-non-rfc5952-mismatch",
            "webpki::cn::ipv6-uncompressed-mismatch",
            "webpki::cn::ipv6-uppercase-mismatch",
            "webpki::cn::not-in-san",
            "webpki::cn::punycode-not-in-san",
            "webpki::cn::utf8-vs-punycode-mismatch",
            "webpki::san::mismatch-apex-subdomain-san",
            "webpki::san::mismatch-domain-san",
            "webpki::san::mismatch-subdomain-apex-san",
            "webpki::san::mismatch-subdomain-san",
            "webpki::san::no-san",
            "webpki::san::public-suffix-multi-label-wildcard-san",
            "webpki::san::public-suffix-private-namespace-wildcard-san",
            "webpki::san::public-suffix-wildcard-san",
            "webpki::san::san-wildcard-only",
            "webpki::san::san-wildcard-only-tld",
            "webpki::san::wildcard-embedded-leftmost-san",
            "webpki::san::wildcard-embedded-ulabel-san",
            "webpki::san::wildcard-match-across-labels-san",
            "webpki::san::wildcard-not-in-leftmost-san",
        ],
    ),
    (
        Difference::ExtendedKeyUsage,
        &[
            "rfc5280::eku::ee-wrong-eku",
            "webpki::eku::ee-anyeku",
            "webpki::eku::ee-critical-eku",
            "webpki::eku::ee-without-eku",
            "webpki::eku::root-has-eku",
        ],
    ),
    (
        Difference::IssuanceProfile,
        &[
            "rfc5280::aki::critical-aki",
            "rfc5280::aki::cross-signed-root-missing-aki",
            "rfc5280::aki::intermediate-missing-aki",
            "rfc5280::aki::leaf-missing-aki",
            "rfc5280::san::noncritical-with-empty-subject",
            "rfc5280::serial::zero",
            "rfc5280::ski::critical-ski",
            "rfc5280::ski::intermediate-missing-ski",
            "webpki::forbidden-rsa-key-not-divisible-by-8-in-leaf",
            "webpki::malformed-aia",
            "webpki::san::san-critical-with-nonempty-subject",
        ],
    ),
    (
        Difference::TrustAnchorProfile,
        &[
            "rfc5280::ca-empty-subject",
            "rfc5280::root-inconsistent-ca-extensions",
            "rfc5280::root-non-critical-basic-constraints",
            "rfc5280::ski::root-missing-ski",
            "rfc5280::unknown-critical-extension-root",
            "webpki::aki::root-with-aki-all-fields",
            "webpki::aki::root-with-aki-authoritycertissuer",
            "webpki::aki::root-with-aki-authoritycertserialnumber",
            "webpki::aki::root-with-aki-missing-keyidentifier",
            "webpki::aki::root-with-aki-ski-mismatch",
            "webpki::forbidden-rsa-not-divisible-by-8-in-root",
        ],
    ),
    (
        Difference::NameConstraintsForm,
        &[
            "rfc5280::nc::invalid-dnsname-leading-period",
            "rfc5280::nc::not-allowed-in-ee-critical",
            "rfc5280::nc::not-allowed-in-ee-noncritical",
            "rfc5280::nc::permitted-dns-match-noncritical",
            "rfc5280::nc::permitted-empty-sequence-excluded-nonempty",
            "rfc5280::nc::permitted-nonempty-excluded-empty-sequence",
            "webpki::nc::intermediate-permitted-excluded-subtrees-both-empty-sequences",
            "webpki::nc::intermediate-permitted-excluded-subtrees-both-null",
        ],
    ),
    (Difference::Policy, &["rfc5280::pc::ica-noncritical-pc"]),
    (
        Difference::ChainDepth,
        &[
            "pathlen::max-chain-depth-0-exhausted",
            "pathlen::max-chain-depth-1-exhausted",
        ],
    ),
    (
        Difference::CaAsLeaf,
        &[
            "pathlen::validation-ignores-pathlen-in-leaf",
            "rfc5280::ca-as-leaf",
        ],
    ),
    (
        Difference::SelfIssuedIntermediate,
        &[
            "pathlen::self-issued-certs-pathlen",
            "rfc5280::nc::permitted-self-issued",
        ],
    ),
    (
        Difference::UnsupportedNameConstraint,
        &[
            "rfc5280::nc::nc-permits-email-domain",
            "rfc5280::nc::nc-permits-email-exact",
            "rfc5280::nc::nc-permits-email-literal-asterisk-exact-match",
            "rfc5280::nc::nc-permits-email-literal-double-asterisk",
            "rfc5280::nc::nc-permits-email-literal-mid-asterisk",
            "rfc5280::nc::permitted-dn-match",
        ],
    ),
];

fn vendored() -> Limbo {
    serde_json::from_str(include_str!("x509-limbo/limbo.json")).unwrap()
}

fn testcase(id: &str) -> Testcase {
    vendored()
        .testcases
        .into_iter()
        .find(|testcase| testcase.id == id)
        .unwrap_or_else(|| panic!("no testcase {id}"))
}

/// The resolver gives the suite's verdict on every vendored testcase, but for the known
/// differences, each of which still differs the way its reason says.
#[test]
fn limbo_vectors() {
    let known: BTreeMap<&str, Difference> = KNOWN_DIFFERENCES
        .iter()
        .flat_map(|(difference, ids)| ids.iter().map(|id| (*id, *difference)))
        .collect();
    let listed: usize = KNOWN_DIFFERENCES.iter().map(|(_, ids)| ids.len()).sum();
    assert_eq!(known.len(), listed, "a testcase is listed twice");
    let limbo = vendored();
    assert_eq!(limbo.testcases.len(), 182);
    let mut unexpected = Vec::new();
    let mut agreed = 0;
    for testcase in &limbo.testcases {
        let result = testcase.validate();
        let same = result.is_ok() == testcase.expects_success();
        match known.get(testcase.id.as_str()) {
            None if same => agreed += 1,
            None => unexpected.push(format!(
                "{}: the suite expects {}, the resolver says {result:?}",
                testcase.id, testcase.expected_result
            )),
            Some(difference) if same => unexpected.push(format!(
                "{}: listed as {difference:?}, but the resolver agrees with the suite",
                testcase.id
            )),
            Some(difference) => assert_eq!(
                difference.accepts(),
                result.is_ok(),
                "{}: {difference:?}, {result:?}",
                testcase.id
            ),
        }
    }
    assert!(unexpected.is_empty(), "{}", unexpected.join("\n"));
    assert_eq!(agreed, limbo.testcases.len() - listed);
    for id in known.keys() {
        assert!(
            limbo.testcases.iter().any(|testcase| testcase.id == *id),
            "{id} is not a testcase"
        );
    }
}

/// What path validation refuses, by the reason it gives.
#[test]
fn limbo_failures_name_their_cause() {
    for (id, cause) in [
        ("rfc5280::validity::expired-leaf", "CertExpired"),
        ("rfc5280::validity::expired-intermediate", "CertExpired"),
        ("rfc5280::validity::expired-root", "CertExpired"),
        ("rfc5280::validity::notbefore-fractional", "CertNotValidYet"),
        // An intermediate that is no CA issues nothing, so the leaf has no issuer.
        (
            "rfc5280::intermediate-ca-missing-basic-constraints",
            "UnknownIssuer",
        ),
        (
            "rfc5280::unknown-critical-extension-intermediate",
            "UnsupportedCriticalExtension",
        ),
        ("rfc5280::nc::excluded-dns-match", "NameConstraintViolation"),
        (
            "pathlen::intermediate-violates-pathlen-0",
            "PathLenConstraintViolated",
        ),
    ] {
        let error = testcase(id).validate().unwrap_err();
        assert!(
            matches!(error, X509Error::PathValidation(_)),
            "{id}: {error}"
        );
        assert!(error.to_string().contains(cause), "{id}: {error}");
    }
    // A critical extension nobody understands, in the leaf, is refused when it is read.
    let error = testcase("rfc5280::unknown-critical-extension-ee")
        .validate()
        .unwrap_err();
    assert!(
        matches!(&error, X509Error::InvalidCertificate { index: 0, .. })
            && error.to_string().contains("UnsupportedCriticalExtension"),
        "{error}"
    );
    // What the resolver checks itself.
    assert!(matches!(
        testcase("rfc5280::leaf-ku-keycertsign").validate(),
        Err(X509Error::KeyUsage)
    ));
    assert!(matches!(
        testcase("rfc5280::root-missing-basic-constraints").validate(),
        Err(X509Error::TrustAnchorNotCa { index: 0 })
    ));
    let weak = testcase("webpki::forbidden-weak-rsa-in-leaf")
        .validate()
        .unwrap_err();
    assert!(
        matches!(&weak, X509Error::UnsupportedKey(reason) if reason.contains("shorter than 2048")),
        "{weak}"
    );
}

/// Runs the whole suite and prints where the resolver differs from it:
/// `X509_LIMBO=/path/to/limbo.json cargo test --features x509 --test x509 -- --ignored
/// --nocapture`.
#[test]
#[ignore = "needs the whole x509-limbo suite, which is too large to vendor"]
#[expect(clippy::print_stdout, reason = "a report for whoever runs it by hand")]
fn whole_suite() {
    let path = std::env::var("X509_LIMBO").expect("X509_LIMBO names limbo.json");
    let limbo: Limbo = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (mut agreed, mut accepted, mut refused) = (0, Vec::new(), Vec::new());
    for testcase in &limbo.testcases {
        match (testcase.expects_success(), testcase.validate()) {
            (true, Ok(_)) | (false, Err(_)) => agreed += 1,
            (false, Ok(_)) => accepted.push(&testcase.id),
            (true, Err(error)) => refused.push(format!("{}: {error}", testcase.id)),
        }
    }
    println!("{agreed} of {} testcases agree", limbo.testcases.len());
    println!(
        "accepted where the suite expects a failure: {}",
        accepted.len()
    );
    for id in accepted {
        println!("  {id}");
    }
    println!("refused where the suite expects success: {}", refused.len());
    for line in refused {
        println!("  {line}");
    }
}

// ---------------------------------------------------------------------------------------------
// A signer with a certificate chain
// ---------------------------------------------------------------------------------------------

/// The chain of the x509-limbo testcase `pathlen::ee-with-intermediate-pathlen-0`, with the
/// key of its leaf (`tests/x509-limbo/signer.json`): `CN=example.com` with the DNS name
/// `example.com`, an intermediate CA and a root, all valid from 1970 to 2969.
#[derive(Debug, Deserialize)]
struct Fixture {
    x5c: Vec<String>,
    trust_anchor: String,
    private_jwk: serde_json::Value,
}

struct Certified {
    /// `[leaf, intermediate]`, DER.
    chain: Vec<Vec<u8>>,
    /// The root, DER.
    anchor: Vec<u8>,
    /// The leaf's public key.
    key: Jwk,
    signer: CertifiedSigner<Es256Signer>,
}

fn certified() -> Certified {
    let fixture: Fixture = serde_json::from_str(include_str!("x509-limbo/signer.json")).unwrap();
    let chain: Vec<Vec<u8>> = fixture
        .x5c
        .iter()
        .map(|certificate| STANDARD.decode(certificate).unwrap())
        .collect();
    let private: Jwk = serde_json::from_value(fixture.private_jwk.clone()).unwrap();
    let d = common::decode(fixture.private_jwk["d"].as_str().unwrap());
    let signer = Es256Signer {
        key: p256::ecdsa::SigningKey::from_slice(&d).unwrap(),
        kid: None,
    };
    Certified {
        anchor: STANDARD.decode(&fixture.trust_anchor).unwrap(),
        key: private.public(),
        signer: CertifiedSigner::new(signer, chain.clone()),
        chain,
    }
}

fn resolver(certified: &Certified) -> X509Resolver {
    X509Resolver::new([certified.anchor.clone()]).unwrap()
}

/// A root no chain of these tests leads to.
fn other_anchor() -> Vec<u8> {
    der(&testcase("rfc5280::nc::permitted-nonempty-excluded-nonempty").trusted_certs[0])
}

// ---------------------------------------------------------------------------------------------
// X509Certificate
// ---------------------------------------------------------------------------------------------

#[test]
fn reads_a_certificate() {
    let certified = certified();
    let leaf = X509Certificate::from_der(&certified.chain[0]).unwrap();
    assert_eq!(leaf.der(), certified.chain[0]);
    assert_eq!(leaf.subject(), "CN=example.com");
    assert!(
        leaf.issuer()
            .starts_with("CN=x509-limbo-intermediate-pathlen-0,OU="),
        "{}",
        leaf.issuer()
    );
    assert_eq!(leaf.dns_names(), ["example.com"]);
    assert!(leaf.uris().is_empty());
    // 1970-01-01T00:00:01Z to 2969-05-03T00:00:01Z.
    assert_eq!((leaf.not_before(), leaf.not_after()), (1, 31_536_000_001));
    assert!(!leaf.is_ca() && !leaf.is_self_issued());
    assert_eq!(leaf.public_key().unwrap(), certified.key);
    {
        use sha2::Digest as _;
        assert_eq!(
            leaf.sha256_thumbprint(),
            common::encode(&sha2::Sha256::digest(&certified.chain[0]))
        );
    }

    // The chain links by key identifier and by name.
    let intermediate = X509Certificate::from_der(&certified.chain[1]).unwrap();
    let root = X509Certificate::from_der(&certified.anchor).unwrap();
    assert!(intermediate.is_ca() && !intermediate.is_self_issued());
    assert!(root.is_ca() && root.is_self_issued());
    assert_eq!(leaf.issuer(), intermediate.subject());
    assert_eq!(intermediate.issuer(), root.subject());
    assert!(leaf.authority_key_identifier().is_some());
    assert_eq!(
        leaf.authority_key_identifier(),
        intermediate.subject_key_identifier()
    );
    assert_eq!(
        intermediate.authority_key_identifier(),
        root.subject_key_identifier()
    );
    assert!(format!("{leaf:?}").contains("CN=example.com"));

    for garbage in [&b""[..], b"not a certificate", &certified.chain[0][..40]] {
        assert!(matches!(
            X509Certificate::from_der(garbage),
            Err(X509Error::InvalidCertificate { index: 0, .. })
        ));
    }
}

/// ISRG Root X2, a root of Let's Encrypt with a P-384 key (<https://letsencrypt.org/certificates/>),
/// SHA-256 fingerprint `69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70`.
const ISRG_ROOT_X2: &str = "\
    MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQswCQYDVQQGEwJVUzEpMCcGA1UE\
    ChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5\
    MDQwMDAwMDBaFw00MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBTZWN1cml0\
    eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvV\
    n4CDCuwJSvMWSj5cz3es3mcFDR0HttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7m\
    AHf7AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAd\
    BgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZIzj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70\
    /aTSVaYgLXTWNLxBo1BfASdWtL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1\
    /q4AaOeMSQ+2b1tbFfLn";

/// A P-384 key reads as an `EC` JWK of that curve: the x509-limbo suite has none.
#[test]
fn reads_a_p384_key() {
    let der = STANDARD.decode(ISRG_ROOT_X2).unwrap();
    let root = X509Certificate::from_der(&der).unwrap();
    assert_eq!(
        root.subject(),
        "CN=ISRG Root X2,O=Internet Security Research Group,C=US"
    );
    assert!(root.is_ca() && root.is_self_issued());
    assert_eq!(
        (root.not_before(), root.not_after()),
        (
            unix_seconds("2020-09-04T00:00:00+00:00"),
            unix_seconds("2040-09-17T16:00:00+00:00")
        )
    );
    let fingerprint =
        common::decode(&root.sha256_thumbprint())
            .iter()
            .fold(String::new(), |mut hex, byte| {
                use core::fmt::Write as _;
                let _ = write!(hex, "{byte:02X}");
                hex
            });
    assert_eq!(
        fingerprint,
        "69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470"
    );

    let key = serde_json::to_value(root.public_key().unwrap()).unwrap();
    assert_eq!((&key["kty"], &key["crv"]), (&json!("EC"), &json!("P-384")));
    let (x, y) = (
        common::decode(key["x"].as_str().unwrap()),
        common::decode(key["y"].as_str().unwrap()),
    );
    assert_eq!((x.len(), y.len()), (48, 48));
    // The coordinates are the uncompressed point the certificate carries.
    let point = [&[0x04][..], &x, &y].concat();
    assert!(der.windows(point.len()).any(|window| window == point));

    // It is a CA certificate, so it can be a trust anchor.
    assert!(X509Resolver::new([der]).is_ok());
}

#[test]
fn binds_an_identifier_through_subject_alternative_names() {
    let certified = certified();
    let leaf = X509Certificate::from_der(&certified.chain[0]).unwrap();
    // An `https` URL whose host is a DNS name of the certificate, ignoring case.
    for bound in [
        "https://example.com",
        "https://example.com/tenant/1",
        "https://EXAMPLE.com:8443/",
    ] {
        assert!(leaf.binds(bound), "{bound}");
    }
    for unbound in [
        "http://example.com",
        "https://sub.example.com",
        "https://example.com.attacker.example",
        "https://example.org",
        "example.com",
        "did:web:example.com",
        "CN=example.com",
        "",
    ] {
        assert!(!leaf.binds(unbound), "{unbound}");
    }

    // A URI name binds exactly itself.
    let with_uris = X509Certificate::from_der(&der(&testcase(
        "rfc5280::nc::nc-permits-uri-host-rejects-subdomain",
    )
    .peer_certificate))
    .unwrap();
    assert_eq!(
        with_uris.uris(),
        [
            "https://example.com/allowed",
            "https://sub.example.com/not-allowed"
        ]
    );
    assert!(with_uris.binds("https://sub.example.com/not-allowed"));
    assert!(!with_uris.binds("https://sub.example.com/"));
    assert!(!with_uris.binds("https://sub.example.com/not-allowed/more"));

    // `KeyReference::binds_to` applies it to the first certificate, and takes no party as
    // the certificate's own subject.
    let reference = KeyReference::X509Chain(certified.chain.clone());
    assert!(reference.binds_to(None, &certified.key));
    assert!(reference.binds_to(Some("https://example.com"), &certified.key));
    assert!(!reference.binds_to(Some("https://issuer.example"), &certified.key));
    assert!(!reference.binds_to(Some("did:example:123"), &certified.key));
}

// ---------------------------------------------------------------------------------------------
// X509Resolver
// ---------------------------------------------------------------------------------------------

#[test]
fn validates_a_chain_to_the_key_of_its_leaf() {
    let certified = certified();
    let resolver = resolver(&certified);
    assert_eq!(
        resolver.anchors().collect::<Vec<_>>(),
        [&certified.anchor[..]]
    );
    assert_eq!(
        resolver.validate(&certified.chain, DEFAULT_TIME).unwrap(),
        certified.key
    );
    assert!(format!("{resolver:?}").contains("anchors: 1"));

    // Without the intermediate there is no path, nor without an anchor.
    for (resolver, chain) in [
        (&resolver, &certified.chain[..1]),
        (
            &X509Resolver::new(Vec::<Vec<u8>>::new()).unwrap(),
            &certified.chain[..],
        ),
    ] {
        let error = resolver.validate(chain, DEFAULT_TIME).unwrap_err();
        assert!(
            matches!(&error, X509Error::PathValidation(_))
                && error.to_string().contains("UnknownIssuer"),
            "{error}"
        );
    }
    // Another root does not trust the chain. The suite's roots share one name, so this one is
    // found as the issuer, and its key did not sign.
    let error = X509Resolver::new([other_anchor()])
        .unwrap()
        .validate(&certified.chain, DEFAULT_TIME)
        .unwrap_err();
    assert!(
        matches!(&error, X509Error::PathValidation(_))
            && error.to_string().contains("InvalidSignatureForPublicKey"),
        "{error}"
    );

    // The certificates after the leaf are a pool: an unrelated one among them changes nothing.
    let mut padded = certified.chain.clone();
    padded.insert(1, other_anchor());
    assert_eq!(
        resolver.validate(&padded, DEFAULT_TIME).unwrap(),
        certified.key
    );

    // A pinned intermediate is an anchor like a root.
    let pinned = X509Resolver::new([certified.chain[1].clone()]).unwrap();
    assert_eq!(
        pinned
            .validate(&certified.chain[..1], DEFAULT_TIME)
            .unwrap(),
        certified.key
    );
}

/// HAIP 1.0 §6.1.1, and the same of every `x5c` it defines: "The X.509 certificate of the
/// trust anchor MUST NOT be included in the x5c JOSE header […]. The X.509 certificate
/// signing the request MUST NOT be self-signed."
#[test]
fn haip_refuses_a_self_signed_signer_and_an_anchor_in_the_chain() {
    let certified = certified();
    let resolver = resolver(&certified);
    // The root signs for itself: self-signed, even though it is trusted.
    assert!(matches!(
        resolver.validate(std::slice::from_ref(&certified.anchor), DEFAULT_TIME),
        Err(X509Error::SelfSigned)
    ));
    // The root rides along at the end of the chain.
    let mut with_root = certified.chain.clone();
    with_root.push(certified.anchor.clone());
    assert!(matches!(
        resolver.validate(&with_root, DEFAULT_TIME),
        Err(X509Error::TrustAnchorInChain { index: 2 })
    ));
    // So does a pinned intermediate.
    let pinned = X509Resolver::new([certified.chain[1].clone()]).unwrap();
    assert!(matches!(
        pinned.validate(&certified.chain, DEFAULT_TIME),
        Err(X509Error::TrustAnchorInChain { index: 1 })
    ));
    // A root the verifier does not trust is not an anchor because the token carries it.
    let untrusting = X509Resolver::new([other_anchor()]).unwrap();
    assert!(matches!(
        untrusting.validate(&with_root, DEFAULT_TIME),
        Err(X509Error::PathValidation(_))
    ));
}

#[test]
fn chain_limits_and_malformed_certificates() {
    let certified = certified();
    let resolver = resolver(&certified);
    assert!(matches!(
        resolver.validate(&[], DEFAULT_TIME),
        Err(X509Error::EmptyChain)
    ));
    let mut long = certified.chain.clone();
    long.resize(X509Resolver::MAX_CHAIN_LENGTH, certified.chain[1].clone());
    assert_eq!(
        resolver.validate(&long, DEFAULT_TIME).unwrap(),
        certified.key
    );
    long.push(certified.chain[1].clone());
    assert!(matches!(
        resolver.validate(&long, DEFAULT_TIME),
        Err(X509Error::ChainTooLong {
            length: 11,
            max: 10
        })
    ));
    assert!(matches!(
        resolver.validate(&[b"not a certificate".to_vec()], DEFAULT_TIME),
        Err(X509Error::InvalidCertificate { index: 0, .. })
    ));
    // A malformed certificate after the leaf is no intermediate, so the path stops there.
    let broken = [certified.chain[0].clone(), b"not a certificate".to_vec()];
    assert!(matches!(
        resolver.validate(&broken, DEFAULT_TIME),
        Err(X509Error::PathValidation(_))
    ));
}

#[test]
fn trust_anchors_are_ca_certificates() {
    let certified = certified();
    // The leaf signs tokens; trusting it as an anchor would let its key issue certificates.
    assert!(matches!(
        X509Resolver::new([certified.anchor.clone(), certified.chain[0].clone()]),
        Err(X509Error::TrustAnchorNotCa { index: 1 })
    ));
    assert!(matches!(
        X509Resolver::new([b"not a certificate".to_vec()]),
        Err(X509Error::InvalidCertificate { index: 0, .. })
    ));

    // From PEM, as trust lists come.
    let pem = |der: &[u8]| {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        )
    };
    let bundle = format!("{}\n{}", pem(&other_anchor()), pem(&certified.anchor));
    let from_pem = X509Resolver::from_pem(&bundle).unwrap();
    assert_eq!(from_pem.anchors().count(), 2);
    assert_eq!(
        from_pem.validate(&certified.chain, DEFAULT_TIME).unwrap(),
        certified.key
    );
    for no_certificate in [
        "",
        "not PEM",
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    ] {
        assert!(
            matches!(
                X509Resolver::from_pem(no_certificate),
                Err(X509Error::InvalidPem(_))
            ),
            "{no_certificate:?}"
        );
    }
    assert!(matches!(
        X509Resolver::from_pem(&pem(&certified.chain[0])),
        Err(X509Error::TrustAnchorNotCa { index: 0 })
    ));
}

/// The chain is valid from 1970-01-01T00:00:01Z to 2969-05-03T00:00:01Z.
#[test]
fn certificates_are_valid_at_the_validation_time() {
    let certified = certified();
    let resolver = resolver(&certified);
    for valid in [1, DEFAULT_TIME, 31_536_000_001] {
        assert!(
            resolver.validate(&certified.chain, valid).is_ok(),
            "{valid}"
        );
    }
    for (invalid, cause) in [(0, "CertNotValidYet"), (31_536_000_002, "CertExpired")] {
        let error = resolver.validate(&certified.chain, invalid).unwrap_err();
        assert!(
            matches!(&error, X509Error::PathValidation(_)) && error.to_string().contains(cause),
            "{invalid}: {error}"
        );
    }
    assert!(matches!(
        resolver.validate(&certified.chain, -1),
        Err(X509Error::InvalidTime(-1))
    ));

    // The anchor's own validity counts: the suite's expired root, with a leaf still valid.
    let expired_root = testcase("rfc5280::validity::expired-root");
    let error = expired_root.validate().unwrap_err();
    assert!(error.to_string().contains("CertExpired"), "{error}");
}

#[tokio::test]
async fn resolves_only_certificate_chains() {
    let certified = certified();
    let resolver = resolver(&certified);
    let chain = KeyReference::X509Chain(certified.chain.clone());
    for role in [KeyRole::Issuer, KeyRole::Subject] {
        assert_eq!(
            resolver.resolve_key(&chain, role).await.unwrap(),
            certified.key
        );
    }
    // At a given time, through the wrappers that forward it and through a composite.
    let after = 31_536_000_002;
    let shared = Arc::new(resolver.clone());
    let composite = CompositeKeyResolver::new()
        .with(JwkResolver)
        .with(resolver.clone());
    let resolvers: [&dyn KeyResolver; 4] = [&resolver, &shared, &&resolver, &composite];
    for resolver in resolvers {
        assert_eq!(
            resolver
                .resolve_key_at(&chain, KeyRole::Issuer, DEFAULT_TIME)
                .await
                .unwrap(),
            certified.key
        );
        let error = resolver
            .resolve_key_at(&chain, KeyRole::Issuer, after)
            .await
            .unwrap_err();
        let KeyResolutionError::Failed(inner) = &error else {
            panic!("{error:?}");
        };
        assert!(
            matches!(
                inner.downcast_ref::<X509Error>(),
                Some(X509Error::PathValidation(_))
            ),
            "{error}"
        );
    }
    // Any other reference is somebody else's.
    let by_value = KeyReference::Jwk(Box::new(certified.key.clone()));
    assert!(
        resolver
            .resolve_key(&by_value, KeyRole::Issuer)
            .await
            .unwrap_err()
            .is_unsupported()
    );
    // A resolver that ignores the time resolves the same key at any.
    assert_eq!(
        JwkResolver
            .resolve_key_at(&by_value, KeyRole::Issuer, after)
            .await
            .unwrap(),
        certified.key
    );
}

/// A signer with a chain names its key by `x5c`, and by nothing else.
#[test]
fn certified_signer_puts_the_chain_in_the_header() {
    let certified = certified();
    assert_eq!(certified.signer.x5c(), Some(&certified.chain[..]));
    assert!(certified.signer.signer().kid.is_none());
    let header = JwsHeader::for_signer(&certified.signer);
    assert_eq!(header.kid, None);
    let expected: Vec<String> = certified
        .chain
        .iter()
        .map(|certificate| STANDARD.encode(certificate))
        .collect();
    assert_eq!(header.additional["x5c"], serde_json::json!(expected));
    assert_eq!(
        JwsHeader::new(header.alg).with_x5c(&certified.chain),
        header
    );
    // Even when the signer has a `kid` of its own.
    let with_kid = CertifiedSigner::new(
        Es256Signer::rfc7515_a3().with_kid("key-1"),
        certified.chain.clone(),
    );
    assert_eq!(with_kid.kid(), Some("key-1"));
    assert_eq!(JwsHeader::for_signer(&with_kid).kid, None);
    // And a signer without a chain keeps its `kid`.
    let plain = Es256Signer::rfc7515_a3().with_kid("key-1");
    assert_eq!(plain.x5c(), None);
    let header = JwsHeader::for_signer(&plain);
    assert_eq!(header.kid.as_deref(), Some("key-1"));
    assert!(!header.additional.contains_key("x5c"));
}

// ---------------------------------------------------------------------------------------------
// A plain JWT
// ---------------------------------------------------------------------------------------------

mod jwt {
    use identity_kit::jose::{DefaultVerifier, JwtClaims, encode_compact};
    use identity_kit::resolver::{JwtValidationError, JwtValidationOptions, JwtValidator};

    use super::*;

    async fn token(certified: &Certified, iss: Option<&str>) -> String {
        let mut claims = JwtClaims::new();
        claims.iss = iss.map(str::to_owned);
        claims.exp = Some(DEFAULT_TIME + 600);
        let header = JwsHeader::for_signer(&certified.signer).with_typ("JWT");
        let payload = serde_json::to_vec(&claims).unwrap();
        encode_compact(&header, &payload, &certified.signer)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn validates_under_the_chain_at_the_validation_time() {
        let certified = certified();
        let validator = JwtValidator::new(resolver(&certified), DefaultVerifier);
        let options = JwtValidationOptions::new().at(DEFAULT_TIME);

        // Without `iss`, the issuer is the subject of the certificate.
        let anonymous = token(&certified, None).await;
        let validated = validator.validate(&anonymous, &options).await.unwrap();
        assert_eq!(validated.key, certified.key);
        let KeyReference::X509Chain(chain) = &validated.key_reference else {
            panic!("{:?}", validated.key_reference);
        };
        assert_eq!(
            X509Certificate::from_der(&chain[0]).unwrap().subject(),
            "CN=example.com"
        );

        // An `iss` the certificate names is the issuer's; any other is not.
        let named = token(&certified, Some("https://example.com")).await;
        assert!(validator.validate(&named, &options).await.is_ok());
        let claimed = token(&certified, Some("https://issuer.example")).await;
        assert!(matches!(
            validator.validate(&claimed, &options).await,
            Err(JwtValidationError::KeyNotIssuers { .. })
        ));

        // A verifier that does not trust the root resolves no key.
        let untrusting = JwtValidator::new(
            X509Resolver::new([other_anchor()]).unwrap(),
            DefaultVerifier,
        );
        assert!(matches!(
            untrusting.validate(&anonymous, &options).await,
            Err(JwtValidationError::KeyResolution { .. })
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// SD-JWT VC (HAIP 1.0 §6.1.1)
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "sd-jwt")]
mod sd_jwt_vc {
    use chrono::{DateTime, TimeZone as _, Utc};
    use identity_kit::jose::DefaultVerifier;
    use identity_kit::resolver::KeyReferenceError;
    use identity_kit::sd_jwt_vc::validation::{SdJwtValidationError, SdJwtValidationOptions};
    use identity_kit::sd_jwt_vc::{SdJwtCredentialValidator, SdJwtVc, SdJwtVcBuilder};
    use identity_kit::vc::CredentialError;
    use identity_kit::vc::validation::{TimeOptions, ValidationError};

    use super::*;

    const VCT: &str = "urn:eudi:pid:1";

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(DEFAULT_TIME, 0).unwrap()
    }

    fn builder() -> SdJwtVcBuilder {
        SdJwtVcBuilder::new(VCT)
            .with_issued_at(now())
            .with_claim("given_name", "Erika")
            .conceal(["given_name"])
    }

    fn options() -> SdJwtValidationOptions {
        SdJwtValidationOptions::new().with_time(TimeOptions::at(now()))
    }

    fn validator<R: KeyResolver>(resolver: R) -> SdJwtCredentialValidator<R> {
        SdJwtCredentialValidator::new(resolver, DefaultVerifier)
    }

    fn key_resolution(
        result: &Result<identity_kit::sd_jwt_vc::ValidatedSdJwtVc, SdJwtValidationError>,
    ) -> bool {
        matches!(
            result,
            Err(SdJwtValidationError::Validation(
                ValidationError::KeyResolution { .. }
            ))
        )
    }

    /// The issuer signs with its certificate chain and names itself by nothing else: the
    /// issuer is the subject of the certificate.
    #[tokio::test]
    async fn issuer_is_the_certificate_subject() {
        let certified = certified();
        let credential = builder().sign(&certified.signer).await.unwrap();
        let header = credential.header();
        assert_eq!(header.typ.as_deref(), Some("dc+sd-jwt"));
        assert!(header.kid.is_none() && header.additional.contains_key("x5c"));
        assert!(credential.claims().iss.is_none());

        let validator = validator(resolver(&certified));
        let validated = validator
            .validate_credential(credential.clone(), &options())
            .await
            .unwrap();
        let KeyReference::X509Chain(chain) = &validated.issuer_key else {
            panic!("{:?}", validated.issuer_key);
        };
        assert_eq!(chain, &certified.chain);
        let issuer = X509Certificate::from_der(&chain[0]).unwrap();
        assert_eq!(issuer.subject(), "CN=example.com");
        assert_eq!(issuer.dns_names(), ["example.com"]);

        // Through the serialized form, as a verifier receives it.
        let received: SdJwtVc = credential.to_string().parse().unwrap();
        assert!(
            validator
                .validate_credential(received, &options())
                .await
                .is_ok()
        );

        // A verifier that trusts another root, or none.
        for untrusting in [
            X509Resolver::new([other_anchor()]).unwrap(),
            X509Resolver::new(Vec::<Vec<u8>>::new()).unwrap(),
        ] {
            assert!(key_resolution(
                &super::sd_jwt_vc::validator(untrusting)
                    .validate_credential(credential.clone(), &options())
                    .await
            ));
        }

        // The certificates must be valid at the validation time, not at the current one: the
        // chain expires in 2969, and the credential itself never does.
        let late = SdJwtValidationOptions::new().with_time(TimeOptions::at(
            Utc.timestamp_opt(31_536_000_002, 0).unwrap(),
        ));
        assert!(key_resolution(
            &validator.validate_credential(credential, &late).await
        ));
    }

    /// SD-JWT VC §3.5: "An `iss` claim, if present, is not authenticated by this mechanism".
    /// It is the issuer only when the certificate names it.
    #[tokio::test]
    async fn iss_must_be_bound_to_the_certificate() {
        let certified = certified();
        let validator = validator(resolver(&certified));
        let named = builder()
            .with_issuer("https://example.com")
            .sign(&certified.signer)
            .await
            .unwrap();
        assert!(
            validator
                .validate_credential(named, &options())
                .await
                .is_ok()
        );

        // Any holder of a certificate under the anchor could claim to be someone else.
        for claimed in ["https://issuer.example", "did:example:123"] {
            let forged = builder()
                .with_issuer(claimed)
                .sign(&certified.signer)
                .await
                .unwrap();
            let result = validator.validate_credential(forged, &options()).await;
            assert!(
                matches!(
                    &result,
                    Err(SdJwtValidationError::Validation(
                        ValidationError::IssuerMismatch { issuer, .. }
                    )) if issuer.as_str() == claimed
                ),
                "{claimed}: {result:?}"
            );
        }
    }

    /// A credential that carries a `kid` and an HTTPS `iss` next to the chain: which
    /// mechanism applies is the verifier's policy, the resolvers it configured.
    #[tokio::test]
    async fn mechanism_is_the_verifiers_policy() {
        let certified = certified();
        let credential = builder()
            .with_issuer("https://example.com")
            .with_kid("key-1")
            .sign(&certified.signer)
            .await
            .unwrap();
        assert_eq!(credential.header().kid.as_deref(), Some("key-1"));
        let candidates = KeyReference::candidates(
            &credential.sd_jwt().jwt().decode().unwrap(),
            Some("https://example.com"),
        )
        .unwrap();
        assert!(
            matches!(
                &candidates[..],
                [KeyReference::X509Chain(_), KeyReference::Jwks { kid, .. }] if kid == "key-1"
            ),
            "{candidates:?}"
        );

        // A verifier of certificate chains takes the chain, alone or among other resolvers.
        let composite = CompositeKeyResolver::new()
            .with(JwkResolver)
            .with(resolver(&certified));
        for validated in [
            validator(resolver(&certified))
                .validate_credential(credential.clone(), &options())
                .await,
            validator(composite)
                .validate_credential(credential.clone(), &options())
                .await,
        ] {
            assert!(matches!(
                validated.unwrap().issuer_key,
                KeyReference::X509Chain(_)
            ));
        }

        // A verifier that resolves neither reports the first reference.
        let result = validator(JwkResolver)
            .validate_credential(credential.clone(), &options())
            .await;
        assert!(
            matches!(
                &result,
                Err(SdJwtValidationError::Validation(ValidationError::KeyResolution { key, source }))
                    if matches!(**key, KeyReference::X509Chain(_)) && source.is_unsupported()
            ),
            "{result:?}"
        );

        // A chain that does not validate ends the search: the key set is not tried.
        let untrusting = CompositeKeyResolver::new()
            .with(X509Resolver::new([other_anchor()]).unwrap())
            .with(JwkResolver);
        assert!(key_resolution(
            &validator(untrusting)
                .validate_credential(credential, &options())
                .await
        ));
    }

    /// A verifier of issuer key sets, which does not resolve chains, falls through to the
    /// key set the `kid` and `iss` name.
    #[cfg(feature = "jwks")]
    #[tokio::test]
    async fn a_key_set_verifier_ignores_the_chain() {
        use identity_kit::resolver::JwksResolver;

        let certified = certified();
        let credential = builder()
            .with_issuer("https://example.com")
            .with_kid("key-1")
            .sign(&certified.signer)
            .await
            .unwrap();
        let mut key = serde_json::to_value(&certified.key).unwrap();
        key["kid"] = "key-1".into();
        let web = common::http::Web::default().serve_json(
            "https://example.com/.well-known/jwt-vc-issuer",
            serde_json::json!({"issuer": "https://example.com", "jwks": {"keys": [key]}}),
        );
        let validated = validator(JwksResolver::new(web))
            .validate_credential(credential, &options())
            .await
            .unwrap();
        assert!(matches!(validated.issuer_key, KeyReference::Jwks { .. }));
    }

    /// Only a certificate chain identifies an issuer without `iss`: a key by value binds to
    /// nobody, so a credential naming its key that way still needs one.
    #[tokio::test]
    async fn only_a_chain_stands_in_for_iss() {
        let certified = certified();
        let mut header =
            JwsHeader::new(identity_kit::jose::JwsAlgorithm::ES256).with_typ("dc+sd-jwt");
        header.jwk = Some(certified.key.clone());
        let claims = identity_kit::sd_jwt_vc::SdJwtVcClaims::new(VCT).to_map();
        let sd_jwt = identity_kit::sd_jwt_vc::SdJwtBuilder::new(claims)
            .sign(&header, certified.signer.signer())
            .await
            .unwrap();
        let result = validator(JwkResolver).validate(&sd_jwt, &options()).await;
        assert!(
            matches!(
                &result,
                Err(SdJwtValidationError::Validation(
                    ValidationError::Credential(CredentialError::MissingClaim("iss"))
                ))
            ),
            "{result:?}"
        );

        // And a credential that names no key at all fails on that.
        let bare = identity_kit::sd_jwt_vc::SdJwtBuilder::new(
            identity_kit::sd_jwt_vc::SdJwtVcClaims::new(VCT).to_map(),
        )
        .sign(
            &JwsHeader::new(identity_kit::jose::JwsAlgorithm::ES256).with_typ("dc+sd-jwt"),
            certified.signer.signer(),
        )
        .await
        .unwrap();
        let result = validator(resolver(&certified))
            .validate(&bare, &options())
            .await;
        assert!(
            matches!(
                &result,
                Err(SdJwtValidationError::Validation(
                    ValidationError::KeyReference(KeyReferenceError::Missing)
                ))
            ),
            "{result:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Status List Token (HAIP 1.0 §6.1)
// ---------------------------------------------------------------------------------------------

#[cfg(all(feature = "status-list", feature = "did-web"))]
mod status_list {
    use chrono::{TimeZone as _, Utc};
    use identity_kit::jose::DefaultVerifier;
    use identity_kit::methods::web::HttpResponse;
    use identity_kit::status_list::{
        Status, StatusList, StatusListCheck, StatusListRef, StatusListToken,
    };
    use identity_kit::vc::validation::{
        CredentialStatus, StatusCheck as _, StatusError, TimeOptions,
    };

    use super::*;
    use common::http::Web;

    const URI: &str = "https://example.com/statuslists/1";

    /// "The public key used to validate the signature on the Status List Token […] MUST be
    /// included in the x5c JOSE header of the Token."
    #[tokio::test]
    async fn token_is_verified_under_its_chain() {
        let certified = certified();
        let issued_at = Utc.timestamp_opt(DEFAULT_TIME, 0).unwrap();
        let token = StatusListToken::new(URI, issued_at, StatusList::new(1, 8).unwrap())
            .sign(&certified.signer)
            .await
            .unwrap();
        let (header, _) = StatusListToken::decode(&token).unwrap();
        assert!(header.kid.is_none() && header.additional.contains_key("x5c"));

        let serving = || Web::default().with(URI, HttpResponse::new(200, token.as_str()));
        let status = Status::status_list(StatusListRef::new(URI, 0));
        let at = |seconds: i64| TimeOptions::at(Utc.timestamp_opt(seconds, 0).unwrap());

        let check = StatusListCheck::new(serving(), resolver(&certified), DefaultVerifier);
        check
            .check(
                CredentialStatus::StatusClaim(&status),
                at(DEFAULT_TIME + 60),
            )
            .await
            .unwrap();

        // A verifier that does not trust the root.
        let untrusting = StatusListCheck::new(
            serving(),
            X509Resolver::new([other_anchor()]).unwrap(),
            DefaultVerifier,
        );
        let result = untrusting
            .check(
                CredentialStatus::StatusClaim(&status),
                at(DEFAULT_TIME + 60),
            )
            .await;
        assert!(
            matches!(&result, Err(StatusError::UnresolvedKey { key, .. }) if key.contains("x5c")),
            "{result:?}"
        );

        // The chain is validated at the validation time of the credential.
        let result = check
            .check(CredentialStatus::StatusClaim(&status), at(31_536_000_002))
            .await;
        assert!(
            matches!(&result, Err(StatusError::UnresolvedKey { .. })),
            "{result:?}"
        );
    }
}
