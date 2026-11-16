//! X.509 (feature `x509`): reading an arbitrary certificate never panics and is stable, and a
//! chain of an arbitrary leaf under a fixed intermediate and root never panics, validating
//! only to the key of that leaf.
#![no_main]

use identity_kit::resolver::{KeyReference, X509Certificate, X509Resolver};
use libfuzzer_sys::fuzz_target;

/// The chain of the x509-limbo testcase `pathlen::ee-with-intermediate-pathlen-0`, whose leaf
/// is the seed `leaf.der`.
const INTERMEDIATE: &[u8] = include_bytes!("../seeds/x509/intermediate.der");
const ROOT: &[u8] = include_bytes!("../seeds/x509/root.der");

/// 2023-11-14, inside the validity of the seeds.
const NOW: i64 = 1_700_000_000;

fuzz_target!(|data: &[u8]| {
    let certificate = X509Certificate::from_der(data);
    if let Ok(certificate) = &certificate {
        assert_eq!(certificate.der(), data);
        assert_eq!(
            X509Certificate::from_der(certificate.der()).as_ref().ok(),
            Some(certificate)
        );
        assert!(certificate.not_before() >= 0 && certificate.not_after() >= 0);
        let _ = (
            certificate.subject(),
            certificate.issuer(),
            certificate.is_ca(),
            certificate.is_self_issued(),
            certificate.subject_key_identifier(),
            certificate.authority_key_identifier(),
            certificate.sha256_thumbprint(),
            certificate.public_key(),
            format!("{certificate:?}"),
        );
        // Only a DNS name binds, and only an `https` URL on it: a URI name is bound when a
        // DNS name of the certificate is its host, never for being a name of the certificate.
        for uri in certificate.uris() {
            if certificate.binds(uri) {
                let on_a_dns_name = certificate.dns_names().iter().any(|name| {
                    uri.strip_prefix("https://").is_some_and(|rest| {
                        rest.get(..name.len())
                            .is_some_and(|host| host.eq_ignore_ascii_case(name))
                    })
                });
                assert!(on_a_dns_name, "{uri} is bound by no DNS name");
            }
        }
        for name in certificate.dns_names() {
            let _ = certificate.binds(&format!("https://{name}"));
        }
        assert!(!certificate.binds(""));
    }

    // As a trust anchor: accepted only when it reads as a certificate.
    if X509Resolver::new([data.to_vec()]).is_ok() {
        assert!(certificate.as_ref().is_ok_and(X509Certificate::is_ca));
    }

    // As the leaf of a chain: a key only when the chain validates, and then the leaf's own.
    let resolver = X509Resolver::new([ROOT.to_vec()]).expect("the root is a CA certificate");
    let chain = vec![data.to_vec(), INTERMEDIATE.to_vec()];
    if let Ok(key) = resolver.validate(&chain, NOW) {
        let leaf = certificate
            .as_ref()
            .expect("a validated leaf is a certificate");
        assert_eq!(leaf.public_key().ok(), Some(key));
        assert!(!leaf.is_self_issued() && !leaf.is_ca());
    }
    // Binding reads the leaf again, whatever it is.
    let reference = KeyReference::X509Chain(chain);
    let _ = reference.to_string();
});
