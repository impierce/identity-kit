//! `X509Resolver`: the key of an `x5c` certificate chain, validated against trust anchors, and
//! `X509Certificate`, what a certificate says about its subject.

use core::fmt;
use core::time::Duration;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use sha2::{Digest as _, Sha256};
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::spki::SubjectPublicKeyInfoRef;

use super::{KeyReference, KeyResolutionError, KeyResolver, KeyRole};
use crate::jose::{Jwk, base64url};

/// `id-ecPublicKey` (RFC 5480 §2.1.1).
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `secp256r1`, the curve P-256 (RFC 5480 §2.1.1.1).
const SECP256R1: &str = "1.2.840.10045.3.1.7";
/// `secp384r1`, the curve P-384.
const SECP384R1: &str = "1.3.132.0.34";
/// `secp256k1`.
#[cfg(feature = "secp256k1")]
const SECP256K1: &str = "1.3.132.0.10";
/// `id-Ed25519` (RFC 8410 §3).
const ED25519: &str = "1.3.101.112";
/// `rsaEncryption` (RFC 8017 Appendix A.1).
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
/// The shortest RSA modulus accepted, as for signatures (RFC 7518 §3.3).
const MIN_RSA_BITS: usize = 2048;

/// Resolves a [`KeyReference::X509Chain`], the `x5c` header of a token (RFC 7515 §4.1.6), to
/// the public key of its first certificate once the chain validates against a trust anchor;
/// every other reference is [`Unsupported`](KeyResolutionError::Unsupported).
///
/// This is the *Inline X.509 Certificates* mechanism of SD-JWT VC §3.5, which the OpenID4VC
/// High Assurance Interoperability Profile (HAIP) 1.0 mandates for SD-JWT VCs (§6.1.1), for
/// Status List Tokens (§6.1) and for the signed requests, metadata and attestations of
/// OID4VCI and OID4VP.
///
/// # What is checked
///
/// The application supplies the trust anchors; the crate ships none, and a certificate is
/// never trusted because the token carries it. For a chain `[leaf, intermediate…]`:
///
/// 1. The chain has at least one and at most [`MAX_CHAIN_LENGTH`](Self::MAX_CHAIN_LENGTH)
///    certificates.
/// 2. Every certificate of the chain reads as one, and the leaf is not self-issued (its
///    subject is not its issuer), which HAIP requires of every `x5c` it defines: "The X.509
///    certificate signing the request MUST NOT be self-signed."
/// 3. A path from the leaf to a trust anchor validates, at the validation time: each
///    signature, each validity period, `basicConstraints` and the path length, name
///    constraints on DNS names, and no critical extension that is not understood. The
///    certificates after the leaf are a pool to build the path from, so their order does not
///    matter, and one that is itself a trust anchor adds nothing. Path building and these
///    checks are [`rustls-webpki`](https://docs.rs/rustls-webpki)'s.
/// 4. Every CA certificate of the path that has a `keyUsage` extension asserts
///    `keyCertSign` (RFC 5280 §6.1.4), the trust anchor included.
/// 5. The trust anchor the path ends at is within its own validity period.
/// 6. A leaf that has a `keyUsage` extension asserts `digitalSignature` or `nonRepudiation`
///    (`contentCommitment`, which qualified seal certificates carry alone), and not
///    `keyCertSign` (RFC 5280 §4.2.1.3).
/// 7. The leaf's key is one a JWS can be verified with: P-256, P-384, secp256k1 (feature
///    `secp256k1`), Ed25519 or RSA of at least 2048 bits.
///
/// Certificates are signed with ECDSA on P-256 or P-384, Ed25519, or RSA from 2048 bits, with
/// SHA-256, SHA-384 or SHA-512. SHA-1, P-521 and Brainpool curves are refused.
///
/// # What is not checked
///
/// - **Revocation.** Neither CRLs nor OCSP are consulted. An application that needs it checks
///   the chain itself, or keeps its trust anchors current.
/// - **Extended key usage and certificate policies.** SD-JWT VC and HAIP define none for
///   credential issuers, so any is accepted. The [`KeyRole`] makes no difference either: a
///   chain is validated the same for an issuer and for a holder.
/// - **Name constraints on anything but DNS names**, which is why only a DNS name binds an
///   `iss` ([`X509Certificate::binds`]).
/// - **Whether the chain leaves out the trust anchor.** HAIP forbids an issuer to include
///   it. A verifier that pins an intermediate CA cannot tell an issuer's chain that includes
///   it from a violation, and a copy of an anchor adds no trust, so such a chain validates.
/// - **Who the subject is.** A valid chain says the key belongs to the subject of the leaf
///   under one of the trust anchors, not that this subject may issue a given credential:
///   that is the application's policy, with [`X509Certificate`] to read the subject from.
///
/// # The issuer of a token
///
/// With `x5c`, the issuer is the subject of the leaf certificate, and an `iss` claim is not
/// authenticated by the chain (SD-JWT VC §3.5). [`KeyReference::binds_to`] therefore accepts
/// an `iss` only when the leaf binds it, as an `https` URL whose host is one of its DNS names
/// ([`X509Certificate::binds`]), and the SD-JWT VC validator accepts a credential without
/// `iss`.
///
/// Every CA under the trust anchors is trusted to certify the names it puts in a leaf, the
/// subject included: name constraints restrict DNS names in the Subject Alternative Name
/// extension, not a common name. Which mechanism verifies a token also follows from what the
/// token carries, a chain or a `kid`, whenever the application configures resolvers for both;
/// an application that must pin one mechanism per issuer (SD-JWT VC §3.5 asks that an
/// attacker cannot choose it) checks the `KeyReference` the validator returns, or gives each
/// issuer's tokens a validator with the one resolver.
///
/// # Time
///
/// A validator passes its validation time through [`KeyResolver::resolve_key_at`];
/// [`resolve_key`](KeyResolver::resolve_key) validates at the current time. A resolver that
/// wraps this one must forward `resolve_key_at`, or its chains are validated at the current
/// time whatever the validator asks.
#[derive(Clone)]
pub struct X509Resolver {
    anchors: Vec<Anchor>,
}

/// A trust anchor: its certificate and when that is valid.
#[derive(Clone)]
struct Anchor {
    der: CertificateDer<'static>,
    not_before: i64,
    not_after: i64,
}

impl X509Resolver {
    /// The most certificates an `x5c` chain may hold.
    pub const MAX_CHAIN_LENGTH: usize = 10;

    /// A resolver trusting `anchors`, DER-encoded certificates: root CAs, or any CA
    /// certificate the application pins.
    ///
    /// Each anchor must be a CA certificate, one whose `basicConstraints` say `cA` and whose
    /// `keyUsage`, if it has one, asserts `keyCertSign`: whoever holds the key of an anchor
    /// can issue certificates this resolver accepts, so a certificate that signs credentials
    /// is refused as an anchor. A resolver without anchors
    /// refuses every chain.
    ///
    /// # Errors
    ///
    /// [`X509Error::InvalidCertificate`] when an anchor is not a certificate, and
    /// [`X509Error::TrustAnchorNotCa`] when it is not a CA certificate.
    pub fn new<I, C>(anchors: I) -> Result<Self, X509Error>
    where
        I: IntoIterator<Item = C>,
        C: Into<Vec<u8>>,
    {
        let anchors = anchors
            .into_iter()
            .enumerate()
            .map(|(index, anchor)| {
                let der = CertificateDer::from(anchor.into());
                let certificate = X509Certificate::parse(&der)
                    .map_err(|e| X509Error::invalid_certificate(index, e))?;
                webpki::anchor_from_trusted_cert(&der)
                    .map_err(|e| X509Error::invalid_certificate(index, e))?;
                if !certificate.may_issue() {
                    return Err(X509Error::TrustAnchorNotCa { index });
                }
                Ok(Anchor {
                    der,
                    not_before: certificate.not_before,
                    not_after: certificate.not_after,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { anchors })
    }

    /// A resolver trusting every certificate of `pem`, a concatenation of
    /// `-----BEGIN CERTIFICATE-----` blocks.
    ///
    /// # Errors
    ///
    /// [`X509Error::InvalidPem`] when `pem` does not read as PEM or holds no certificate, and
    /// [`X509Error::InvalidCertificate`] when one of them is not a certificate.
    pub fn from_pem(pem: &str) -> Result<Self, X509Error> {
        let anchors = CertificateDer::pem_slice_iter(pem.as_bytes())
            .map(|certificate| certificate.map(|certificate| certificate.to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| X509Error::InvalidPem(e.to_string()))?;
        if anchors.is_empty() {
            return Err(X509Error::InvalidPem("no certificate".to_owned()));
        }
        Self::new(anchors)
    }

    /// The trust anchors, DER-encoded.
    pub fn anchors(&self) -> impl Iterator<Item = &[u8]> {
        self.anchors.iter().map(|anchor| anchor.der.as_ref())
    }

    /// Validates `chain`, the certificates of an `x5c` header, leaf first and DER-encoded, at
    /// `now` (seconds since the Unix epoch), and returns the public key of the leaf.
    ///
    /// # Errors
    ///
    /// An [`X509Error`] naming the first check of the [type documentation](Self) that fails.
    pub fn validate(&self, chain: &[Vec<u8>], now: i64) -> Result<Jwk, X509Error> {
        let (leaf_der, intermediates) = chain.split_first().ok_or(X509Error::EmptyChain)?;
        if chain.len() > Self::MAX_CHAIN_LENGTH {
            return Err(X509Error::ChainTooLong {
                length: chain.len(),
                max: Self::MAX_CHAIN_LENGTH,
            });
        }
        let certificates = chain
            .iter()
            .enumerate()
            .map(|(index, certificate)| {
                X509Certificate::parse(certificate)
                    .map_err(|e| X509Error::invalid_certificate(index, e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = &certificates[0];
        if leaf.is_self_issued() {
            return Err(X509Error::SelfSigned);
        }

        let time = u64::try_from(now)
            .map(|now| UnixTime::since_unix_epoch(Duration::from_secs(now)))
            .map_err(|_| X509Error::InvalidTime(now))?;
        let anchors = self
            .anchors
            .iter()
            .map(|anchor| webpki::anchor_from_trusted_cert(&anchor.der))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| X509Error::PathValidation(Box::new(e)))?;
        // What `rustls-webpki` leaves to its caller, for each path it has verified; an error
        // makes path building try another one.
        let check_path = |path: &webpki::VerifiedPath<'_>| {
            // A CA certificate with a `keyUsage` that lacks `keyCertSign` issues nothing.
            for intermediate in path.intermediate_certificates() {
                let der = intermediate.der();
                let may_issue = certificates
                    .iter()
                    .find(|certificate| certificate.der == der.as_ref())
                    .is_some_and(X509Certificate::may_issue);
                if !may_issue {
                    return Err(webpki::Error::EndEntityUsedAsCa);
                }
            }
            anchor_validity(path.anchor(), anchors.iter().zip(&self.anchors), now)
        };
        let intermediates: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|certificate| CertificateDer::from(certificate.as_slice()))
            .collect();
        let leaf_der = CertificateDer::from(leaf_der.as_slice());
        let end_entity =
            EndEntityCert::try_from(&leaf_der).map_err(|e| X509Error::invalid_certificate(0, e))?;
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                time,
                AnyExtendedKeyUsage,
                None,
                Some(&check_path),
            )
            .map_err(|e| X509Error::PathValidation(Box::new(e)))?;

        if !leaf.may_sign_tokens() {
            return Err(X509Error::KeyUsage);
        }
        leaf.public_key()
    }
}

impl fmt::Debug for X509Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Resolver")
            .field("anchors", &self.anchors.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl KeyResolver for X509Resolver {
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            });
        self.resolve_key_at(key, role, now).await
    }

    async fn resolve_key_at(
        &self,
        key: &KeyReference,
        _: KeyRole,
        now: i64,
    ) -> Result<Jwk, KeyResolutionError> {
        match key {
            KeyReference::X509Chain(chain) => {
                self.validate(chain, now).map_err(KeyResolutionError::new)
            }
            other => Err(KeyResolutionError::unsupported(other)),
        }
    }
}

/// Whether a certificate configured as the trust anchor `used` is valid at `now`; the error
/// of the last one that is not, otherwise.
///
/// `rustls-webpki` reads a trust anchor as a name, a key and name constraints, without a
/// validity period, so `used` stands for every configured certificate with those three alike.
/// A certificate with the same name and key and other constraints is another anchor, which
/// the path was not verified under: it lends this one no validity.
fn anchor_validity<'a>(
    used: &TrustAnchor<'_>,
    configured: impl IntoIterator<Item = (&'a TrustAnchor<'a>, &'a Anchor)>,
    now: i64,
) -> Result<(), webpki::Error> {
    let mut error = webpki::Error::UnknownIssuer;
    for (anchor, certificate) in configured {
        if anchor.subject != used.subject
            || anchor.subject_public_key_info != used.subject_public_key_info
            || anchor.name_constraints != used.name_constraints
        {
            continue;
        }
        match outside_validity(now, certificate.not_before, certificate.not_after) {
            None => return Ok(()),
            Some(outside) => error = outside,
        }
    }
    Err(error)
}

/// Why a certificate valid from `not_before` to `not_after`, both inclusive and in seconds
/// since the Unix epoch, is not valid at `now`; `None` when it is.
fn outside_validity(now: i64, not_before: i64, not_after: i64) -> Option<webpki::Error> {
    let time = |seconds: i64| {
        UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(seconds).unwrap_or(0)))
    };
    if now < not_before {
        Some(webpki::Error::CertNotValidYet {
            time: time(now),
            not_before: time(not_before),
        })
    } else if now > not_after {
        Some(webpki::Error::CertExpired {
            time: time(now),
            not_after: time(not_after),
        })
    } else {
        None
    }
}

/// Accepts any extended key usage, and a certificate without one: the specifications that
/// use `x5c` here define none.
struct AnyExtendedKeyUsage;

impl ExtendedKeyUsageValidator for AnyExtendedKeyUsage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        // Reading every entry still refuses an extension that is not a list of OIDs.
        for purpose in iter {
            purpose?;
        }
        Ok(())
    }
}

/// The `keyUsage` bits this module reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Usage {
    digital_signature: bool,
    non_repudiation: bool,
    key_cert_sign: bool,
}

/// What an X.509 certificate says: its subject and issuer, the names of its Subject
/// Alternative Name extension, its validity period, its key identifiers and its public key.
///
/// Reading a certificate verifies nothing: [`X509Resolver`] decides whether it is trusted.
/// With an `x5c` header the issuer of a token is the subject of the first certificate, so this
/// is what an application reads to decide whether that issuer may say what the token says.
///
/// # Examples
///
/// ```
/// use identity_kit::resolver::{KeyReference, X509Certificate};
///
/// /// The subject of the certificate that signed a token, when it was signed with `x5c`.
/// fn signer(key: &KeyReference) -> Option<String> {
///     let KeyReference::X509Chain(chain) = key else { return None };
///     let leaf = X509Certificate::from_der(chain.first()?).ok()?;
///     Some(leaf.subject().to_owned())
/// }
/// # let _ = signer;
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct X509Certificate {
    der: Vec<u8>,
    subject: String,
    issuer: String,
    self_issued: bool,
    ca: bool,
    dns_names: Vec<String>,
    uris: Vec<String>,
    not_before: i64,
    not_after: i64,
    subject_key_identifier: Option<Vec<u8>>,
    authority_key_identifier: Option<Vec<u8>>,
    key_usage: Option<Usage>,
    public_key: Vec<u8>,
}

impl X509Certificate {
    /// Reads a DER-encoded certificate.
    ///
    /// # Errors
    ///
    /// [`X509Error::InvalidCertificate`], with index 0, when `der` is not a certificate or one
    /// of the extensions read here is malformed.
    pub fn from_der(der: &[u8]) -> Result<Self, X509Error> {
        Self::parse(der).map_err(|e| X509Error::invalid_certificate(0, e))
    }

    fn parse(der: &[u8]) -> Result<Self, x509_cert::der::Error> {
        let certificate = Certificate::from_der(der)?;
        let tbs = certificate.tbs_certificate();
        let (mut dns_names, mut uris) = (Vec::new(), Vec::new());
        if let Some((_, SubjectAltName(names))) = tbs.get_extension::<SubjectAltName>()? {
            for name in names {
                match name {
                    GeneralName::DnsName(name) => dns_names.push(name.to_string()),
                    GeneralName::UniformResourceIdentifier(uri) => uris.push(uri.to_string()),
                    _ => {}
                }
            }
        }
        let subject_key_identifier = tbs
            .get_extension::<SubjectKeyIdentifier>()?
            .map(|(_, identifier)| identifier.0.as_bytes().to_vec());
        let authority_key_identifier = tbs
            .get_extension::<AuthorityKeyIdentifier>()?
            .and_then(|(_, identifier)| identifier.key_identifier)
            .map(|identifier| identifier.as_bytes().to_vec());
        let key_usage = tbs.get_extension::<KeyUsage>()?.map(|(_, usage)| Usage {
            digital_signature: usage.digital_signature(),
            non_repudiation: usage.non_repudiation(),
            key_cert_sign: usage.key_cert_sign(),
        });
        let ca = tbs
            .get_extension::<BasicConstraints>()?
            .is_some_and(|(_, constraints)| constraints.ca);
        let seconds = |time: x509_cert::time::Time| {
            i64::try_from(time.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
        };
        Ok(Self {
            der: der.to_vec(),
            subject: tbs.subject().to_string(),
            issuer: tbs.issuer().to_string(),
            self_issued: tbs.subject().to_der()? == tbs.issuer().to_der()?,
            ca,
            dns_names,
            uris,
            not_before: seconds(tbs.validity().not_before),
            not_after: seconds(tbs.validity().not_after),
            subject_key_identifier,
            authority_key_identifier,
            key_usage,
            public_key: tbs.subject_public_key_info().to_der()?,
        })
    }

    /// The certificate, DER-encoded.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The subject's distinguished name, as a string (RFC 4514): `CN=Example Issuer,O=Example,C=DE`.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The issuer's distinguished name, as a string (RFC 4514).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Whether the subject and the issuer are the same name: a self-signed certificate, or
    /// one a CA issued to itself.
    pub fn is_self_issued(&self) -> bool {
        self.self_issued
    }

    /// Whether the `basicConstraints` extension says the subject is a CA.
    pub fn is_ca(&self) -> bool {
        self.ca
    }

    /// The `dNSName` entries of the Subject Alternative Name extension.
    pub fn dns_names(&self) -> &[String] {
        &self.dns_names
    }

    /// The `uniformResourceIdentifier` entries of the Subject Alternative Name extension.
    pub fn uris(&self) -> &[String] {
        &self.uris
    }

    /// The start of the validity period, in seconds since the Unix epoch.
    pub fn not_before(&self) -> i64 {
        self.not_before
    }

    /// The end of the validity period, in seconds since the Unix epoch.
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// The Subject Key Identifier extension, if present.
    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.subject_key_identifier.as_deref()
    }

    /// The `keyIdentifier` of the Authority Key Identifier extension, if present: what an
    /// `aki` trusted authorities query of OID4VP §6.1.1.1 compares, base64url-encoded.
    pub fn authority_key_identifier(&self) -> Option<&[u8]> {
        self.authority_key_identifier.as_deref()
    }

    /// The SHA-256 hash of the DER encoding, base64url-encoded: the `x5t#S256` of RFC 7515
    /// §4.1.8 and the value of an `x509_hash` client identifier of OID4VP §5.9.3.
    pub fn sha256_thumbprint(&self) -> String {
        base64url::encode(&Sha256::digest(&self.der))
    }

    /// The subject's public key.
    ///
    /// # Errors
    ///
    /// [`X509Error::UnsupportedKey`] for a key no JWS algorithm of this crate uses, and
    /// [`X509Error::InvalidKey`] for one that does not decode.
    pub fn public_key(&self) -> Result<Jwk, X509Error> {
        jwk_from_spki(&self.public_key)
    }

    /// Whether this certificate binds `identifier`, the `iss` of a token it signed: an `https`
    /// URL whose host is one of the `dNSName` entries of the Subject Alternative Name
    /// extension.
    ///
    /// The URL must be written the one way every parser reads alike, since the `iss` goes on
    /// to other components as a string: no credentials, query or fragment, a domain name
    /// rather than an IP address as host, in lower case and, when internationalized, in its
    /// ASCII form, with nothing a URL parser would normalize away. A port and a path are the
    /// issuer's own. Wildcard names bind nothing.
    ///
    /// A `uniformResourceIdentifier` entry binds nothing, an `https` URL or a DID alike: name
    /// constraints on DNS names, which is how a CA is usually confined to its domains, do not
    /// reach URIs, so a confined CA could certify any. [`uris`](Self::uris) has them for an
    /// application that trusts its CAs with that.
    pub fn binds(&self, identifier: &str) -> bool {
        let Ok(url) = url::Url::parse(identifier) else {
            return false;
        };
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return false;
        }
        let Some(url::Host::Domain(host)) = url.host() else {
            return false;
        };
        // The parser accepts and repairs much that is not the URL it returns (white space,
        // backslashes, an upper-case or percent-encoded host); only what it returns unchanged
        // is bound, give or take the `/` of an empty path.
        let canonical = url.as_str();
        let written_canonically = identifier == canonical
            || (url.path() == "/" && canonical.strip_suffix('/') == Some(identifier));
        written_canonically
            && self
                .dns_names
                .iter()
                .any(|name| !name.contains('*') && name.eq_ignore_ascii_case(host))
    }

    /// Whether this certificate may issue others: a CA whose `keyUsage`, if it has one,
    /// asserts `keyCertSign` (RFC 5280 §4.2.1.3, §6.1.4).
    fn may_issue(&self) -> bool {
        self.ca && self.key_usage.is_none_or(|usage| usage.key_cert_sign)
    }

    /// Whether this certificate's `keyUsage`, if it has one, lets its key sign a token:
    /// `digitalSignature` or `nonRepudiation`, and not `keyCertSign`.
    fn may_sign_tokens(&self) -> bool {
        self.key_usage.is_none_or(|usage| {
            (usage.digital_signature || usage.non_repudiation) && !usage.key_cert_sign
        })
    }
}

impl fmt::Debug for X509Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Certificate")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("dns_names", &self.dns_names)
            .field("uris", &self.uris)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

/// The JWK of a DER-encoded `SubjectPublicKeyInfo`, whatever its algorithm.
fn jwk_from_spki(der: &[u8]) -> Result<Jwk, X509Error> {
    let invalid = |e: &dyn fmt::Display| X509Error::InvalidKey(e.to_string());
    let spki = SubjectPublicKeyInfoRef::from_der(der).map_err(|e| invalid(&e))?;
    let key = spki.subject_public_key.raw_bytes();
    let algorithm = spki.algorithm.oid.to_string();
    match algorithm.as_str() {
        EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters_oid()
                .map_err(|e| invalid(&e))?
                .to_string();
            match curve.as_str() {
                SECP256R1 => Jwk::from_p256_public(key).map_err(|e| invalid(&e)),
                SECP384R1 => p384_jwk(key),
                #[cfg(feature = "secp256k1")]
                SECP256K1 => Jwk::from_secp256k1_public(key).map_err(|e| invalid(&e)),
                _ => Err(X509Error::UnsupportedKey(format!("elliptic curve {curve}"))),
            }
        }
        ED25519 => Jwk::from_ed25519_public(key).map_err(|e| invalid(&e)),
        RSA_ENCRYPTION => {
            let jwk = Jwk::from_pkcs1_der(key).map_err(|e| invalid(&e))?;
            let (modulus, _) = jwk.rsa_public_components().map_err(|e| invalid(&e))?;
            let bits = modulus
                .iter()
                .position(|&byte| byte != 0)
                .map_or(0, |first| {
                    (modulus.len() - first) * 8 - modulus[first].leading_zeros() as usize
                });
            if bits < MIN_RSA_BITS {
                return Err(X509Error::UnsupportedKey(format!(
                    "RSA key of {bits} bits, shorter than {MIN_RSA_BITS}"
                )));
            }
            Ok(jwk)
        }
        _ => Err(X509Error::UnsupportedKey(format!("algorithm {algorithm}"))),
    }
}

/// The JWK of an uncompressed P-384 point, `0x04 || x || y`.
fn p384_jwk(point: &[u8]) -> Result<Jwk, X509Error> {
    const COORDINATE: usize = 48;
    let invalid = || X509Error::InvalidKey("not an uncompressed P-384 point".to_owned());
    let (tag, coordinates) = point.split_first().ok_or_else(invalid)?;
    if *tag != 0x04 || coordinates.len() != 2 * COORDINATE {
        return Err(invalid());
    }
    let (x, y) = coordinates.split_at(COORDINATE);
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-384",
        "x": base64url::encode(x),
        "y": base64url::encode(y),
    }))
    .map_err(|e| X509Error::InvalidKey(e.to_string()))
}

/// Why an `x5c` chain yields no key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum X509Error {
    /// The chain holds no certificate.
    #[error("the certificate chain is empty")]
    EmptyChain,
    /// The chain holds more certificates than [`X509Resolver::MAX_CHAIN_LENGTH`].
    #[error("the certificate chain has {length} certificates, more than {max}")]
    ChainTooLong {
        /// The number of certificates.
        length: usize,
        /// The limit.
        max: usize,
    },
    /// A certificate does not decode.
    #[error("certificate {index} is invalid: {source}")]
    InvalidCertificate {
        /// The index of the certificate in the chain, or among the trust anchors.
        index: usize,
        /// Why it does not decode.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// The PEM text does not hold certificates.
    #[error("invalid PEM: {0}")]
    InvalidPem(String),
    /// The first certificate is self-issued: its subject is its issuer, as in a self-signed
    /// certificate. HAIP forbids it, and a certificate is not a trust anchor because a token
    /// carries it.
    #[error("the signing certificate is self-signed")]
    SelfSigned,
    /// The validation time is before the Unix epoch.
    #[error("the validation time {0} is before 1970")]
    InvalidTime(i64),
    /// No path from the first certificate to a trust anchor validates: an unknown issuer, a
    /// wrong signature, an expired certificate, a CA constraint. The source says which.
    #[error("the certificate chain does not validate: {0}")]
    PathValidation(#[source] Box<dyn Error + Send + Sync>),
    /// A trust anchor is not a CA certificate, or its `keyUsage` lacks `keyCertSign`.
    #[error("trust anchor {index} is not a CA certificate")]
    TrustAnchorNotCa {
        /// The index of the anchor among those given.
        index: usize,
    },
    /// The first certificate has a `keyUsage` extension that does not allow signing a token:
    /// it has neither `digitalSignature` nor `nonRepudiation`, or asserts `keyCertSign`.
    #[error("the signing certificate's key usage does not allow signing a token")]
    KeyUsage,
    /// The first certificate's key is of a kind no JWS algorithm of this crate uses.
    #[error("unsupported certificate key: {0}")]
    UnsupportedKey(String),
    /// The first certificate's key does not decode.
    #[error("invalid certificate key: {0}")]
    InvalidKey(String),
}

impl X509Error {
    /// [`InvalidCertificate`](Self::InvalidCertificate) for the certificate at `index`.
    fn invalid_certificate<E: Error + Send + Sync + 'static>(index: usize, source: E) -> Self {
        Self::InvalidCertificate {
            index,
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_is_inclusive_at_both_ends() {
        for now in [100, 150, 200] {
            assert!(outside_validity(now, 100, 200).is_none(), "{now}");
        }
        assert!(matches!(
            outside_validity(99, 100, 200),
            Some(webpki::Error::CertNotValidYet { .. })
        ));
        assert!(matches!(
            outside_validity(201, 100, 200),
            Some(webpki::Error::CertExpired { .. })
        ));
    }

    /// A CA reissued with the same name and key is one trust anchor when its name
    /// constraints are the same, and the validity of either certificate is the anchor's. With
    /// other constraints it is another anchor: an expired certificate without constraints is
    /// not valid again because a constrained one with its name and key is.
    #[test]
    fn anchor_validity_is_that_of_the_anchor_the_path_was_verified_under() {
        use rustls_pki_types::Der;

        let anchor = |constraints: Option<&'static [u8]>| TrustAnchor {
            subject: Der::from_slice(b"subject"),
            subject_public_key_info: Der::from_slice(b"key"),
            name_constraints: constraints.map(Der::from_slice),
        };
        let valid = |not_before, not_after| Anchor {
            der: CertificateDer::from(Vec::new()),
            not_before,
            not_after,
        };
        let (unconstrained, constrained) = (anchor(None), anchor(Some(b"allowed.example")));
        let (expired, current) = (valid(100, 200), valid(150, 300));
        let now = 250;

        let configured = [(&unconstrained, &expired), (&constrained, &current)];
        assert!(matches!(
            anchor_validity(&unconstrained, configured, now),
            Err(webpki::Error::CertExpired { .. })
        ));
        assert!(anchor_validity(&constrained, configured, now).is_ok());

        // The same anchor twice: the certificate that is valid decides, in either order.
        for configured in [
            [(&unconstrained, &expired), (&unconstrained, &current)],
            [(&unconstrained, &current), (&unconstrained, &expired)],
        ] {
            assert!(anchor_validity(&unconstrained, configured, now).is_ok());
        }
        // An anchor that is not configured, by its name or by its key.
        let other = TrustAnchor {
            subject: Der::from_slice(b"other"),
            ..anchor(None)
        };
        assert!(matches!(
            anchor_validity(&other, configured, now),
            Err(webpki::Error::UnknownIssuer)
        ));
    }

    /// A certificate with the names `dns_names` and `uris`, and the key usage `usage`.
    fn certificate(dns_names: &[&str], uris: &[&str], usage: Option<Usage>) -> X509Certificate {
        X509Certificate {
            der: Vec::new(),
            subject: "CN=example".to_owned(),
            issuer: "CN=ca".to_owned(),
            self_issued: false,
            ca: false,
            dns_names: dns_names.iter().map(|&name| name.to_owned()).collect(),
            uris: uris.iter().map(|&uri| uri.to_owned()).collect(),
            not_before: 0,
            not_after: 0,
            subject_key_identifier: None,
            authority_key_identifier: None,
            key_usage: usage,
            public_key: Vec::new(),
        }
    }

    /// An `iss` binds only as a URL every parser reads the same way.
    #[test]
    fn binds_only_canonical_https_urls() {
        let named = certificate(&["issuer.example", "xn--mnchen-3ya.example"], &[], None);
        for bound in [
            "https://issuer.example",
            "https://issuer.example/",
            "https://issuer.example/tenant/1",
            "https://issuer.example:8443/tenant/",
            "https://xn--mnchen-3ya.example",
        ] {
            assert!(named.binds(bound), "{bound}");
        }
        for unbound in [
            // Another host, however the URL is dressed up.
            "https://victim.example",
            "https://issuer.example.victim.example",
            "https://victim.example@issuer.example",
            "https://victim.example:pw@issuer.example/",
            "https://issuer.example\\@victim.example",
            "https://issuer.example?x=https://victim.example",
            "https://issuer.example#https://victim.example",
            // The right host, written as a parser would not write it.
            " https://issuer.example",
            "https://issuer.example ",
            "https:issuer.example",
            "https:\\\\issuer.example",
            "https://issuer.exam\tple",
            "https://ISSUER.example",
            "HTTPS://issuer.example",
            "https://issuer.example.",
            "https://issuer.example:443",
            "https://%69ssuer.example",
            "https://\u{ff49}ssuer.example",
            "https://m\u{fc}nchen.example",
            // Not an `https` URL at all.
            "http://issuer.example",
            "issuer.example",
            "did:web:issuer.example",
            "",
        ] {
            assert!(!named.binds(unbound), "{unbound:?}");
        }
        // An IP address written as a DNS name binds no way of writing that address.
        let address = certificate(&["192.168.1.1"], &[], None);
        for unbound in [
            "https://192.168.1.1",
            "https://0xc0.0xa8.1.1",
            "https://3232235777",
        ] {
            assert!(!address.binds(unbound), "{unbound}");
        }
        // Wildcards bind nothing, and neither does an empty name.
        let wild = certificate(&["*.issuer.example", "*", ""], &[], None);
        for unbound in [
            "https://a.issuer.example",
            "https://*.issuer.example",
            "https://",
        ] {
            assert!(!wild.binds(unbound), "{unbound}");
        }
    }

    /// A URI name binds nothing: name constraints on DNS names do not reach it. An `https`
    /// URL the certificate also has as a URI name is bound by the DNS name of its host alone.
    #[test]
    fn uri_names_bind_nothing() {
        let uris = [
            "https://victim.example",
            "did:web:victim.example",
            "https://issuer.example/tenant",
            "",
        ];
        let without_dns_names = certificate(&[], &uris, None);
        for uri in uris {
            assert!(!without_dns_names.binds(uri), "{uri:?}");
        }
        let with_dns_name = certificate(&["issuer.example"], &uris, None);
        assert!(with_dns_name.binds("https://issuer.example/tenant"));
        for unbound in ["https://victim.example", "did:web:victim.example", ""] {
            assert!(!with_dns_name.binds(unbound), "{unbound:?}");
        }
    }

    /// RFC 5280 §4.2.1.3: `digitalSignature` and `nonRepudiation` are for signatures "other
    /// than signatures on certificates", `keyCertSign` for those on certificates.
    #[test]
    fn key_usage_decides_what_a_key_signs() {
        let usage = |digital_signature, non_repudiation, key_cert_sign| {
            Some(Usage {
                digital_signature,
                non_repudiation,
                key_cert_sign,
            })
        };
        let leaf = |usage| certificate(&[], &[], usage);
        for signs in [
            None,
            usage(true, false, false),
            usage(false, true, false),
            usage(true, true, false),
        ] {
            assert!(leaf(signs).may_sign_tokens(), "{signs:?}");
        }
        for refused in [
            usage(false, false, false),
            usage(true, false, true),
            usage(false, true, true),
            usage(false, false, true),
        ] {
            assert!(!leaf(refused).may_sign_tokens(), "{refused:?}");
        }

        let ca = |usage| X509Certificate {
            ca: true,
            ..certificate(&[], &[], usage)
        };
        assert!(ca(None).may_issue());
        assert!(ca(usage(false, false, true)).may_issue());
        assert!(ca(usage(true, false, true)).may_issue());
        assert!(!ca(usage(true, false, false)).may_issue());
        // Without `cA`, `keyCertSign` is not enough.
        assert!(!leaf(usage(false, false, true)).may_issue());
        assert!(!leaf(None).may_issue());
    }

    #[test]
    fn p384_points_are_uncompressed() {
        let mut point = vec![0x04];
        point.extend([0x11; 48]);
        point.extend([0x22; 48]);
        let jwk = serde_json::to_value(p384_jwk(&point).unwrap()).unwrap();
        assert_eq!(jwk["crv"], "P-384");
        assert_eq!(
            base64url::decode(jwk["x"].as_str().unwrap()).unwrap(),
            [0x11; 48]
        );
        assert_eq!(
            base64url::decode(jwk["y"].as_str().unwrap()).unwrap(),
            [0x22; 48]
        );
        // Compressed, truncated, or empty.
        let mut compressed = vec![0x02];
        compressed.extend([0x11; 48]);
        for invalid in [&compressed[..], &point[..96], &[]] {
            assert!(matches!(p384_jwk(invalid), Err(X509Error::InvalidKey(_))));
        }
    }
}
