//! `X509Resolver`: the key of an `x5c` certificate chain, validated against trust anchors, and
//! `X509Certificate`, what a certificate says about its subject.

use core::fmt;
use core::time::Duration;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, UnixTime};
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
/// 2. The leaf is not self-signed, and no certificate of the chain is one of the trust
///    anchors: HAIP requires both of every `x5c` it defines.
/// 3. A path from the leaf to a trust anchor validates as RFC 5280 §6 describes, at the
///    validation time: each signature, each validity period, `basicConstraints` and the path
///    length, name constraints, and no critical extension that is not understood. The
///    certificates after the leaf are a pool to build the path from, so their order does not
///    matter. Path validation is [`rustls-webpki`](https://docs.rs/rustls-webpki)'s.
/// 4. The trust anchor the path ends at is within its own validity period.
/// 5. A leaf that has a `keyUsage` extension asserts `digitalSignature` and not `keyCertSign`
///    (RFC 5280 §4.2.1.3).
/// 6. The leaf's key is one a JWS can be verified with: P-256, P-384, secp256k1 (feature
///    `secp256k1`), Ed25519 or RSA of at least 2048 bits.
///
/// Certificates are signed with ECDSA on P-256 or P-384, Ed25519, or RSA from 2048 bits, with
/// SHA-256, SHA-384 or SHA-512. SHA-1, P-521 and Brainpool curves are refused.
///
/// # What is not checked
///
/// - **Revocation.** Neither CRLs nor OCSP are consulted. An application that needs it checks
///   the chain itself, or keeps its trust anchors current.
/// - **Extended key usage.** SD-JWT VC and HAIP define none for credential issuers, so any is
///   accepted.
/// - **Who the subject is.** A valid chain says the key belongs to the subject of the leaf
///   under one of the trust anchors, not that this subject may issue a given credential:
///   that is the application's policy, with [`X509Certificate`] to read the subject from.
///
/// # The issuer of a token
///
/// With `x5c`, the issuer is the subject of the leaf certificate, and an `iss` claim is not
/// authenticated by the chain (SD-JWT VC §3.5). [`KeyReference::binds_to`] therefore accepts
/// an `iss` only when the leaf binds it through a Subject Alternative Name, and the SD-JWT VC
/// validator accepts a credential without `iss`.
///
/// # Time
///
/// A validator passes its validation time through [`KeyResolver::resolve_key_at`];
/// [`resolve_key`](KeyResolver::resolve_key) validates at the current time.
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
    /// Each anchor must be a CA certificate, one whose `basicConstraints` say `cA`: whoever
    /// holds the key of an anchor can issue certificates this resolver accepts, so a
    /// certificate that signs credentials is refused as an anchor. A resolver without anchors
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
                if !certificate.is_ca() {
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
        let leaf = X509Certificate::from_der(leaf_der)?;
        if leaf.is_self_issued() {
            return Err(X509Error::SelfSigned);
        }
        if let Some(index) = chain.iter().position(|certificate| {
            self.anchors
                .iter()
                .any(|anchor| anchor.der.as_ref() == certificate.as_slice())
        }) {
            return Err(X509Error::TrustAnchorInChain { index });
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
        // `rustls-webpki` reads a trust anchor as a name and a key, without a validity period.
        // A path is accepted only when a certificate of its anchor, among those configured
        // with that name and key, is valid now; otherwise path building tries another one.
        let anchor_is_current = |path: &webpki::VerifiedPath<'_>| {
            let used = path.anchor();
            let mut error = webpki::Error::UnknownIssuer;
            for (anchor, configured) in anchors.iter().zip(&self.anchors) {
                if anchor.subject != used.subject
                    || anchor.subject_public_key_info != used.subject_public_key_info
                {
                    continue;
                }
                match outside_validity(now, configured.not_before, configured.not_after) {
                    None => return Ok(()),
                    Some(outside) => error = outside,
                }
            }
            Err(error)
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
                Some(&anchor_is_current),
            )
            .map_err(|e| X509Error::PathValidation(Box::new(e)))?;

        if leaf
            .key_usage
            .is_some_and(|usage| !usage.digital_signature || usage.key_cert_sign)
        {
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

    /// Whether this certificate binds `identifier`, the `iss` of a token it signed, through
    /// its Subject Alternative Name extension: a `uniformResourceIdentifier` equal to
    /// `identifier`, or, for an `https` URL, a `dNSName` equal to its host, ignoring case.
    /// Wildcard names bind nothing.
    pub fn binds(&self, identifier: &str) -> bool {
        if self.uris.iter().any(|uri| uri == identifier) {
            return true;
        }
        let Ok(url) = url::Url::parse(identifier) else {
            return false;
        };
        if url.scheme() != "https" {
            return false;
        }
        url.host_str().is_some_and(|host| {
            self.dns_names
                .iter()
                .any(|name| !name.contains('*') && name.eq_ignore_ascii_case(host))
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
    /// The first certificate is self-signed: its subject is its issuer. HAIP forbids it, and
    /// a certificate is not a trust anchor because a token carries it.
    #[error("the signing certificate is self-signed")]
    SelfSigned,
    /// A certificate of the chain is one of the trust anchors, which HAIP forbids.
    #[error("certificate {index} of the chain is a trust anchor")]
    TrustAnchorInChain {
        /// The index of the certificate in the chain.
        index: usize,
    },
    /// The validation time is before the Unix epoch.
    #[error("the validation time {0} is before 1970")]
    InvalidTime(i64),
    /// No path from the first certificate to a trust anchor validates: an unknown issuer, a
    /// wrong signature, an expired certificate, a CA constraint. The source says which.
    #[error("the certificate chain does not validate: {0}")]
    PathValidation(#[source] Box<dyn Error + Send + Sync>),
    /// A trust anchor is not a CA certificate.
    #[error("trust anchor {index} is not a CA certificate")]
    TrustAnchorNotCa {
        /// The index of the anchor among those given.
        index: usize,
    },
    /// The first certificate has a `keyUsage` extension that does not allow signing a token:
    /// it lacks `digitalSignature`, or asserts `keyCertSign`.
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
