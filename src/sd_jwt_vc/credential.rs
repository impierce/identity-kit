//! SD-JWT VC: an SD-JWT whose payload is a verifiable digital credential of a `vct` type.

use core::fmt;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::{
    ClaimPath, Disclosure, HashAlgorithm, KeyBinding, PathComponent, Processed, SdJwt,
    SdJwtBuilder, SdJwtError, Status,
};
use crate::did::DidUrl;
use crate::jose::{Jwk, JwsHeader, Signer};
use crate::resolver::{KeyReference, KeyReferenceError};
use crate::vc::JwtClaims;

/// The `typ` of the issuer-signed JWT of an SD-JWT VC, `dc+sd-jwt`.
pub const TYP: &str = "dc+sd-jwt";

/// The `typ` earlier drafts of SD-JWT VC used, `vc+sd-jwt`; accepted when parsing.
pub const LEGACY_TYP: &str = "vc+sd-jwt";

/// The media type of an SD-JWT VC, `application/dc+sd-jwt`.
pub const MEDIA_TYPE: &str = "application/dc+sd-jwt";

/// The registered claims that, with their sub-claims, must not be selectively disclosed
/// (SD-JWT VC §2.2.2.3).
pub const NON_DISCLOSABLE_CLAIMS: [&str; 8] = [
    "iss",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "vct#integrity",
    "aka_vcts",
    "status",
];

/// The `cnf` claim (RFC 7800): the holder's key, by value as `jwk` or by reference as `kid`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Confirmation {
    /// The holder's public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// A reference to the holder's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Every other confirmation method.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl Confirmation {
    /// A confirmation by the public part of `jwk`.
    pub fn jwk(jwk: &Jwk) -> Self {
        Self {
            jwk: Some(jwk.public()),
            ..Self::default()
        }
    }

    /// A confirmation by key reference: an absolute DID URL naming a verification method of
    /// the holder, which a verifier resolves under `authentication`.
    pub fn kid(kid: impl Into<String>) -> Self {
        Self {
            kid: Some(kid.into()),
            ..Self::default()
        }
    }
}

impl KeyReference {
    /// Where the holder's key of a `cnf` claim (RFC 7800) is: `jwk` if present, else a `kid`
    /// that is an absolute DID URL, else `jku` with the `kid`.
    ///
    /// RFC 7800 §3.4 leaves the meaning of a key id to the application, and the confirmation
    /// carries no DID or key set to resolve a `#fragment` or a bare id against (using `sub`
    /// would conflate the subject with the holder), so a `cnf.kid` must be an absolute DID URL
    /// without a path or DID parameters (ADR 0006).
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::resolver::{KeyReference, KeyReferenceError};
    /// use identity_kit::sd_jwt_vc::Confirmation;
    ///
    /// let cnf = Confirmation::kid("did:example:holder#key-1");
    /// assert_eq!(KeyReference::from_confirmation(&cnf)?.to_string(), "did:example:holder#key-1");
    ///
    /// let relative = Confirmation::kid("#key-1");
    /// assert!(matches!(
    ///     KeyReference::from_confirmation(&relative),
    ///     Err(KeyReferenceError::InvalidKid { .. })
    /// ));
    /// # Ok::<(), KeyReferenceError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`KeyReferenceError::Missing`] for an empty `cnf`,
    /// [`KeyReferenceError::UnsupportedConfirmation`] for one that names its key only by another
    /// method (`x5t#S256`, `jwe`), and otherwise the member that is wrong.
    pub fn from_confirmation(cnf: &Confirmation) -> Result<Self, KeyReferenceError> {
        if let Some(jwk) = &cnf.jwk {
            if jwk.is_private() {
                return Err(KeyReferenceError::InvalidJwk(
                    "`cnf.jwk` holds a private key".to_owned(),
                ));
            }
            return Ok(Self::Jwk(Box::new(jwk.clone())));
        }
        let jku = cnf.additional.get("jku");
        if let Some(kid) = &cnf.kid {
            match DidUrl::parse(kid) {
                Ok(url) if url.path().is_some() || url.query().is_some() => {
                    return Err(KeyReferenceError::KidWithParameters(url));
                }
                Ok(url) => return Ok(Self::DidUrl(url)),
                Err(source) if jku.is_none() => {
                    return Err(KeyReferenceError::InvalidKid {
                        kid: kid.clone(),
                        source,
                    });
                }
                Err(_) => {}
            }
        }
        if let Some(jku) = jku {
            let url = jku
                .as_str()
                .and_then(|jku| url::Url::parse(jku).ok())
                .ok_or_else(|| KeyReferenceError::InvalidUrl {
                    parameter: "jku",
                    value: jku.to_string(),
                    reason: "not an absolute URL".to_owned(),
                })?;
            return Ok(Self::Jku {
                url,
                kid: cnf.kid.clone(),
            });
        }
        match cnf.additional.keys().next() {
            Some(method) => Err(KeyReferenceError::UnsupportedConfirmation(method.clone())),
            None => Err(KeyReferenceError::Missing),
        }
    }
}

/// The claims of an SD-JWT VC (SD-JWT VC §2.2.2): the credential type and the registered
/// claims as fields, every claim about the subject in `claims`.
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::SdJwtVcClaims;
/// use serde_json::json;
///
/// // SD-JWT VC §2.2.2.1, Figure 3.
/// let claims: SdJwtVcClaims = serde_json::from_value(json!({
///   "vct": "https://credentials.example.com/identity_credential",
///   "given_name": "Russ",
///   "family_name": "Lasky",
///   "exp": 1777707000,
///   "cnf": { "jwk": { "kty": "EC", "crv": "P-256",
///     "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
///     "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ" } }
/// }))?;
/// assert_eq!(claims.vct, "https://credentials.example.com/identity_credential");
/// assert_eq!(claims.exp, Some(1777707000));
/// assert_eq!(claims.claims["given_name"], "Russ");
/// assert_eq!(claims.holder_key().map(|k| k.crv()), Some(Some("P-256")));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SdJwtVcClaims {
    /// `vct`: the credential type, a collision-resistant name.
    pub vct: String,
    /// `vct#integrity`: the integrity metadata of the type metadata document.
    #[serde(
        rename = "vct#integrity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub vct_integrity: Option<String>,
    /// `aka_vcts`: further types the credential is of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aka_vcts: Option<Vec<String>>,
    /// `iss`: the issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// `sub`: the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// `jti`: the identifier of the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// `iat`: when the credential was issued. A `NumericDate` with a fraction is floored.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::vc::numeric_date"
    )]
    pub iat: Option<i64>,
    /// `nbf`: when the credential becomes valid. A `NumericDate` with a fraction is floored.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::vc::numeric_date"
    )]
    pub nbf: Option<i64>,
    /// `exp`: when the credential expires. A `NumericDate` with a fraction is floored.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::vc::numeric_date"
    )]
    pub exp: Option<i64>,
    /// `cnf`: the holder's key, for key binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,
    /// `status`: how to learn the status of the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Every other claim, in insertion order.
    #[serde(flatten)]
    pub claims: IndexMap<String, Value>,
}

impl SdJwtVcClaims {
    /// Claims of the type `vct`, nothing else set.
    pub fn new(vct: impl Into<String>) -> Self {
        Self {
            vct: vct.into(),
            vct_integrity: None,
            aka_vcts: None,
            iss: None,
            sub: None,
            jti: None,
            iat: None,
            nbf: None,
            exp: None,
            cnf: None,
            status: None,
            claims: IndexMap::new(),
        }
    }

    /// These claims with `iss`.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.iss = Some(issuer.into());
        self
    }

    /// These claims with `sub`.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.sub = Some(subject.into());
        self
    }

    /// These claims with `jti`.
    #[must_use]
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// These claims with `iat`.
    #[must_use]
    pub fn with_issued_at(mut self, time: DateTime<Utc>) -> Self {
        self.iat = Some(JwtClaims::numeric_date(time));
        self
    }

    /// These claims with `nbf`.
    #[must_use]
    pub fn with_not_before(mut self, time: DateTime<Utc>) -> Self {
        self.nbf = Some(JwtClaims::numeric_date(time));
        self
    }

    /// These claims with `exp`.
    #[must_use]
    pub fn with_expires_at(mut self, time: DateTime<Utc>) -> Self {
        self.exp = Some(JwtClaims::numeric_date(time));
        self
    }

    /// These claims with `cnf`.
    #[must_use]
    pub fn with_confirmation(mut self, cnf: Confirmation) -> Self {
        self.cnf = Some(cnf);
        self
    }

    /// These claims with `cnf` holding the public part of `jwk`.
    #[must_use]
    pub fn with_holder_key(self, jwk: &Jwk) -> Self {
        self.with_confirmation(Confirmation::jwk(jwk))
    }

    /// These claims with `status`.
    #[must_use]
    pub fn with_status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// These claims with `vct#integrity`.
    #[must_use]
    pub fn with_type_integrity(mut self, integrity: impl Into<String>) -> Self {
        self.vct_integrity = Some(integrity.into());
        self
    }

    /// These claims with `vct` added to `aka_vcts`.
    #[must_use]
    pub fn with_aka_vct(mut self, vct: impl Into<String>) -> Self {
        self.aka_vcts.get_or_insert_with(Vec::new).push(vct.into());
        self
    }

    /// These claims with the claim `name` set to `value`.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.claims.insert(name.into(), value.into());
        self
    }

    /// The holder's public key, when `cnf` carries one by value.
    pub fn holder_key(&self) -> Option<&Jwk> {
        self.cnf.as_ref()?.jwk.as_ref()
    }

    /// Checks the rules on the registered claims: `aka_vcts` is non-empty and does not repeat
    /// `vct`.
    ///
    /// # Errors
    ///
    /// [`SdJwtVcError::InvalidClaim`].
    pub fn check(&self) -> Result<(), SdJwtVcError> {
        if let Some(aka) = &self.aka_vcts {
            if aka.is_empty() {
                return Err(SdJwtVcError::InvalidClaim {
                    claim: "aka_vcts",
                    reason: "the array is empty".into(),
                });
            }
            if aka.contains(&self.vct) {
                return Err(SdJwtVcError::InvalidClaim {
                    claim: "aka_vcts",
                    reason: "the array repeats `vct`".into(),
                });
            }
        }
        Ok(())
    }

    /// The claims as a JSON object.
    pub fn to_map(&self) -> Map<String, Value> {
        match serde_json::to_value(self).expect("claims serialize") {
            Value::Object(map) => map,
            _ => unreachable!("a struct serializes to an object"),
        }
    }
}

/// Why an SD-JWT is not an SD-JWT VC.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtVcError {
    /// The SD-JWT itself is invalid.
    #[error(transparent)]
    SdJwt(#[from] SdJwtError),
    /// The issuer-signed JWT has no `typ`.
    #[error("the issuer-signed JWT has no `typ`; `{TYP}` is required")]
    MissingTyp,
    /// The `typ` is neither `dc+sd-jwt` nor `vc+sd-jwt`.
    #[error("header `typ` is {0:?}, not `{TYP}`")]
    UnexpectedTyp(String),
    /// The `typ` is `vc+sd-jwt` and the payload has `@context` and no `vct`: a VCDM 2.0
    /// credential secured with SD-JWT (VC-JOSE-COSE), which
    /// [`SdJwtCredentialV2`](super::SdJwtCredentialV2) parses, not an SD-JWT VC.
    #[error(
        "header `typ` is `{LEGACY_TYP}` and the payload has `@context` and no `vct`: a VCDM 2.0 \
         credential secured with SD-JWT, not an SD-JWT VC"
    )]
    VcdmPayload,
    /// A claim that must not be selectively disclosed came from a disclosure.
    #[error("`{0}` must not be selectively disclosed")]
    DisclosedRegisteredClaim(String),
    /// The processed payload is not an SD-JWT VC claims set: no `vct`, say. The source is the
    /// JSON error.
    #[error("the payload is not an SD-JWT VC: {0}")]
    Claims(#[source] serde_json::Error),
    /// A registered claim breaks a rule of SD-JWT VC.
    #[error("claim `{claim}`: {reason}")]
    InvalidClaim {
        /// The claim.
        claim: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

/// Issues an SD-JWT VC: the registered claims first-class, the claims about the subject
/// selectively disclosable at the paths given to [`conceal`](Self::conceal), signed with
/// `typ: dc+sd-jwt`.
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::SdJwtVcBuilder;
/// use serde_json::json;
///
/// let builder = SdJwtVcBuilder::new("https://credentials.example.com/identity_credential")
///     .with_issuer("https://example.com/issuer")
///     .with_claim("given_name", "John")
///     .with_claim("address", json!({"street_address": "123 Main St", "country": "US"}))
///     .conceal(["given_name"])
///     .conceal(["address"]);
/// assert_eq!(builder.claims().vct, "https://credentials.example.com/identity_credential");
/// // `iss` is a registered claim that cannot be concealed.
/// assert!(builder.clone_claims().conceal(["iss"]).check_concealed().is_err());
/// ```
pub struct SdJwtVcBuilder {
    claims: SdJwtVcClaims,
    kid: Option<String>,
    concealed: Vec<ClaimPath>,
    decoys: usize,
    alg: HashAlgorithm,
    salts: Option<Box<dyn FnMut() -> String + Send>>,
}

impl SdJwtVcBuilder {
    /// A builder for a credential of type `vct`.
    pub fn new(vct: impl Into<String>) -> Self {
        Self::from_claims(SdJwtVcClaims::new(vct))
    }

    /// A builder over `claims`.
    pub fn from_claims(claims: SdJwtVcClaims) -> Self {
        Self {
            claims,
            kid: None,
            concealed: Vec::new(),
            decoys: 0,
            alg: HashAlgorithm::default(),
            salts: None,
        }
    }

    /// The claims so far.
    pub fn claims(&self) -> &SdJwtVcClaims {
        &self.claims
    }

    /// A builder over a copy of these claims, nothing concealed.
    pub fn clone_claims(&self) -> Self {
        Self::from_claims(self.claims.clone())
    }

    /// This builder with `iss`.
    #[must_use]
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.claims = self.claims.with_issuer(issuer);
        self
    }

    /// This builder with `sub`.
    #[must_use]
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.claims = self.claims.with_subject(subject);
        self
    }

    /// This builder with `jti`.
    #[must_use]
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.claims = self.claims.with_jti(jti);
        self
    }

    /// This builder with `iat`.
    #[must_use]
    pub fn with_issued_at(mut self, time: DateTime<Utc>) -> Self {
        self.claims = self.claims.with_issued_at(time);
        self
    }

    /// This builder with `nbf`.
    #[must_use]
    pub fn with_not_before(mut self, time: DateTime<Utc>) -> Self {
        self.claims = self.claims.with_not_before(time);
        self
    }

    /// This builder with `exp`.
    #[must_use]
    pub fn with_expires_at(mut self, time: DateTime<Utc>) -> Self {
        self.claims = self.claims.with_expires_at(time);
        self
    }

    /// This builder with `cnf`.
    #[must_use]
    pub fn with_confirmation(mut self, cnf: Confirmation) -> Self {
        self.claims = self.claims.with_confirmation(cnf);
        self
    }

    /// This builder with `cnf` holding the public part of `jwk`.
    #[must_use]
    pub fn with_holder_key(mut self, jwk: &Jwk) -> Self {
        self.claims = self.claims.with_holder_key(jwk);
        self
    }

    /// This builder with `status`.
    #[must_use]
    pub fn with_status(mut self, status: Status) -> Self {
        self.claims = self.claims.with_status(status);
        self
    }

    /// This builder with `vct#integrity`.
    #[must_use]
    pub fn with_type_integrity(mut self, integrity: impl Into<String>) -> Self {
        self.claims = self.claims.with_type_integrity(integrity);
        self
    }

    /// This builder with `vct` added to `aka_vcts`.
    #[must_use]
    pub fn with_aka_vct(mut self, vct: impl Into<String>) -> Self {
        self.claims = self.claims.with_aka_vct(vct);
        self
    }

    /// This builder with the claim `name` set to `value`.
    #[must_use]
    pub fn with_claim(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.claims = self.claims.with_claim(name, value);
        self
    }

    /// This builder signing with `kid` in the header, instead of the signer's.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// This builder concealing the claim at `path`; see [`SdJwtBuilder::conceal`].
    #[must_use]
    pub fn conceal(mut self, path: impl Into<ClaimPath>) -> Self {
        self.concealed.push(path.into());
        self
    }

    /// This builder adding `count` decoy digests to every `_sd` array.
    #[must_use]
    pub fn with_decoys(mut self, count: usize) -> Self {
        self.decoys = count;
        self
    }

    /// This builder hashing with `alg`.
    #[must_use]
    pub fn with_hash_algorithm(mut self, alg: HashAlgorithm) -> Self {
        self.alg = alg;
        self
    }

    /// This builder taking its salts from `salts`; see [`SdJwtBuilder::with_salt_generator`].
    #[must_use]
    pub fn with_salt_generator(mut self, salts: impl FnMut() -> String + Send + 'static) -> Self {
        self.salts = Some(Box::new(salts));
        self
    }

    /// Checks that no path to conceal starts at a claim of [`NON_DISCLOSABLE_CLAIMS`].
    ///
    /// # Errors
    ///
    /// [`SdJwtError::NotConcealable`].
    pub fn check_concealed(&self) -> Result<(), SdJwtVcError> {
        for path in &self.concealed {
            if let Some(PathComponent::Key(name)) = path.components().first()
                && NON_DISCLOSABLE_CLAIMS.contains(&name.as_str())
            {
                return Err(SdJwtError::NotConcealable {
                    path: path.clone(),
                    reason: format!("SD-JWT VC does not allow `{name}` to be disclosed"),
                }
                .into());
            }
        }
        Ok(())
    }

    /// The credential, signed with `signer` under `alg`, `typ: dc+sd-jwt` and the `kid`
    /// given or the signer's.
    ///
    /// # Errors
    ///
    /// [`SdJwtVcError::InvalidClaim`], [`SdJwtError::NotConcealable`], and the errors of
    /// [`SdJwtBuilder::sign`].
    pub async fn sign(self, signer: &dyn Signer) -> Result<SdJwtVc, SdJwtVcError> {
        self.claims.check()?;
        self.check_concealed()?;
        let mut header = JwsHeader::new(signer.alg()).with_typ(TYP);
        header.kid = self.kid.or_else(|| signer.kid().map(str::to_owned));
        let mut builder = SdJwtBuilder::new(self.claims.to_map())
            .with_decoys(self.decoys)
            .with_hash_algorithm(self.alg);
        for path in self.concealed {
            builder = builder.conceal(path);
        }
        if let Some(salts) = self.salts {
            builder = builder.with_salt_generator(salts);
        }
        let sd_jwt = builder.sign(&header, signer).await?;
        SdJwtVc::from_sd_jwt(sd_jwt)
    }
}

impl fmt::Debug for SdJwtVcBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtVcBuilder")
            .field("claims", &self.claims)
            .field("kid", &self.kid)
            .field("concealed", &self.concealed)
            .field("decoys", &self.decoys)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

/// An SD-JWT VC: an [`SdJwt`] with `typ: dc+sd-jwt` whose processed payload is an
/// [`SdJwtVcClaims`] set, with the registered claims not selectively disclosed.
///
/// Parsing processes the disclosures (so the digests and the structure are checked) but
/// verifies no signature: that is [`SdJwtCredentialValidator`](super::SdJwtCredentialValidator).
///
/// # Examples
///
/// The presentation without key binding of SD-JWT VC §2.3.2, Figure 10.
///
/// ```
/// use identity_kit::sd_jwt_vc::SdJwtVc;
///
/// let presentation = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCJ9.eyJfc2QiOiBbIjA5dkt\
///     ySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1\
///     RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVV\
///     HRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgw\
///     UjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkp\
///     HbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiam\
///     RyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKb\
///     HpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAi\
///     aWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5\
///     leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiJ9.1ar8IhAJaZ8Jn\
///     bPGD2dx-6c8PzGQUUafDJdsjRD1FwRna2CICwhANOQfXi5RPkP_iH8hOHFh5-2WJg8VsMJUcA~WyJsa2x4RjVqT\
///     VlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgI\
///     mFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24i\
///     LCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~";
/// let credential: SdJwtVc = presentation.parse()?;
/// assert_eq!(credential.claims().vct, "https://credentials.example.com/identity_credential");
/// assert_eq!(credential.claims().iss.as_deref(), Some("https://example.com/issuer"));
/// assert_eq!(credential.claims().claims["is_over_65"], true);
/// assert_eq!(credential.claims().claims["address"]["locality"], "Anytown");
/// assert!(!credential.claims().claims.contains_key("given_name"));
/// # Ok::<(), identity_kit::sd_jwt_vc::SdJwtVcError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SdJwtVc {
    sd_jwt: SdJwt,
    header: JwsHeader,
    processed: Processed,
    claims: SdJwtVcClaims,
}

impl SdJwtVc {
    /// Parses the compact serialization and processes the disclosures.
    ///
    /// # Errors
    ///
    /// As [`from_sd_jwt`](Self::from_sd_jwt).
    pub fn parse(s: &str) -> Result<Self, SdJwtVcError> {
        Self::from_sd_jwt(SdJwt::parse(s)?)
    }

    /// Takes `sd_jwt` as an SD-JWT VC: checks `typ`, processes the disclosures, reads the
    /// claims and checks that none of [`NON_DISCLOSABLE_CLAIMS`] came from a disclosure.
    ///
    /// `vc+sd-jwt` is also the `typ` of a VCDM 2.0 credential secured with SD-JWT
    /// (VC-JOSE-COSE), so it is accepted only when the payload has `vct`; see the [module
    /// documentation](super#two-sd-jwt-credential-types).
    ///
    /// # Errors
    ///
    /// [`SdJwtVcError::MissingTyp`], [`SdJwtVcError::UnexpectedTyp`],
    /// [`SdJwtVcError::VcdmPayload`], [`SdJwtVcError::DisclosedRegisteredClaim`],
    /// [`SdJwtVcError::Claims`], [`SdJwtVcError::InvalidClaim`], or the [`SdJwtError`] of
    /// processing.
    pub fn from_sd_jwt(sd_jwt: SdJwt) -> Result<Self, SdJwtVcError> {
        let header = sd_jwt
            .jwt()
            .decode()
            .map_err(SdJwtError::from)?
            .header()
            .clone();
        match header.typ.as_deref() {
            None => return Err(SdJwtVcError::MissingTyp),
            Some(TYP | LEGACY_TYP) => {}
            Some(other) => return Err(SdJwtVcError::UnexpectedTyp(other.to_owned())),
        }
        let processed = sd_jwt.process()?;
        if header.typ.as_deref() == Some(LEGACY_TYP)
            && !processed.payload.contains_key("vct")
            && processed.payload.contains_key("@context")
        {
            return Err(SdJwtVcError::VcdmPayload);
        }
        for claim in &processed.disclosed {
            if let Some(PathComponent::Key(name)) = claim.path.components().first()
                && NON_DISCLOSABLE_CLAIMS.contains(&name.as_str())
            {
                return Err(SdJwtVcError::DisclosedRegisteredClaim(name.clone()));
            }
        }
        let claims: SdJwtVcClaims =
            serde_json::from_value(Value::Object(processed.payload.clone()))
                .map_err(SdJwtVcError::Claims)?;
        claims.check()?;
        Ok(Self {
            sd_jwt,
            header,
            processed,
            claims,
        })
    }

    /// The SD-JWT.
    pub fn sd_jwt(&self) -> &SdJwt {
        &self.sd_jwt
    }

    /// The SD-JWT.
    pub fn into_sd_jwt(self) -> SdJwt {
        self.sd_jwt
    }

    /// The header of the issuer-signed JWT.
    pub fn header(&self) -> &JwsHeader {
        &self.header
    }

    /// Whether the `typ` is the pre-standard `vc+sd-jwt`.
    pub fn has_legacy_typ(&self) -> bool {
        self.header.typ.as_deref() == Some(LEGACY_TYP)
    }

    /// The claims, with the disclosures this SD-JWT carries applied.
    pub fn claims(&self) -> &SdJwtVcClaims {
        &self.claims
    }

    /// The processed payload as a JSON object.
    pub fn payload(&self) -> &Map<String, Value> {
        &self.processed.payload
    }

    /// The outcome of processing: which claims the disclosures revealed.
    pub fn processed(&self) -> &Processed {
        &self.processed
    }

    /// The holder's public key from `cnf`, if given by value. A key given by reference
    /// ([`Confirmation::kid`]) is in [`confirmation`](Self::confirmation), and
    /// [`KeyReference::from_confirmation`] reads either.
    pub fn holder_key(&self) -> Option<&Jwk> {
        self.claims.holder_key()
    }

    /// `cnf`: the holder's key, for key binding.
    pub fn confirmation(&self) -> Option<&Confirmation> {
        self.claims.cnf.as_ref()
    }

    /// This credential with only the disclosures at `paths` and beneath them, plus those they
    /// are nested in, without key binding; see [`SdJwt::disclose`].
    ///
    /// # Errors
    ///
    /// As [`SdJwt::disclose`].
    pub fn disclose<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a ClaimPath>,
    ) -> Result<Self, SdJwtVcError> {
        Self::from_sd_jwt(self.sd_jwt.disclose(paths)?)
    }

    /// This credential with only the disclosures `keep` selects, without key binding; see
    /// [`SdJwt::select`].
    ///
    /// # Errors
    ///
    /// As [`SdJwt::select`].
    pub fn select(&self, keep: impl FnMut(&Disclosure) -> bool) -> Result<Self, SdJwtVcError> {
        Self::from_sd_jwt(self.sd_jwt.select(keep)?)
    }

    /// This credential as an SD-JWT+KB; see [`SdJwt::sign_key_binding`].
    ///
    /// # Errors
    ///
    /// As [`SdJwt::sign_key_binding`].
    pub async fn sign_key_binding(
        self,
        binding: &KeyBinding,
        signer: &dyn Signer,
    ) -> Result<Self, SdJwtVcError> {
        let sd_jwt = self.sd_jwt.sign_key_binding(binding, signer).await?;
        Ok(Self { sd_jwt, ..self })
    }
}

impl fmt::Debug for SdJwtVc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtVc")
            .field("header", &self.header)
            .field("claims", &self.claims)
            .field("sd_jwt", &self.sd_jwt)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SdJwtVc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.sd_jwt, f)
    }
}

impl FromStr for SdJwtVc {
    type Err = SdJwtVcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SdJwtVc {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SdJwtVc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}
