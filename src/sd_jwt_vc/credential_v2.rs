//! VCDM 2.0 credentials secured with SD-JWT (VC-JOSE-COSE §3.2.1): the credential is the
//! payload of the issuer-signed JWT, `typ` is `vc+sd-jwt`.

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use super::{
    ClaimPath, Confirmation, Disclosure, HashAlgorithm, KeyBinding, PathComponent, Processed,
    SdJwt, SdJwtBuilder, SdJwtError, Status,
};
use crate::jose::{Jwk, JwsHeader, Signer};
use crate::vc::{CredentialError, CredentialV2, JwtClaims};

/// Why an SD-JWT is not a VCDM 2.0 credential secured with SD-JWT.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtCredentialV2Error {
    /// The SD-JWT itself is invalid.
    #[error(transparent)]
    SdJwt(#[from] SdJwtError),
    /// The `typ` is present and is not `vc+sd-jwt` (nor one the caller accepts).
    #[error("header `typ` is {0:?}, not `vc+sd-jwt`")]
    UnexpectedTyp(String),
    /// A claim that must not be selectively disclosed came from a disclosure.
    #[error("`{0}` must not be selectively disclosed")]
    DisclosedRegisteredClaim(String),
    /// The processed payload is not a JWT claims set.
    #[error("the payload is not a JWT claims set: {0}")]
    Payload(String),
    /// `cnf` or `status` is not what the claim must hold.
    #[error("claim `{claim}`: {reason}")]
    InvalidClaim {
        /// The claim.
        claim: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// The processed payload is not a VCDM 2.0 credential, or its registered claims disagree
    /// with it.
    #[error(transparent)]
    Credential(#[from] CredentialError),
}

/// A VCDM 2.0 credential secured with SD-JWT (VC-JOSE-COSE §3.2.1): an [`SdJwt`] whose
/// processed payload is a [`CredentialV2`], with `typ: vc+sd-jwt`, and `iss`, `cnf` and
/// `status` beside it.
///
/// This is the VCDM counterpart of [`SdJwtVc`](super::SdJwtVc), which models the IETF SD-JWT
/// VC claims set with its `vct`. Both are SD-JWTs and share [`SdJwt`]; telling them apart is
/// described in the [module documentation](super#two-sd-jwt-credential-types).
///
/// Parsing processes the disclosures (so the digests and the structure are checked), reads
/// the payload as a credential through [`CredentialV2::from_jwt_claims`] (so `iss`, `jti` and
/// `sub`, when present, agree with `issuer`, `id` and the subject, and a `vc` claim is
/// refused) and checks that none of [`NON_DISCLOSABLE_CLAIMS`](Self::NON_DISCLOSABLE_CLAIMS)
/// came from a disclosure. No signature is verified: that is
/// [`SdJwtCredentialValidator::validate_v2`](super::SdJwtCredentialValidator::validate_v2).
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::{SdJwt, SdJwtCredentialV2};
///
/// // The W3C VC-JOSE-COSE test suite's "SD-JWT Basic Credential Verification" input, with
/// // `firstName` and `lastName` selectively disclosable, both disclosed. (Its `iat` is an RFC
/// // 3339 string where RFC 7519 wants a NumericDate, so it processes as an SD-JWT but does
/// // not map to a credential; the crate's tests cover both.)
/// let sd_jwt: SdJwt = "eyJhbGciOiJFUzM4NCIsImN0eSI6InZjIiwia2lkIjoiOTZxQm5EcHZTNng4WVNDSF94bW5\
///     MbFhaTWtEaEhCcjhsajk5dTVhb2c3cyIsInR5cCI6InZjK3NkLWp3dCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3\
///     d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZ\
///     XhhbXBsZXMvdjIiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbImtuYzN2Z2pmZlpUUDdwRHk2OVAxVndO\
///     V1RGVFhxblg1b0R1Nl9wU2RTYzAiLCIxeElDZkE3Z3VLVXZwU3F6RF9TelhwTU55U1RyWVRDSWNwNEwxOU1Ydn\
///     FzIl0sImJpcnRoRGF0ZSI6IjE5OTAtMDEtMDEiLCJpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFj\
///     Mjc2ZTEyZWMyMSJ9LCJpYXQiOiIyMDI0LTAxLTAxVDAwOjAwOjAwWiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS\
///     5pc3N1ZXIvdmMtam9zZS1jb3NlIiwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmlzc3Vlci92Yy1qb3NlLWNv\
///     c2UiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDcmVkZW50aWFsIl0sInZhbGlkRn\
///     JvbSI6IjIwMjQtMDEtMDFUMDA6MDA6MDBaIn0.bCgz_EgNH5ELRr-xvudGvtIWMQxobkjKLnQer3iXV3iZk4_v\
///     KpMG8hUzvrrWlcpoxJo-Dh_Usm8LYcFOdnCHXdVNlnfz8baLEvNRcUc-60NkEwD739qjbEEvrCnYY9jb~WyI0b\
///     UZLME14VEsyRmluZFNxQ0ktSzhBIiwiZmlyc3ROYW1lIiwiSmFuZSJd~WyJvU3lzbndsZ1ZGREUzZzdsbTJKZF\
///     ZRIiwibGFzdE5hbWUiLCJEb2UiXQ~"
///     .parse()?;
/// assert_eq!(
///     sd_jwt.jwt().decode()?.header().typ.as_deref(),
///     Some(SdJwtCredentialV2::TYP)
/// );
/// let processed = sd_jwt.process()?;
/// assert_eq!(processed.payload["credentialSubject"]["firstName"], "Jane");
/// assert_eq!(processed.payload["credentialSubject"]["lastName"], "Doe");
/// assert_eq!(processed.disclosed.len(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SdJwtCredentialV2 {
    sd_jwt: SdJwt,
    header: JwsHeader,
    processed: Processed,
    claims: JwtClaims,
    credential: CredentialV2,
    cnf: Option<Confirmation>,
    status: Option<Status>,
}

impl SdJwtCredentialV2 {
    /// The `typ` of the issuer-signed JWT, `vc+sd-jwt`.
    pub const TYP: &'static str = "vc+sd-jwt";

    /// The media type, `application/vc+sd-jwt`.
    pub const MEDIA_TYPE: &'static str = "application/vc+sd-jwt";

    /// The claims that, with their sub-claims, must not be selectively disclosed: those a
    /// verifier needs before it can decide anything about the credential, and those SD-JWT
    /// reserves.
    pub const NON_DISCLOSABLE_CLAIMS: [&'static str; 7] = [
        "@context", "type", "issuer", "_sd_alg", "iss", "cnf", "status",
    ];

    /// Parses the compact serialization and processes the disclosures.
    ///
    /// # Errors
    ///
    /// As [`from_sd_jwt`](Self::from_sd_jwt).
    pub fn parse(s: &str) -> Result<Self, SdJwtCredentialV2Error> {
        Self::from_sd_jwt(SdJwt::parse(s)?)
    }

    /// Takes `sd_jwt` as a VCDM 2.0 credential secured with SD-JWT: `typ`, when present, is
    /// `vc+sd-jwt`; the disclosures are processed; the payload is read as a credential; none
    /// of [`NON_DISCLOSABLE_CLAIMS`](Self::NON_DISCLOSABLE_CLAIMS) came from a disclosure.
    ///
    /// # Errors
    ///
    /// [`SdJwtCredentialV2Error::UnexpectedTyp`],
    /// [`SdJwtCredentialV2Error::DisclosedRegisteredClaim`],
    /// [`SdJwtCredentialV2Error::Payload`], [`SdJwtCredentialV2Error::InvalidClaim`],
    /// [`SdJwtCredentialV2Error::Credential`], or the [`SdJwtError`] of processing.
    pub fn from_sd_jwt(sd_jwt: SdJwt) -> Result<Self, SdJwtCredentialV2Error> {
        Self::from_sd_jwt_with(sd_jwt, &BTreeSet::new())
    }

    /// [`from_sd_jwt`](Self::from_sd_jwt), also accepting a `typ` in `additional_typ`.
    ///
    /// # Errors
    ///
    /// As [`from_sd_jwt`](Self::from_sd_jwt).
    pub fn from_sd_jwt_with(
        sd_jwt: SdJwt,
        additional_typ: &BTreeSet<String>,
    ) -> Result<Self, SdJwtCredentialV2Error> {
        let header = sd_jwt
            .jwt()
            .decode()
            .map_err(SdJwtError::from)?
            .header()
            .clone();
        if let Some(typ) = header.typ.as_deref()
            && typ != Self::TYP
            && !additional_typ.contains(typ)
        {
            return Err(SdJwtCredentialV2Error::UnexpectedTyp(typ.to_owned()));
        }
        let processed = sd_jwt.process()?;
        for claim in &processed.disclosed {
            if let Some(PathComponent::Key(name)) = claim.path.components().first()
                && Self::NON_DISCLOSABLE_CLAIMS.contains(&name.as_str())
            {
                return Err(SdJwtCredentialV2Error::DisclosedRegisteredClaim(
                    name.clone(),
                ));
            }
        }
        let claims: JwtClaims = serde_json::from_value(Value::Object(processed.payload.clone()))
            .map_err(|e| SdJwtCredentialV2Error::Payload(e.to_string()))?;
        let mut rest = claims.clone();
        let cnf = take_claim(&mut rest, "cnf")?;
        let status = take_claim(&mut rest, "status")?;
        let credential = CredentialV2::from_jwt_claims(&rest)?;
        Ok(Self {
            sd_jwt,
            header,
            processed,
            claims,
            credential,
            cnf,
            status,
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

    /// The credential, with the disclosures this SD-JWT carries applied.
    pub fn credential(&self) -> &CredentialV2 {
        &self.credential
    }

    /// The processed payload as a claims set: the registered claims (`iss`, `iat`, `exp`, …)
    /// as fields, the credential's properties, `cnf` and `status` under `additional`.
    pub fn claims(&self) -> &JwtClaims {
        &self.claims
    }

    /// `cnf`: the holder's key, for key binding.
    pub fn confirmation(&self) -> Option<&Confirmation> {
        self.cnf.as_ref()
    }

    /// `status`: how to learn the status of the credential (Token Status List), beside any
    /// `credentialStatus` of the credential itself.
    pub fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// The processed payload as a JSON object.
    pub fn payload(&self) -> &Map<String, Value> {
        &self.processed.payload
    }

    /// The outcome of processing: which claims the disclosures revealed.
    pub fn processed(&self) -> &Processed {
        &self.processed
    }

    /// The holder's public key from `cnf`, if given by value.
    pub fn holder_key(&self) -> Option<&Jwk> {
        self.cnf.as_ref()?.jwk.as_ref()
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
    ) -> Result<Self, SdJwtCredentialV2Error> {
        Self::from_sd_jwt_with(self.sd_jwt.disclose(paths)?, &self.accepted_typ())
    }

    /// This credential with only the disclosures `keep` selects, without key binding; see
    /// [`SdJwt::select`].
    ///
    /// # Errors
    ///
    /// As [`SdJwt::select`].
    pub fn select(
        &self,
        keep: impl FnMut(&Disclosure) -> bool,
    ) -> Result<Self, SdJwtCredentialV2Error> {
        Self::from_sd_jwt_with(self.sd_jwt.select(keep)?, &self.accepted_typ())
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
    ) -> Result<Self, SdJwtCredentialV2Error> {
        let sd_jwt = self.sd_jwt.sign_key_binding(binding, signer).await?;
        Ok(Self { sd_jwt, ..self })
    }

    /// The `typ` this credential was accepted with, so that a derived credential is too.
    fn accepted_typ(&self) -> BTreeSet<String> {
        self.header.typ.iter().cloned().collect()
    }
}

/// Removes `claim` from `claims.additional` and reads it as a `T`.
fn take_claim<T: serde::de::DeserializeOwned>(
    claims: &mut JwtClaims,
    claim: &'static str,
) -> Result<Option<T>, SdJwtCredentialV2Error> {
    claims
        .additional
        .shift_remove(claim)
        .map(|value| {
            serde_json::from_value(value).map_err(|e| SdJwtCredentialV2Error::InvalidClaim {
                claim,
                reason: e.to_string(),
            })
        })
        .transpose()
}

impl fmt::Debug for SdJwtCredentialV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtCredentialV2")
            .field("header", &self.header)
            .field("credential", &self.credential)
            .field("cnf", &self.cnf)
            .field("status", &self.status)
            .field("sd_jwt", &self.sd_jwt)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SdJwtCredentialV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.sd_jwt, f)
    }
}

impl FromStr for SdJwtCredentialV2 {
    type Err = SdJwtCredentialV2Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SdJwtCredentialV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SdJwtCredentialV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Issues a VCDM 2.0 credential secured with SD-JWT: the credential is the payload, with
/// `iss` set to its issuer and the registered time claims, `cnf` and `status` given here
/// beside it; the properties at the paths given to [`conceal`](Self::conceal) are selectively
/// disclosable; the issuer signs with `typ: vc+sd-jwt`.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Uri;
/// use identity_kit::sd_jwt_vc::SdJwtCredentialV2Builder;
/// use identity_kit::vc::{CredentialV2, Subject};
/// use serde_json::json;
///
/// let credential = CredentialV2::new(
///     Uri::parse("did:example:issuer")?,
///     Subject::new(Uri::parse("did:example:holder")?)
///         .with_property("given_name", "Erika")
///         .with_property("degree", json!({ "type": "ExampleBachelorDegree" })),
/// );
/// let builder = SdJwtCredentialV2Builder::new(credential)
///     .conceal(["credentialSubject", "given_name"])
///     .with_decoys(2);
/// assert!(builder.check_concealed().is_ok());
/// // `issuer` and `@context` are needed to validate the credential and cannot be concealed.
/// assert!(builder.clone_credential().conceal(["issuer"]).check_concealed().is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SdJwtCredentialV2Builder {
    credential: CredentialV2,
    iat: Option<i64>,
    nbf: Option<i64>,
    exp: Option<i64>,
    cnf: Option<Confirmation>,
    status: Option<Status>,
    kid: Option<String>,
    concealed: Vec<ClaimPath>,
    decoys: usize,
    alg: HashAlgorithm,
    salts: Option<Box<dyn FnMut() -> String + Send>>,
}

impl SdJwtCredentialV2Builder {
    /// A builder over `credential`.
    pub fn new(credential: CredentialV2) -> Self {
        Self {
            credential,
            iat: None,
            nbf: None,
            exp: None,
            cnf: None,
            status: None,
            kid: None,
            concealed: Vec::new(),
            decoys: 0,
            alg: HashAlgorithm::default(),
            salts: None,
        }
    }

    /// The credential.
    pub fn credential(&self) -> &CredentialV2 {
        &self.credential
    }

    /// A builder over a copy of this credential, nothing else set.
    pub fn clone_credential(&self) -> Self {
        Self::new(self.credential.clone())
    }

    /// This builder with `iat`, beside the credential's `validFrom`.
    #[must_use]
    pub fn with_issued_at(mut self, time: DateTime<Utc>) -> Self {
        self.iat = Some(JwtClaims::numeric_date(time));
        self
    }

    /// This builder with `nbf`.
    #[must_use]
    pub fn with_not_before(mut self, time: DateTime<Utc>) -> Self {
        self.nbf = Some(JwtClaims::numeric_date(time));
        self
    }

    /// This builder with `exp`, beside the credential's `validUntil`.
    #[must_use]
    pub fn with_expires_at(mut self, time: DateTime<Utc>) -> Self {
        self.exp = Some(JwtClaims::numeric_date(time));
        self
    }

    /// This builder with `cnf`.
    #[must_use]
    pub fn with_confirmation(mut self, cnf: Confirmation) -> Self {
        self.cnf = Some(cnf);
        self
    }

    /// This builder with `cnf` holding the public part of `jwk`.
    #[must_use]
    pub fn with_holder_key(self, jwk: &Jwk) -> Self {
        self.with_confirmation(Confirmation::jwk(jwk))
    }

    /// This builder with `status`.
    #[must_use]
    pub fn with_status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// This builder signing with `kid` in the header, instead of the signer's.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// This builder concealing the property at `path` (`credentialSubject.given_name`, an
    /// array element, …); see [`SdJwtBuilder::conceal`].
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

    /// Checks that no path to conceal starts at one of
    /// [`SdJwtCredentialV2::NON_DISCLOSABLE_CLAIMS`].
    ///
    /// # Errors
    ///
    /// [`SdJwtError::NotConcealable`].
    pub fn check_concealed(&self) -> Result<(), SdJwtCredentialV2Error> {
        for path in &self.concealed {
            if let Some(PathComponent::Key(name)) = path.components().first()
                && SdJwtCredentialV2::NON_DISCLOSABLE_CLAIMS.contains(&name.as_str())
            {
                return Err(SdJwtError::NotConcealable {
                    path: path.clone(),
                    reason: format!("a credential secured with SD-JWT keeps `{name}` disclosed"),
                }
                .into());
            }
        }
        Ok(())
    }

    /// The claims set to secure: the credential, `iss`, the time claims, `cnf` and `status`.
    fn claims(&self) -> JwtClaims {
        let mut claims = self.credential.to_jwt_claims();
        claims.iss = Some(self.credential.issuer.id().to_string());
        claims.iat = self.iat;
        claims.nbf = self.nbf;
        claims.exp = self.exp;
        if let Some(cnf) = &self.cnf {
            claims.additional.insert(
                "cnf".to_owned(),
                serde_json::to_value(cnf).expect("a confirmation serializes"),
            );
        }
        if let Some(status) = &self.status {
            claims.additional.insert(
                "status".to_owned(),
                serde_json::to_value(status).expect("a status serializes"),
            );
        }
        claims
    }

    /// The credential, signed with `signer` under `alg`, `typ: vc+sd-jwt` and the `kid` given
    /// or the signer's.
    ///
    /// # Errors
    ///
    /// [`SdJwtError::NotConcealable`], the errors of [`SdJwtBuilder::sign`], and those of
    /// [`SdJwtCredentialV2::from_sd_jwt`] should the credential not read back.
    pub async fn sign(
        self,
        signer: &dyn Signer,
    ) -> Result<SdJwtCredentialV2, SdJwtCredentialV2Error> {
        self.check_concealed()?;
        let claims = match serde_json::to_value(self.claims()).expect("claims serialize") {
            Value::Object(map) => map,
            _ => unreachable!("a struct serializes to an object"),
        };
        let mut header = JwsHeader::new(signer.alg()).with_typ(SdJwtCredentialV2::TYP);
        header.kid = self.kid.or_else(|| signer.kid().map(str::to_owned));
        let mut builder = SdJwtBuilder::new(claims)
            .with_decoys(self.decoys)
            .with_hash_algorithm(self.alg);
        for path in self.concealed {
            builder = builder.conceal(path);
        }
        if let Some(salts) = self.salts {
            builder = builder.with_salt_generator(salts);
        }
        let sd_jwt = builder.sign(&header, signer).await?;
        SdJwtCredentialV2::from_sd_jwt(sd_jwt)
    }
}

impl fmt::Debug for SdJwtCredentialV2Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdJwtCredentialV2Builder")
            .field("credential", &self.credential)
            .field("iat", &self.iat)
            .field("nbf", &self.nbf)
            .field("exp", &self.exp)
            .field("cnf", &self.cnf)
            .field("status", &self.status)
            .field("kid", &self.kid)
            .field("concealed", &self.concealed)
            .field("decoys", &self.decoys)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}
