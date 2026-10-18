//! `Credential`: a Verifiable Credentials Data Model 1.1 credential and its JWT profile.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use crate::did::{Context, OneOrMany, Uri};

use super::model::{CONTEXT_V1, append_context, check_context_and_type, push_type};
use super::{CredentialError, JwtClaims, Party, Subject, TypedObject, claims};

/// A verifiable credential of the Verifiable Credentials Data Model 1.1, as data.
///
/// The properties the data model defines are fields; everything else, `proof` included, lives in
/// `properties` in insertion order. Deserialization checks the structural requirements of the
/// data model: the first `@context` is the base context, `type` includes
/// `VerifiableCredential`, there is at least one subject. Nothing is verified: a credential is
/// secured by signing its JWT form, see [`to_jwt_claims`](Self::to_jwt_claims).
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::did::Uri;
/// use identity_kit::vc::{Credential, Subject};
/// use serde_json::json;
///
/// // VCDM 1.1 Example 1, as data.
/// let credential = Credential::new(
///     Uri::parse("https://example.edu/issuers/565049")?,
///     Utc.with_ymd_and_hms(2010, 1, 1, 0, 0, 0).unwrap(),
///     Subject::new(Uri::parse("did:example:ebfeb1f712ebc6f1c276e12ec21")?)
///         .with_property("alumniOf", json!({ "id": "did:example:c276e12ec21ebfeb1f712ebc6f1" })),
/// )
/// .with_context("https://www.w3.org/2018/credentials/examples/v1")
/// .with_id(Uri::parse("http://example.edu/credentials/1872")?)
/// .with_type("AlumniCredential");
///
/// let json = serde_json::to_value(&credential)?;
/// assert_eq!(json["type"], json!(["VerifiableCredential", "AlumniCredential"]));
/// assert_eq!(json["issuanceDate"], "2010-01-01T00:00:00Z");
/// assert_eq!(serde_json::from_value::<Credential>(json)?, credential);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(remote = "Self")]
pub struct Credential {
    /// `@context`, starting with [`Credential::CONTEXT`].
    #[serde(rename = "@context")]
    pub context: Context,
    /// The identifier of the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uri>,
    /// `type`, including [`Credential::TYPE`].
    #[serde(rename = "type")]
    pub types: OneOrMany<String>,
    /// The issuer.
    pub issuer: Party,
    /// When the credential becomes valid.
    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,
    /// When the credential ceases to be valid.
    #[serde(
        rename = "expirationDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiration_date: Option<DateTime<Utc>>,
    /// The subjects and the claims about them; one, in a credential that has a JWT form.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: OneOrMany<Subject>,
    /// `credentialStatus`: where to learn whether the credential is revoked or suspended.
    #[serde(
        rename = "credentialStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_status: Option<TypedObject>,
    /// `credentialSchema`.
    #[serde(
        rename = "credentialSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_schema: Option<OneOrMany<TypedObject>>,
    /// `refreshService`.
    #[serde(
        rename = "refreshService",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_service: Option<OneOrMany<TypedObject>>,
    /// `termsOfUse`.
    #[serde(
        rename = "termsOfUse",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub terms_of_use: Option<OneOrMany<TypedObject>>,
    /// `evidence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<OneOrMany<TypedObject>>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Serialize for Credential {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Credential {
    /// Reads the credential and checks it with [`Credential::check`].
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let credential = Self::deserialize(deserializer)?;
        credential.check().map_err(de::Error::custom)?;
        Ok(credential)
    }
}

impl Credential {
    /// The base context, `https://www.w3.org/2018/credentials/v1`.
    pub const CONTEXT: &'static str = CONTEXT_V1;

    /// The type every credential has, `VerifiableCredential`.
    pub const TYPE: &'static str = "VerifiableCredential";

    /// A credential of type `VerifiableCredential` in the base context, issued by `issuer` at
    /// `issuance_date` about `subject`.
    pub fn new(issuer: impl Into<Party>, issuance_date: DateTime<Utc>, subject: Subject) -> Self {
        Self {
            context: Context::uri(Self::CONTEXT),
            id: None,
            types: OneOrMany::One(Self::TYPE.to_owned()),
            issuer: issuer.into(),
            issuance_date,
            expiration_date: None,
            credential_subject: OneOrMany::One(subject),
            credential_status: None,
            credential_schema: None,
            refresh_service: None,
            terms_of_use: None,
            evidence: None,
            properties: IndexMap::new(),
        }
    }

    /// This credential with `context` appended to its `@context`.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = append_context(self.context, context.into());
        self
    }

    /// This credential with its `id` set.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<Uri>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// This credential with `credential_type` appended to its `type`.
    #[must_use]
    pub fn with_type(mut self, credential_type: impl Into<String>) -> Self {
        push_type(&mut self.types, credential_type.into());
        self
    }

    /// This credential with its `expirationDate` set.
    #[must_use]
    pub fn with_expiration_date(mut self, expiration_date: DateTime<Utc>) -> Self {
        self.expiration_date = Some(expiration_date);
        self
    }

    /// This credential with another subject.
    #[must_use]
    pub fn with_subject(mut self, subject: Subject) -> Self {
        let mut subjects =
            core::mem::replace(&mut self.credential_subject, OneOrMany::Many(Vec::new()))
                .into_vec();
        subjects.push(subject);
        self.credential_subject = OneOrMany::Many(subjects);
        self
    }

    /// This credential with its `credentialStatus` set.
    #[must_use]
    pub fn with_status(mut self, status: TypedObject) -> Self {
        self.credential_status = Some(status);
        self
    }

    /// This credential with a `credentialSchema` added.
    #[must_use]
    pub fn with_schema(mut self, schema: TypedObject) -> Self {
        self.credential_schema = Some(push(self.credential_schema.take(), schema));
        self
    }

    /// This credential with a `termsOfUse` added.
    #[must_use]
    pub fn with_terms_of_use(mut self, terms: TypedObject) -> Self {
        self.terms_of_use = Some(push(self.terms_of_use.take(), terms));
        self
    }

    /// This credential with an `evidence` added.
    #[must_use]
    pub fn with_evidence(mut self, evidence: TypedObject) -> Self {
        self.evidence = Some(push(self.evidence.take(), evidence));
        self
    }

    /// This credential with the property `name` set to `value`.
    #[must_use]
    pub fn with_property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.insert(name.into(), value.into());
        self
    }

    /// The one subject, when there is exactly one.
    pub fn subject(&self) -> Option<&Subject> {
        (self.credential_subject.len() == 1).then(|| self.credential_subject.first())?
    }

    /// Whether `credential_type` is among the types.
    pub fn has_type(&self, credential_type: &str) -> bool {
        self.types.iter().any(|t| t == credential_type)
    }

    /// Checks the structural requirements of the data model: the first `@context` is the base
    /// context, `type` includes `VerifiableCredential`, there is a subject, and
    /// `expirationDate` is not before `issuanceDate`.
    ///
    /// # Errors
    ///
    /// The first [`CredentialError`] found.
    pub fn check(&self) -> Result<(), CredentialError> {
        check_context_and_type(&self.context, Self::CONTEXT, &self.types, Self::TYPE)?;
        if self.credential_subject.is_empty() {
            return Err(CredentialError::NoSubject);
        }
        if self
            .expiration_date
            .is_some_and(|until| until < self.issuance_date)
        {
            return Err(CredentialError::InvalidValidity {
                from: "issuanceDate",
                until: "expirationDate",
            });
        }
        Ok(())
    }

    /// The JWT claims set of the credential (VCDM 1.1 §6.3.1 "JWT Encoding"): `iss` is the
    /// issuer, `jti` the id, `nbf` the issuance date, `exp` the expiration date, `sub` the id of
    /// the subject, and the credential without those properties is the `vc` claim. An issuer
    /// object stays in `vc`, as `iss` carries only its `id`.
    ///
    /// # Errors
    ///
    /// What [`check`](Self::check) reports, and [`CredentialError::MultipleSubjects`] for a
    /// credential with several subjects, which a JWT cannot express.
    pub fn to_jwt_claims(&self) -> Result<JwtClaims, CredentialError> {
        self.check()?;
        let mut vc = claims::to_object(self);
        let jti = claims::take_id(&mut vc, "id");
        let iss = claims::take_id(&mut vc, "issuer");
        vc.shift_remove("issuanceDate");
        vc.shift_remove("expirationDate");
        let sub = claims::take_subject(&mut vc)?;
        Ok(JwtClaims {
            iss,
            sub,
            aud: None,
            exp: self.expiration_date.map(JwtClaims::numeric_date),
            nbf: Some(JwtClaims::numeric_date(self.issuance_date)),
            iat: None,
            jti,
            additional: IndexMap::from([("vc".to_owned(), Value::Object(vc))]),
        })
    }

    /// The credential of a JWT claims set (VCDM 1.1 §6.3.1 "JWT Decoding"): the `vc` claim with
    /// `iss`, `jti`, `nbf`, `exp` and `sub` mapped back to its properties. A property present
    /// in both places must agree with the claim.
    ///
    /// # Errors
    ///
    /// [`CredentialError::MissingClaim`] without a `vc` claim, [`CredentialError::InvalidClaim`]
    /// when a claim or the credential it yields is malformed, [`CredentialError::ClaimMismatch`]
    /// when a claim and its property disagree, and what [`check`](Self::check) reports.
    pub fn from_jwt_claims(jwt_claims: &JwtClaims) -> Result<Self, CredentialError> {
        let mut vc = claims::claim_object(jwt_claims, "vc")?;
        claims::merge_id(&mut vc, "id", "jti", jwt_claims.jti.as_deref())?;
        claims::merge_id(&mut vc, "issuer", "iss", jwt_claims.iss.as_deref())?;
        claims::merge_time(&mut vc, "issuanceDate", "nbf", jwt_claims.nbf)?;
        claims::merge_time(&mut vc, "expirationDate", "exp", jwt_claims.exp)?;
        claims::merge_subject(&mut vc, jwt_claims.sub.as_deref())?;
        let credential: Self = serde_json::from_value(Value::Object(vc)).map_err(|e| {
            CredentialError::InvalidClaim {
                claim: "vc",
                reason: e.to_string(),
            }
        })?;
        Ok(credential)
    }
}

/// `list` with `item` appended.
pub(super) fn push<T>(list: Option<OneOrMany<T>>, item: T) -> OneOrMany<T> {
    match list {
        None => OneOrMany::One(item),
        Some(list) => {
            let mut items = list.into_vec();
            items.push(item);
            OneOrMany::Many(items)
        }
    }
}
