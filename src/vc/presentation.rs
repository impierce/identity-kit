//! `Presentation`: a Verifiable Credentials Data Model 1.1 presentation of JWT credentials.

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use crate::did::{Context, OneOrMany, Uri};

use super::model::{CONTEXT_V1, append_context, check_context_and_type, push_type};
use super::{CredentialError, Jwt, JwtClaims, Party, claims};

/// A verifiable presentation of the Verifiable Credentials Data Model 1.1 whose credentials are
/// JWTs, as data.
///
/// Deserialization checks that the first `@context` is the base context and `type` includes
/// `VerifiablePresentation`. A presentation is secured by signing its JWT form, see
/// [`to_jwt_claims`](Self::to_jwt_claims); the holder signs it, so the holder is the `iss`.
///
/// # Examples
///
/// ```
/// use identity_kit::did::{Did, Uri};
/// use identity_kit::vc::{Jwt, Presentation};
///
/// let credential: Jwt = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
///     hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
///     .parse()?;
/// let presentation = Presentation::new()
///     .with_id(Uri::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")?)
///     .with_holder(Did::parse("did:example:ebfeb1f712ebc6f1c276e12ec21")?)
///     .with_credential(credential);
///
/// let claims = presentation.to_jwt_claims()?.with_aud("did:example:4a57546973436f6f6c4a4a57573");
/// assert_eq!(claims.iss.as_deref(), Some("did:example:ebfeb1f712ebc6f1c276e12ec21"));
/// assert_eq!(claims.jti.as_deref(), Some("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5"));
/// assert_eq!(claims.additional["vp"]["verifiableCredential"].as_array().map(Vec::len), Some(1));
/// assert_eq!(Presentation::from_jwt_claims(&claims)?, presentation);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(remote = "Self")]
pub struct Presentation {
    /// `@context`, starting with [`Presentation::CONTEXT`].
    #[serde(rename = "@context")]
    pub context: Context,
    /// The identifier of the presentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uri>,
    /// `type`, including [`Presentation::TYPE`].
    #[serde(rename = "type")]
    pub types: OneOrMany<String>,
    /// The presented credentials, as JWTs.
    #[serde(
        rename = "verifiableCredential",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verifiable_credential: Vec<Jwt>,
    /// The holder presenting the credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<Party>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Serialize for Presentation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Presentation {
    /// Reads the presentation and checks it with [`Presentation::check`].
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let presentation = Self::deserialize(deserializer)?;
        presentation.check().map_err(de::Error::custom)?;
        Ok(presentation)
    }
}

impl Default for Presentation {
    fn default() -> Self {
        Self::new()
    }
}

impl Presentation {
    /// The base context, `https://www.w3.org/2018/credentials/v1`.
    pub const CONTEXT: &'static str = CONTEXT_V1;

    /// The type every presentation has, `VerifiablePresentation`.
    pub const TYPE: &'static str = "VerifiablePresentation";

    /// An empty presentation of type `VerifiablePresentation` in the base context.
    pub fn new() -> Self {
        Self {
            context: Context::uri(Self::CONTEXT),
            id: None,
            types: OneOrMany::One(Self::TYPE.to_owned()),
            verifiable_credential: Vec::new(),
            holder: None,
            properties: IndexMap::new(),
        }
    }

    /// This presentation with `context` appended to its `@context`.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = append_context(self.context, context.into());
        self
    }

    /// This presentation with its `id` set.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<Uri>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// This presentation with `presentation_type` appended to its `type`.
    #[must_use]
    pub fn with_type(mut self, presentation_type: impl Into<String>) -> Self {
        push_type(&mut self.types, presentation_type.into());
        self
    }

    /// This presentation with its `holder` set.
    #[must_use]
    pub fn with_holder(mut self, holder: impl Into<Party>) -> Self {
        self.holder = Some(holder.into());
        self
    }

    /// This presentation with `credential` added.
    #[must_use]
    pub fn with_credential(mut self, credential: Jwt) -> Self {
        self.verifiable_credential.push(credential);
        self
    }

    /// This presentation with the property `name` set to `value`.
    #[must_use]
    pub fn with_property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.insert(name.into(), value.into());
        self
    }

    /// Whether `presentation_type` is among the types.
    pub fn has_type(&self, presentation_type: &str) -> bool {
        self.types.iter().any(|t| t == presentation_type)
    }

    /// Checks that the first `@context` is the base context and `type` includes
    /// `VerifiablePresentation`.
    ///
    /// # Errors
    ///
    /// The first [`CredentialError`] found.
    pub fn check(&self) -> Result<(), CredentialError> {
        check_context_and_type(&self.context, Self::CONTEXT, &self.types, Self::TYPE)
    }

    /// The JWT claims set of the presentation (VCDM 1.1 §6.3.1 "JWT Encoding"): `iss` is the
    /// holder, `jti` the id, and the presentation without those properties is the `vp` claim.
    /// `aud`, `nbf`, `exp` and `nonce` are the caller's to add.
    ///
    /// # Errors
    ///
    /// What [`check`](Self::check) reports.
    pub fn to_jwt_claims(&self) -> Result<JwtClaims, CredentialError> {
        self.check()?;
        let mut vp = claims::to_object(self);
        let jti = claims::take_id(&mut vp, "id");
        let iss = claims::take_id(&mut vp, "holder");
        Ok(JwtClaims {
            iss,
            jti,
            additional: IndexMap::from([("vp".to_owned(), Value::Object(vp))]),
            ..JwtClaims::default()
        })
    }

    /// The presentation of a JWT claims set (VCDM 1.1 §6.3.1 "JWT Decoding"): the `vp` claim
    /// with `iss` and `jti` mapped back to `holder` and `id`.
    ///
    /// # Errors
    ///
    /// As [`Credential::from_jwt_claims`](super::Credential::from_jwt_claims), for `vp`.
    pub fn from_jwt_claims(jwt_claims: &JwtClaims) -> Result<Self, CredentialError> {
        let mut vp = claims::claim_object(jwt_claims, "vp")?;
        claims::merge_id(&mut vp, "id", "jti", jwt_claims.jti.as_deref())?;
        claims::merge_id(&mut vp, "holder", "iss", jwt_claims.iss.as_deref())?;
        serde_json::from_value(Value::Object(vp)).map_err(|e| CredentialError::InvalidClaim {
            claim: "vp",
            reason: e.to_string(),
        })
    }
}
