//! Verifiable Credentials Data Model 2.0: [`CredentialV2`] and [`PresentationV2`] secured as
//! JWTs per VC-JOSE-COSE, and the [`EnvelopedVc`] and [`EnvelopedVp`] objects that carry a
//! secured credential or presentation in a `data:` URL.

use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use crate::did::{Context, OneOrMany, Uri};

use super::credential::push;
use super::model::{CONTEXT_V2, append_context, check_context_and_type, push_type};
use super::{CredentialError, Jwt, JwtClaims, Party, Subject, TypedObject, claims};

/// A verifiable credential of the Verifiable Credentials Data Model 2.0, as data.
///
/// Secured per VC-JOSE-COSE, the credential itself is the JWT payload: `@context` and the other
/// properties are claims next to the registered ones, with `typ: vc+jwt` in the header. See
/// [`to_jwt_claims`](Self::to_jwt_claims).
///
/// Deserialization checks that the first `@context` is the base context, `type` includes
/// `VerifiableCredential`, there is a subject, and `validUntil` is not before `validFrom`.
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone as _, Utc};
/// use identity_kit::did::Uri;
/// use identity_kit::vc::{CredentialV2, Subject};
/// use serde_json::json;
///
/// let credential = CredentialV2::new(
///     Uri::parse("https://university.example/issuers/14")?,
///     Subject::new(Uri::parse("did:example:ebfeb1f712ebc6f1c276e12ec21")?)
///         .with_property("degree", json!({ "type": "ExampleBachelorDegree" })),
/// )
/// .with_type("ExampleDegreeCredential")
/// .with_valid_from(Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap());
///
/// let claims = credential.to_jwt_claims();
/// assert_eq!(claims.additional["validFrom"], "2010-01-01T19:23:24Z");
/// assert_eq!(CredentialV2::from_jwt_claims(&claims)?, credential);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(remote = "Self")]
pub struct CredentialV2 {
    /// `@context`, starting with [`CredentialV2::CONTEXT`].
    #[serde(rename = "@context")]
    pub context: Context,
    /// The identifier of the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uri>,
    /// `type`, including [`CredentialV2::TYPE`].
    #[serde(rename = "type")]
    pub types: OneOrMany<String>,
    /// `name`: a string or language-tagged values, kept as JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Value>,
    /// `description`: a string or language-tagged values, kept as JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Value>,
    /// The issuer.
    pub issuer: Party,
    /// When the credential becomes valid.
    #[serde(rename = "validFrom", default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    /// When the credential ceases to be valid.
    #[serde(
        rename = "validUntil",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_until: Option<DateTime<Utc>>,
    /// `credentialStatus`: where to learn whether the credential is revoked or suspended.
    #[serde(
        rename = "credentialStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_status: Option<OneOrMany<TypedObject>>,
    /// The subjects and the claims about them.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: OneOrMany<Subject>,
    /// `credentialSchema`.
    #[serde(
        rename = "credentialSchema",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_schema: Option<OneOrMany<TypedObject>>,
    /// Every other property (`relatedResource`, `termsOfUse`, `evidence`, `refreshService`,
    /// …), in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Serialize for CredentialV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for CredentialV2 {
    /// Reads the credential and checks it with [`CredentialV2::check`].
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let credential = Self::deserialize(deserializer)?;
        credential.check().map_err(de::Error::custom)?;
        Ok(credential)
    }
}

impl CredentialV2 {
    /// The base context, `https://www.w3.org/ns/credentials/v2`.
    pub const CONTEXT: &'static str = CONTEXT_V2;

    /// The type every credential has, `VerifiableCredential`.
    pub const TYPE: &'static str = "VerifiableCredential";

    /// The `typ` of a JWT securing a credential, `vc+jwt`.
    pub const JWT_TYP: &'static str = "vc+jwt";

    /// The media type of a JWT securing a credential, `application/vc+jwt`.
    pub const JWT_MEDIA_TYPE: &'static str = "application/vc+jwt";

    /// A credential of type `VerifiableCredential` in the base context, issued by `issuer`
    /// about `subject`, valid indefinitely.
    pub fn new(issuer: impl Into<Party>, subject: Subject) -> Self {
        Self {
            context: Context::uri(Self::CONTEXT),
            id: None,
            types: OneOrMany::One(Self::TYPE.to_owned()),
            name: None,
            description: None,
            issuer: issuer.into(),
            valid_from: None,
            valid_until: None,
            credential_status: None,
            credential_subject: OneOrMany::One(subject),
            credential_schema: None,
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

    /// This credential with its `name` set.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<Value>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// This credential with its `description` set.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<Value>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// This credential with its `validFrom` set.
    #[must_use]
    pub fn with_valid_from(mut self, valid_from: DateTime<Utc>) -> Self {
        self.valid_from = Some(valid_from);
        self
    }

    /// This credential with its `validUntil` set.
    #[must_use]
    pub fn with_valid_until(mut self, valid_until: DateTime<Utc>) -> Self {
        self.valid_until = Some(valid_until);
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

    /// This credential with a `credentialStatus` added.
    #[must_use]
    pub fn with_status(mut self, status: TypedObject) -> Self {
        self.credential_status = Some(push(self.credential_status.take(), status));
        self
    }

    /// This credential with a `credentialSchema` added.
    #[must_use]
    pub fn with_schema(mut self, schema: TypedObject) -> Self {
        self.credential_schema = Some(push(self.credential_schema.take(), schema));
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

    /// The status entries, in order; none when `credentialStatus` is absent.
    pub fn statuses(&self) -> impl Iterator<Item = &TypedObject> {
        self.credential_status.iter().flat_map(OneOrMany::iter)
    }

    /// Checks the structural requirements of the data model: the first `@context` is the base
    /// context, `type` includes `VerifiableCredential`, there is a subject, and `validUntil`
    /// is not before `validFrom`.
    ///
    /// # Errors
    ///
    /// The first [`CredentialError`] found.
    pub fn check(&self) -> Result<(), CredentialError> {
        check_context_and_type(&self.context, Self::CONTEXT, &self.types, Self::TYPE)?;
        if self.credential_subject.is_empty() {
            return Err(CredentialError::NoSubject);
        }
        if let (Some(from), Some(until)) = (self.valid_from, self.valid_until) {
            if until < from {
                return Err(CredentialError::InvalidValidity {
                    from: "validFrom",
                    until: "validUntil",
                });
            }
        }
        Ok(())
    }

    /// The JWT claims set securing the credential (VC-JOSE-COSE §3.1.1): the credential's own
    /// properties, nothing else. `iss`, `jti`, `sub`, `iat` and `exp` are the caller's to add
    /// and must agree with the credential when they are.
    pub fn to_jwt_claims(&self) -> JwtClaims {
        JwtClaims {
            additional: claims::to_object(self).into_iter().collect(),
            ..JwtClaims::default()
        }
    }

    /// The credential a JWT claims set secures: its non-registered claims, with `iss`, `jti`
    /// and `sub`, when present, checked against `issuer`, `id` and the subject.
    ///
    /// # Errors
    ///
    /// [`CredentialError::InvalidClaim`] when the claims hold a `vc` claim or do not form a
    /// credential, [`CredentialError::ClaimMismatch`] when a registered claim disagrees with
    /// the property it duplicates, and what [`check`](Self::check) reports.
    pub fn from_jwt_claims(jwt_claims: &JwtClaims) -> Result<Self, CredentialError> {
        let mut vc = payload_object(jwt_claims, "vc")?;
        claims::merge_id(&mut vc, "id", "jti", jwt_claims.jti.as_deref())?;
        claims::merge_id(&mut vc, "issuer", "iss", jwt_claims.iss.as_deref())?;
        claims::merge_subject(&mut vc, jwt_claims.sub.as_deref())?;
        serde_json::from_value(Value::Object(vc)).map_err(|e| CredentialError::InvalidClaim {
            claim: "@context",
            reason: e.to_string(),
        })
    }
}

/// A verifiable presentation of the Verifiable Credentials Data Model 2.0 whose credentials
/// are [`EnvelopedVc`] objects, as data.
///
/// Secured per VC-JOSE-COSE, the presentation itself is the JWT payload, with `typ: vp+jwt`
/// in the header; the holder signs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(remote = "Self")]
pub struct PresentationV2 {
    /// `@context`, starting with [`PresentationV2::CONTEXT`].
    #[serde(rename = "@context")]
    pub context: Context,
    /// The identifier of the presentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uri>,
    /// `type`, including [`PresentationV2::TYPE`].
    #[serde(rename = "type")]
    pub types: OneOrMany<String>,
    /// The holder presenting the credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<Party>,
    /// The presented credentials, each enveloped.
    #[serde(
        rename = "verifiableCredential",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verifiable_credential: Vec<EnvelopedVc>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Serialize for PresentationV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for PresentationV2 {
    /// Reads the presentation and checks it with [`PresentationV2::check`].
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let presentation = Self::deserialize(deserializer)?;
        presentation.check().map_err(de::Error::custom)?;
        Ok(presentation)
    }
}

impl Default for PresentationV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl PresentationV2 {
    /// The base context, `https://www.w3.org/ns/credentials/v2`.
    pub const CONTEXT: &'static str = CONTEXT_V2;

    /// The type every presentation has, `VerifiablePresentation`.
    pub const TYPE: &'static str = "VerifiablePresentation";

    /// The `typ` of a JWT securing a presentation, `vp+jwt`.
    pub const JWT_TYP: &'static str = "vp+jwt";

    /// The media type of a JWT securing a presentation, `application/vp+jwt`.
    pub const JWT_MEDIA_TYPE: &'static str = "application/vp+jwt";

    /// An empty presentation of type `VerifiablePresentation` in the base context.
    pub fn new() -> Self {
        Self {
            context: Context::uri(Self::CONTEXT),
            id: None,
            types: OneOrMany::One(Self::TYPE.to_owned()),
            holder: None,
            verifiable_credential: Vec::new(),
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
    pub fn with_credential(mut self, credential: EnvelopedVc) -> Self {
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

    /// The JWT claims set securing the presentation (VC-JOSE-COSE §3.1.2): the presentation's
    /// own properties. `iss`, `aud`, `nonce` and the rest are the caller's to add.
    pub fn to_jwt_claims(&self) -> JwtClaims {
        JwtClaims {
            additional: claims::to_object(self).into_iter().collect(),
            ..JwtClaims::default()
        }
    }

    /// The presentation a JWT claims set secures, with `iss` and `jti`, when present, checked
    /// against `holder` and `id`.
    ///
    /// # Errors
    ///
    /// As [`CredentialV2::from_jwt_claims`].
    pub fn from_jwt_claims(jwt_claims: &JwtClaims) -> Result<Self, CredentialError> {
        let mut vp = payload_object(jwt_claims, "vp")?;
        claims::merge_id(&mut vp, "id", "jti", jwt_claims.jti.as_deref())?;
        claims::merge_id(&mut vp, "holder", "iss", jwt_claims.iss.as_deref())?;
        serde_json::from_value(Value::Object(vp)).map_err(|e| CredentialError::InvalidClaim {
            claim: "@context",
            reason: e.to_string(),
        })
    }
}

/// The non-registered claims as the object of a VCDM 2.0 payload, which must not hold the
/// VCDM 1.1 claim `forbidden`.
fn payload_object(
    jwt_claims: &JwtClaims,
    forbidden: &'static str,
) -> Result<serde_json::Map<String, Value>, CredentialError> {
    if jwt_claims.additional.contains_key(forbidden) {
        return Err(CredentialError::InvalidClaim {
            claim: forbidden,
            reason: "must not be present in a VC-JOSE-COSE payload".to_owned(),
        });
    }
    Ok(jwt_claims
        .additional
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect())
}

/// The parts of an RFC 2397 `data:` URL: media type, whether `;base64` is set, and the data.
fn parse_data_url(uri: &str) -> Option<(&str, bool, &str)> {
    let (meta, data) = uri.strip_prefix("data:")?.split_once(',')?;
    let (media_type, base64) = match meta.strip_suffix(";base64") {
        Some(media_type) => (media_type, true),
        None => (meta, false),
    };
    Some((media_type, base64, data))
}

macro_rules! enveloped {
    (
        $(#[$doc:meta])*
        $name:ident, $kind:literal, $object_type:literal, $media_type:expr
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[non_exhaustive]
        #[serde(remote = "Self")]
        pub struct $name {
            /// `@context`, which must define the type; the base context does.
            #[serde(rename = "@context")]
            pub context: Context,
            /// The `data:` URL holding the secured form.
            pub id: Uri,
            /// `type`, including the enveloped type.
            #[serde(rename = "type")]
            pub types: OneOrMany<String>,
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                Self::serialize(self, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            /// Reads the object and checks its `type` and that `id` is a `data:` URL.
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let enveloped = Self::deserialize(deserializer)?;
                enveloped.check().map_err(de::Error::custom)?;
                Ok(enveloped)
            }
        }

        impl $name {
            /// The `type`.
            pub const TYPE: &'static str = $object_type;

            /// The media type of the JWT form this crate reads.
            pub const JWT_MEDIA_TYPE: &'static str = $media_type;

            /// An envelope for `data` of `media_type`, in the base context.
            ///
            /// `data` is placed in the URL as is; a JWT needs no encoding, other media types
            /// may.
            pub fn new(media_type: &str, data: &str) -> Self {
                Self {
                    context: Context::uri(CONTEXT_V2),
                    id: Uri::parse(&format!("data:{media_type},{data}"))
                        .expect("a data URL of URI characters"),
                    types: OneOrMany::One(Self::TYPE.to_owned()),
                }
            }

            /// An envelope for `jwt`.
            pub fn from_jwt(jwt: &Jwt) -> Self {
                Self::new(Self::JWT_MEDIA_TYPE, jwt.as_str())
            }

            /// The media type of the `data:` URL.
            pub fn media_type(&self) -> &str {
                parse_data_url(self.id.as_str()).map_or("", |(media_type, _, _)| media_type)
            }

            /// The data of the `data:` URL, as written.
            pub fn data(&self) -> &str {
                parse_data_url(self.id.as_str()).map_or("", |(_, _, data)| data)
            }

            /// The JWT the envelope holds.
            ///
            /// # Errors
            ///
            /// [`CredentialError::UnsupportedMediaType`] when the media type is not the JWT
            /// one, and [`CredentialError::InvalidClaim`] when the data is not a JWT.
            pub fn to_jwt(&self) -> Result<Jwt, CredentialError> {
                let (media_type, base64, data) = parse_data_url(self.id.as_str())
                    .ok_or_else(|| CredentialError::NotDataUrl(self.id.to_string()))?;
                if media_type != Self::JWT_MEDIA_TYPE || base64 {
                    return Err(CredentialError::UnsupportedMediaType {
                        kind: $kind,
                        media_type: if base64 {
                            format!("{media_type};base64")
                        } else {
                            media_type.to_owned()
                        },
                        expected: Self::JWT_MEDIA_TYPE,
                    });
                }
                Jwt::new(data).map_err(|e| CredentialError::InvalidClaim {
                    claim: "id",
                    reason: e.to_string(),
                })
            }

            /// Checks that `type` includes the enveloped type and `id` is a `data:` URL.
            ///
            /// # Errors
            ///
            /// [`CredentialError::MissingType`] or [`CredentialError::NotDataUrl`].
            pub fn check(&self) -> Result<(), CredentialError> {
                if !self.types.iter().any(|t| t == Self::TYPE) {
                    return Err(CredentialError::MissingType(Self::TYPE));
                }
                if parse_data_url(self.id.as_str()).is_none() {
                    return Err(CredentialError::NotDataUrl(self.id.to_string()));
                }
                Ok(())
            }
        }
    };
}

enveloped!(
    /// An `EnvelopedVerifiableCredential` (VCDM 2.0 §4.12.1): a secured credential carried in
    /// a `data:` URL, the form a credential takes inside a [`PresentationV2`].
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::vc::{EnvelopedVc, Jwt};
    ///
    /// let jwt: Jwt = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
    ///     hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
    ///     .parse()?;
    /// let enveloped = EnvelopedVc::from_jwt(&jwt);
    /// assert_eq!(enveloped.media_type(), "application/vc+jwt");
    /// assert_eq!(enveloped.to_jwt()?, jwt);
    /// assert_eq!(
    ///     serde_json::to_value(&enveloped)?["type"],
    ///     "EnvelopedVerifiableCredential"
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    EnvelopedVc,
    "credential",
    "EnvelopedVerifiableCredential",
    CredentialV2::JWT_MEDIA_TYPE
);

enveloped!(
    /// An `EnvelopedVerifiablePresentation` (VCDM 2.0 §4.12.2): a secured presentation carried
    /// in a `data:` URL.
    EnvelopedVp,
    "presentation",
    "EnvelopedVerifiablePresentation",
    PresentationV2::JWT_MEDIA_TYPE
);
