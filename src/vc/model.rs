//! Building blocks shared by credentials and presentations: a [`Party`] (the issuer or the
//! holder), a [`Subject`] and the [`TypedObject`] of every extension point.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::did::{Context, Did, DidUrl, OneOrMany, Uri};

use super::CredentialError;

/// The base context of the Verifiable Credentials Data Model 1.1.
pub const CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";

/// The base context of the Verifiable Credentials Data Model 2.0.
pub const CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// The issuer of a credential or the holder of a presentation: a URI, or an object whose `id`
/// is that URI and that carries further properties, a name say.
///
/// # Examples
///
/// ```
/// use identity_kit::vc::Party;
/// use serde_json::json;
///
/// let issuer: Party = serde_json::from_value(json!("https://example.edu/issuers/565049"))?;
/// assert_eq!(issuer.id().as_str(), "https://example.edu/issuers/565049");
///
/// let issuer: Party = serde_json::from_value(json!({
///     "id": "https://example.edu/issuers/565049",
///     "name": "Example University"
/// }))?;
/// assert_eq!(issuer.id().as_str(), "https://example.edu/issuers/565049");
/// assert_eq!(issuer.properties().and_then(|p| p.get("name")), Some(&json!("Example University")));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Party {
    /// Just the identifier.
    Uri(Uri),
    /// The identifier with further properties.
    Object {
        /// The identifier.
        id: Uri,
        /// Every other property, in insertion order.
        #[serde(flatten)]
        properties: IndexMap<String, Value>,
    },
}

impl Party {
    /// A party with `properties` besides its `id`.
    pub fn object(id: impl Into<Uri>, properties: IndexMap<String, Value>) -> Self {
        Self::Object {
            id: id.into(),
            properties,
        }
    }

    /// The identifier.
    pub fn id(&self) -> &Uri {
        match self {
            Self::Uri(id) | Self::Object { id, .. } => id,
        }
    }

    /// The properties besides `id`, when the party is an object.
    pub fn properties(&self) -> Option<&IndexMap<String, Value>> {
        match self {
            Self::Uri(_) => None,
            Self::Object { properties, .. } => Some(properties),
        }
    }
}

impl From<Uri> for Party {
    fn from(id: Uri) -> Self {
        Self::Uri(id)
    }
}

impl From<Did> for Party {
    fn from(did: Did) -> Self {
        Self::Uri(did.into())
    }
}

impl From<&Did> for Party {
    fn from(did: &Did) -> Self {
        Self::Uri(did.into())
    }
}

impl From<DidUrl> for Party {
    fn from(url: DidUrl) -> Self {
        Self::Uri(url.into())
    }
}

/// A `credentialSubject`: the optional `id` of the subject and the claims about it.
///
/// A subject without `id` makes a bearer credential.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Uri;
/// use identity_kit::vc::Subject;
/// use serde_json::json;
///
/// let subject = Subject::new(Uri::parse("did:example:ebfeb1f712ebc6f1c276e12ec21")?)
///     .with_property("alumniOf", json!({ "name": "Example University" }));
/// assert_eq!(
///     serde_json::to_string(&subject)?,
///     r#"{"id":"did:example:ebfeb1f712ebc6f1c276e12ec21","alumniOf":{"name":"Example University"}}"#
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Subject {
    /// The identifier of the subject, absent in a bearer credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uri>,
    /// The claims about the subject, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Subject {
    /// A subject identified by `id`, without claims yet.
    pub fn new(id: impl Into<Uri>) -> Self {
        Self {
            id: Some(id.into()),
            properties: IndexMap::new(),
        }
    }

    /// This subject with the claim `name` set to `value`.
    #[must_use]
    pub fn with_property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.insert(name.into(), value.into());
        self
    }
}

/// An object with a `type` and usually an `id`: a `credentialStatus`, `credentialSchema`,
/// `refreshService`, `termsOfUse` or `evidence` entry, whose meaning the type defines.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Uri;
/// use identity_kit::vc::TypedObject;
/// use serde_json::json;
///
/// let status = TypedObject::new("StatusList2021Entry")
///     .with_id(Uri::parse("https://example.edu/status/24#94567")?)
///     .with_property("statusPurpose", "revocation")
///     .with_property("statusListIndex", "94567");
/// assert!(status.has_type("StatusList2021Entry"));
/// assert_eq!(
///     serde_json::to_string(&status)?,
///     r#"{"id":"https://example.edu/status/24#94567","type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"94567"}"#
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TypedObject {
    /// The identifier, which most extension points require.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uri>,
    /// The `type`, which selects the meaning of the other properties.
    #[serde(rename = "type")]
    pub types: OneOrMany<String>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl TypedObject {
    /// An object of type `object_type`, without `id`.
    pub fn new(object_type: impl Into<String>) -> Self {
        Self {
            id: None,
            types: OneOrMany::One(object_type.into()),
            properties: IndexMap::new(),
        }
    }

    /// This object with its `id` set.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<Uri>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// This object with the property `name` set to `value`.
    #[must_use]
    pub fn with_property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.insert(name.into(), value.into());
        self
    }

    /// Whether `object_type` is among the types.
    pub fn has_type(&self, object_type: &str) -> bool {
        self.types.iter().any(|t| t == object_type)
    }

    /// The first type.
    pub fn object_type(&self) -> &str {
        self.types.first().map_or("", String::as_str)
    }
}

/// The first URI of `context`, which the data model requires to be its base context.
pub(super) fn first_context(context: &Context) -> Option<&str> {
    match context.as_value() {
        Value::String(uri) => Some(uri),
        Value::Array(items) => items.first().and_then(Value::as_str),
        _ => None,
    }
}

/// Checks that `context` starts with `base` and `types` include `required`.
pub(super) fn check_context_and_type(
    context: &Context,
    base: &'static str,
    types: &OneOrMany<String>,
    required: &'static str,
) -> Result<(), CredentialError> {
    if first_context(context) != Some(base) {
        return Err(CredentialError::InvalidContext { expected: base });
    }
    if !types.iter().any(|t| t == required) {
        return Err(CredentialError::MissingType(required));
    }
    Ok(())
}

/// `context` with `uri` appended.
pub(super) fn append_context(context: Context, uri: String) -> Context {
    let mut uris = match context.into_value() {
        Value::Array(items) => items,
        single => vec![single],
    };
    uris.push(Value::String(uri));
    Context::new(Value::Array(uris)).expect("a non-empty array")
}

/// `types` with `added` appended, as a list.
pub(super) fn push_type(types: &mut OneOrMany<String>, added: String) {
    let mut list = core::mem::replace(types, OneOrMany::Many(Vec::new())).into_vec();
    list.push(added);
    *types = OneOrMany::Many(list);
}
