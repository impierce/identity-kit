//! The DID document data model (DID Core §5) and operations on it.

use core::fmt;
use core::mem;
use core::str::FromStr;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use indexmap::{IndexMap, IndexSet};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::{Did, DidUrl, DidUrlReference, Uri};
use crate::jose::Jwk;

/// Why a [`DidDocument`] operation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DocumentError {
    /// `@context` is not a string, a map or a non-empty array.
    #[error("`@context` must be a string, a map or a non-empty array")]
    InvalidContext,
    /// A verification method with this id is already in the document, or the document defines
    /// the id twice with different material.
    #[error("verification method `{0}` already exists")]
    DuplicateVerificationMethod(DidUrl),
    /// A service with this id is already in the document.
    #[error("service `{0}` already exists")]
    DuplicateService(DidUrl),
    /// No verification method with this id is in the document.
    #[error("verification method `{0}` not found")]
    VerificationMethodNotFound(DidUrl),
    /// The DID URL belongs to another DID than the document.
    #[error("`{url}` does not belong to document `{document}`")]
    ForeignDid {
        /// The DID URL that was looked up.
        url: DidUrl,
        /// The `id` of the document.
        document: Did,
    },
    /// The verification method exists but is not listed under the relationship.
    #[error("verification method `{id}` is not listed under `{relationship}`")]
    NotInRelationship {
        /// The id of the verification method.
        id: DidUrl,
        /// The relationship that was required.
        relationship: VerificationRelationship,
    },
    /// Not the name of a verification relationship.
    #[error("unknown verification relationship `{0}`")]
    UnknownRelationship(String),
    /// An extension property with the name of a core property.
    #[error("`{0}` is a core property, not an extension property")]
    ReservedProperty(String),
}

// ---------------------------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------------------------

/// A value that is either one `T` or a list of them, serialized without the list when single.
///
/// DID Core uses this for `controller` and `type` of a service.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single value.
    One(T),
    /// A list of values, kept as a list even when it holds one.
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    /// The values, in order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        match self {
            Self::One(one) => core::slice::from_ref(one).iter(),
            Self::Many(many) => many.iter(),
        }
    }

    /// The values, mutably.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        match self {
            Self::One(one) => core::slice::from_mut(one).iter_mut(),
            Self::Many(many) => many.iter_mut(),
        }
    }

    /// The number of values.
    pub fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Many(many) => many.len(),
        }
    }

    /// Whether there are no values (an empty list).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The first value, if any.
    pub fn first(&self) -> Option<&T> {
        self.iter().next()
    }

    /// Whether `value` is among the values.
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.iter().any(|v| v == value)
    }

    /// The values as a `Vec`.
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(one) => vec![one],
            Self::Many(many) => many,
        }
    }
}

/// `skip_serializing_if` for optional lists: `None` and empty lists are omitted alike.
fn is_none_or_empty<T>(value: &Option<OneOrMany<T>>) -> bool {
    value.as_ref().is_none_or(OneOrMany::is_empty)
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(values: Vec<T>) -> Self {
        Self::Many(values)
    }
}

/// The `@context` of a DID document, carried verbatim: a string, a map or a non-empty array of
/// them.
///
/// This crate does no JSON-LD processing; the context is data that round-trips.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Context;
///
/// let context = Context::uris([Context::DID_V1, "https://w3id.org/security/suites/jws-2020/v1"]);
/// assert!(context.contains(Context::DID_V1));
/// assert_eq!(
///     serde_json::to_string(&context)?,
///     r#"["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"]"#
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Context(Value);

impl Context {
    /// The DID Core 1.0 context URI.
    pub const DID_V1: &'static str = "https://www.w3.org/ns/did/v1";

    /// The context `"https://www.w3.org/ns/did/v1"`.
    pub fn did_v1() -> Self {
        Self::uri(Self::DID_V1)
    }

    /// A single context URI.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self(Value::String(uri.into()))
    }

    /// An array of context URIs.
    pub fn uris<I, S>(uris: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(Value::Array(
            uris.into_iter().map(|s| Value::String(s.into())).collect(),
        ))
    }

    /// Any JSON value allowed as a context.
    ///
    /// # Errors
    ///
    /// [`DocumentError::InvalidContext`] unless `value` is a string, a map or a non-empty array.
    pub fn new(value: Value) -> Result<Self, DocumentError> {
        match &value {
            Value::String(_) | Value::Object(_) => Ok(Self(value)),
            Value::Array(items) if !items.is_empty() => Ok(Self(value)),
            _ => Err(DocumentError::InvalidContext),
        }
    }

    /// The context as JSON.
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    /// The context as JSON.
    pub fn into_value(self) -> Value {
        self.0
    }

    /// Whether `uri` is the context or one of the strings in the context array.
    pub fn contains(&self, uri: &str) -> bool {
        match &self.0 {
            Value::String(s) => s == uri,
            Value::Array(items) => items.iter().any(|item| item.as_str() == Some(uri)),
            _ => false,
        }
    }
}

impl<'de> Deserialize<'de> for Context {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Value::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A verification relationship (DID Core §5.3): the purpose a verification method may be used
/// for. The `Display` and `FromStr` forms are the DID document property names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationRelationship {
    /// `authentication`
    Authentication,
    /// `assertionMethod`
    AssertionMethod,
    /// `keyAgreement`
    KeyAgreement,
    /// `capabilityInvocation`
    CapabilityInvocation,
    /// `capabilityDelegation`
    CapabilityDelegation,
}

impl VerificationRelationship {
    /// Every relationship, in the order DID Core lists them.
    pub const ALL: &'static [VerificationRelationship] = &[
        Self::Authentication,
        Self::AssertionMethod,
        Self::KeyAgreement,
        Self::CapabilityInvocation,
        Self::CapabilityDelegation,
    ];

    /// The DID document property name, for example `assertionMethod`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::AssertionMethod => "assertionMethod",
            Self::KeyAgreement => "keyAgreement",
            Self::CapabilityInvocation => "capabilityInvocation",
            Self::CapabilityDelegation => "capabilityDelegation",
        }
    }
}

impl fmt::Display for VerificationRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for VerificationRelationship {
    type Err = DocumentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|rel| rel.as_str() == s)
            .ok_or_else(|| DocumentError::UnknownRelationship(s.to_owned()))
    }
}

/// The `type` of a verification method: an open string with constants for the types this crate
/// produces.
///
/// # Examples
///
/// ```
/// use identity_kit::did::MethodType;
///
/// assert_eq!(MethodType::JSON_WEB_KEY_2020.as_str(), "JsonWebKey2020");
/// assert_eq!(MethodType::new("JsonWebKey2020"), MethodType::JSON_WEB_KEY_2020);
/// assert_eq!(serde_json::to_string(&MethodType::MULTIKEY)?, "\"Multikey\"");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MethodType(Cow<'static, str>);

impl MethodType {
    /// `JsonWebKey2020`: `publicKeyJwk` material (JSON Web Signature 2020 suite).
    pub const JSON_WEB_KEY_2020: MethodType = MethodType(Cow::Borrowed("JsonWebKey2020"));
    /// `JsonWebKey`: `publicKeyJwk` material (Controlled Identifiers 1.0).
    pub const JSON_WEB_KEY: MethodType = MethodType(Cow::Borrowed("JsonWebKey"));
    /// `Multikey`: `publicKeyMultibase` material (Controlled Identifiers 1.0).
    pub const MULTIKEY: MethodType = MethodType(Cow::Borrowed("Multikey"));
    /// `Ed25519VerificationKey2020`: `publicKeyMultibase` material (Ed25519 Signature 2020 suite).
    pub const ED25519_VERIFICATION_KEY_2020: MethodType =
        MethodType(Cow::Borrowed("Ed25519VerificationKey2020"));

    /// Any type name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(Cow::Owned(name.into()))
    }

    /// The type name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MethodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for MethodType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for MethodType {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
}

impl From<String> for MethodType {
    fn from(name: String) -> Self {
        Self::new(name)
    }
}

impl PartialEq<str> for MethodType {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for MethodType {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Serialize for MethodType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MethodType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

// ---------------------------------------------------------------------------------------------
// Verification methods
// ---------------------------------------------------------------------------------------------

/// The verification material of a verification method (DID Core §5.2.1): exactly one of
/// `publicKeyJwk` and `publicKeyMultibase`.
///
/// A `publicKeyJwk` must not carry private parameters; such a key is rejected when read and
/// refused when written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationMaterial {
    /// `publicKeyJwk`: a public JSON Web Key.
    PublicKeyJwk(Box<Jwk>),
    /// `publicKeyMultibase`: a multibase-encoded public key.
    PublicKeyMultibase(String),
}

impl VerificationMaterial {
    /// `publicKeyJwk` with the public part of `jwk`.
    pub fn jwk(jwk: &Jwk) -> Self {
        Self::PublicKeyJwk(Box::new(jwk.public()))
    }

    /// `publicKeyMultibase`.
    pub fn multibase(value: impl Into<String>) -> Self {
        Self::PublicKeyMultibase(value.into())
    }

    /// The JWK, when the material is `publicKeyJwk`.
    pub fn as_jwk(&self) -> Option<&Jwk> {
        match self {
            Self::PublicKeyJwk(jwk) => Some(jwk),
            Self::PublicKeyMultibase(_) => None,
        }
    }

    /// The multibase string, when the material is `publicKeyMultibase`.
    pub fn as_multibase(&self) -> Option<&str> {
        match self {
            Self::PublicKeyMultibase(value) => Some(value),
            Self::PublicKeyJwk(_) => None,
        }
    }
}

impl Serialize for VerificationMaterial {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::PublicKeyJwk(jwk) => {
                if jwk.is_private() {
                    return Err(serde::ser::Error::custom(
                        "`publicKeyJwk` must not contain private parameters",
                    ));
                }
                map.serialize_entry("publicKeyJwk", jwk)?;
            }
            Self::PublicKeyMultibase(value) => map.serialize_entry("publicKeyMultibase", value)?,
        }
        map.end()
    }
}

/// The two material members as optional fields, so they can be flattened out of a method.
#[derive(Deserialize)]
struct MaterialMembers {
    #[serde(rename = "publicKeyJwk", default)]
    public_key_jwk: Option<Jwk>,
    #[serde(rename = "publicKeyMultibase", default)]
    public_key_multibase: Option<String>,
}

impl<'de> Deserialize<'de> for VerificationMaterial {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let members = MaterialMembers::deserialize(deserializer)?;
        match (members.public_key_jwk, members.public_key_multibase) {
            (Some(jwk), None) if jwk.is_private() => Err(de::Error::custom(
                "`publicKeyJwk` must not contain private parameters",
            )),
            (Some(jwk), None) => Ok(Self::PublicKeyJwk(Box::new(jwk))),
            (None, Some(value)) => Ok(Self::PublicKeyMultibase(value)),
            (None, None) => Err(de::Error::custom(
                "verification method has neither `publicKeyJwk` nor `publicKeyMultibase`",
            )),
            (Some(_), Some(_)) => Err(de::Error::custom(
                "verification method has both `publicKeyJwk` and `publicKeyMultibase`",
            )),
        }
    }
}

/// A verification method (DID Core §5.2): a public key with an id, a type and a controller.
///
/// Members other than the four core ones live in `properties`, in insertion order.
///
/// # Examples
///
/// ```
/// use identity_kit::did::{MethodType, VerificationMaterial, VerificationMethod};
///
/// let json = r#"{
///   "id": "did:example:123#key-1",
///   "type": "Multikey",
///   "controller": "did:example:123",
///   "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
/// }"#;
/// let method: VerificationMethod = serde_json::from_str(json)?;
/// assert_eq!(method.method_type, MethodType::MULTIKEY);
/// assert_eq!(method.controller.as_str(), "did:example:123");
/// assert_eq!(
///     method.material.as_multibase(),
///     Some("z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu")
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VerificationMethod {
    /// The DID URL identifying the method, usually the document DID with a fragment.
    pub id: DidUrl,
    /// The `type`, which tells which cryptographic suite reads the material.
    #[serde(rename = "type")]
    pub method_type: MethodType,
    /// The DID of the controller of the key.
    pub controller: Did,
    /// `publicKeyJwk` or `publicKeyMultibase`.
    #[serde(flatten)]
    pub material: VerificationMaterial,
    /// Every other member, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl VerificationMethod {
    /// A verification method with the four core members.
    pub fn new(
        id: DidUrl,
        method_type: MethodType,
        controller: Did,
        material: VerificationMaterial,
    ) -> Self {
        Self {
            id,
            method_type,
            controller,
            material,
            properties: IndexMap::new(),
        }
    }

    /// The `publicKeyJwk`, if that is the material.
    pub fn public_key_jwk(&self) -> Option<&Jwk> {
        self.material.as_jwk()
    }

    /// The `publicKeyMultibase`, if that is the material.
    pub fn public_key_multibase(&self) -> Option<&str> {
        self.material.as_multibase()
    }
}

/// An entry of a verification relationship: a reference to a method in `verificationMethod`,
/// or a method embedded in the relationship and usable for that purpose only (DID Core §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodRef {
    /// A DID URL (possibly relative) of a method listed under `verificationMethod`.
    Reference(DidUrlReference),
    /// A method defined in place.
    Embedded(Box<VerificationMethod>),
}

impl MethodRef {
    /// A reference to `id`.
    pub fn reference(id: impl Into<DidUrlReference>) -> Self {
        Self::Reference(id.into())
    }

    /// An embedded method.
    pub fn embedded(method: VerificationMethod) -> Self {
        Self::Embedded(Box::new(method))
    }

    /// The embedded method, if this entry embeds one.
    pub fn as_embedded(&self) -> Option<&VerificationMethod> {
        match self {
            Self::Embedded(method) => Some(method),
            Self::Reference(_) => None,
        }
    }

    /// The reference, if this entry is one.
    pub fn as_reference(&self) -> Option<&DidUrlReference> {
        match self {
            Self::Reference(reference) => Some(reference),
            Self::Embedded(_) => None,
        }
    }

    /// Whether this entry denotes the method `id` in a document whose `id` is `base`.
    pub fn refers_to(&self, id: &DidUrl, base: &Did) -> bool {
        match self {
            Self::Reference(reference) => reference.refers_to(id, base),
            Self::Embedded(method) => method.id == *id,
        }
    }
}

impl From<DidUrl> for MethodRef {
    fn from(id: DidUrl) -> Self {
        Self::Reference(id.into())
    }
}

impl From<DidUrlReference> for MethodRef {
    fn from(reference: DidUrlReference) -> Self {
        Self::Reference(reference)
    }
}

impl From<VerificationMethod> for MethodRef {
    fn from(method: VerificationMethod) -> Self {
        Self::embedded(method)
    }
}

impl Serialize for MethodRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Reference(reference) => reference.serialize(serializer),
            Self::Embedded(method) => method.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for MethodRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MethodRefVisitor;

        impl<'de> Visitor<'de> for MethodRefVisitor {
            type Value = MethodRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a DID URL string or a verification method object")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                DidUrlReference::parse(value)
                    .map(MethodRef::Reference)
                    .map_err(E::custom)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                VerificationMethod::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(MethodRef::embedded)
            }
        }

        deserializer.deserialize_any(MethodRefVisitor)
    }
}

// ---------------------------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------------------------

/// The `serviceEndpoint` of a service (DID Core §5.4): a URI, a set of URIs, or a map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ServiceEndpoint {
    /// A single URI.
    Uri(Uri),
    /// A non-empty set of URIs, in document order.
    Set(IndexSet<Uri>),
    /// A map, carried verbatim.
    Map(IndexMap<String, Value>),
}

impl ServiceEndpoint {
    /// A single URI.
    pub fn uri(uri: Uri) -> Self {
        Self::Uri(uri)
    }

    /// The URIs, when the endpoint is a URI or a set of them.
    pub fn uris(&self) -> impl Iterator<Item = &Uri> {
        let slice: Box<dyn Iterator<Item = &Uri>> = match self {
            Self::Uri(uri) => Box::new(core::iter::once(uri)),
            Self::Set(set) => Box::new(set.iter()),
            Self::Map(_) => Box::new(core::iter::empty()),
        };
        slice
    }
}

impl From<Uri> for ServiceEndpoint {
    fn from(uri: Uri) -> Self {
        Self::Uri(uri)
    }
}

impl<'de> Deserialize<'de> for ServiceEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EndpointVisitor;

        impl<'de> Visitor<'de> for EndpointVisitor {
            type Value = ServiceEndpoint;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a URI string, a non-empty array of URI strings, or an object")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Uri::parse(value)
                    .map(ServiceEndpoint::Uri)
                    .map_err(E::custom)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut set = IndexSet::new();
                while let Some(uri) = seq.next_element::<Uri>()? {
                    set.insert(uri);
                }
                if set.is_empty() {
                    return Err(de::Error::custom(
                        "`serviceEndpoint` set must contain at least one URI",
                    ));
                }
                Ok(ServiceEndpoint::Set(set))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut entries = IndexMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    entries.insert(key, value);
                }
                Ok(ServiceEndpoint::Map(entries))
            }
        }

        deserializer.deserialize_any(EndpointVisitor)
    }
}

/// A service (DID Core §5.4): a way of interacting with the DID subject.
///
/// `type` serializes as a string when single. Members other than the three core ones live in
/// `properties`, in insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Service {
    /// The DID URL identifying the service, usually the document DID with a fragment.
    pub id: DidUrl,
    /// The service type or types.
    #[serde(rename = "type")]
    pub service_type: OneOrMany<String>,
    /// Where the service is.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: ServiceEndpoint,
    /// Every other member, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Service {
    /// A service with the three core members.
    pub fn new(
        id: DidUrl,
        service_type: impl Into<OneOrMany<String>>,
        service_endpoint: impl Into<ServiceEndpoint>,
    ) -> Self {
        Self {
            id,
            service_type: service_type.into(),
            service_endpoint: service_endpoint.into(),
            properties: IndexMap::new(),
        }
    }

    /// Whether `service_type` is among the service's types.
    pub fn has_type(&self, service_type: &str) -> bool {
        self.service_type.iter().any(|t| t == service_type)
    }
}

impl From<&str> for OneOrMany<String> {
    fn from(value: &str) -> Self {
        Self::One(value.to_owned())
    }
}

// ---------------------------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------------------------

/// A DID document (DID Core §5): the core properties as fields, everything else in `properties`.
///
/// The JSON representation is deterministic: `@context` comes first, then `id`, the core
/// properties in the order DID Core lists them, and extension properties in insertion order.
/// `None` and empty lists are omitted. A document parsed from JSON and written again holds the
/// same members with the same values; the bytes are identical when the input already used that
/// order. Extension properties must not use a core property name (see
/// [`CORE_PROPERTIES`](Self::CORE_PROPERTIES)); the builder refuses one, and a document whose
/// `properties` field holds one serializes a duplicate member.
///
/// The fields are public for reading and plain mutation; the methods keep the invariants that
/// DID Core requires (unique method and service ids, references that point at listed methods).
/// Deserialization enforces them too: a document that defines one verification method id twice
/// with different content (listed or embedded) is rejected, so no lookup can pick different
/// material for one id, and so is one with two services sharing an id, as DID Core §5.4 requires
/// of a consumer. Embedding the same method under several relationships, as DID Core's own
/// examples do, is one definition and allowed.
///
/// # Examples
///
/// ```
/// use identity_kit::did::{DidDocument, VerificationRelationship};
///
/// // DID Core §4.1, Example 1 (with its editorial typo fixed).
/// let json = r#"{
///   "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
///   "id": "did:example:123456789abcdefghi",
///   "authentication": [{
///     "id": "did:example:123456789abcdefghi#keys-1",
///     "type": "Ed25519VerificationKey2020",
///     "controller": "did:example:123456789abcdefghi",
///     "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
///   }]
/// }"#;
/// let document: DidDocument = serde_json::from_str(json)?;
/// assert_eq!(document.id.as_str(), "did:example:123456789abcdefghi");
///
/// let key = document.id.join("#keys-1")?;
/// let method = document.resolve_verification_method(&key, Some(VerificationRelationship::Authentication))?;
/// assert_eq!(method.public_key_multibase(), Some("zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"));
///
/// // The method is embedded under `authentication` and usable for nothing else.
/// assert!(document.resolve_verification_method(&key, Some(VerificationRelationship::AssertionMethod)).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(remote = "Self")]
pub struct DidDocument {
    /// `@context`, carried verbatim.
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    /// The DID of the subject.
    pub id: Did,
    /// Other identifiers of the subject.
    #[serde(rename = "alsoKnownAs", default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<Uri>,
    /// The DIDs whose controllers may change this document; omitted when `None` or empty, and
    /// `None` when read as an empty set.
    #[serde(default, skip_serializing_if = "is_none_or_empty")]
    pub controller: Option<OneOrMany<Did>>,
    /// Verification methods that relationships may reference.
    #[serde(
        rename = "verificationMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_method: Vec<VerificationMethod>,
    /// `authentication`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<MethodRef>,
    /// `assertionMethod`
    #[serde(
        rename = "assertionMethod",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub assertion_method: Vec<MethodRef>,
    /// `keyAgreement`
    #[serde(
        rename = "keyAgreement",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub key_agreement: Vec<MethodRef>,
    /// `capabilityInvocation`
    #[serde(
        rename = "capabilityInvocation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_invocation: Vec<MethodRef>,
    /// `capabilityDelegation`
    #[serde(
        rename = "capabilityDelegation",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub capability_delegation: Vec<MethodRef>,
    /// Services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl Serialize for DidDocument {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Self::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for DidDocument {
    /// Reads the document and rejects duplicate verification method or service ids. An empty
    /// `controller` set reads as no controller, which is how it is written.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut document = Self::deserialize(deserializer)?;
        document.check_unique_ids().map_err(de::Error::custom)?;
        if is_none_or_empty(&document.controller) {
            document.controller = None;
        }
        Ok(document)
    }
}

impl DidDocument {
    /// The property names DID Core §5 defines, which `properties` must not contain.
    pub const CORE_PROPERTIES: &'static [&'static str] = &[
        "@context",
        "id",
        "alsoKnownAs",
        "controller",
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
        "service",
    ];

    /// An empty document for `id`.
    pub fn new(id: Did) -> Self {
        Self {
            context: None,
            id,
            also_known_as: Vec::new(),
            controller: None,
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            capability_invocation: Vec::new(),
            capability_delegation: Vec::new(),
            service: Vec::new(),
            properties: IndexMap::new(),
        }
    }

    /// A builder for a document for `id`.
    pub fn builder(id: Did) -> DidDocumentBuilder {
        DidDocumentBuilder {
            document: Self::new(id),
            error: None,
        }
    }

    /// The entries of `relationship`.
    pub fn relationship(&self, relationship: VerificationRelationship) -> &[MethodRef] {
        match relationship {
            VerificationRelationship::Authentication => &self.authentication,
            VerificationRelationship::AssertionMethod => &self.assertion_method,
            VerificationRelationship::KeyAgreement => &self.key_agreement,
            VerificationRelationship::CapabilityInvocation => &self.capability_invocation,
            VerificationRelationship::CapabilityDelegation => &self.capability_delegation,
        }
    }

    /// The entries of `relationship`, mutably.
    pub fn relationship_mut(
        &mut self,
        relationship: VerificationRelationship,
    ) -> &mut Vec<MethodRef> {
        match relationship {
            VerificationRelationship::Authentication => &mut self.authentication,
            VerificationRelationship::AssertionMethod => &mut self.assertion_method,
            VerificationRelationship::KeyAgreement => &mut self.key_agreement,
            VerificationRelationship::CapabilityInvocation => &mut self.capability_invocation,
            VerificationRelationship::CapabilityDelegation => &mut self.capability_delegation,
        }
    }

    /// The methods embedded in any relationship.
    fn embedded_methods(&self) -> impl Iterator<Item = &VerificationMethod> {
        VerificationRelationship::ALL
            .iter()
            .flat_map(|rel| self.relationship(*rel))
            .filter_map(MethodRef::as_embedded)
    }

    /// The verification method with `id`, listed under `verificationMethod` or embedded in a
    /// relationship.
    pub fn verification_method(&self, id: &DidUrl) -> Option<&VerificationMethod> {
        self.verification_method
            .iter()
            .chain(self.embedded_methods())
            .find(|method| method.id == *id)
    }

    /// The verification methods usable for `relationship`, or every method in the document
    /// when `relationship` is `None`.
    ///
    /// References are followed; a reference to a method that is not listed under
    /// `verificationMethod` yields nothing.
    pub fn methods(
        &self,
        relationship: Option<VerificationRelationship>,
    ) -> impl Iterator<Item = &VerificationMethod> {
        let entries: Box<dyn Iterator<Item = &VerificationMethod>> =
            match relationship {
                None => Box::new(
                    self.verification_method
                        .iter()
                        .chain(self.embedded_methods()),
                ),
                Some(rel) => Box::new(self.relationship(rel).iter().filter_map(
                    |entry| match entry {
                        MethodRef::Embedded(method) => Some(&**method),
                        MethodRef::Reference(reference) => {
                            let id = reference.resolve(&self.id).ok()?;
                            self.verification_method.iter().find(|m| m.id == id)
                        }
                    },
                )),
            };
        entries
    }

    /// The verification method `id`, optionally restricted to those usable for `relationship`.
    ///
    /// `id` must belong to this document's DID. The method may be listed under
    /// `verificationMethod` or embedded in a relationship; with a `relationship`, it must be
    /// referenced (absolutely or relatively) or embedded under that relationship.
    ///
    /// # Errors
    ///
    /// - [`DocumentError::ForeignDid`] when `id` is a DID URL of another DID.
    /// - [`DocumentError::VerificationMethodNotFound`] when no method has that id.
    /// - [`DocumentError::NotInRelationship`] when it exists but not under `relationship`.
    pub fn resolve_verification_method(
        &self,
        id: &DidUrl,
        relationship: Option<VerificationRelationship>,
    ) -> Result<&VerificationMethod, DocumentError> {
        if id.did() != &self.id {
            return Err(DocumentError::ForeignDid {
                url: id.clone(),
                document: self.id.clone(),
            });
        }
        let Some(relationship) = relationship else {
            return self
                .verification_method(id)
                .ok_or_else(|| DocumentError::VerificationMethodNotFound(id.clone()));
        };
        for entry in self.relationship(relationship) {
            match entry {
                MethodRef::Embedded(method) if method.id == *id => return Ok(method),
                MethodRef::Reference(reference) if reference.refers_to(id, &self.id) => {
                    return self
                        .verification_method
                        .iter()
                        .find(|method| method.id == *id)
                        .ok_or_else(|| DocumentError::VerificationMethodNotFound(id.clone()));
                }
                _ => {}
            }
        }
        if self.verification_method(id).is_some() {
            Err(DocumentError::NotInRelationship {
                id: id.clone(),
                relationship,
            })
        } else {
            Err(DocumentError::VerificationMethodNotFound(id.clone()))
        }
    }

    /// [`resolve_verification_method`](Self::resolve_verification_method) for a reference that
    /// may be relative (`#key-1`), resolved against this document's `id`.
    ///
    /// # Errors
    ///
    /// As [`resolve_verification_method`](Self::resolve_verification_method).
    pub fn resolve_method_reference(
        &self,
        reference: &DidUrlReference,
        relationship: Option<VerificationRelationship>,
    ) -> Result<&VerificationMethod, DocumentError> {
        // A relative reference this type accepted always joins to a DID.
        let id = reference.resolve(&self.id).map_err(|_| match reference {
            DidUrlReference::Absolute(url) => DocumentError::ForeignDid {
                url: url.clone(),
                document: self.id.clone(),
            },
            DidUrlReference::Relative(_) => {
                DocumentError::VerificationMethodNotFound(self.id.to_url())
            }
        })?;
        self.resolve_verification_method(&id, relationship)
    }

    /// Adds `method` under `verificationMethod` and references it from each of `relationships`.
    ///
    /// # Errors
    ///
    /// [`DocumentError::DuplicateVerificationMethod`] when a method with that id exists, listed
    /// or embedded; the document is unchanged.
    pub fn insert_verification_method(
        &mut self,
        method: VerificationMethod,
        relationships: impl IntoIterator<Item = VerificationRelationship>,
    ) -> Result<(), DocumentError> {
        if self.verification_method(&method.id).is_some() {
            return Err(DocumentError::DuplicateVerificationMethod(method.id));
        }
        let id = method.id.clone();
        self.verification_method.push(method);
        for relationship in relationships {
            self.attach_relationship(&id, relationship)?;
        }
        Ok(())
    }

    /// Checks that every verification method id (listed or embedded) has one definition and that
    /// no two services share an id: the invariant the mutating methods keep and deserialization
    /// enforces. The same method embedded under several relationships is one definition.
    ///
    /// # Errors
    ///
    /// [`DocumentError::DuplicateVerificationMethod`] naming the first id defined twice with
    /// different content, or [`DocumentError::DuplicateService`] naming the first repeated
    /// service id.
    pub fn check_unique_ids(&self) -> Result<(), DocumentError> {
        let mut seen = HashMap::new();
        for method in self
            .verification_method
            .iter()
            .chain(self.embedded_methods())
        {
            if *seen.entry(&method.id).or_insert(method) != method {
                return Err(DocumentError::DuplicateVerificationMethod(
                    method.id.clone(),
                ));
            }
        }
        let mut seen = HashSet::new();
        for service in &self.service {
            if !seen.insert(&service.id) {
                return Err(DocumentError::DuplicateService(service.id.clone()));
            }
        }
        Ok(())
    }

    /// Removes the method `id`, listed or embedded, and every relationship entry for it.
    pub fn remove_verification_method(&mut self, id: &DidUrl) -> Option<VerificationMethod> {
        // Every listed entry with the id goes, should plain mutation have duplicated it.
        let (matching, rest): (Vec<_>, Vec<_>) = mem::take(&mut self.verification_method)
            .into_iter()
            .partition(|method| method.id == *id);
        self.verification_method = rest;
        let listed = matching.into_iter().next();
        let mut embedded = None;
        let base = self.id.clone();
        for relationship in VerificationRelationship::ALL {
            let entries = self.relationship_mut(*relationship);
            let mut index = 0;
            while index < entries.len() {
                if entries[index].refers_to(id, &base) {
                    if let MethodRef::Embedded(method) = entries.remove(index) {
                        embedded.get_or_insert(*method);
                    }
                } else {
                    index += 1;
                }
            }
        }
        listed.or(embedded)
    }

    /// References the listed method `id` from `relationship`.
    ///
    /// Returns whether an entry was added: `Ok(false)` when the relationship already references
    /// or embeds the method.
    ///
    /// # Errors
    ///
    /// [`DocumentError::VerificationMethodNotFound`] when `id` is not listed under
    /// `verificationMethod` (a reference to an embedded method would dangle).
    pub fn attach_relationship(
        &mut self,
        id: &DidUrl,
        relationship: VerificationRelationship,
    ) -> Result<bool, DocumentError> {
        if !self.verification_method.iter().any(|m| m.id == *id) {
            return Err(DocumentError::VerificationMethodNotFound(id.clone()));
        }
        let base = self.id.clone();
        let entries = self.relationship_mut(relationship);
        if entries.iter().any(|entry| entry.refers_to(id, &base)) {
            return Ok(false);
        }
        entries.push(MethodRef::Reference(id.clone().into()));
        Ok(true)
    }

    /// Removes every entry for the method `id` from `relationship`, returning whether there
    /// was one.
    pub fn detach_relationship(
        &mut self,
        id: &DidUrl,
        relationship: VerificationRelationship,
    ) -> bool {
        let base = self.id.clone();
        let entries = self.relationship_mut(relationship);
        let before = entries.len();
        entries.retain(|entry| !entry.refers_to(id, &base));
        entries.len() != before
    }

    /// The service `id`.
    pub fn service(&self, id: &DidUrl) -> Option<&Service> {
        self.service.iter().find(|service| service.id == *id)
    }

    /// Adds `service`.
    ///
    /// # Errors
    ///
    /// [`DocumentError::DuplicateService`] when a service with that id exists.
    pub fn insert_service(&mut self, service: Service) -> Result<(), DocumentError> {
        if self.service(&service.id).is_some() {
            return Err(DocumentError::DuplicateService(service.id));
        }
        self.service.push(service);
        Ok(())
    }

    /// Removes the service `id`.
    pub fn remove_service(&mut self, id: &DidUrl) -> Option<Service> {
        self.service
            .iter()
            .position(|service| service.id == *id)
            .map(|index| self.service.remove(index))
    }

    /// Rewrites every DID in the document through `f`: the `id`, the controllers, the ids and
    /// controllers of verification methods (listed and embedded), absolute relationship
    /// references and service ids. Relative references, `alsoKnownAs` and extension properties
    /// are left as they are.
    ///
    /// This is how a method whose DID depends on the document (a `did:web` moving domains, a
    /// placeholder DID replaced by the registered one) produces its final document.
    ///
    /// `f` is expected to map distinct DIDs to distinct DIDs. Merging two DIDs into one can give
    /// two methods or services the same id; that is not checked here, and
    /// [`check_unique_ids`](Self::check_unique_ids) reports it.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{Did, DidDocument, MethodType, VerificationMaterial, VerificationMethod, VerificationRelationship};
    ///
    /// let placeholder = Did::parse("did:example:placeholder")?;
    /// let mut document = DidDocument::new(placeholder.clone());
    /// document.insert_verification_method(
    ///     VerificationMethod::new(
    ///         placeholder.join("#key-1")?,
    ///         MethodType::MULTIKEY,
    ///         placeholder.clone(),
    ///         VerificationMaterial::multibase("z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"),
    ///     ),
    ///     [VerificationRelationship::Authentication],
    /// )?;
    ///
    /// let registered = Did::parse("did:web:example.com")?;
    /// document.map_dids(|did| if did == placeholder { registered.clone() } else { did });
    ///
    /// assert_eq!(document.id, registered);
    /// assert_eq!(document.verification_method[0].id.as_str(), "did:web:example.com#key-1");
    /// assert_eq!(document.verification_method[0].controller, registered);
    /// let key = registered.join("#key-1")?;
    /// assert!(document.resolve_verification_method(&key, Some(VerificationRelationship::Authentication)).is_ok());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn map_dids(&mut self, mut f: impl FnMut(Did) -> Did) {
        fn map_url(url: &mut DidUrl, f: &mut impl FnMut(Did) -> Did) {
            let did = f(url.did().clone());
            if &did != url.did() {
                *url = url.with_did(did);
            }
        }
        fn map_method(method: &mut VerificationMethod, f: &mut impl FnMut(Did) -> Did) {
            map_url(&mut method.id, f);
            method.controller = f(method.controller.clone());
        }

        self.id = f(self.id.clone());
        if let Some(controller) = &mut self.controller {
            for did in controller.iter_mut() {
                *did = f(did.clone());
            }
        }
        for method in &mut self.verification_method {
            map_method(method, &mut f);
        }
        for relationship in VerificationRelationship::ALL {
            for entry in self.relationship_mut(*relationship) {
                match entry {
                    MethodRef::Reference(DidUrlReference::Absolute(url)) => map_url(url, &mut f),
                    MethodRef::Reference(DidUrlReference::Relative(_)) => {}
                    MethodRef::Embedded(method) => map_method(method, &mut f),
                }
            }
        }
        for service in &mut self.service {
            map_url(&mut service.id, &mut f);
        }
    }
}

/// Builds a [`DidDocument`], reporting the first invariant violation at [`build`](Self::build).
#[derive(Debug, Clone)]
pub struct DidDocumentBuilder {
    document: DidDocument,
    error: Option<DocumentError>,
}

impl DidDocumentBuilder {
    /// Sets `@context`.
    #[must_use]
    pub fn context(mut self, context: Context) -> Self {
        self.document.context = Some(context);
        self
    }

    /// Adds an `alsoKnownAs` URI.
    #[must_use]
    pub fn also_known_as(mut self, uri: Uri) -> Self {
        self.document.also_known_as.push(uri);
        self
    }

    /// Adds a controller; one controller serializes as a string, more as an array.
    #[must_use]
    pub fn controller(mut self, did: Did) -> Self {
        self.document.controller = Some(match self.document.controller.take() {
            None => OneOrMany::One(did),
            Some(existing) => {
                let mut dids = existing.into_vec();
                dids.push(did);
                OneOrMany::Many(dids)
            }
        });
        self
    }

    /// Adds a verification method under `verificationMethod`, referenced from `relationships`.
    #[must_use]
    pub fn verification_method(
        mut self,
        method: VerificationMethod,
        relationships: impl IntoIterator<Item = VerificationRelationship>,
    ) -> Self {
        if self.error.is_none() {
            self.error = self
                .document
                .insert_verification_method(method, relationships)
                .err();
        }
        self
    }

    /// Embeds a verification method in `relationship`, usable for that purpose only.
    #[must_use]
    pub fn embedded_method(
        mut self,
        relationship: VerificationRelationship,
        method: VerificationMethod,
    ) -> Self {
        if self.error.is_none() {
            if self.document.verification_method(&method.id).is_some() {
                self.error = Some(DocumentError::DuplicateVerificationMethod(method.id));
            } else {
                self.document
                    .relationship_mut(relationship)
                    .push(MethodRef::embedded(method));
            }
        }
        self
    }

    /// Adds a service.
    #[must_use]
    pub fn service(mut self, service: Service) -> Self {
        if self.error.is_none() {
            self.error = self.document.insert_service(service).err();
        }
        self
    }

    /// Adds an extension property; a core property name is refused at
    /// [`build`](Self::build) with [`DocumentError::ReservedProperty`].
    #[must_use]
    pub fn property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        let name = name.into();
        if DidDocument::CORE_PROPERTIES.contains(&name.as_str()) {
            if self.error.is_none() {
                self.error = Some(DocumentError::ReservedProperty(name));
            }
        } else {
            self.document.properties.insert(name, value.into());
        }
        self
    }

    /// The document.
    ///
    /// # Errors
    ///
    /// The first [`DocumentError`] an addition raised: a duplicate method or service id.
    pub fn build(self) -> Result<DidDocument, DocumentError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.document),
        }
    }
}
