//! OpenAPI schemas for the JSON types (feature `utoipa`): [`utoipa::ToSchema`] for
//! [`DidDocument`], [`VerificationMethod`], [`MethodRef`], [`Service`], [`Jwk`],
//! `DomainLinkageConfiguration`, `ClaimPath`, `TypeMetadata` with its display and claim
//! metadata, and `StatusType`.
//!
//! The schemas are written by hand rather than derived: every type carries open extension
//! properties and custom serialization that a derive cannot express. Each schema describes the
//! properties its specification defines and, where the specification leaves the object open,
//! allows additional properties.

use std::borrow::Cow;

use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{
    AdditionalProperties, ArrayBuilder, ArrayItems, ObjectBuilder, OneOfBuilder, Ref, RefBuilder,
    Schema, SchemaFormat, SchemaType, Type,
};
use utoipa::{PartialSchema, ToSchema};

use crate::did::{DidDocument, MethodRef, Service, VerificationMethod};
use crate::jose::Jwk;

/// DID Core §3.1 as a regular expression: `did:`, a method name of lowercase letters and
/// digits, then a method-specific id of `idchar`s and `:` that does not end in `:`.
const DID_PATTERN: &str =
    r"^did:[a-z0-9]+:(([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})*:)*([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$";

type Schemas = Vec<(String, RefOr<Schema>)>;

/// Adds the schema of `T`, and the schemas it references, unless already present.
fn collect<T: ToSchema>(schemas: &mut Schemas) {
    let name = T::name();
    if schemas.iter().any(|(present, _)| *present == name) {
        return;
    }
    schemas.push((name.into_owned(), T::schema()));
    T::schemas(schemas);
}

fn schema_ref<T: ToSchema>() -> Ref {
    Ref::from_schema_name(T::name().into_owned())
}

fn string(description: &str) -> ObjectBuilder {
    ObjectBuilder::new()
        .schema_type(Type::String)
        .description(Some(description))
}

fn did(description: &str) -> ObjectBuilder {
    string(description).pattern(Some(DID_PATTERN))
}

fn uri(description: &str) -> ObjectBuilder {
    string(description).format(Some(SchemaFormat::Custom("uri".to_owned())))
}

/// An object with any properties.
fn any_object(description: &str) -> ObjectBuilder {
    ObjectBuilder::new()
        .description(Some(description))
        .additional_properties(Some(AdditionalProperties::FreeForm(true)))
}

fn array(items: impl Into<RefOr<Schema>>, description: &str) -> ArrayBuilder {
    ArrayBuilder::new()
        .items(ArrayItems::RefOrSchema(Box::new(items.into())))
        .description(Some(description))
}

fn one_of<const N: usize>(items: [RefOr<Schema>; N], description: &str) -> OneOfBuilder {
    items
        .into_iter()
        .fold(OneOfBuilder::new(), OneOfBuilder::item)
        .description(Some(description))
}

/// A string, or a non-empty array of strings.
fn string_or_strings(item: &str, description: &str) -> OneOfBuilder {
    one_of(
        [
            string(item).into(),
            array(string(item), "")
                .min_items(Some(1))
                .description(None::<String>)
                .into(),
        ],
        description,
    )
}

// ---------------------------------------------------------------------------------------------
// DID documents
// ---------------------------------------------------------------------------------------------

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl PartialSchema for DidDocument {
    fn schema() -> RefOr<Schema> {
        let relationship = |name: &str, section: &str| {
            array(
                schema_ref::<MethodRef>(),
                &format!("The `{name}` relationship (DID Core §{section})."),
            )
        };
        ObjectBuilder::new()
            .description(Some(
                "A DID document (DID Core §4): the core properties, plus any extension \
                 property.",
            ))
            .property(
                "@context",
                one_of(
                    [
                        uri("A context URI.").into(),
                        array(
                            ObjectBuilder::new().schema_type(SchemaType::AnyValue),
                            "Context URIs and objects.",
                        )
                        .min_items(Some(1))
                        .into(),
                        any_object("A context object.").into(),
                    ],
                    "The JSON-LD context, carried as data (DID Core §6.3.1).",
                ),
            )
            .property("id", did("The DID of the subject (DID Core §5.1.1)."))
            .required("id")
            .property(
                "alsoKnownAs",
                array(
                    uri("A URI."),
                    "Other identifiers of the subject (DID Core §5.1.3).",
                ),
            )
            .property(
                "controller",
                one_of(
                    [
                        did("The DID of the controller.").into(),
                        array(did("The DID of a controller."), "")
                            .description(None::<String>)
                            .into(),
                    ],
                    "The DIDs whose controllers may change this document (DID Core §5.1.2); \
                     an empty set means none.",
                ),
            )
            .property(
                "verificationMethod",
                array(
                    schema_ref::<VerificationMethod>(),
                    "Verification methods the relationships may reference (DID Core §5.2).",
                ),
            )
            .property("authentication", relationship("authentication", "5.3.1"))
            .property("assertionMethod", relationship("assertionMethod", "5.3.2"))
            .property("keyAgreement", relationship("keyAgreement", "5.3.3"))
            .property(
                "capabilityInvocation",
                relationship("capabilityInvocation", "5.3.4"),
            )
            .property(
                "capabilityDelegation",
                relationship("capabilityDelegation", "5.3.5"),
            )
            .property(
                "service",
                array(
                    schema_ref::<Service>(),
                    "Ways of interacting with the subject (DID Core §5.4).",
                ),
            )
            .additional_properties(Some(AdditionalProperties::FreeForm(true)))
            .into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl ToSchema for DidDocument {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("DidDocument")
    }

    fn schemas(schemas: &mut Schemas) {
        collect::<VerificationMethod>(schemas);
        collect::<MethodRef>(schemas);
        collect::<Service>(schemas);
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl PartialSchema for VerificationMethod {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .description(Some(
                "A verification method (DID Core §5.2): a public key, carried as a JWK or a \
                 multibase string, with its type and controller.",
            ))
            .property(
                "id",
                string("The DID URL of the method, usually the document's DID with a fragment."),
            )
            .required("id")
            .property(
                "type",
                string(
                    "The verification method type, such as `JsonWebKey2020`, `JsonWebKey` or \
                     `Multikey`.",
                ),
            )
            .required("type")
            .property("controller", did("The DID of the controller of the key."))
            .required("controller")
            .property(
                "publicKeyJwk",
                RefBuilder::new()
                    .ref_location_from_schema_name(Jwk::name().into_owned())
                    .description(Some("The public key as a JWK (DID Core §5.2.1)."))
                    .build(),
            )
            .property(
                "publicKeyMultibase",
                string("The public key as a multibase string (DID Core §5.2.1)."),
            )
            .additional_properties(Some(AdditionalProperties::FreeForm(true)))
            .into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl ToSchema for VerificationMethod {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("VerificationMethod")
    }

    fn schemas(schemas: &mut Schemas) {
        collect::<Jwk>(schemas);
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl PartialSchema for MethodRef {
    fn schema() -> RefOr<Schema> {
        one_of(
            [
                string("A DID URL, possibly relative, of a method under `verificationMethod`.")
                    .into(),
                schema_ref::<VerificationMethod>().into(),
            ],
            "An entry of a verification relationship (DID Core §5.3): a reference to a \
             verification method, or a method embedded in the relationship.",
        )
        .into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl ToSchema for MethodRef {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("MethodRef")
    }

    fn schemas(schemas: &mut Schemas) {
        collect::<VerificationMethod>(schemas);
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl PartialSchema for Service {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .description(Some(
                "A service (DID Core §5.4): a way of interacting with the DID subject.",
            ))
            .property(
                "id",
                string("The DID URL of the service, usually the document's DID with a fragment."),
            )
            .required("id")
            .property(
                "type",
                string_or_strings("A service type.", "The service type or types."),
            )
            .required("type")
            .property(
                "serviceEndpoint",
                one_of(
                    [
                        uri("The endpoint URI.").into(),
                        array(uri("An endpoint URI."), "")
                            .min_items(Some(1))
                            .description(None::<String>)
                            .into(),
                        any_object("An endpoint map.").into(),
                    ],
                    "Where the service is: a URI, a set of URIs, or a map.",
                ),
            )
            .required("serviceEndpoint")
            .additional_properties(Some(AdditionalProperties::FreeForm(true)))
            .into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl ToSchema for Service {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("Service")
    }
}

// ---------------------------------------------------------------------------------------------
// JOSE
// ---------------------------------------------------------------------------------------------

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl PartialSchema for Jwk {
    fn schema() -> RefOr<Schema> {
        let base64url = |description: &str| string(description);
        ObjectBuilder::new()
            .description(Some(
                "A JSON Web Key (RFC 7517 §4): the key type, the parameters of RFC 7518 §6 and \
                 RFC 8037 §2 for that type, and the common members. Parameters are \
                 base64url-encoded without padding.",
            ))
            .property(
                "kty",
                string("The key type (RFC 7517 §4.1): `EC`, `OKP`, `RSA` or `oct`."),
            )
            .required("kty")
            .property(
                "crv",
                string("The curve of an `EC` or `OKP` key: `P-256`, `secp256k1`, `Ed25519`, ..."),
            )
            .property("x", base64url("The x coordinate of an `EC` key, or the `OKP` public key."))
            .property("y", base64url("The y coordinate of an `EC` key."))
            .property("n", base64url("The modulus of an `RSA` key."))
            .property("e", base64url("The public exponent of an `RSA` key."))
            .property(
                "d",
                base64url("The private key of an `EC` or `OKP` key, or the private exponent of an `RSA` key."),
            )
            .property("p", base64url("The first prime factor of an `RSA` private key."))
            .property("q", base64url("The second prime factor of an `RSA` private key."))
            .property("dp", base64url("The first factor CRT exponent of an `RSA` private key."))
            .property("dq", base64url("The second factor CRT exponent of an `RSA` private key."))
            .property("qi", base64url("The first CRT coefficient of an `RSA` private key."))
            .property(
                "oth",
                array(
                    ObjectBuilder::new()
                        .property("r", base64url("The prime factor."))
                        .required("r")
                        .property("d", base64url("The factor CRT exponent."))
                        .required("d")
                        .property("t", base64url("The factor CRT coefficient."))
                        .required("t"),
                    "Other primes of an `RSA` private key (RFC 7518 §6.3.2.7).",
                ),
            )
            .property("k", base64url("The value of an `oct` key."))
            .property(
                "use",
                string("The intended use of the key (RFC 7517 §4.2): `sig` or `enc`."),
            )
            .property(
                "key_ops",
                array(
                    string("An operation, such as `sign` or `verify`."),
                    "The operations the key is intended for (RFC 7517 §4.3).",
                ),
            )
            .property(
                "alg",
                string("The algorithm intended for use with the key (RFC 7517 §4.4)."),
            )
            .property("kid", string("The key id (RFC 7517 §4.5)."))
            .additional_properties(Some(AdditionalProperties::FreeForm(true)))
            .into()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "utoipa")))]
impl ToSchema for Jwk {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("Jwk")
    }
}

// ---------------------------------------------------------------------------------------------
// DIF Well Known DID Configuration
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "domain-linkage")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "domain-linkage"))))]
impl PartialSchema for crate::domain_linkage::DomainLinkageConfiguration {
    fn schema() -> RefOr<Schema> {
        ObjectBuilder::new()
            .description(Some(
                "A DID configuration resource (Well Known DID Configuration §3.1): the context \
                 and the domain linkage credentials, one per linked DID.",
            ))
            .property(
                "@context",
                string("The DID configuration context.")
                    .enum_values(Some([crate::domain_linkage::CONTEXT])),
            )
            .required("@context")
            .property(
                "linked_dids",
                array(
                    one_of(
                        [
                            string(
                                "A domain linkage credential in the JSON Web Token proof \
                                 format: a compact JWS.",
                            )
                            .into(),
                            any_object(
                                "A domain linkage credential in the Linked Data Proof format.",
                            )
                            .into(),
                        ],
                        "A domain linkage credential.",
                    ),
                    "The domain linkage credentials.",
                ),
            )
            .required("linked_dids")
            .additional_properties(Some(AdditionalProperties::FreeForm(false)))
            .into()
    }
}

#[cfg(feature = "domain-linkage")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "domain-linkage"))))]
impl ToSchema for crate::domain_linkage::DomainLinkageConfiguration {
    fn name() -> Cow<'static, str> {
        Cow::Borrowed("DomainLinkageConfiguration")
    }
}

// ---------------------------------------------------------------------------------------------
// Claim paths
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "vc")]
mod claim_path {
    use super::*;
    use crate::vc::ClaimPath;

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "vc"))))]
    impl PartialSchema for ClaimPath {
        fn schema() -> RefOr<Schema> {
            array(
                one_of(
                    [
                        string("An object key.").into(),
                        ObjectBuilder::new()
                            .schema_type(Type::Integer)
                            .minimum(Some(0))
                            .description(Some("An array index."))
                            .into(),
                        ObjectBuilder::new()
                            .schema_type(Type::Null)
                            .description(Some("Every element of an array."))
                            .into(),
                    ],
                    "A path component.",
                ),
                "A claim path (SD-JWT VC §5.6.1), the claims path pointer of OID4VP §7: where a \
                 claim sits in a JSON credential.",
            )
            .min_items(Some(1))
            .into()
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "vc"))))]
    impl ToSchema for ClaimPath {
        fn name() -> Cow<'static, str> {
            Cow::Borrowed("ClaimPath")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SD-JWT VC type metadata
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "sd-jwt")]
mod type_metadata {
    use super::*;
    use crate::sd_jwt_vc::{ClaimDisplay, ClaimMetadata, DisplayMetadata, TypeMetadata};
    use crate::vc::ClaimPath;

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl PartialSchema for TypeMetadata {
        fn schema() -> RefOr<Schema> {
            ObjectBuilder::new()
                .description(Some(
                    "SD-JWT VC type metadata (SD-JWT VC §5): what a `vct` means, how to \
                     display it, and which claims it carries.",
                ))
                .property(
                    "vct",
                    string("The type described: a case-sensitive collision-resistant name."),
                )
                .required("vct")
                .property("name", string("A name for developers."))
                .property("description", string("A description for developers."))
                .property("extends", uri("The type this one extends."))
                .property(
                    "extends#integrity",
                    string(
                        "The integrity metadata of the extended type's document (SD-JWT VC §6).",
                    ),
                )
                .property(
                    "display",
                    array(
                        schema_ref::<DisplayMetadata>(),
                        "Display information per locale (SD-JWT VC §5.5).",
                    ),
                )
                .property(
                    "claims",
                    array(
                        schema_ref::<ClaimMetadata>(),
                        "Claim metadata (SD-JWT VC §5.6).",
                    ),
                )
                .additional_properties(Some(AdditionalProperties::FreeForm(true)))
                .into()
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl ToSchema for TypeMetadata {
        fn name() -> Cow<'static, str> {
            Cow::Borrowed("TypeMetadata")
        }

        fn schemas(schemas: &mut Schemas) {
            collect::<DisplayMetadata>(schemas);
            collect::<ClaimMetadata>(schemas);
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl PartialSchema for DisplayMetadata {
        fn schema() -> RefOr<Schema> {
            ObjectBuilder::new()
                .description(Some(
                    "Display information for a type in one locale (SD-JWT VC §5.5).",
                ))
                .property("locale", string("The language tag (RFC 5646)."))
                .required("locale")
                .property("name", string("The name of the type for end users."))
                .required("name")
                .property("description", string("A description for end users."))
                .property(
                    "rendering",
                    any_object("Rendering information: `simple`, `svg_templates`."),
                )
                .additional_properties(Some(AdditionalProperties::FreeForm(true)))
                .into()
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl ToSchema for DisplayMetadata {
        fn name() -> Cow<'static, str> {
            Cow::Borrowed("DisplayMetadata")
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl PartialSchema for ClaimMetadata {
        fn schema() -> RefOr<Schema> {
            ObjectBuilder::new()
                .description(Some(
                    "Metadata for the claim or claims at a path (SD-JWT VC §5.6).",
                ))
                .property(
                    "path",
                    RefBuilder::new()
                        .ref_location_from_schema_name(ClaimPath::name())
                        .description(Some("The claim path (SD-JWT VC §5.6.1).")),
                )
                .required("path")
                .property(
                    "display",
                    array(
                        schema_ref::<ClaimDisplay>(),
                        "Display information per locale (SD-JWT VC §5.6.2).",
                    ),
                )
                .property(
                    "mandatory",
                    ObjectBuilder::new()
                        .schema_type(Type::Boolean)
                        .description(Some(
                            "Whether the issuer must include the claim; default false.",
                        )),
                )
                .property(
                    "sd",
                    string(
                        "Whether the claim is selectively disclosable (SD-JWT VC §5.6.4); \
                         default `allowed`.",
                    )
                    .enum_values(Some(["always", "allowed", "never"])),
                )
                .property("svg_id", string("The id of the claim in SVG templates."))
                .additional_properties(Some(AdditionalProperties::FreeForm(true)))
                .into()
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl ToSchema for ClaimMetadata {
        fn name() -> Cow<'static, str> {
            Cow::Borrowed("ClaimMetadata")
        }

        fn schemas(schemas: &mut Schemas) {
            collect::<ClaimDisplay>(schemas);
            collect::<ClaimPath>(schemas);
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl PartialSchema for ClaimDisplay {
        fn schema() -> RefOr<Schema> {
            ObjectBuilder::new()
                .description(Some(
                    "Display information for a claim in one locale (SD-JWT VC §5.6.2).",
                ))
                .property("locale", string("The language tag (RFC 5646)."))
                .required("locale")
                .property("label", string("The label of the claim for end users."))
                .required("label")
                .property("description", string("A description for end users."))
                .additional_properties(Some(AdditionalProperties::FreeForm(true)))
                .into()
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl ToSchema for ClaimDisplay {
        fn name() -> Cow<'static, str> {
            Cow::Borrowed("ClaimDisplay")
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Token Status List
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "sd-jwt")]
mod status {
    use super::*;
    use crate::sd_jwt_vc::StatusType;

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl PartialSchema for StatusType {
        fn schema() -> RefOr<Schema> {
            one_of(
                [
                    string("A status type with a registered name of its own.")
                        .enum_values(Some(["VALID", "INVALID", "SUSPENDED"]))
                        .into(),
                    ObjectBuilder::new()
                        .schema_type(Type::Integer)
                        .minimum(Some(0))
                        .maximum(Some(255))
                        .description(Some("Any other status type value."))
                        .into(),
                ],
                "A status type (Token Status List §7): its registered name, or its value.",
            )
            .into()
        }
    }

    #[cfg_attr(docsrs, doc(cfg(all(feature = "utoipa", feature = "sd-jwt"))))]
    impl ToSchema for StatusType {
        fn name() -> Cow<'static, str> {
            Cow::Borrowed("StatusType")
        }
    }
}
