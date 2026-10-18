//! SD-JWT VC type metadata (§5) and the integrity metadata of referenced documents (§6).

use core::fmt;
use core::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;

use super::sd_jwt::ELLIPSIS_KEY;
use super::{ClaimPath, ClaimPathError, PathComponent, Processed};

/// Whether a claim is selectively disclosable (`sd` of claim metadata, §5.6.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum SdPolicy {
    /// The issuer must make the claim selectively disclosable.
    Always,
    /// The issuer may; the default.
    #[default]
    Allowed,
    /// The issuer must not.
    Never,
}

impl fmt::Display for SdPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Always => "always",
            Self::Allowed => "allowed",
            Self::Never => "never",
        })
    }
}

/// Display information for a type, per locale (§5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DisplayMetadata {
    /// The language tag.
    pub locale: String,
    /// The name of the type for end users.
    pub name: String,
    /// A description for end users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Rendering information (`simple`, `svg_templates`), carried as data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendering: Option<Value>,
    /// Every other property.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl DisplayMetadata {
    /// Display information in `locale` naming the type `name`.
    pub fn new(locale: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            locale: locale.into(),
            name: name.into(),
            description: None,
            rendering: None,
            additional: IndexMap::new(),
        }
    }
}

/// Display information for a claim, per locale (§5.6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClaimDisplay {
    /// The language tag.
    pub locale: String,
    /// The label of the claim for end users.
    pub label: String,
    /// A description for end users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Every other property.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl ClaimDisplay {
    /// A label in `locale`.
    pub fn new(locale: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            locale: locale.into(),
            label: label.into(),
            description: None,
            additional: IndexMap::new(),
        }
    }
}

/// Metadata for the claim or claims at a path (§5.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClaimMetadata {
    /// Which claim(s) this describes.
    pub path: ClaimPath,
    /// Display information per locale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<ClaimDisplay>,
    /// Whether the issuer must include the claim; `None` is omitted, which means `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
    /// Whether the claim is selectively disclosable; `None` is omitted, which means
    /// [`SdPolicy::Allowed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd: Option<SdPolicy>,
    /// The id of the claim in SVG templates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub svg_id: Option<String>,
    /// Every other property.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl ClaimMetadata {
    /// Metadata for the claim at `path`.
    pub fn new(path: impl Into<ClaimPath>) -> Self {
        Self {
            path: path.into(),
            display: Vec::new(),
            mandatory: None,
            sd: None,
            svg_id: None,
            additional: IndexMap::new(),
        }
    }

    /// This metadata with `display` added.
    #[must_use]
    pub fn with_display(mut self, display: ClaimDisplay) -> Self {
        self.display.push(display);
        self
    }

    /// This metadata with `mandatory`.
    #[must_use]
    pub fn with_mandatory(mut self, mandatory: bool) -> Self {
        self.mandatory = Some(mandatory);
        self
    }

    /// This metadata with `sd`.
    #[must_use]
    pub fn with_sd(mut self, sd: SdPolicy) -> Self {
        self.sd = Some(sd);
        self
    }

    /// This metadata with `svg_id`.
    #[must_use]
    pub fn with_svg_id(mut self, svg_id: impl Into<String>) -> Self {
        self.svg_id = Some(svg_id.into());
        self
    }

    /// Whether the claim is mandatory: `mandatory`, `false` when omitted.
    pub fn is_mandatory(&self) -> bool {
        self.mandatory.unwrap_or(false)
    }

    /// The selective disclosure policy: `sd`, [`SdPolicy::Allowed`] when omitted.
    pub fn sd_policy(&self) -> SdPolicy {
        self.sd.unwrap_or_default()
    }

    /// Checks the structure: a non-empty path, a well-formed `svg_id` not used with a `null`
    /// path component.
    ///
    /// # Errors
    ///
    /// [`TypeMetadataError::InvalidClaimMetadata`].
    pub fn check(&self) -> Result<(), TypeMetadataError> {
        let invalid = |reason: &str| TypeMetadataError::InvalidClaimMetadata {
            path: self.path.clone(),
            reason: reason.to_owned(),
        };
        if self.path.is_empty() {
            return Err(invalid("the path is empty"));
        }
        if let Some(svg_id) = &self.svg_id {
            let well_formed = svg_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !svg_id.is_empty()
                && !svg_id.starts_with(|c: char| c.is_ascii_digit());
            if !well_formed {
                return Err(invalid(
                    "`svg_id` must be alphanumeric or `_` and not start with a digit",
                ));
            }
            if !self.path.is_concrete() {
                return Err(invalid(
                    "`svg_id` cannot be used with a `null` path component",
                ));
            }
        }
        Ok(())
    }
}

/// Why type metadata could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypeMetadataError {
    /// The document is not JSON of the expected shape.
    #[error("invalid type metadata: {0}")]
    Json(String),
    /// A claim metadata object breaks a structural rule.
    #[error("claim metadata {path}: {reason}")]
    InvalidClaimMetadata {
        /// The claim.
        path: ClaimPath,
        /// What is wrong.
        reason: String,
    },
    /// An `svg_id` is used twice.
    #[error("`svg_id` {0:?} is used more than once")]
    DuplicateSvgId(String),
    /// The document extends a type other than the one given as its parent.
    #[error("type {vct:?} extends {extends:?}, not {parent:?}")]
    WrongParent {
        /// The extending type.
        vct: String,
        /// Its `extends`.
        extends: Option<String>,
        /// The `vct` of the document given as its parent.
        parent: String,
    },
    /// An extending type changes a claim's `sd` from `always` or `never`, or its `mandatory`
    /// from `true`.
    #[error(
        "claim metadata {path}: an extending type cannot change {property} from {parent} to {child}"
    )]
    IllegalOverride {
        /// The claim.
        path: ClaimPath,
        /// `sd` or `mandatory`.
        property: &'static str,
        /// The extended type's value.
        parent: String,
        /// The extending type's value.
        child: String,
    },
    /// A claim path does not fit the payload.
    #[error(transparent)]
    Path(#[from] ClaimPathError),
    /// A mandatory claim is missing from a complete credential.
    #[error("mandatory claim {0} is missing")]
    MissingMandatoryClaim(ClaimPath),
    /// A claim is not selectively disclosable as its `sd` requires.
    #[error("claim {path}: `sd` is {policy}, but the claim is{} selectively disclosable", if *disclosable { "" } else { " not" })]
    SdViolation {
        /// The claim.
        path: ClaimPath,
        /// The required policy.
        policy: SdPolicy,
        /// Whether the claim is selectively disclosable.
        disclosable: bool,
    },
}

/// A type metadata document (§5.2).
///
/// # Examples
///
/// SD-JWT VC §5.6.5.2: a type extending another, and the effective claim metadata.
///
/// ```
/// use identity_kit::sd_jwt_vc::{ClaimPath, TypeMetadata};
/// use serde_json::json;
///
/// let base: TypeMetadata = serde_json::from_value(json!({
///   "vct": "https://example.com/base-type-metadata",
///   "claims": [
///     { "path": ["name"], "display": [{"label": "Full Name", "locale": "en"}] },
///     { "path": ["address", "city"], "display": [{"label": "City", "locale": "en"}] }
///   ]
/// }))?;
/// let child: TypeMetadata = serde_json::from_value(json!({
///   "vct": "https://example.com/custom-type-metadata",
///   "extends": "https://example.com/base-type-metadata",
///   "claims": [
///     { "path": ["address", "city"], "display": [{"label": "Town", "locale": "en"}] },
///     { "path": ["nationalities"], "display": [{"label": "Nationalities", "locale": "en"}] }
///   ]
/// }))?;
/// let effective = child.extend(&base)?;
/// let labels: Vec<_> = effective.claims.iter().map(|c| c.display[0].label.as_str()).collect();
/// assert_eq!(labels, ["Full Name", "Town", "Nationalities"]);
/// assert_eq!(effective.claims[1].path, ClaimPath::new(["address", "city"]));
/// assert_eq!(effective.extends, None);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TypeMetadata {
    /// The type described.
    pub vct: String,
    /// A name for developers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A description for developers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The type this one extends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    /// The integrity metadata of the extended type's document.
    #[serde(
        rename = "extends#integrity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub extends_integrity: Option<String>,
    /// Display information per locale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<DisplayMetadata>,
    /// Claim metadata.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimMetadata>,
    /// Every other property.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl TypeMetadata {
    /// Metadata for the type `vct`.
    pub fn new(vct: impl Into<String>) -> Self {
        Self {
            vct: vct.into(),
            name: None,
            description: None,
            extends: None,
            extends_integrity: None,
            display: Vec::new(),
            claims: Vec::new(),
            additional: IndexMap::new(),
        }
    }

    /// Parses a type metadata document and checks its structure.
    ///
    /// # Errors
    ///
    /// [`TypeMetadataError::Json`], or the errors of [`check`](Self::check).
    pub fn parse(document: &[u8]) -> Result<Self, TypeMetadataError> {
        let metadata: Self =
            serde_json::from_slice(document).map_err(|e| TypeMetadataError::Json(e.to_string()))?;
        metadata.check()?;
        Ok(metadata)
    }

    /// This metadata with `name`.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// This metadata with `description`.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// This metadata extending `vct`, with the integrity metadata of its document if known.
    #[must_use]
    pub fn with_extends(mut self, vct: impl Into<String>, integrity: Option<String>) -> Self {
        self.extends = Some(vct.into());
        self.extends_integrity = integrity;
        self
    }

    /// This metadata with `display` added.
    #[must_use]
    pub fn with_display(mut self, display: DisplayMetadata) -> Self {
        self.display.push(display);
        self
    }

    /// This metadata with `claim` added.
    #[must_use]
    pub fn with_claim(mut self, claim: ClaimMetadata) -> Self {
        self.claims.push(claim);
        self
    }

    /// Checks the claim metadata: each well-formed, `svg_id`s unique.
    ///
    /// # Errors
    ///
    /// [`TypeMetadataError::InvalidClaimMetadata`] or [`TypeMetadataError::DuplicateSvgId`].
    pub fn check(&self) -> Result<(), TypeMetadataError> {
        let mut svg_ids = std::collections::HashSet::new();
        for claim in &self.claims {
            claim.check()?;
            if let Some(svg_id) = &claim.svg_id {
                if !svg_ids.insert(svg_id) {
                    return Err(TypeMetadataError::DuplicateSvgId(svg_id.clone()));
                }
            }
        }
        Ok(())
    }

    /// The claim metadata for `path`, if any.
    pub fn claim(&self, path: &ClaimPath) -> Option<&ClaimMetadata> {
        self.claims.iter().find(|claim| claim.path == *path)
    }

    /// The effective metadata of this type given the metadata of the type it extends (§5.4):
    /// the parent's display information unless this type has its own (§5.5.2), the parent's
    /// claim metadata with this type's properties taking precedence per path (§5.6.5), and
    /// the parent's `extends` so that a chain can be folded parent by parent.
    ///
    /// # Errors
    ///
    /// [`TypeMetadataError::WrongParent`] when `parent` is not the type this one extends,
    /// [`TypeMetadataError::IllegalOverride`] when this type changes a claim's `sd` from
    /// `always` or `never` or its `mandatory` from `true`.
    pub fn extend(self, parent: &TypeMetadata) -> Result<Self, TypeMetadataError> {
        if self.extends.as_deref() != Some(parent.vct.as_str()) {
            return Err(TypeMetadataError::WrongParent {
                vct: self.vct,
                extends: self.extends,
                parent: parent.vct.clone(),
            });
        }
        let mut claims = Vec::with_capacity(parent.claims.len() + self.claims.len());
        let mut overridden = vec![false; self.claims.len()];
        for inherited in &parent.claims {
            let child = self
                .claims
                .iter()
                .position(|claim| claim.path == inherited.path);
            match child {
                Some(i) => {
                    overridden[i] = true;
                    claims.push(merge_claim(inherited, &self.claims[i])?);
                }
                None => claims.push(inherited.clone()),
            }
        }
        claims.extend(
            self.claims
                .iter()
                .zip(&overridden)
                .filter(|(_, overridden)| !**overridden)
                .map(|(claim, _)| claim.clone()),
        );
        let display = if self.display.is_empty() {
            parent.display.clone()
        } else {
            self.display
        };
        Ok(Self {
            vct: self.vct,
            name: self.name,
            description: self.description,
            extends: parent.extends.clone(),
            extends_integrity: parent.extends_integrity.clone(),
            display,
            claims,
            additional: self.additional,
        })
    }

    /// Validates `processed` against the claim metadata (§5.6): every path must fit the
    /// payload, a claim with `sd: always` must have come from a disclosure, one with
    /// `sd: never` must not have, and, when `complete` says every disclosure is at hand (the
    /// holder's view), every mandatory claim must be present, unless its path runs through an
    /// undisclosed array element, whose contents are unknown.
    ///
    /// Paths are evaluated against the payload as issued, so an undisclosed array element
    /// counts as present and selectively disclosable, with nothing beneath it.
    ///
    /// # Errors
    ///
    /// [`TypeMetadataError::Path`], [`TypeMetadataError::SdViolation`] or
    /// [`TypeMetadataError::MissingMandatoryClaim`].
    pub fn check_claims(
        &self,
        processed: &Processed,
        complete: bool,
    ) -> Result<(), TypeMetadataError> {
        let issued = Value::Object(processed.as_issued().clone());
        for claim in &self.claims {
            let (selected, truncated) = resolve_issued(&claim.path, &issued)?;
            if complete && claim.is_mandatory() && selected.is_empty() && !truncated {
                return Err(TypeMetadataError::MissingMandatoryClaim(claim.path.clone()));
            }
            let policy = claim.sd_policy();
            for (path, placeholder) in selected {
                let disclosable = placeholder || processed.is_disclosed(&path);
                let violated = match policy {
                    SdPolicy::Always => !disclosable,
                    SdPolicy::Never => disclosable,
                    SdPolicy::Allowed => false,
                };
                if violated {
                    return Err(TypeMetadataError::SdViolation {
                        path,
                        policy,
                        disclosable,
                    });
                }
            }
        }
        Ok(())
    }
}

/// The parent's claim metadata overridden by the child's (§5.6.5).
fn merge_claim(
    parent: &ClaimMetadata,
    child: &ClaimMetadata,
) -> Result<ClaimMetadata, TypeMetadataError> {
    let sd = match (parent.sd, child.sd) {
        (Some(fixed @ (SdPolicy::Always | SdPolicy::Never)), Some(other)) if other != fixed => {
            return Err(TypeMetadataError::IllegalOverride {
                path: child.path.clone(),
                property: "sd",
                parent: fixed.to_string(),
                child: other.to_string(),
            });
        }
        (parent, child) => child.or(parent),
    };
    let mandatory = match (parent.mandatory, child.mandatory) {
        (Some(true), Some(false)) => {
            return Err(TypeMetadataError::IllegalOverride {
                path: child.path.clone(),
                property: "mandatory",
                parent: "true".into(),
                child: "false".into(),
            });
        }
        (parent, child) => child.or(parent),
    };
    let mut additional = parent.additional.clone();
    additional.extend(child.additional.clone());
    Ok(ClaimMetadata {
        path: child.path.clone(),
        display: if child.display.is_empty() {
            parent.display.clone()
        } else {
            child.display.clone()
        },
        mandatory,
        sd,
        svg_id: child.svg_id.clone().or_else(|| parent.svg_id.clone()),
        additional,
    })
}

/// Whether `value` is the placeholder of an undisclosed array element.
fn is_placeholder(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == 1 && object.get(ELLIPSIS_KEY).is_some_and(Value::is_string)
    })
}

/// [`ClaimPath::resolve`] over a payload as issued: a placeholder is selected as a leaf
/// (flagged `true`) and nothing is selected beneath it; the second result says whether the
/// path went through a placeholder, whose contents are unknown.
fn resolve_issued(
    path: &ClaimPath,
    root: &Value,
) -> Result<(Vec<(ClaimPath, bool)>, bool), ClaimPathError> {
    let mut selected = vec![(ClaimPath::root(), root)];
    let mut truncated = false;
    for (depth, component) in path.components().iter().enumerate() {
        let mut next = Vec::new();
        for (current, value) in selected {
            if is_placeholder(value) {
                truncated = true;
                continue;
            }
            match (component, value) {
                (PathComponent::Key(key), Value::Object(object)) => {
                    if let Some(value) = object.get(key) {
                        next.push((current.join(key.as_str()), value));
                    }
                }
                (PathComponent::Index(index), Value::Array(array)) => {
                    if let Some(value) = array.get(*index) {
                        next.push((current.join(*index), value));
                    }
                }
                (PathComponent::All, Value::Array(array)) => {
                    next.extend(
                        array
                            .iter()
                            .enumerate()
                            .map(|(index, value)| (current.join(index), value)),
                    );
                }
                (PathComponent::Key(_), _) => {
                    return Err(ClaimPathError {
                        path: path.clone(),
                        depth,
                        expected: "an object",
                    });
                }
                _ => {
                    return Err(ClaimPathError {
                        path: path.clone(),
                        depth,
                        expected: "an array",
                    });
                }
            }
        }
        selected = next;
    }
    let selected = selected
        .into_iter()
        .map(|(path, value)| (path, is_placeholder(value)))
        .collect();
    Ok((selected, truncated))
}

/// A hash algorithm of integrity metadata (W3C SRI §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum IntegrityAlgorithm {
    /// `sha256`.
    Sha256,
    /// `sha384`.
    Sha384,
    /// `sha512`.
    Sha512,
}

impl IntegrityAlgorithm {
    /// The prefix of the algorithm in integrity metadata.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// The algorithm with `prefix`, if this crate supports it.
    fn parse(prefix: &str) -> Option<Self> {
        match prefix {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Why a document does not match its integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntegrityError {
    /// The metadata has no hash expression this crate supports.
    #[error("integrity metadata {0:?} uses no supported hash algorithm")]
    NoSupportedAlgorithm(String),
    /// The document's digest matches none of the expressions of the strongest algorithm.
    #[error("the document does not match its {} integrity metadata", algorithm.prefix())]
    Mismatch {
        /// The algorithm compared under.
        algorithm: IntegrityAlgorithm,
    },
}

/// Integrity metadata (SD-JWT VC §6, W3C SRI §3): one or more `<algorithm>-<base64 digest>`
/// expressions separated by whitespace, verified against the octets of the retrieved
/// document with the strongest algorithm this crate supports.
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::{Integrity, IntegrityAlgorithm};
///
/// let document = br#"{"vct":"https://example.com/base-type-metadata"}"#;
/// let integrity = Integrity::compute(IntegrityAlgorithm::Sha256, document);
/// assert!(integrity.as_str().starts_with("sha256-"));
/// assert!(integrity.verify(document).is_ok());
/// assert!(integrity.verify(b"{}").is_err());
///
/// // SD-JWT VC §5.1, Figure 17.
/// let integrity: Integrity = "sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=".parse()?;
/// assert_eq!(integrity.algorithms(), vec![IntegrityAlgorithm::Sha256]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    metadata: String,
    expressions: Vec<(IntegrityAlgorithm, Vec<u8>)>,
}

impl Integrity {
    /// Parses `metadata`, keeping the expressions of the algorithms this crate supports.
    pub fn parse(metadata: &str) -> Self {
        let expressions = metadata
            .split_ascii_whitespace()
            .filter_map(|expression| {
                let (prefix, rest) = expression.split_once('-')?;
                let digest = rest.split('?').next()?;
                let algorithm = IntegrityAlgorithm::parse(prefix)?;
                let digest = STANDARD.decode(digest).ok()?;
                Some((algorithm, digest))
            })
            .collect();
        Self {
            metadata: metadata.to_owned(),
            expressions,
        }
    }

    /// The integrity metadata of `document` under `algorithm`.
    pub fn compute(algorithm: IntegrityAlgorithm, document: &[u8]) -> Self {
        let digest = algorithm.digest(document);
        Self {
            metadata: format!("{}-{}", algorithm.prefix(), STANDARD.encode(&digest)),
            expressions: vec![(algorithm, digest)],
        }
    }

    /// The metadata string.
    pub fn as_str(&self) -> &str {
        &self.metadata
    }

    /// The supported algorithms the metadata uses, strongest last.
    pub fn algorithms(&self) -> Vec<IntegrityAlgorithm> {
        let mut algorithms: Vec<_> = self.expressions.iter().map(|(a, _)| *a).collect();
        algorithms.sort_unstable();
        algorithms.dedup();
        algorithms
    }

    /// Checks `document` against the expressions of the strongest supported algorithm.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::NoSupportedAlgorithm`] or [`IntegrityError::Mismatch`].
    pub fn verify(&self, document: &[u8]) -> Result<(), IntegrityError> {
        let algorithm = self
            .expressions
            .iter()
            .map(|(a, _)| *a)
            .max()
            .ok_or_else(|| IntegrityError::NoSupportedAlgorithm(self.metadata.clone()))?;
        let digest = algorithm.digest(document);
        let matched = self
            .expressions
            .iter()
            .any(|(a, expected)| *a == algorithm && *expected == digest);
        if matched {
            Ok(())
        } else {
            Err(IntegrityError::Mismatch { algorithm })
        }
    }
}

impl fmt::Display for Integrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.metadata)
    }
}

impl FromStr for Integrity {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}
