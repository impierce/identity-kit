//! Claim paths (SD-JWT VC §5.6.1): where a claim sits in a payload.

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One step of a [`ClaimPath`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PathComponent {
    /// The property with this name of the selected object(s).
    Key(String),
    /// The element at this index of the selected array(s).
    Index(usize),
    /// Every element of the selected array(s), `null` in JSON.
    All,
}

impl From<&str> for PathComponent {
    fn from(key: &str) -> Self {
        Self::Key(key.to_owned())
    }
}

impl From<String> for PathComponent {
    fn from(key: String) -> Self {
        Self::Key(key)
    }
}

impl From<usize> for PathComponent {
    fn from(index: usize) -> Self {
        Self::Index(index)
    }
}

impl From<()> for PathComponent {
    fn from((): ()) -> Self {
        Self::All
    }
}

impl fmt::Display for PathComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => write!(f, "{key:?}"),
            Self::Index(index) => write!(f, "{index}"),
            Self::All => f.write_str("null"),
        }
    }
}

/// A path into a JSON payload, as the `path` of SD-JWT VC claim metadata: a non-empty list of
/// property names, array indexes and `null` (every element). A path names the claim as if
/// everything were disclosed.
///
/// # Examples
///
/// ```
/// use identity_kit::sd_jwt_vc::ClaimPath;
/// use serde_json::json;
///
/// // SD-JWT VC §5.6.1.1.
/// let credential = json!({
///   "name": "Arthur Dent",
///   "address": { "street_address": "42 Market Street", "city": "Milliways" },
///   "degrees": [
///     { "type": "Bachelor of Science", "university": "University of Betelgeuse" },
///     { "type": "Master of Science", "university": "University of Betelgeuse" }
///   ],
///   "nationalities": ["British", "Betelgeusian"]
/// });
/// let path: ClaimPath = serde_json::from_value(json!(["degrees", null, "type"]))?;
/// assert_eq!(
///     path.select(&credential)?,
///     vec![&json!("Bachelor of Science"), &json!("Master of Science")]
/// );
/// let street = ClaimPath::new(["address", "street_address"]);
/// assert_eq!(street.select(&credential)?, vec![&json!("42 Market Street")]);
/// assert!(ClaimPath::new(["name", "first"]).select(&credential).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClaimPath(Vec<PathComponent>);

impl ClaimPath {
    /// The path through `components`: `&str` names, `usize` indexes and `()` for every
    /// element.
    pub fn new<I, C>(components: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<PathComponent>,
    {
        Self(components.into_iter().map(Into::into).collect())
    }

    /// The empty path: the payload itself.
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// The components.
    pub fn components(&self) -> &[PathComponent] {
        &self.0
    }

    /// Whether the path has no components.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether every component names one element: no `null`.
    pub fn is_concrete(&self) -> bool {
        !self.0.contains(&PathComponent::All)
    }

    /// Whether this path, which may contain `null` components, covers the concrete `path`.
    pub fn matches(&self, path: &ClaimPath) -> bool {
        self.0.len() == path.0.len()
            && self.0.iter().zip(&path.0).all(|(pattern, component)| {
                *pattern == PathComponent::All && matches!(component, PathComponent::Index(_))
                    || pattern == component
            })
    }

    /// Whether this path, which may contain `null` components, covers the concrete `path` or
    /// one of its ancestors.
    pub fn is_prefix_of(&self, path: &ClaimPath) -> bool {
        self.0.len() <= path.0.len()
            && self.0.iter().zip(&path.0).all(|(pattern, component)| {
                *pattern == PathComponent::All && matches!(component, PathComponent::Index(_))
                    || pattern == component
            })
    }

    /// This path with `component` appended.
    #[must_use]
    pub fn join(&self, component: impl Into<PathComponent>) -> Self {
        let mut components = self.0.clone();
        components.push(component.into());
        Self(components)
    }

    /// The values the path selects in `root`, per the processing rules of SD-JWT VC §5.6.1.2:
    /// empty when a name or an index does not exist.
    ///
    /// # Errors
    ///
    /// [`ClaimPathError`] when a component meets a value of the wrong kind: a name against a
    /// non-object, an index or `null` against a non-array.
    pub fn select<'a>(&self, root: &'a Value) -> Result<Vec<&'a Value>, ClaimPathError> {
        let mut selected = vec![root];
        for (depth, component) in self.0.iter().enumerate() {
            let mut next = Vec::new();
            for value in selected {
                match (component, value) {
                    (PathComponent::Key(key), Value::Object(object)) => {
                        next.extend(object.get(key));
                    }
                    (PathComponent::Index(index), Value::Array(array)) => {
                        next.extend(array.get(*index));
                    }
                    (PathComponent::All, Value::Array(array)) => next.extend(array),
                    (PathComponent::Key(_), _) => {
                        return Err(ClaimPathError {
                            path: self.clone(),
                            depth,
                            expected: "an object",
                        });
                    }
                    _ => {
                        return Err(ClaimPathError {
                            path: self.clone(),
                            depth,
                            expected: "an array",
                        });
                    }
                }
            }
            selected = next;
        }
        Ok(selected)
    }

    /// The concrete paths (every `null` resolved to the indexes it selects) at which the path
    /// selects a value in `root`, in document order.
    ///
    /// # Errors
    ///
    /// As [`select`](Self::select).
    pub fn resolve(&self, root: &Value) -> Result<Vec<ClaimPath>, ClaimPathError> {
        let mut selected = vec![(ClaimPath(Vec::new()), root)];
        for (depth, component) in self.0.iter().enumerate() {
            let mut next = Vec::new();
            for (path, value) in selected {
                match (component, value) {
                    (PathComponent::Key(key), Value::Object(object)) => {
                        if let Some(value) = object.get(key) {
                            next.push((path.join(key.as_str()), value));
                        }
                    }
                    (PathComponent::Index(index), Value::Array(array)) => {
                        if let Some(value) = array.get(*index) {
                            next.push((path.join(*index), value));
                        }
                    }
                    (PathComponent::All, Value::Array(array)) => {
                        next.extend(
                            array
                                .iter()
                                .enumerate()
                                .map(|(index, value)| (path.join(index), value)),
                        );
                    }
                    (PathComponent::Key(_), _) => {
                        return Err(ClaimPathError {
                            path: self.clone(),
                            depth,
                            expected: "an object",
                        });
                    }
                    _ => {
                        return Err(ClaimPathError {
                            path: self.clone(),
                            depth,
                            expected: "an array",
                        });
                    }
                }
            }
            selected = next;
        }
        Ok(selected.into_iter().map(|(path, _)| path).collect())
    }
}

impl<C: Into<PathComponent>> FromIterator<C> for ClaimPath {
    fn from_iter<I: IntoIterator<Item = C>>(iter: I) -> Self {
        Self::new(iter)
    }
}

impl<C: Into<PathComponent>, const N: usize> From<[C; N]> for ClaimPath {
    fn from(components: [C; N]) -> Self {
        Self::new(components)
    }
}

impl From<Vec<PathComponent>> for ClaimPath {
    fn from(components: Vec<PathComponent>) -> Self {
        Self(components)
    }
}

impl fmt::Display for ClaimPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, component) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{component}")?;
        }
        f.write_str("]")
    }
}

/// A [`ClaimPath`](crate::sd_jwt_vc::ClaimPath) from components of mixed kinds: string
/// literals for names, integers for indexes, `()` for every element.
///
/// # Examples
///
/// ```
/// use identity_kit::claim_path;
/// use identity_kit::sd_jwt_vc::{ClaimPath, PathComponent};
///
/// let path = claim_path!["degrees", (), "type"];
/// assert_eq!(
///     path,
///     ClaimPath::from(vec![PathComponent::from("degrees"), PathComponent::All, PathComponent::from("type")])
/// );
/// assert_eq!(claim_path!["nationalities", 1].to_string(), r#"["nationalities", 1]"#);
/// ```
#[macro_export]
macro_rules! claim_path {
    ($($component:expr),* $(,)?) => {
        $crate::sd_jwt_vc::ClaimPath::from(vec![$($crate::sd_jwt_vc::PathComponent::from($component)),*])
    };
}

/// A [`ClaimPath`] component met a value it cannot select from.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("claim path {path}: component {depth} expects {expected}")]
pub struct ClaimPathError {
    /// The path.
    pub path: ClaimPath,
    /// The position of the offending component.
    pub depth: usize,
    /// What the component needs: `an object` or `an array`.
    pub expected: &'static str,
}
