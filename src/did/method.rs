//! `DidMethod`: a DID method name with an optional namespace, such as `did:demo` or
//! `did:demo:dev`.

use core::fmt;
use core::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::DidError;
use super::syntax::{
    DEFAULT_MAX_LEN, Did, check_len, is_idchar, is_method_char, is_pct_encoded_at,
};

/// A DID method, named with an optional namespace: `did:demo` or `did:demo:dev`.
///
/// Parties that declare or negotiate support for DID methods (SIOPv2's
/// `subject_syntax_types_supported`, a wallet's configuration, a resolver's registry) exchange
/// method identifiers rather than DIDs. A `DidMethod` is such an identifier: the method name of
/// [DID Core §3.1] (`method-name = 1*method-char`, lowercase ASCII letters and digits only),
/// optionally followed by one `idchar` segment that names a namespace within the method, as
/// `dev` in `did:demo:dev` or `zXYZ` in `did:ebsi:zXYZ`. SIOPv2 lists methods without a
/// namespace; wallets and issuers that distinguish networks of one method exchange the namespaced
/// form; both parse.
///
/// A `DidMethod` is validated when it is constructed and keeps the input unchanged. It displays,
/// serializes and deserializes as `did:<name>` or `did:<name>:<namespace>`, where
/// deserialization validates. Equality is field-wise; the ordering is by name, then namespace,
/// with the bare method before its namespaced forms.
///
/// [`DidMethod::matches`] tells whether a [`Did`] belongs to the method: its method name is
/// equal and, when a namespace is set, the first colon-separated segment of its method-specific
/// id is that namespace. [`Did::method`] keeps returning the name as a `&str`;
/// `DidMethod::from(&did)` is the method of a DID, without a namespace.
///
/// # Errors
///
/// A method name that is empty or has a character outside `a-z` and `0-9` is
/// [`DidError::InvalidMethodName`], as it is for a [`Did`]. A namespace that is empty, has a
/// second segment (`did:demo:dev:x`) or a character that is not an `idchar` is
/// [`DidError::InvalidNamespace`]; an incomplete percent-encoding in it is
/// [`DidError::InvalidPercentEncoding`]. Parsing a string also reports
/// [`DidError::MissingScheme`] and [`DidError::TooLong`] as [`Did::parse`] does. Positions are
/// byte offsets into the input that was given: the string for the parsing forms, the name for
/// [`DidMethod::new`], the namespace for [`DidMethod::with_namespace`].
///
/// # Examples
///
/// ```
/// use identity_kit::did::{Did, DidError, DidMethod};
///
/// let demo: DidMethod = "did:demo".parse()?;
/// let namespaced = DidMethod::new("demo")?.with_namespace("dev")?;
/// assert_eq!(demo.name(), "demo");
/// assert_eq!(demo.namespace(), None);
/// assert_eq!(namespaced.namespace(), Some("dev"));
/// assert_eq!(namespaced.to_string(), "did:demo:dev");
///
/// let did = Did::parse("did:demo:dev:0xabc")?;
/// assert!(demo.matches(&did));
/// assert!(namespaced.matches(&did));
/// assert!(!DidMethod::parse("did:demo:alt")?.matches(&did));
/// assert_eq!(DidMethod::from(&did), demo);
///
/// // The method name is lowercase; the namespace is one non-empty segment.
/// assert_eq!(
///     DidMethod::parse("did:Example"),
///     Err(DidError::InvalidMethodName { position: 4 })
/// );
/// assert_eq!(
///     DidMethod::parse("did:demo:"),
///     Err(DidError::InvalidNamespace { position: 9 })
/// );
/// assert_eq!(
///     DidMethod::parse("did:demo:dev:x"),
///     Err(DidError::InvalidNamespace { position: 12 })
/// );
/// # Ok::<(), DidError>(())
/// ```
///
/// [DID Core §3.1]: https://www.w3.org/TR/did-core/#did-syntax
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DidMethod {
    /// The method name: `demo` in `did:demo:dev`.
    name: String,
    /// The namespace within the method: `dev` in `did:demo:dev`.
    namespace: Option<String>,
}

impl DidMethod {
    /// A method named `name`, without a namespace.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidMethodName`] when `name` is empty or has a character outside
    /// `a-z` and `0-9`, with the byte offset into `name`.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{DidError, DidMethod};
    ///
    /// assert_eq!(DidMethod::new("web")?.to_string(), "did:web");
    /// assert_eq!(
    ///     DidMethod::new("ex_ample"),
    ///     Err(DidError::InvalidMethodName { position: 2 })
    /// );
    /// # Ok::<(), DidError>(())
    /// ```
    pub fn new(name: impl Into<String>) -> Result<Self, DidError> {
        let name = name.into();
        validate_name(&name, 0)?;
        Ok(Self {
            name,
            namespace: None,
        })
    }

    /// This method with its namespace set to `namespace`.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidNamespace`] when `namespace` is empty or has a character that
    /// is not an `idchar` (a `:` among them), or [`DidError::InvalidPercentEncoding`] when a `%`
    /// is not followed by two hexadecimal digits, with the byte offset into `namespace`.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{DidError, DidMethod};
    ///
    /// let ebsi = DidMethod::new("ebsi")?;
    /// assert_eq!(ebsi.clone().with_namespace("zXYZ")?.to_string(), "did:ebsi:zXYZ");
    /// assert_eq!(
    ///     ebsi.with_namespace("a:b"),
    ///     Err(DidError::InvalidNamespace { position: 1 })
    /// );
    /// # Ok::<(), DidError>(())
    /// ```
    pub fn with_namespace(self, namespace: impl Into<String>) -> Result<Self, DidError> {
        let namespace = namespace.into();
        validate_namespace(&namespace, 0)?;
        Ok(Self {
            name: self.name,
            namespace: Some(namespace),
        })
    }

    /// Parses `did:<name>` or `did:<name>:<namespace>`, rejecting input longer than
    /// [`DEFAULT_MAX_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`DidError`] describing the first violation, as listed for [`DidMethod`].
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{DidError, DidMethod};
    ///
    /// let method = DidMethod::parse("did:ebsi:zXYZ")?;
    /// assert_eq!(method.name(), "ebsi");
    /// assert_eq!(method.namespace(), Some("zXYZ"));
    ///
    /// assert_eq!(DidMethod::parse("ebsi"), Err(DidError::MissingScheme));
    /// # Ok::<(), DidError>(())
    /// ```
    pub fn parse(s: &str) -> Result<Self, DidError> {
        check_len(s, DEFAULT_MAX_LEN)?;
        let Some(rest) = s.strip_prefix(SCHEME) else {
            return Err(DidError::MissingScheme);
        };
        let (name, namespace) = match rest.split_once(':') {
            Some((name, namespace)) => (name, Some(namespace)),
            None => (rest, None),
        };
        validate_name(name, SCHEME.len())?;
        if let Some(namespace) = namespace {
            validate_namespace(namespace, SCHEME.len() + name.len() + 1)?;
        }
        Ok(Self {
            name: name.to_owned(),
            namespace: namespace.map(str::to_owned),
        })
    }

    /// The method name: `demo` in `did:demo:dev`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The namespace within the method: `dev` in `did:demo:dev`, `None` in `did:demo`.
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Whether `did` belongs to this method: its method name is [`name`](Self::name) and, when a
    /// namespace is set, the first colon-separated segment of its method-specific id is that
    /// namespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{Did, DidMethod};
    ///
    /// let did = Did::parse("did:demo:dev:0xabc")?;
    /// assert!(DidMethod::parse("did:demo")?.matches(&did));
    /// assert!(DidMethod::parse("did:demo:dev")?.matches(&did));
    /// assert!(!DidMethod::parse("did:demo:alt")?.matches(&did));
    /// assert!(!DidMethod::parse("did:web")?.matches(&did));
    /// # Ok::<(), identity_kit::did::DidError>(())
    /// ```
    pub fn matches(&self, did: &Did) -> bool {
        if did.method() != self.name {
            return false;
        }
        match &self.namespace {
            None => true,
            Some(namespace) => {
                let id = did.method_specific_id();
                let first = id.split_once(':').map_or(id, |(first, _)| first);
                first == namespace
            }
        }
    }
}

/// The method of a DID, without a namespace: `did:demo` for `did:demo:dev:0xabc`.
impl From<&Did> for DidMethod {
    fn from(did: &Did) -> Self {
        Self {
            name: did.method().to_owned(),
            namespace: None,
        }
    }
}

impl fmt::Display for DidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SCHEME)?;
        f.write_str(&self.name)?;
        if let Some(namespace) = &self.namespace {
            f.write_str(":")?;
            f.write_str(namespace)?;
        }
        Ok(())
    }
}

impl FromStr for DidMethod {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for DidMethod {
    type Error = DidError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for DidMethod {
    type Error = DidError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl Serialize for DidMethod {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DidMethod {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(D::Error::custom)
    }
}

const SCHEME: &str = "did:";

/// Checks `name` against `method-name = 1*method-char`; positions are reported from `offset`.
fn validate_name(name: &str, offset: usize) -> Result<(), DidError> {
    if name.is_empty() {
        return Err(DidError::InvalidMethodName { position: offset });
    }
    match name.bytes().position(|c| !is_method_char(c)) {
        None => Ok(()),
        Some(i) => Err(DidError::InvalidMethodName {
            position: offset + i,
        }),
    }
}

/// Checks `namespace` against `1*idchar`; positions are reported from `offset`.
///
/// The scanner only advances over ASCII bytes, so every position it reports is a `char` boundary.
fn validate_namespace(namespace: &str, offset: usize) -> Result<(), DidError> {
    let bytes = namespace.as_bytes();
    if bytes.is_empty() {
        return Err(DidError::InvalidNamespace { position: offset });
    }
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if is_pct_encoded_at(bytes, i) => i += 3,
            b'%' => {
                return Err(DidError::InvalidPercentEncoding {
                    position: offset + i,
                });
            }
            c if is_idchar(c) => i += 1,
            _ => {
                return Err(DidError::InvalidNamespace {
                    position: offset + i,
                });
            }
        }
    }
    Ok(())
}
