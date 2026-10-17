//! `Did` and `DidUrl`: owned, validated strings plus the scanner that validates them.
//!
//! Both types store the input unchanged. The scanner only ever advances over ASCII bytes, so every
//! offset it reports or stores is a `char` boundary of the input.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::DidError;

/// Default maximum input length in bytes for [`Did::parse`] and [`DidUrl::parse`]: 2 KiB.
pub const DEFAULT_MAX_LEN: usize = 2048;

/// A decentralized identifier such as `did:web:example.com`.
///
/// A `Did` is validated against the DID syntax of [W3C DID Core §3.1] when it is constructed and
/// stores the input unchanged: no percent-decoding, no case folding, no normalization. Two DIDs are
/// equal exactly when their strings are equal.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Did;
///
/// let did = Did::parse("did:web:example.com%3A8443:user:alice")?;
/// assert_eq!(did.method(), "web");
/// assert_eq!(did.method_specific_id(), "example.com%3A8443:user:alice");
/// assert_eq!(did.as_str(), "did:web:example.com%3A8443:user:alice");
///
/// // The scheme and the method name are lowercase; a DID has no path, query or fragment.
/// assert!(Did::parse("DID:web:example.com").is_err());
/// assert!(Did::parse("did:Web:example.com").is_err());
/// assert!(Did::parse("did:web:example.com#key-1").is_err());
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
///
/// A `Did` serializes as its string and deserialization validates:
///
/// ```
/// use identity_kit::did::Did;
/// use serde::Deserialize;
/// use serde::de::IntoDeserializer;
/// use serde::de::value::{Error, StrDeserializer};
///
/// let input: StrDeserializer<'_, Error> = "did:example:123".into_deserializer();
/// let did = Did::deserialize(input)?;
/// assert_eq!(did.as_str(), "did:example:123");
///
/// let input: StrDeserializer<'_, Error> = "did:example:".into_deserializer();
/// assert!(Did::deserialize(input).is_err());
/// # Ok::<(), Error>(())
/// ```
///
/// [W3C DID Core §3.1]: https://www.w3.org/TR/did-core/#did-syntax
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Did(String);

impl Did {
    /// Parses a DID, rejecting input longer than [`DEFAULT_MAX_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`DidError`] describing the first violation of the DID syntax.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{Did, DidError};
    ///
    /// let did = Did::parse("did:example:123456789abcdefghi")?;
    /// assert_eq!(did.method(), "example");
    /// assert_eq!(did.method_specific_id(), "123456789abcdefghi");
    ///
    /// assert_eq!(Did::parse("example:123"), Err(DidError::MissingScheme));
    /// assert_eq!(Did::parse("did:example:a:"), Err(DidError::EmptyMethodSpecificId));
    /// assert_eq!(
    ///     Did::parse("did:example:ab%2"),
    ///     Err(DidError::InvalidPercentEncoding { position: 14 })
    /// );
    /// # Ok::<(), DidError>(())
    /// ```
    pub fn parse(s: &str) -> Result<Self, DidError> {
        Self::parse_with_max_len(s, DEFAULT_MAX_LEN)
    }

    /// Parses a DID, rejecting input longer than `max_len` bytes with [`DidError::TooLong`].
    ///
    /// # Errors
    ///
    /// Returns a [`DidError`] describing the first violation of the DID syntax.
    pub fn parse_with_max_len(s: &str, max_len: usize) -> Result<Self, DidError> {
        validate_did(s, max_len)?;
        Ok(Self(s.to_owned()))
    }

    /// The method name, for example `web` in `did:web:example.com`.
    pub fn method(&self) -> &str {
        &self.0[SCHEME.len()..self.method_end()]
    }

    /// The method-specific id, for example `example.com` in `did:web:example.com`.
    pub fn method_specific_id(&self) -> &str {
        &self.0[self.method_end() + 1..]
    }

    /// The DID as it was parsed.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// This DID as a [`DidUrl`] without path, query or fragment.
    #[must_use]
    pub fn to_url(&self) -> DidUrl {
        DidUrl {
            url: self.0.clone(),
            did: self.clone(),
            query_start: None,
            fragment_start: None,
        }
    }

    /// Appends a relative reference (`"#key-1"`, `"/path"`, `"?versionId=1"` or a combination
    /// such as `"/path?versionId=1#key-1"`) to this DID.
    ///
    /// The relative reference is taken as already percent-encoded. An empty reference yields the
    /// same as [`Did::to_url`].
    ///
    /// # Errors
    ///
    /// Returns [`DidError::InvalidPath`] when `relative` does not start with `/`, `?` or `#`, and
    /// the respective [`DidError`] when a component is not valid per RFC 3986.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{Did, DidError};
    ///
    /// let did = Did::parse("did:example:123")?;
    ///
    /// let key = did.join("#key-1")?;
    /// assert_eq!(key.fragment(), Some("key-1"));
    /// assert_eq!(key.to_string(), "did:example:123#key-1");
    ///
    /// let versioned = did.join("/path?versionId=1")?;
    /// assert_eq!(versioned.path(), Some("/path"));
    /// assert_eq!(versioned.query(), Some("versionId=1"));
    /// assert_eq!(versioned.fragment(), None);
    ///
    /// assert_eq!(did.join("key-1"), Err(DidError::InvalidPath));
    /// # Ok::<(), DidError>(())
    /// ```
    pub fn join(&self, relative: &str) -> Result<DidUrl, DidError> {
        if !relative.is_empty() && !relative.starts_with(['/', '?', '#']) {
            return Err(DidError::InvalidPath);
        }
        let mut url = String::with_capacity(self.0.len() + relative.len());
        url.push_str(&self.0);
        url.push_str(relative);
        let (query_start, fragment_start) = scan_url_suffix(&url, self.0.len())?;
        Ok(DidUrl {
            url,
            did: self.clone(),
            query_start,
            fragment_start,
        })
    }

    /// Byte offset of the `:` that ends the method name.
    fn method_end(&self) -> usize {
        // Always present: construction guarantees `did:` + method name + `:`.
        self.0[SCHEME.len()..]
            .find(':')
            .map_or(self.0.len(), |i| SCHEME.len() + i)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Did {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for Did {
    type Error = DidError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for Did {
    type Error = DidError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        validate_did(&s, DEFAULT_MAX_LEN)?;
        Ok(Self(s))
    }
}

impl Serialize for Did {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(D::Error::custom)
    }
}

/// A DID URL such as `did:example:123/path?versionId=1#key-1`.
///
/// A `DidUrl` is a [`Did`] followed by an optional path, query and fragment as defined by
/// [W3C DID Core §3.2] and RFC 3986. It is validated on construction and stores the input unchanged.
/// A `DidUrl` without path, query or fragment displays as the bare DID.
///
/// Equality, ordering and hashing are those of the URL string.
///
/// # Examples
///
/// ```
/// use identity_kit::did::DidUrl;
///
/// let url = DidUrl::parse("did:example:123/path/to?versionId=1#frag")?;
/// assert_eq!(url.did().as_str(), "did:example:123");
/// assert_eq!(url.path(), Some("/path/to"));
/// assert_eq!(url.query(), Some("versionId=1"));
/// assert_eq!(url.fragment(), Some("frag"));
///
/// let key = DidUrl::parse("did:example:123#key-1")?;
/// assert_eq!(key.path(), None);
/// assert_eq!(key.without_fragment().as_str(), "did:example:123");
/// assert_eq!(key.with_fragment("key-2").as_str(), "did:example:123#key-2");
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
///
/// [W3C DID Core §3.2]: https://www.w3.org/TR/did-core/#did-url-syntax
#[derive(Clone)]
pub struct DidUrl {
    /// The whole URL as parsed.
    url: String,
    /// The DID prefix of `url`.
    did: Did,
    /// Byte offset of the `?` that starts the query, if any.
    query_start: Option<usize>,
    /// Byte offset of the `#` that starts the fragment, if any.
    fragment_start: Option<usize>,
}

impl DidUrl {
    /// Parses a DID URL, rejecting input longer than [`DEFAULT_MAX_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`DidError`] describing the first violation of the DID URL syntax.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{DidError, DidUrl};
    ///
    /// let url = DidUrl::parse("did:example:123?service=agent&relativeRef=%2Fsome%2Fpath")?;
    /// assert_eq!(url.query(), Some("service=agent&relativeRef=%2Fsome%2Fpath"));
    ///
    /// // An empty fragment is present but empty, as in RFC 3986.
    /// assert_eq!(DidUrl::parse("did:example:123#")?.fragment(), Some(""));
    ///
    /// assert_eq!(DidUrl::parse("did:example:123#a#b"), Err(DidError::InvalidFragment));
    /// # Ok::<(), DidError>(())
    /// ```
    pub fn parse(s: &str) -> Result<Self, DidError> {
        Self::parse_with_max_len(s, DEFAULT_MAX_LEN)
    }

    /// Parses a DID URL, rejecting input longer than `max_len` bytes with [`DidError::TooLong`].
    ///
    /// # Errors
    ///
    /// Returns a [`DidError`] describing the first violation of the DID URL syntax.
    pub fn parse_with_max_len(s: &str, max_len: usize) -> Result<Self, DidError> {
        Self::from_string(s.to_owned(), max_len)
    }

    /// The DID this URL refers to.
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// The path, starting with `/`, or `None` when the URL has no path.
    pub fn path(&self) -> Option<&str> {
        let end = self
            .query_start
            .or(self.fragment_start)
            .unwrap_or(self.url.len());
        let path = &self.url[self.did.0.len()..end];
        (!path.is_empty()).then_some(path)
    }

    /// The query without the leading `?`, or `None` when the URL has no `?`.
    pub fn query(&self) -> Option<&str> {
        self.query_start
            .map(|start| &self.url[start + 1..self.fragment_start.unwrap_or(self.url.len())])
    }

    /// The fragment without the leading `#`, or `None` when the URL has no `#`.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment_start.map(|start| &self.url[start + 1..])
    }

    /// The DID URL as it was parsed.
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// A copy of this URL with its fragment replaced by `fragment`.
    ///
    /// `fragment` is taken as already percent-encoded: a `%` followed by two hexadecimal digits is
    /// kept, and every other byte that RFC 3986 does not allow in a fragment (including a stray
    /// `%`) is percent-encoded, so the result is always a valid DID URL.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::DidUrl;
    ///
    /// let url = DidUrl::parse("did:example:123?versionId=1#key-1")?;
    /// assert_eq!(url.with_fragment("key-2").as_str(), "did:example:123?versionId=1#key-2");
    /// assert_eq!(url.with_fragment("a b").fragment(), Some("a%20b"));
    /// # Ok::<(), identity_kit::did::DidError>(())
    /// ```
    #[must_use]
    pub fn with_fragment(&self, fragment: &str) -> Self {
        let base = self.fragment_start.unwrap_or(self.url.len());
        let mut url = String::with_capacity(base + 1 + fragment.len());
        url.push_str(&self.url[..base]);
        url.push('#');
        encode_fragment_into(&mut url, fragment);
        Self {
            url,
            did: self.did.clone(),
            query_start: self.query_start,
            fragment_start: Some(base),
        }
    }

    /// A copy of this URL with its DID replaced by `did`, keeping path, query and fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::did::{Did, DidUrl};
    ///
    /// let url = DidUrl::parse("did:example:123/path?versionId=1#key-1")?;
    /// let moved = url.with_did(Did::parse("did:web:example.com")?);
    /// assert_eq!(moved.as_str(), "did:web:example.com/path?versionId=1#key-1");
    /// assert_eq!(moved.fragment(), Some("key-1"));
    /// # Ok::<(), identity_kit::did::DidError>(())
    /// ```
    #[must_use]
    pub fn with_did(&self, did: Did) -> Self {
        let old_len = self.did.0.len();
        let suffix = &self.url[old_len..];
        let mut url = String::with_capacity(did.0.len() + suffix.len());
        url.push_str(&did.0);
        url.push_str(suffix);
        let shift = |offset: usize| offset - old_len + did.0.len();
        Self {
            url,
            query_start: self.query_start.map(shift),
            fragment_start: self.fragment_start.map(shift),
            did,
        }
    }

    /// A copy of this URL without a fragment.
    #[must_use]
    pub fn without_fragment(&self) -> Self {
        let end = self.fragment_start.unwrap_or(self.url.len());
        Self {
            url: self.url[..end].to_owned(),
            did: self.did.clone(),
            query_start: self.query_start,
            fragment_start: None,
        }
    }

    /// Validates `url` and takes ownership of it.
    fn from_string(url: String, max_len: usize) -> Result<Self, DidError> {
        check_len(&url, max_len)?;
        let did_end = scan_did(&url)?;
        let (query_start, fragment_start) = scan_url_suffix(&url, did_end)?;
        let did = Did(url[..did_end].to_owned());
        Ok(Self {
            url,
            did,
            query_start,
            fragment_start,
        })
    }
}

impl fmt::Debug for DidUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DidUrl").field(&self.url).finish()
    }
}

impl fmt::Display for DidUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url)
    }
}

impl PartialEq for DidUrl {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for DidUrl {}

impl PartialOrd for DidUrl {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DidUrl {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.url.cmp(&other.url)
    }
}

impl Hash for DidUrl {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl AsRef<str> for DidUrl {
    fn as_ref(&self) -> &str {
        &self.url
    }
}

impl FromStr for DidUrl {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for DidUrl {
    type Error = DidError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for DidUrl {
    type Error = DidError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_string(s, DEFAULT_MAX_LEN)
    }
}

impl Serialize for DidUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.url)
    }
}

impl<'de> Deserialize<'de> for DidUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::try_from(s).map_err(D::Error::custom)
    }
}

// ---------------------------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------------------------

const SCHEME: &str = "did:";

/// Checks that `s` is a complete DID of at most `max_len` bytes.
fn validate_did(s: &str, max_len: usize) -> Result<(), DidError> {
    check_len(s, max_len)?;
    let end = scan_did(s)?;
    if end < s.len() {
        return Err(invalid_char(s, end));
    }
    Ok(())
}

fn check_len(s: &str, max_len: usize) -> Result<(), DidError> {
    if s.len() > max_len {
        return Err(DidError::TooLong { max: max_len });
    }
    Ok(())
}

/// Scans the DID at the start of `s` and returns the byte offset where it ends.
///
/// The DID ends at the end of the input or at the first character that is neither an `idchar` nor
/// `:`. The caller decides whether anything may follow.
fn scan_did(s: &str) -> Result<usize, DidError> {
    let bytes = s.as_bytes();
    if !s.starts_with(SCHEME) {
        return Err(DidError::MissingScheme);
    }

    // method-name = 1*method-char
    let mut i = SCHEME.len();
    while i < bytes.len() && is_method_char(bytes[i]) {
        i += 1;
    }
    if i == SCHEME.len() {
        return Err(DidError::InvalidMethodName { position: i });
    }
    match bytes.get(i) {
        Some(b':') => i += 1,
        None | Some(b'/' | b'?' | b'#') => return Err(DidError::EmptyMethodSpecificId),
        Some(_) => return Err(DidError::InvalidMethodName { position: i }),
    }

    // method-specific-id = *( *idchar ":" ) 1*idchar
    let mut segment_len = 0;
    while i < bytes.len() {
        match bytes[i] {
            b':' => {
                segment_len = 0;
                i += 1;
            }
            b'%' => {
                check_pct_encoded(bytes, i)?;
                segment_len += 3;
                i += 3;
            }
            c if is_idchar(c) => {
                segment_len += 1;
                i += 1;
            }
            _ => break,
        }
    }
    if segment_len == 0 {
        return match bytes.get(i) {
            None | Some(b'/' | b'?' | b'#') => Err(DidError::EmptyMethodSpecificId),
            Some(_) => Err(invalid_char(s, i)),
        };
    }
    Ok(i)
}

/// Scans `path-abempty [ "?" query ] [ "#" fragment ]` from `start` to the end of `s`.
///
/// Returns the byte offsets of the `?` and the `#`, if present.
fn scan_url_suffix(s: &str, start: usize) -> Result<(Option<usize>, Option<usize>), DidError> {
    let bytes = s.as_bytes();
    let mut i = start;

    // path-abempty = *( "/" segment ); segment = *pchar
    if bytes.get(i) == Some(&b'/') {
        while i < bytes.len() {
            match bytes[i] {
                b'?' | b'#' => break,
                b'%' => {
                    check_pct_encoded(bytes, i)?;
                    i += 3;
                }
                c if is_pchar(c) || c == b'/' => i += 1,
                _ => return Err(DidError::InvalidPath),
            }
        }
    }

    // query = *( pchar / "/" / "?" )
    let mut query_start = None;
    if bytes.get(i) == Some(&b'?') {
        query_start = Some(i);
        i += 1;
        while i < bytes.len() {
            match bytes[i] {
                b'#' => break,
                b'%' => {
                    check_pct_encoded(bytes, i)?;
                    i += 3;
                }
                c if is_fragment_or_query_char(c) => i += 1,
                _ => return Err(DidError::InvalidQuery),
            }
        }
    }

    // fragment = *( pchar / "/" / "?" )
    let mut fragment_start = None;
    if bytes.get(i) == Some(&b'#') {
        fragment_start = Some(i);
        i += 1;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    check_pct_encoded(bytes, i)?;
                    i += 3;
                }
                c if is_fragment_or_query_char(c) => i += 1,
                _ => return Err(DidError::InvalidFragment),
            }
        }
    }

    if i < bytes.len() {
        return Err(invalid_char(s, i));
    }
    Ok((query_start, fragment_start))
}

/// Checks that the `%` at `position` is followed by two hexadecimal digits.
fn check_pct_encoded(bytes: &[u8], position: usize) -> Result<(), DidError> {
    if is_pct_encoded_at(bytes, position) {
        Ok(())
    } else {
        Err(DidError::InvalidPercentEncoding { position })
    }
}

fn is_pct_encoded_at(bytes: &[u8], position: usize) -> bool {
    matches!(
        bytes.get(position..position + 3),
        Some([b'%', hi, lo]) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit()
    )
}

/// Percent-encodes `fragment` into `out`, keeping bytes that RFC 3986 allows in a fragment and
/// complete percent-encoded triplets as they are.
fn encode_fragment_into(out: &mut String, fragment: &str) {
    let bytes = fragment.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'%' && is_pct_encoded_at(bytes, i) {
            out.push_str(&fragment[i..i + 3]);
            i += 3;
        } else {
            if is_fragment_or_query_char(c) {
                out.push(char::from(c));
            } else {
                out.push('%');
                out.push(char::from(HEX_UPPER[usize::from(c >> 4)]));
                out.push(char::from(HEX_UPPER[usize::from(c & 0x0f)]));
            }
            i += 1;
        }
    }
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// The character at byte offset `position`, which the scanner guarantees is a `char` boundary.
fn invalid_char(s: &str, position: usize) -> DidError {
    let ch = s
        .get(position..)
        .and_then(|rest| rest.chars().next())
        .unwrap_or(char::REPLACEMENT_CHARACTER);
    DidError::InvalidChar { position, ch }
}

/// `method-char = %x61-7A / DIGIT`
fn is_method_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

/// `idchar = ALPHA / DIGIT / "." / "-" / "_"`, without `pct-encoded`, which the scanner handles.
fn is_idchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')
}

/// `pchar = unreserved / sub-delims / ":" / "@"`, without `pct-encoded`, which the scanner handles.
fn is_pchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
        )
}

/// `pchar / "/" / "?"`, the characters allowed in a query and in a fragment.
fn is_fragment_or_query_char(c: u8) -> bool {
    is_pchar(c) || c == b'/' || c == b'?'
}
