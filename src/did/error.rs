/// Why a string is not a valid DID or DID URL.
///
/// Positions are byte offsets into the input that was parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DidError {
    /// The input does not start with the lowercase `did:` scheme.
    #[error("missing `did:` scheme prefix")]
    MissingScheme,
    /// The method name is empty or contains a character other than `a-z` and `0-9`.
    #[error("invalid method name: unexpected character at byte {position}")]
    InvalidMethodName {
        /// Byte offset of the offending character.
        position: usize,
    },
    /// The method-specific id is missing, empty, or ends with `:`.
    #[error("method-specific id is empty or ends with `:`")]
    EmptyMethodSpecificId,
    /// A character that is not allowed at this position of a DID.
    #[error("invalid character {ch:?} at byte {position}")]
    InvalidChar {
        /// Byte offset of the offending character.
        position: usize,
        /// The offending character.
        ch: char,
    },
    /// A `%` that is not followed by exactly two hexadecimal digits.
    #[error("incomplete or non-hex percent-encoding at byte {position}")]
    InvalidPercentEncoding {
        /// Byte offset of the `%`.
        position: usize,
    },
    /// The input is longer than the configured maximum.
    #[error("input exceeds the maximum length of {max} bytes")]
    TooLong {
        /// The maximum number of bytes accepted.
        max: usize,
    },
    /// The DID URL path is not a valid RFC 3986 `path-abempty`.
    #[error("invalid DID URL path")]
    InvalidPath,
    /// The DID URL query contains a character not allowed by RFC 3986.
    #[error("invalid DID URL query")]
    InvalidQuery,
    /// The DID URL fragment contains a character not allowed by RFC 3986.
    #[error("invalid DID URL fragment")]
    InvalidFragment,
}
