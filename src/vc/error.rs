//! `CredentialError`: what is wrong with a credential or presentation as data.

/// Why a credential or presentation is not well-formed, or cannot be mapped to or from the
/// claims of a JWT.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The first `@context` is not the base context of the data model.
    #[error("the first `@context` must be `{expected}`")]
    InvalidContext {
        /// The base context required.
        expected: &'static str,
    },
    /// `type` lacks the type the data model requires.
    #[error("`type` must include `{0}`")]
    MissingType(&'static str),
    /// `credentialSubject` is an empty list.
    #[error("`credentialSubject` is empty")]
    NoSubject,
    /// The validity period ends before it starts.
    #[error("`{until}` precedes `{from}`")]
    InvalidValidity {
        /// The property naming the start, `issuanceDate` or `validFrom`.
        from: &'static str,
        /// The property naming the end, `expirationDate` or `validUntil`.
        until: &'static str,
    },
    /// A JWT carries one `sub`, so a credential with several subjects has no JWT form.
    #[error("a JWT encodes one subject; the credential has {0}")]
    MultipleSubjects(usize),
    /// The JWT claims set lacks the claim the profile requires.
    #[error("JWT claim `{0}` is missing")]
    MissingClaim(&'static str),
    /// A JWT claim has the wrong shape or an invalid value.
    #[error("JWT claim `{claim}` is invalid: {reason}")]
    InvalidClaim {
        /// The claim.
        claim: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// A JWT claim and the property it duplicates disagree.
    #[error("JWT claim `{claim}` does not match `{property}`")]
    ClaimMismatch {
        /// The claim.
        claim: &'static str,
        /// The property of the credential or presentation.
        property: &'static str,
    },
    /// The enveloped credential or presentation is not in a form this crate reads.
    #[error("enveloped {kind} has media type `{media_type}`, not `{expected}`")]
    UnsupportedMediaType {
        /// `credential` or `presentation`.
        kind: &'static str,
        /// The media type of the `data:` URL.
        media_type: String,
        /// The media type this crate reads.
        expected: &'static str,
    },
    /// An enveloped credential or presentation does not hold a `data:` URL.
    #[error("`{0}` is not a `data:` URL")]
    NotDataUrl(String),
}
