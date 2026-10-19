//! The specification vectors the tests of this crate run against (feature `test-vectors`), so
//! that a crate building on this one can test against the same examples: RFC 9901 (SD-JWT),
//! SD-JWT VC, the Token Status List, the DIF Well Known DID Configuration and DIF Linked
//! Verifiable Presentation.
//!
//! Every constant is the text of the specification's example exactly as published, with a
//! trailing newline; a compact token is one line, call `trim` before parsing it. The JOSE,
//! DID and W3C VC examples the tests also use are short enough to live inline in the tests,
//! and are not repeated here.
//!
//! ```
//! use identity_kit::sd_jwt_vc::SdJwt;
//! use identity_kit::vectors::sd_jwt::simple;
//!
//! let issuance = SdJwt::parse(simple::ISSUANCE.trim())?;
//! assert_eq!(issuance.disclosures().len(), simple::DISCLOSURES.lines().count());
//! # Ok::<(), identity_kit::sd_jwt_vc::SdJwtError>(())
//! ```

macro_rules! vectors {
    ($($(#[$doc:meta])* $name:ident = $path:literal;)*) => {
        $(
            $(#[$doc])*
            pub const $name: &str = include_str!(concat!("../tests/vectors/", $path));
        )*
    };
}

/// RFC 9901 (SD-JWT), all signed with the issuer key of Appendix A.5.
pub mod sd_jwt {
    /// §5: the simple example, issued and presented with key binding.
    pub mod simple {
        vectors! {
            /// The issuer's claims before selective disclosure.
            USER_CLAIMS = "sd_jwt/simple/user_claims.json";
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/simple/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/simple/disclosures.txt";
            /// The issuer-signed JWT alone.
            JWS = "sd_jwt/simple/jws.txt";
            /// The SD-JWT as issued.
            ISSUANCE = "sd_jwt/simple/issuance.txt";
            /// The presentation with key binding.
            PRESENTATION = "sd_jwt/simple/presentation.txt";
            /// The payload of the key binding JWT.
            KB_PAYLOAD = "sd_jwt/simple/kb_payload.json";
            /// The claims the verifier obtains from the presentation.
            VERIFIED = "sd_jwt/simple/verified.json";
        }
    }

    /// §6.1: a flat SD-JWT, `address` disclosable as a whole.
    pub mod flat {
        vectors! {
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/flat/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/flat/disclosures.txt";
        }
    }

    /// §6.2: a structured SD-JWT, the members of `address` disclosable one by one.
    pub mod structured {
        vectors! {
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/structured/payload.json";
            /// The payload with `country` always disclosed.
            PAYLOAD_ONE_OPEN = "sd_jwt/structured/payload_one_open.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/structured/disclosures.txt";
        }
    }

    /// §6.3: recursive disclosures, `address` and its members disclosable.
    pub mod recursive {
        vectors! {
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/recursive/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/recursive/disclosures.txt";
        }
    }

    /// Appendix A.1: a simple structured SD-JWT with decoy digests.
    pub mod simple_structured {
        vectors! {
            /// The issuer's claims before selective disclosure.
            USER_CLAIMS = "sd_jwt/simple_structured/user_claims.json";
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/simple_structured/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/simple_structured/disclosures.txt";
            /// The decoy digests, one per line.
            DECOYS = "sd_jwt/simple_structured/decoys.txt";
            /// The presentation.
            PRESENTATION = "sd_jwt/simple_structured/presentation.txt";
            /// The claims the verifier obtains from the presentation.
            VERIFIED = "sd_jwt/simple_structured/verified.json";
        }
    }

    /// Appendix A.2: the complex structured eKYC example.
    pub mod complex_ekyc {
        vectors! {
            /// The issuer's claims before selective disclosure.
            USER_CLAIMS = "sd_jwt/complex_ekyc/user_claims.json";
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/complex_ekyc/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/complex_ekyc/disclosures.txt";
            /// The presentation.
            PRESENTATION = "sd_jwt/complex_ekyc/presentation.txt";
            /// The claims the verifier obtains from the presentation.
            VERIFIED = "sd_jwt/complex_ekyc/verified.json";
        }
    }

    /// Appendix A.3: an SD-JWT-based verifiable credential.
    pub mod sd_jwt_vc {
        vectors! {
            /// The issuer's claims before selective disclosure.
            USER_CLAIMS = "sd_jwt/sd_jwt_vc/user_claims.json";
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/sd_jwt_vc/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/sd_jwt_vc/disclosures.txt";
            /// The SD-JWT as issued.
            ISSUANCE = "sd_jwt/sd_jwt_vc/issuance.txt";
            /// The presentation with key binding.
            PRESENTATION = "sd_jwt/sd_jwt_vc/presentation.txt";
            /// The payload of the key binding JWT.
            KB_PAYLOAD = "sd_jwt/sd_jwt_vc/kb_payload.json";
            /// The claims the verifier obtains from the presentation.
            VERIFIED = "sd_jwt/sd_jwt_vc/verified.json";
        }
    }

    /// Appendix A.4: a W3C Verifiable Credentials Data Model credential.
    pub mod w3c_vcdm {
        vectors! {
            /// The issuer's claims before selective disclosure.
            USER_CLAIMS = "sd_jwt/w3c_vcdm/user_claims.json";
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt/w3c_vcdm/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt/w3c_vcdm/disclosures.txt";
            /// The SD-JWT as issued.
            ISSUANCE = "sd_jwt/w3c_vcdm/issuance.txt";
            /// The presentation with key binding.
            PRESENTATION = "sd_jwt/w3c_vcdm/presentation.txt";
            /// The claims the verifier obtains from the presentation.
            VERIFIED = "sd_jwt/w3c_vcdm/verified.json";
        }
    }
}

/// SD-JWT VC: the credentials of §2.3 and Appendix A.1.
pub mod sd_jwt_vc {
    /// §2.3: the identity credential, issued and presented with and without key binding.
    pub mod identity_credential {
        vectors! {
            /// The issuer's claims before selective disclosure.
            USER_CLAIMS = "sd_jwt_vc/identity_credential/user_claims.json";
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt_vc/identity_credential/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt_vc/identity_credential/disclosures.txt";
            /// The SD-JWT VC as issued.
            ISSUANCE = "sd_jwt_vc/identity_credential/issuance.txt";
            /// The presentation with key binding.
            PRESENTATION = "sd_jwt_vc/identity_credential/presentation.txt";
            /// The claims the verifier obtains from the presentation with key binding.
            VERIFIED = "sd_jwt_vc/identity_credential/verified.json";
            /// The presentation without key binding.
            PRESENTATION_NO_KB = "sd_jwt_vc/identity_credential/presentation_no_kb.txt";
            /// The claims the verifier obtains from the presentation without key binding.
            VERIFIED_NO_KB = "sd_jwt_vc/identity_credential/verified_no_kb.json";
        }
    }

    /// Appendix A.1: the person identification data (PID) credential.
    pub mod pid {
        vectors! {
            /// The payload of the issuer-signed JWT.
            PAYLOAD = "sd_jwt_vc/pid/payload.json";
            /// The disclosures, one per line.
            DISCLOSURES = "sd_jwt_vc/pid/disclosures.txt";
            /// The SD-JWT VC as issued.
            ISSUANCE = "sd_jwt_vc/pid/issuance.txt";
            /// The presentation with key binding.
            PRESENTATION = "sd_jwt_vc/pid/presentation.txt";
            /// The payload of the key binding JWT.
            KB_PAYLOAD = "sd_jwt_vc/pid/kb_payload.json";
            /// The claims the verifier obtains from the presentation.
            VERIFIED = "sd_jwt_vc/pid/verified.json";
        }
    }
}

/// SD-JWT VC type metadata (SD-JWT VC §5 and Appendix A.2).
pub mod type_metadata {
    vectors! {
        /// §5.1: the type metadata document of the education credential, version 42.
        EDUCATION_CREDENTIAL_V42 = "type_metadata/education_credential_v42.json";
        /// Appendix A.2: the education credential's type metadata with display and claim
        /// metadata.
        EDUCATION_CREDENTIAL = "type_metadata/education_credential.json";
        /// §5.6.1: the credential payload the claim path examples select from.
        PAYLOAD = "type_metadata/payload.json";
    }
}

/// The Token Status List.
pub mod status_list {
    vectors! {
        /// §4.1: a list of 16 one-bit statuses.
        LIST_1BIT = "status_list/list_1bit.json";
        /// §4.2: a list of 12 two-bit statuses.
        LIST_2BIT = "status_list/list_2bit.json";
        /// §5: the status list token as a JWT.
        TOKEN = "status_list/token.txt";
        /// §5: the header of the status list token.
        TOKEN_HEADER = "status_list/token_header.json";
        /// §5: the payload of the status list token.
        TOKEN_PAYLOAD = "status_list/token_payload.json";
        /// §6: the header of the referenced token.
        REFERENCED_HEADER = "status_list/referenced_header.json";
        /// §6.2: the payload of a referenced token, with its `status` claim.
        REFERENCED_PAYLOAD = "status_list/referenced_payload.json";
        /// §6.2: an SD-JWT carrying the `status` claim.
        REFERENCED_SD_JWT = "status_list/referenced_sd_jwt.txt";
        /// §6.2: the processed payload of that SD-JWT.
        REFERENCED_PROCESSED = "status_list/referenced_processed.json";
        /// Appendix C.1: a one-bit status list.
        C1_1BIT = "status_list/c1_1bit.json";
        /// Appendix C.1: the statuses of the one-bit list, by index.
        C1_1BIT_STATUSES = "status_list/c1_1bit_statuses.json";
        /// Appendix C.2: a two-bit status list.
        C2_2BIT = "status_list/c2_2bit.json";
        /// Appendix C.2: the statuses of the two-bit list, by index.
        C2_2BIT_STATUSES = "status_list/c2_2bit_statuses.json";
        /// Appendix C.3: a four-bit status list.
        C3_4BIT = "status_list/c3_4bit.json";
        /// Appendix C.3: the statuses of the four-bit list, by index.
        C3_4BIT_STATUSES = "status_list/c3_4bit_statuses.json";
        /// Appendix C.4: an eight-bit status list.
        C4_8BIT = "status_list/c4_8bit.json";
        /// Appendix C.4: the statuses of the eight-bit list, by index.
        C4_8BIT_STATUSES = "status_list/c4_8bit_statuses.json";
    }
}

/// DIF Well Known DID Configuration: the example resource and its credentials, and the example
/// DID document with `LinkedDomains` services.
pub mod did_configuration {
    vectors! {
        /// The example DID configuration resource, with a Linked Data Proof entry and a JSON
        /// Web Token entry.
        RESOURCE = "did_configuration/resource.json";
        /// The Linked Data Proof entry of the resource.
        LINKED_DATA_CREDENTIAL = "did_configuration/linked_data_credential.json";
        /// The JSON Web Token entry of the resource.
        JWT = "did_configuration/jwt.txt";
        /// The header of that JWT.
        HEADER = "did_configuration/header.json";
        /// The payload of that JWT.
        PAYLOAD = "did_configuration/payload.json";
        /// The example DID document with two `LinkedDomains` services, one listing two origins
        /// in an `origins` object, one a single origin string.
        DID_DOCUMENT = "did_configuration/did_document.json";
    }
}

/// DIF Linked Verifiable Presentation v1.0.0: the example DID documents and presentations.
pub mod linked_vp {
    vectors! {
        /// The example DID document with an HTTPS and an IPFS `LinkedVerifiablePresentation`
        /// service.
        DID_DOCUMENT = "linked_vp/did_document.json";
        /// The same document with hashlink-protected URLs (Security Considerations).
        DID_DOCUMENT_HASHLINKS = "linked_vp/did_document_hashlinks.json";
        /// The example presentation in the JSON Web Token form, one credential JWT inside.
        JWT = "linked_vp/jwt.txt";
        /// The header of that JWT, `typ` the literal `'vp+ld+jwt'`.
        HEADER = "linked_vp/header.json";
        /// The header of the credential JWT inside, `typ` the literal `'vc+ld+jwt'`.
        CREDENTIAL_HEADER = "linked_vp/credential_header.json";
        /// The example presentation in the JSON-LD form.
        JSON_LD = "linked_vp/presentation.jsonld";
        /// The presentation the specification repository's generator wrote with the
        /// presentation members at the top level of the payload rather than in `vp`, which
        /// the specification's "decoded JWT payload" example shows.
        FLAT_JWT = "linked_vp/flat_jwt.txt";
        /// The verification method that signed [`JWT`] and [`FLAT_JWT`], from the
        /// specification repository's generator
        /// (`resources/linked-vp/generate-config/keys/did-key-ed25519.json`, public part).
        /// The example DID document shows another key, which verifies neither.
        VERIFICATION_METHOD = "linked_vp/verification_method.json";
    }
}
