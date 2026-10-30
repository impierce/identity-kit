# IdentityKit

The language of this crate: the terms of the specifications it implements (W3C DID Core and VC Data Model, the JOSE RFCs, RFC 9901 SD-JWT, SD-JWT VC, the IETF Token Status List, DIF Well Known DID Configuration and Linked Verifiable Presentation), spelled as those specifications spell them, plus the few terms this crate adds. Code, issues, tests and docs use these names.

## Language

### Identifiers

**DID**:
A decentralized identifier, `did:<method>:<method-specific-id>`, naming a subject whose DID document says how to verify it.
_Avoid_: Identity (see below), address, account

**DID URL**:
A DID followed by an optional path, query and fragment, naming a resource relative to the DID, typically one verification method.
_Avoid_: Key reference when the URL itself is meant, DID when the fragment matters

**DID method**:
The specification that defines how a DID of one method name (and optional namespace) is created and resolved, such as `did:web` or `did:key`.
_Avoid_: DID type, driver

**DID document**:
The document a DID resolves to: its verification methods, the verification relationships that use them, and its services.
_Avoid_: DID doc, DID profile

**Controller**:
The DID that is authorised to make changes to a DID document or that a verification method belongs to.
_Avoid_: Owner

**Verification method**:
An entry of a DID document that holds public key material, as `publicKeyJwk` or `publicKeyMultibase`, under a DID URL.
_Avoid_: Key, public key entry

**Verification relationship**:
The purpose a DID document grants a verification method: `authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation` or `capabilityDelegation`.
_Avoid_: Key purpose, key usage

**Service**:
An entry of a DID document that advertises an endpoint, such as `LinkedDomains` or `LinkedVerifiablePresentation`.

**DID resolution**:
Turning a DID into its DID document with resolution metadata; **dereferencing** turns a DID URL into the resource it names.
_Avoid_: Lookup, fetching

**DID resolver**:
The extension point that implements DID resolution for one or more DID methods (`DidResolver`); a **DID producer** (`DidProducer`) creates DIDs and documents for a method.
_Avoid_: Driver, provider

### Keys and signing

**Key store**:
The extension point that holds private keys and signs with them (`KeyStore`), shaped by remote signers such as a KMS or HSM.
_Avoid_: Wallet, vault, keychain

**Key id**:
The opaque name a key store gives a key (`KeyId`): a label, a PKCS#11 object label or a cloud KMS key ARN.
_Avoid_: `kid` (the JWS header parameter, which names a verification method or JWK)

**Signer**:
One key with one algorithm that produces JWS signatures (`Signer`), wherever the private key lives.
_Avoid_: Key pair, signing key

**Identity**:
The signing party: which identifiers it controls and the signer that answers for a chosen identifier kind and algorithm (`Identity`).
_Avoid_: DID, account, profile

**JWK thumbprint**:
The RFC 7638 hash of a JWK's required members, used as an identifier when no DID is involved.

**Key reference**:
What a token names as its signing key (`KeyReference`): a DID URL, an embedded JWK, an `x5c` certificate chain, or a `kid` in an HTTPS issuer's key set, from which the key resolver finds the key.
_Avoid_: `kid` when the other forms are meant

**Key resolver**:
The extension point that turns a key reference into a verified public key, under a required verification relationship (`KeyResolver`).

### Credentials

**Verifiable credential**:
A set of claims an issuer makes about a subject, secured here as a JWT, an SD-JWT or a VCDM 2.0 JWT payload.
_Avoid_: Certificate, attestation (except in names the specifications use)

**Verifiable presentation**:
A holder's signed package of one or more verifiable credentials for a verifier.
_Avoid_: Proof, presentation token

**Issuer**:
The party that signs a verifiable credential.

**Holder**:
The party a credential is bound to and that presents it.
_Avoid_: Owner, user

**Verifier**:
The party that validates a verifiable presentation or credential.
_Avoid_: Relying party (an OpenID term, used only in OpenID contexts)

**Credential subject**:
The entity the claims of a verifiable credential are about; not necessarily the holder.

**SD-JWT**:
A JWT with selectively disclosable claims, issued with disclosures and presented with the subset the holder chooses (RFC 9901).

**Disclosure**:
The salted, base64url-encoded claim an SD-JWT conceals by its digest and reveals only when the holder includes it.

**Key binding**:
Proof that the presenter of an SD-JWT holds the key named in its `cnf` claim, given by a key binding JWT.
_Avoid_: Holder binding when the `cnf` key is meant

**SD-JWT VC**:
An SD-JWT whose payload follows the SD-JWT VC profile, typed `dc+sd-jwt` and naming its credential type in `vct`.

**Type metadata**:
The document a `vct` refers to, describing a credential type's claims, display and integrity.

### Status

**Credential status**:
The part of a credential that says where to check whether it is still valid: `credentialStatus` (VCDM) or the `status` claim (Token Status List).

**Status list**:
A compressed bit array in which each credential's index holds its status value, such as valid, invalid or suspended.
_Avoid_: Revocation list (it carries more than revocation)

**Status list token**:
A signed JWT, typed `statuslist+jwt`, that carries a status list and is fetched from the URI a credential's status names.

### Linking DIDs to the web

**Domain linkage**:
Proof that a DID and a web origin are controlled by the same party, through a DID configuration resource at `/.well-known/did-configuration.json` and a `LinkedDomains` service.
_Avoid_: Domain verification, well-known DID

**Linked verifiable presentation**:
A verifiable presentation a DID document advertises through a `LinkedVerifiablePresentation` service, so that anyone can fetch it.

### This crate

**Lower layer**:
The modules `did`, `jose`, `keys`, `identity`, `resolver` and `methods`: identifiers, keys and signing, which never import the upper layer.

**Upper layer**:
The feature-gated modules `vc`, `sd_jwt_vc`, `status_list`, `domain_linkage` and `linked_vp`: credentials and what builds on them.

**Extension point**:
A trait this crate defines for consumers to implement, such as `DidResolver`, `KeyStore`, `KeyResolver` or `StatusCheck`, never a closed enum.
