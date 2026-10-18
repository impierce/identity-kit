//! DID syntax (DID Core §3.1 and §3.2): `Did`, `DidUrl`, `DidUrlReference` and `Uri` never
//! panic on arbitrary input, and whatever they accept survives a round trip through its string.
#![no_main]

use identity_kit::did::{Did, DidError, DidUrl, DidUrlReference, Uri};
use libfuzzer_sys::fuzz_target;

fn base() -> Did {
    Did::parse("did:example:123").expect("a valid DID")
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(did) = Did::parse(input) {
        assert_eq!(did.as_str(), input);
        assert_eq!(Did::parse(did.as_str()).as_ref(), Ok(&did));
        assert!(!did.method().is_empty());
        assert_eq!(
            format!("did:{}:{}", did.method(), did.method_specific_id()),
            input
        );
        let url = did.to_url();
        assert_eq!(url.as_str(), input);
        assert_eq!(url.did(), &did);
        assert_eq!(
            (url.path(), url.query(), url.fragment()),
            (None, None, None)
        );
        assert_eq!(DidUrl::parse(input).as_ref(), Ok(&url));
        assert_eq!(did.join("").as_ref(), Ok(&url));
        assert!(Uri::parse(input).is_ok_and(|uri| uri.is_did_url()));
    }

    if let Ok(url) = DidUrl::parse(input) {
        assert_eq!(url.as_str(), input);
        assert_eq!(DidUrl::parse(url.as_str()).as_ref(), Ok(&url));
        assert!(input.starts_with(url.did().as_str()));
        assert_eq!(
            DidUrlReference::parse(input),
            Ok(DidUrlReference::Absolute(url.clone()))
        );

        // `with_fragment` and `with_did` cannot fail, so their result may exceed the default
        // limit by the few bytes they add; it still parses back without one.
        let fragment = url.with_fragment("key-1");
        assert_eq!(fragment.fragment(), Some("key-1"));
        assert_eq!(
            DidUrl::parse_with_max_len(fragment.as_str(), usize::MAX).as_ref(),
            Ok(&fragment)
        );
        let bare = url.without_fragment();
        assert_eq!(bare.fragment(), None);
        assert_eq!(bare.did(), url.did());
        assert_eq!(bare.path(), url.path());
        assert_eq!(bare.query(), url.query());
        assert_eq!(DidUrl::parse(bare.as_str()).as_ref(), Ok(&bare));
        let moved = url.with_did(base());
        assert_eq!(moved.did(), &base());
        assert_eq!(moved.path(), url.path());
        assert_eq!(moved.query(), url.query());
        assert_eq!(moved.fragment(), url.fragment());
        assert_eq!(
            DidUrl::parse_with_max_len(moved.as_str(), usize::MAX).as_ref(),
            Ok(&moved)
        );
    }

    if let Ok(reference) = DidUrlReference::parse(input) {
        assert_eq!(reference.as_str(), input);
        assert_eq!(reference.is_relative(), input.starts_with(['/', '?', '#']));
        match reference.resolve(&base()) {
            Ok(resolved) => {
                assert_eq!(DidUrl::parse(resolved.as_str()).as_ref(), Ok(&resolved));
                assert!(reference.refers_to(&resolved, &base()));
                if reference.is_relative() {
                    assert_eq!(resolved.did(), &base());
                    assert_eq!(base().join(input).as_ref(), Ok(&resolved));
                }
            }
            // A reference within the limit on its own may not fit it together with the base.
            Err(DidError::TooLong { max }) => {
                assert!(reference.is_relative());
                assert!(base().as_str().len() + input.len() > max);
            }
            Err(error) => panic!("an accepted reference resolves: {error}"),
        }
    }

    if let Ok(uri) = Uri::parse(input) {
        assert_eq!(uri.as_str(), input);
        assert!(!uri.scheme().is_empty());
        assert!(input.starts_with(uri.scheme()));
    }

    let _ = Did::parse_with_max_len(input, 32);
    let _ = DidUrl::parse_with_max_len(input, 32);
    if let Ok(joined) = base().join(input) {
        assert_eq!(joined.did(), &base());
        assert_eq!(DidUrl::parse(joined.as_str()).as_ref(), Ok(&joined));
    }
});
