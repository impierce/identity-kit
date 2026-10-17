//! `Resolver`: the registry of method resolvers, and its builder.

use core::fmt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::{DidResolver, DocumentCache};
use crate::did::{Did, DidDocument, ResolutionError, ResolutionOptions, ResolutionResult};

/// Routes each DID to the [`DidResolver`] registered for its method, with an optional
/// [`DocumentCache`] in front.
///
/// Built with [`Resolver::builder`]. The resolver is `Send + Sync` and meant to be shared, in an
/// `Arc` or by reference, by every task of an application. See the [module
/// documentation](super) for the resolution and dereferencing semantics and an example.
pub struct Resolver {
    methods: HashMap<String, Arc<dyn DidResolver>>,
    cache: Option<DocumentCache>,
}

impl Resolver {
    /// A builder with no method registered and no cache.
    pub fn builder() -> ResolverBuilder {
        ResolverBuilder::new()
    }

    /// The registered method names, sorted.
    pub fn methods(&self) -> Vec<&str> {
        let mut methods: Vec<&str> = self.methods.keys().map(String::as_str).collect();
        methods.sort_unstable();
        methods
    }

    /// Whether a resolver for `method` (`web`, not `did:web`) is registered.
    pub fn supports(&self, method: &str) -> bool {
        self.methods.contains_key(method)
    }

    /// The resolver registered for `method`, if any.
    pub fn resolver(&self, method: &str) -> Option<&Arc<dyn DidResolver>> {
        self.methods.get(method)
    }

    /// The cache, when the resolver was built with one.
    pub fn cache(&self) -> Option<&DocumentCache> {
        self.cache.as_ref()
    }

    /// Resolves `did` without options, through the cache when there is one.
    ///
    /// On success the result holds the document, or no document and `deactivated: true` in its
    /// document metadata when the DID has been deactivated.
    ///
    /// # Errors
    ///
    /// [`ResolutionError::MethodNotSupported`] when no resolver is registered for the method
    /// of `did`; otherwise what the method's resolver reports, as `Err` or in its resolution
    /// metadata; [`ResolutionError::NotFound`] when it reports neither a document nor an error
    /// nor deactivation; [`ResolutionError::InvalidDidDocument`] when the document's `id` is
    /// neither `did` nor the `canonicalId` of the document metadata.
    pub async fn resolve(&self, did: &Did) -> Result<ResolutionResult, ResolutionError> {
        self.resolve_with(did, &ResolutionOptions::default()).await
    }

    /// Resolves `did` with `options`, bypassing the cache unless `options` is empty.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve).
    pub async fn resolve_with(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        let resolver = self
            .methods
            .get(did.method())
            .ok_or(ResolutionError::MethodNotSupported)?;
        let cache = self
            .cache
            .as_ref()
            .filter(|_| options.accept.is_none() && options.properties.is_empty());
        if let Some(hit) = cache.and_then(|cache| cache.get(did)) {
            return Ok(hit);
        }
        let result = check_result(did, resolver.resolve(did, options).await?)?;
        if let Some(cache) = cache {
            cache.insert(did.clone(), result.clone());
        }
        Ok(result)
    }

    /// The DID document of `did`.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve); a deactivated DID is [`ResolutionError::NotFound`].
    pub async fn resolve_document(&self, did: &Did) -> Result<DidDocument, ResolutionError> {
        self.resolve(did).await?.into_document()
    }
}

/// Normalizes what a method resolver returned: an error in the metadata becomes `Err`, a
/// result with nothing in it is `notFound`, and the document must be the one asked for.
fn check_result(did: &Did, result: ResolutionResult) -> Result<ResolutionResult, ResolutionError> {
    if let Some(error) = &result.resolution_metadata.error {
        return Err(error.clone());
    }
    match &result.document {
        Some(document) => {
            let canonical = result.document_metadata.canonical_id.as_ref();
            if document.id != *did && canonical != Some(&document.id) {
                return Err(ResolutionError::InvalidDidDocument);
            }
        }
        None if result.document_metadata.is_deactivated() => {}
        None => return Err(ResolutionError::NotFound),
    }
    Ok(result)
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("methods", &self.methods())
            .field("cache", &self.cache)
            .finish()
    }
}

/// Builds a [`Resolver`].
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use identity_kit::did::{Did, ResolutionError, ResolutionOptions, ResolutionResult};
/// use identity_kit::resolver::{DidResolver, Resolver};
///
/// struct Nothing;
///
/// #[async_trait::async_trait]
/// impl DidResolver for Nothing {
///     fn method(&self) -> &'static str {
///         "example"
///     }
///
///     async fn resolve(
///         &self,
///         _: &Did,
///         _: &ResolutionOptions,
///     ) -> Result<ResolutionResult, ResolutionError> {
///         Err(ResolutionError::NotFound)
///     }
/// }
///
/// let resolver = Resolver::builder()
///     .with(Nothing)
///     .cache(Duration::from_secs(60))
///     .build();
/// assert_eq!(resolver.methods(), ["example"]);
/// assert!(resolver.supports("example") && !resolver.supports("web"));
/// assert_eq!(resolver.cache().map(|cache| cache.ttl()), Some(Duration::from_secs(60)));
/// ```
#[derive(Default)]
pub struct ResolverBuilder {
    methods: HashMap<String, Arc<dyn DidResolver>>,
    cache: Option<DocumentCache>,
}

impl ResolverBuilder {
    /// A builder with no method registered and no cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `resolver` for its method, replacing any resolver registered for the same
    /// method before, so a later registration overrides a default.
    #[must_use]
    pub fn with(self, resolver: impl DidResolver + 'static) -> Self {
        self.with_arc(Arc::new(resolver))
    }

    /// Registers an already shared `resolver`, as [`with`](Self::with).
    #[must_use]
    pub fn with_arc(mut self, resolver: Arc<dyn DidResolver>) -> Self {
        self.methods.insert(resolver.method().to_owned(), resolver);
        self
    }

    /// Caches resolution results for `ttl` in a [`DocumentCache`] of default capacity.
    #[must_use]
    pub fn cache(self, ttl: Duration) -> Self {
        self.with_cache(DocumentCache::new(ttl))
    }

    /// Caches resolution results in `cache`.
    #[must_use]
    pub fn with_cache(mut self, cache: DocumentCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// The resolver.
    pub fn build(self) -> Resolver {
        Resolver {
            methods: self.methods,
            cache: self.cache,
        }
    }
}

impl fmt::Debug for ResolverBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut methods: Vec<&str> = self.methods.keys().map(String::as_str).collect();
        methods.sort_unstable();
        f.debug_struct("ResolverBuilder")
            .field("methods", &methods)
            .field("cache", &self.cache)
            .finish()
    }
}
