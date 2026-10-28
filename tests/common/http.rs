//! An `HttpClient` serving fixed responses, for the tests that fetch over `did:web`'s client.

use std::collections::HashMap;
use std::sync::Mutex;

use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
use url::Url;

/// A client serving fixed responses by URL and failing for any other URL, as an unreachable
/// host would. It records each request with the media type it asked for, `None` for a plain
/// [`get`](HttpClient::get).
#[derive(Debug, Default)]
pub(crate) struct Web {
    routes: HashMap<String, Result<HttpResponse, String>>,
    requests: Mutex<Vec<(String, Option<String>)>>,
}

impl Web {
    /// Serves `response` at `url`.
    pub(crate) fn with(mut self, url: &str, response: HttpResponse) -> Self {
        self.routes.insert(url.to_owned(), Ok(response));
        self
    }

    /// Serves `body` with `status` at `url`.
    pub(crate) fn serving(self, url: &str, status: u16, body: impl Into<Vec<u8>>) -> Self {
        self.with(url, HttpResponse::new(status, body))
    }

    /// Serves `body` as JSON with status 200 at `url`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers pass `json!` values, which read best by value"
    )]
    pub(crate) fn serve_json(self, url: &str, body: serde_json::Value) -> Self {
        self.serving(url, 200, body.to_string())
    }

    /// Redirects `url` to `location` with `status`.
    pub(crate) fn redirect(self, url: &str, status: u16, location: &str) -> Self {
        self.with(
            url,
            HttpResponse::new(status, Vec::new()).with_location(location),
        )
    }

    /// Fails requests for `url` with `message`, as a transport error.
    pub(crate) fn failing(mut self, url: &str, message: &str) -> Self {
        self.routes.insert(url.to_owned(), Err(message.to_owned()));
        self
    }

    /// The URLs requested so far, in order.
    pub(crate) fn fetched(&self) -> Vec<String> {
        let requests = self.requests.lock().unwrap();
        requests.iter().map(|(url, _)| url.clone()).collect()
    }

    /// The requests so far, each with the media type it asked for, forgotten after.
    pub(crate) fn take(&self) -> Vec<(String, Option<String>)> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }

    fn respond(&self, url: &Url, accept: Option<&str>) -> Result<HttpResponse, HttpError> {
        self.requests
            .lock()
            .unwrap()
            .push((url.to_string(), accept.map(str::to_owned)));
        match self.routes.get(url.as_str()) {
            Some(Ok(response)) => Ok(response.clone()),
            Some(Err(message)) => Err(HttpError::msg(message)),
            None => Err(HttpError::msg("connection refused")),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for Web {
    async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
        self.respond(url, None)
    }

    async fn get_accepting(&self, url: &Url, media_type: &str) -> Result<HttpResponse, HttpError> {
        self.respond(url, Some(media_type))
    }
}
