//! The futures of the validators are `Send`, so an application can await them on a
//! multi-threaded runtime: in a spawned task, an `axum` handler or a method whose future must be
//! `Send`. The checks are type checks; the futures are never polled.
#![cfg(all(feature = "vc", feature = "sd-jwt"))]

use std::future::Future;

use identity_kit::jose::DefaultVerifier;
use identity_kit::resolver::{JwtValidationOptions, JwtValidator, Resolver};
use identity_kit::sd_jwt_vc::{SdJwt, SdJwtCredentialValidator, SdJwtValidationOptions};
use identity_kit::vc::Jwt;
use identity_kit::vc::validation::{
    CredentialValidationOptions, JwtCredentialValidator, JwtPresentationValidator,
    PresentationValidationOptions,
};

fn assert_send<F: Future + Send>(_future: F) {}

/// Futures that borrow from the `async` block awaiting them, as an application's handler does.
#[expect(dead_code, reason = "only type checked")]
fn validation_futures_are_send(
    credentials: JwtCredentialValidator<Resolver, DefaultVerifier>,
    presentations: JwtPresentationValidator<Resolver, DefaultVerifier>,
    sd_jwts: SdJwtCredentialValidator<Resolver, DefaultVerifier>,
    jwts: JwtValidator<Resolver, DefaultVerifier>,
    jwt: Jwt,
    sd_jwt: SdJwt,
) {
    assert_send(async move {
        let options = CredentialValidationOptions::default();
        let _ = credentials.validate(&jwt, &options).await;
        let _ = credentials.validate_v2(&jwt, &options).await;

        let options = PresentationValidationOptions::default();
        let _ = presentations.validate(&jwt, &options).await;
        let _ = presentations.validate_v2(&jwt, &options).await;

        let options = SdJwtValidationOptions::default();
        let _ = sd_jwts.validate(&sd_jwt, &options).await;
        let _ = sd_jwts.validate_v2(&sd_jwt, &options).await;

        let options = JwtValidationOptions::new();
        let _ = jwts.validate(jwt.as_str(), &options).await;
    });
}
