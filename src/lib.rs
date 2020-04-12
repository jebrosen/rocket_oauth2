//! # rocket_oauth2
//!
//! OAuth2 ([RFC 6749](https://tools.ietf.org/html/rfc6749)) for
//! [Rocket](https://rocket.rs) applications.
//!
//! ## Requirements
//!
//! * Rocket 0.4
//!
//! ## API Stability
//!
//! `rocket_oauth2` is still in its early stages and the API is subject
//! to heavy change in the future.
//!
//! ## Features
//!
//! * Handles the Authorization Code Grant (RFC 6749, §4.1)
//! * Built-in support for a few popular OAuth2 providers
//! * Support for custom providers
//! * Support for custom adapters
//! * Refreshing tokens
//!
//! ## Not-yet-planned Features
//!
//! * Grant types other than Authorization Code.
//!
//! ## Design
//!
//! This crate is designed around 2 traits: [`Callback`] and [`Adapter`]. The
//! [`Adapter`] trait is implemented by types that can generate authorization
//! URLs and perform token exchanges. The [`Callback`] trait is implemented by
//! applications to perform actions when a token has been exchanged
//! successfully.
//!
//! Generally, a Rocket application will only need to implement [`Callback`],
//! once per service the application will connect to. The [`OAuth2`] type
//! registers routes and handlers in the application for the OAuth2 redirect and
//! an optional login handler for convenience.
//!
//! ## Adapter Implementations
//!
//! `rocket_oauth2` currently provides only one [`Adapter`] itself:
//!
//! * `hyper_rustls`: Uses [`hyper-rustls`](https://github.com/ctz/hyper-rustls).
//!
//! `hyper_rustls` was chosen because it uses *ring*, which Rocket already
//! depends on. Usually, custom `Adapter`s should only be needed to work around
//! non-compliant service providers.
//!
//! ## Usage
//!
//! Add `rocket_oauth2` to your `Cargo.toml`:
//!
//! ```toml
//! rocket_oauth2 = { version = "0.0.0" }
//! ```
//!
//! Implement `Callback` for your type, or write a free function:
//!
//! ```rust
//! # extern crate rocket;
//! # extern crate rocket_oauth2;
//! # use rocket::http::{Cookie, Cookies, SameSite};
//! # use rocket::Request;
//! # use rocket::response::{Redirect, Responder, ResultFuture};
//! use rocket_oauth2::{Callback, OAuth2, TokenResponse};
//! use rocket_oauth2::hyper_rustls_adapter::HyperRustlsAdapter;
//!
//! fn github_callback<'r>(request: &'r Request, token: TokenResponse)
//!     -> ResultFuture<'r>
//! {
//!     let mut cookies = request.guard::<Cookies>().expect("request cookies");
//!
//!     // Set a private cookie with the access token
//!     cookies.add_private(
//!         Cookie::build("token", token.access_token().to_string())
//!             .same_site(SameSite::Lax)
//!             .finish()
//!     );
//!     Redirect::to("/").respond_to(request)
//! }
//! ```
//!
//! Configure your OAuth client settings in `Rocket.toml`:
//! ```toml
//! [global.oauth.github]
//! provider = "GitHub"
//! client_id = "..."
//! client_secret = "..."
//! redirect_uri = "http://localhost:8000/auth/github"
//! ```
//!
//! Create and attach the [`OAuth2`] fairing:
//!
//! ```rust
//! # extern crate rocket;
//! # extern crate rocket_oauth2;
//! # use std::pin::Pin;
//! # use std::future::Future;
//! # use rocket::http::{Cookie, Cookies, SameSite};
//! # use rocket::Request;
//! # use rocket::response::ResultFuture;
//! use rocket::fairing::AdHoc;
//! use rocket_oauth2::{Callback, OAuth2, OAuthConfig, TokenResponse};
//! use rocket_oauth2::hyper_rustls_adapter::HyperRustlsAdapter;
//!
//! # fn github_callback<'r>(request: &'r Request<'_>, token: TokenResponse) -> ResultFuture<'r>
//! # {
//! #     unimplemented!();
//! # }
//!
//! # fn check_only() {
//! rocket::ignite()
//! .attach(OAuth2::fairing(
//!     HyperRustlsAdapter,
//!     github_callback,
//!     "github",
//!
//!     // Set up a handler for the redirect uri
//!     "/auth/github",
//!
//!     // Set up a redirect from /login/github that will request the 'user:read' scope
//!     Some(("/login/github", vec!["user:read".to_string()])),
//! ))
//! # ;
//! # }
//! ```
//!
//! ### Provider selection
//!
//! Providers can be specified as a known provider name (case-insensitive).  The
//! known provider names are listed as associated constants on the
//! [`StaticProvider`] type.
//!
//! ```toml
//! [global.oauth.github]
//! # Using a known provider name
//! provider = "GitHub"
//! client_id = "..."
//! client_secret = "..."
//! redirect_uri = "http://localhost:8000/auth/github"
//! ```
//!
//! The provider can also be specified as a table with `auth_uri` and
//! `token_uri` values:
//!
//! ```toml
//! [global.oauth.custom]
//! provider = { auth_uri = "https://example.com/oauth/authorize", token_uri = "https://example.com/oauth/token" }
//! client_id = "..."
//! client_secret = "..."
//! redirect_uri = "http://localhost:8000/auth/custom"
//! ```

#![warn(future_incompatible, nonstandard_style, missing_docs)]

mod config;
mod core;
mod error;
mod provider;

pub use self::config::*;
pub use self::core::*;
pub use self::error::*;
pub use self::provider::*;

#[cfg(feature = "hyper_rustls_adapter")]
pub mod hyper_rustls_adapter;
