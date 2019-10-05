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
//! Rocket applications to perform application-specific actions when a token has
//! been exchanged successfully.
//!
//! Generally, a Rocket application will implement [`Callback`] on one type per
//! service the application will connect to. The [`OAuth2`] type registers
//! routes and handlers in the application for the OAuth2 redirect and an
//! optional login handler for convenience.
//!
//! ## Implementations
//!
//! `rocket_oauth2` currently provides only one [`Adapter`] itself:
//!
//! * `hyper_sync_rustls`: Uses [`hyper-sync-rustls`](https://github.com/SergioBenitez/hyper-sync-rustls).
//!
//! `hyper_sync_rustls` was chosen because it is already a dependency of Rocket.
//! In general, custom `Adapter`s should only be needed to work around
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
//! # use rocket::response::Redirect;
//! use rocket_oauth2::{Callback, OAuth2, TokenResponse};
//! use rocket_oauth2::hyper_sync_rustls_adapter::HyperSyncRustlsAdapter;
//!
//! fn github_callback(request: &Request, token: TokenResponse)
//!     -> Result<Redirect, Box<::std::error::Error>>
//! {
//!     let mut cookies = request.guard::<Cookies>().expect("request cookies");
//!
//!     // Set a private cookie with the access token
//!     cookies.add_private(
//!         Cookie::build("token", token.access_token)
//!             .same_site(SameSite::Lax)
//!             .finish()
//!     );
//!     Ok(Redirect::to("/"))
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
//! # use rocket::http::{Cookie, Cookies, SameSite};
//! # use rocket::Request;
//! # use rocket::response::Redirect;
//! use rocket::fairing::AdHoc;
//! use rocket_oauth2::{Callback, OAuth2, OAuthConfig, TokenResponse};
//! use rocket_oauth2::hyper_sync_rustls_adapter::HyperSyncRustlsAdapter;
//!
//! # fn github_callback(request: &Request, token: TokenResponse)
//! #     -> Result<Redirect, Box<::std::error::Error>>
//! # {
//! #     unimplemented!();
//! # }
//!
//! # fn check_only() {
//! rocket::ignite()
//! .attach(OAuth2::fairing(
//!     HyperSyncRustlsAdapter,
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

#![warn(future_incompatible, nonstandard_style, missing_docs)]

mod config;
mod core;
mod error;
mod provider;

pub use self::config::*;
pub use self::core::*;
pub use self::error::*;
pub use self::provider::*;

#[cfg(feature = "hyper_sync_rustls_adapter")]
pub mod hyper_sync_rustls_adapter;

fn generate_state() -> String {
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    thread_rng().sample_iter(&Alphanumeric).take(20).collect()
}
