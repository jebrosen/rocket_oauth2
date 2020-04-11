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
//! Implement a callback route:
//!
//! ```rust
//! # #![feature(proc_macro_hygiene, decl_macro)]
//! # #[macro_use] extern crate rocket;
//! # extern crate rocket_oauth2;
//! # use rocket::http::{Cookie, Cookies, SameSite};
//! # use rocket::Request;
//! # use rocket::response::Redirect;
//! use rocket_oauth2::{OAuth2, TokenResponse};
//! use rocket_oauth2::hyper_sync_rustls_adapter::HyperSyncRustlsAdapter;
//!
//! struct GitHub;
//!
//! #[get("/auth/github")]
//! fn github_callback(token: TokenResponse<GitHub>, mut cookies: Cookies<'_>)
//!     -> Result<Redirect, Box<::std::error::Error>>
//! {
//!     // Set a private cookie with the access token
//!     cookies.add_private(
//!         Cookie::build("token", token.access_token().to_string())
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
//! # #![feature(proc_macro_hygiene, decl_macro)]
//! # #[macro_use] extern crate rocket;
//! # extern crate rocket_oauth2;
//! # use rocket::http::{Cookie, Cookies, SameSite};
//! # use rocket::Request;
//! # use rocket::response::Redirect;
//! use rocket::fairing::AdHoc;
//! use rocket_oauth2::{OAuth2, OAuthConfig, TokenResponse};
//!
//! # struct GitHub;
//!
//! # #[get("/auth/github")]
//! # fn github_callback(token: TokenResponse<GitHub>, mut cookies: Cookies<'_>)
//! #     -> Result<Redirect, Box<::std::error::Error>>
//! # {
//! #     unimplemented!();
//! # }
//!
//! # fn check_only() {
//! rocket::ignite()
//! .mount("/", routes![])
//! .attach(OAuth2::<GitHub>::fairing(
//!     "github",
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
mod error;

#[cfg(feature = "hyper_sync_rustls_adapter")]
pub mod hyper_sync_rustls_adapter;

pub use self::config::*;
pub use self::error::*;

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use rocket::fairing::{AdHoc, Fairing};
use rocket::handler;
use rocket::http::uri::Absolute;
use rocket::http::{Cookie, Cookies, Method, SameSite, Status};
use rocket::request::{self, FormItems, FromForm, FromRequest, Request};
use rocket::response::Redirect;
use rocket::{Data, Outcome, Route, State};
use serde_json::Value;

const STATE_COOKIE_NAME: &str = "rocket_oauth2_state";

// Random generation of state for defense against CSRF.
// See RFC 6749 §10.12 for more details.
fn generate_state(rng: &dyn SecureRandom) -> Result<String, Error> {
    let mut buf = [0; 16]; // 128 bits
    rng.fill(&mut buf).map_err(|_| {
        Error::new_from(
            ErrorKind::Other,
            String::from("Failed to generate random data"),
        )
    })?;
    Ok(base64::encode_config(&buf, base64::URL_SAFE_NO_PAD))
}

/// The token types which can be exchanged with the token endpoint
#[derive(Clone, PartialEq, Debug)]
pub enum TokenRequest {
    /// Used for the Authorization Code exchange
    AuthorizationCode(String),
    /// Used to refresh an access token
    RefreshToken(String),
}

/// The server's response to a successful token exchange, defined in
/// in RFC 6749 §5.1.
///
/// `TokenResponse<K>` implements `FromRequest`, and is used in the callback
/// route to complete the token exchange.
#[derive(Clone, PartialEq, Debug)]
pub struct TokenResponse<K> {
    data: Value,
    _k: PhantomData<fn() -> K>,
}

impl std::convert::TryFrom<Value> for TokenResponse<()> {
    type Error = Error;

    /// Construct a TokenResponse from a [Value].
    ///
    /// Returns an [Error] if data is not a JSON Object, or the access_token or token_type is
    /// missing or not a string.
    fn try_from(data: Value) -> Result<Self, Error> {
        if !data.is_object() {
            return Err(Error::new_from(
                ErrorKind::ExchangeFailure,
                String::from("TokenResponse data was not an object"),
            ));
        }
        match data.get("access_token") {
            Some(val) if val.is_string() => (),
            _ => {
                return Err(Error::new_from(
                    ErrorKind::ExchangeFailure,
                    String::from("TokenResponse access_token was missing or not a string"),
                ))
            }
        }
        match data.get("token_type") {
            Some(val) if val.is_string() => (),
            _ => {
                return Err(Error::new_from(
                    ErrorKind::ExchangeFailure,
                    String::from("TokenResponse token_type was missing or not a string"),
                ))
            }
        }

        Ok(Self { data, _k: PhantomData })
    }
}

impl<K> TokenResponse<K> {
    /// Reinterprets this `TokenResponse` as if it were keyed by `L` instead.
    /// This function can be used to "funnel" disparate `TokenResponse`s into a
    /// single concrete type such as `TokenResponse<()>`.
    pub fn cast<L>(self) -> TokenResponse<L> {
        TokenResponse { data: self.data, _k: PhantomData }
    }
}

impl<'a, 'r, K: 'static> FromRequest<'a, 'r> for TokenResponse<K> {
    type Error = Error;

    // TODO: Decide if BadRequest is the appropriate error code.
    // TODO: What do providers do if they *reject* the authorization?
    /// Handle the redirect callback, delegating to the adapter and callback to
    /// perform the token exchange and application-specific actions.
    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let oauth2 = request
            .guard::<State<Arc<Shared<K>>>>()
            .expect("OAuth2 fairing was not attached for this key type!")
            .inner();

        // Parse the query data.
        let query = match request.uri().query() {
            Some(q) => q,
            None => return Outcome::Failure((Status::BadRequest, Error::new_from(
                ErrorKind::ExchangeFailure, "Missing query string in request"
            ))),
        };

        #[derive(FromForm)]
        struct CallbackQuery {
            code: String,
            state: String,
            // Nonstandard (but see below)
            scope: Option<String>,
        }

        let params = match CallbackQuery::from_form(&mut FormItems::from(query), false) {
            Ok(p) => p,
            Err(e) => return Outcome::Failure((Status::BadRequest, Error::new_from(
                ErrorKind::ExchangeFailure, format!("{:?}", e)
            ))),
        };

        {
            // Verify that the given state is the same one in the cookie.
            // Begin a new scope so that cookies is not kept around too long.
            let mut cookies = request.guard::<Cookies<'_>>().expect("request cookies");
            match cookies.get_private(STATE_COOKIE_NAME) {
                Some(ref cookie) if cookie.value() == params.state => {
                    cookies.remove(cookie.clone());
                }
                _ => return Outcome::Failure((Status::BadRequest, Error::new_from(
                    ErrorKind::ExchangeFailure, "The state returned from the server did match the stored state."
                ))),
            }
        }

        // Have the adapter perform the token exchange.
        match oauth2
            .adapter
            .exchange_code(&oauth2.config, TokenRequest::AuthorizationCode(params.code))
        {
            Ok(mut token) => {
                // Some providers (at least Strava) provide 'scope' in the callback
                // parameters instead of the token response as the RFC prescribes.
                // Therefore the 'scope' from the callback params is used as a fallback
                // if the token response does not specify one.
                let data = token
                    .data
                    .as_object_mut()
                    .expect("data is guaranteed to be an Object");
                if let (None, Some(scope)) = (data.get("scope"), params.scope) {
                    data.insert(String::from("scope"), Value::String(scope));
                }
                Outcome::Success(token.cast())
            }
            Err(e) => Outcome::Failure((Status::BadRequest, e)),
        }
    }
}

impl<K> TokenResponse<K> {
    /// Get the TokenResponse data as a raw JSON [Value]. It is guaranteed to
    /// be of type Object.
    pub fn as_value(&self) -> &Value {
        &self.data
    }

    /// Get the access token issued by the authorization server.
    pub fn access_token(&self) -> &str {
        self.data
            .get("access_token")
            .and_then(Value::as_str)
            .expect("access_token required at construction")
    }

    /// Get the type of token, described in RFC 6749 §7.1.
    pub fn token_type(&self) -> &str {
        self.data
            .get("token_type")
            .and_then(Value::as_str)
            .expect("token_type required at construction")
    }

    /// Get the lifetime in seconds of the access token, if the authorization server provided one.
    pub fn expires_in(&self) -> Option<i64> {
        self.data.get("expires_in").and_then(Value::as_i64)
    }

    /// Get the refresh token, if the server provided one.
    pub fn refresh_token(&self) -> Option<&str> {
        self.data.get("refresh_token").and_then(Value::as_str)
    }

    /// Get the (space-separated) list of scopes associated with the access
    /// token.  The authorization server is required to provide this if it
    /// differs from the requested set of scopes.
    ///
    /// If `scope` was not provided by the server as a string, this method will
    /// return `None`. For those providers, use `.as_value().get("scope")
    /// instead.
    pub fn scope(&self) -> Option<&str> {
        self.data.get("scope").and_then(Value::as_str)
    }
}

/// An OAuth2 `Adapater` can be implemented by any type that facilitates the
/// Authorization Code Grant as described in RFC 6749 §4.1. The implementing
/// type must be able to generate an authorization URI and perform the token
/// exchange.
pub trait Adapter: Send + Sync + 'static {
    /// Generate an authorization URI as described by RFC 6749 §4.1.1
    /// given configuration, state, and scopes.
    fn authorization_uri(
        &self,
        config: &OAuthConfig,
        state: &str,
        scopes: &[&str],
    ) -> Result<Absolute<'static>, Error>;

    /// Perform the token exchange in accordance with RFC 6749 §4.1.3 given the
    /// authorization code provided by the service.
    fn exchange_code(
        &self,
        config: &OAuthConfig,
        token: TokenRequest,
    ) -> Result<TokenResponse<()>, Error>;
}

struct Shared<K> {
    adapter: Box<dyn Adapter>,
    config: OAuthConfig,
    login_scopes: Vec<String>,
    rng: SystemRandom,
    _k: PhantomData<fn() -> TokenResponse<K>>,
}

/// The `OAuth2` structure implements OAuth in a Rocket application by setting
/// up OAuth-related route handlers.
///
/// ## Redirect handler
/// `OAuth2` handles the redirect URI. It verifies the `state` token to prevent
/// CSRF attacks, then instructs the Adapter to perform the token exchange. The
/// resulting token is passed to the `Callback`.
///
/// ## Login handler
/// `OAuth2` optionally handles a login route, which simply redirects to the
/// authorization URI generated by the `Adapter`. Whether or not `OAuth2` is
/// handling a login URI, `get_redirect` can be used to get a `Redirect` to the
/// OAuth login flow manually.
pub struct OAuth2<K>(Arc<Shared<K>>);

#[cfg(feature = "hyper_sync_rustls_adapter")]
impl<K: 'static> OAuth2<K> {
    /// Returns an OAuth2 fairing. The fairing will place an instance of
    /// `OAuth2<K>` in managed state and mount a redirect handler. It will
    /// also mount a login handler if `login` is `Some`.
    pub fn fairing(
        config_name: &str,
        login: Option<(&str, Vec<String>)>,
    ) -> impl Fairing {
        // Unfortunate allocations, but necessary because on_attach requires 'static
        let config_name = config_name.to_string();
        let mut login = login.map(|(lu, ls)| (lu.to_string(), ls));

        AdHoc::on_attach("OAuth Init", move |rocket| {
            let config = match OAuthConfig::from_config(rocket.config(), &config_name) {
                Ok(c) => c,
                Err(e) => {
                    log::error!("Invalid configuration: {:?}", e);
                    return Err(rocket);
                }
            };

            let mut new_login = None;
            if let Some((lu, ls)) = login.as_mut() {
                let new_ls = std::mem::replace(ls, vec![]);
                new_login = Some((lu.as_str(), new_ls));
            };

            Ok(rocket.attach(Self::custom(
                hyper_sync_rustls_adapter::HyperSyncRustlsAdapter,
                config,
                new_login,
            )))
        })
    }
}

impl<K: 'static> OAuth2<K> {
    /// Returns an OAuth2 fairing with custom configuration. The fairing will
    /// place an instance of `OAuth2<C>` in managed state and mount a
    /// redirect handler. It will also mount a login handler if `login` is
    /// `Some`.
    pub fn custom<A: Adapter>(
        adapter: A,
        config: OAuthConfig,
        login: Option<(&str, Vec<String>)>,
    ) -> impl Fairing {
        let mut routes = Vec::new();

        let mut login_scopes = vec![];
        if let Some((uri, scopes)) = login {
            routes.push(Route::new(Method::Get, uri, login_handler::<K>));
            login_scopes = scopes;
        }

        let shared = Shared::<K> {
            adapter: Box::new(adapter),
            config,
            login_scopes,
            rng: SystemRandom::new(),
            _k: PhantomData,
        };

        AdHoc::on_attach("OAuth Mount", |rocket| {
            Ok(rocket.manage(Arc::new(shared)).mount("/", routes))
        })
    }

    /// Prepare an authentication redirect. This sets a state cookie and returns
    /// a `Redirect` to the provider's authorization page.
    pub fn get_redirect(
        &self,
        cookies: &mut Cookies<'_>,
        scopes: &[&str],
    ) -> Result<Redirect, Error> {
        let state = generate_state(&self.0.rng)?;
        let uri = self
            .0
            .adapter
            .authorization_uri(&self.0.config, &state, scopes)?;
        cookies.add_private(
            Cookie::build(STATE_COOKIE_NAME, state)
                .same_site(SameSite::Lax)
                .finish(),
        );
        Ok(Redirect::to(uri))
    }

    /// Request a new access token given a refresh token. The refresh token
    /// must have been returned by the provider in a previous [`TokenResponse`].
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenResponse<K>, Error> {
        self.0.adapter.exchange_code(
            &self.0.config,
            TokenRequest::RefreshToken(refresh_token.to_string()),
        ).map(TokenResponse::cast)
    }

}

impl<'a, 'r, K: 'static> FromRequest<'a, 'r> for OAuth2<K> {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        Outcome::Success(OAuth2(
            request
            .guard::<State<Arc<Shared<K>>>>()
            .expect("OAuth2 fairing was not attached for this key type!")
            .clone()
        ))
    }
}

impl<C: fmt::Debug> fmt::Debug for OAuth2<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OAuth2")
            .field("adapter", &(..))
            .field("config", &self.0.config)
            .field("login_scopes", &self.0.login_scopes)
            .finish()
    }
}

// These cannot be closures becuase of the lifetime parameter.
// TODO: cross-reference rust-lang/rust issues.

/// Handles a login route, performing a redirect
fn login_handler<'r, K: 'static>(request: &'r Request<'_>, _data: Data) -> handler::Outcome<'r> {
    let oauth = match request.guard::<OAuth2<K>>() {
        Outcome::Success(oauth) => oauth,
        Outcome::Failure(_) => return handler::Outcome::failure(Status::InternalServerError),
        Outcome::Forward(()) => unreachable!(),
    };
    let mut cookies = request.guard::<Cookies<'_>>().expect("request cookies");
    let scopes: Vec<_> = oauth.0.login_scopes.iter().map(String::as_str).collect();
    handler::Outcome::from(request, oauth.get_redirect(&mut cookies, &scopes))
}
