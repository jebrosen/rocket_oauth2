use std::fmt::{self, Debug};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ring::rand::{SecureRandom, SystemRandom};
use rocket::fairing::{AdHoc, Fairing};
use rocket::handler;
use rocket::http::uri::Absolute;
use rocket::http::{Cookie, Cookies, Method, SameSite, Status};
use rocket::outcome::{IntoOutcome, Outcome};
use rocket::request::{FormItems, FromForm, Request};
use rocket::response::{Redirect, Response};
use rocket::{Data, Route, State};
use serde_json::Value;

use crate::{Error, ErrorKind, OAuthConfig};

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
#[derive(Clone, PartialEq, Debug, serde::Deserialize)]
pub struct TokenResponse {
    data: Value,
}

impl std::convert::TryFrom<Value> for TokenResponse {
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

        Ok(Self { data })
    }
}

impl TokenResponse {
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
#[rocket::async_trait]
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
    async fn exchange_code<'a>(
        &'a self,
        config: &'a OAuthConfig,
        token: TokenRequest,
    ) -> Result<TokenResponse, Error>;
}

/// An OAuth2 `Callback` implements application-specific OAuth client logic,
/// such as setting login cookies and making database and API requests. It is
/// tied to a specific `Adapter`, and will recieve an instance of the Adapter's
/// `Token` type.
pub trait Callback: Send + Sync + 'static {
    /// This method will be called when a token exchange has successfully
    /// completed and will be provided with the request and the token.
    /// Implementors should perform application-specific logic here, such as
    /// checking a database or setting a login cookie.
    fn callback<'r>(
        &self,
        request: &'r Request<'_>,
        token: TokenResponse,
    ) -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>>;
}

impl<F> Callback for F
where
    F: (for<'r> Fn(
            &'r Request<'_>,
            TokenResponse,
        )
            -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>>)
        + Send
        + Sync
        + 'static,
{
    fn callback<'r>(
        &self,
        request: &'r Request<'_>,
        token: TokenResponse,
    ) -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>> {
        (self)(request, token)
    }
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
pub struct OAuth2<C> {
    adapter: Box<dyn Adapter>,
    callback: C,
    config: OAuthConfig,
    login_scopes: Vec<String>,
    rng: SystemRandom,
}

impl<C: Callback> OAuth2<C> {
    /// Returns an OAuth2 fairing. The fairing will place an instance of
    /// `OAuth2<C>` in managed state and mount a redirect handler. It will
    /// also mount a login handler if `login` is `Some`.
    pub fn fairing<A: Adapter>(
        adapter: A,
        callback: C,
        config_name: &str,
        callback_uri: &str,
        login: Option<(&str, Vec<String>)>,
    ) -> impl Fairing {
        // Unfortunate allocations, but necessary because on_attach requires 'static
        let config_name = config_name.to_string();
        let callback_uri = callback_uri.to_string();
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
                adapter,
                callback,
                config,
                &callback_uri,
                new_login,
            )))
        })
    }

    /// Returns an OAuth2 fairing with custom configuration. The fairing will
    /// place an instance of `OAuth2<C>` in managed state and mount a
    /// redirect handler. It will also mount a login handler if `login` is
    /// `Some`.
    pub fn custom<A: Adapter>(
        adapter: A,
        callback: C,
        config: OAuthConfig,
        callback_uri: &str,
        login: Option<(&str, Vec<String>)>,
    ) -> impl Fairing {
        let mut routes = Vec::new();

        routes.push(Route::new(Method::Get, callback_uri, redirect_handler::<C>));

        let mut login_scopes = vec![];
        if let Some((uri, scopes)) = login {
            routes.push(Route::new(Method::Get, uri, login_handler::<C>));
            login_scopes = scopes;
        }

        let oauth2 = Self {
            adapter: Box::new(adapter),
            callback,
            config,
            login_scopes,
            rng: SystemRandom::new(),
        };

        AdHoc::on_attach("OAuth Mount", |rocket| {
            Ok(rocket.manage(Arc::new(oauth2)).mount("/", routes))
        })
    }

    /// Prepare an authentication redirect. This sets a state cookie and returns
    /// a `Redirect` to the provider's authorization page.
    pub fn get_redirect(
        &self,
        cookies: &mut Cookies<'_>,
        scopes: &[&str],
    ) -> Result<Redirect, Error> {
        let state = generate_state(&self.rng)?;
        let uri = self
            .adapter
            .authorization_uri(&self.config, &state, scopes)?;
        cookies.add_private(
            Cookie::build(STATE_COOKIE_NAME, state)
                .same_site(SameSite::Lax)
                .finish(),
        );
        Ok(Redirect::to(uri))
    }

    /// Request a new access token given a refresh token. The refresh token
    /// must have been returned by the provider in a previous [`TokenResponse`].
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, Error> {
        self.adapter
            .exchange_code(
                &self.config,
                TokenRequest::RefreshToken(refresh_token.to_string()),
            )
            .await
    }

    // TODO: Decide if BadRequest is the appropriate error code.
    // TODO: What do providers do if they *reject* the authorization?
    /// Handle the redirect callback, delegating to the adapter and callback to
    /// perform the token exchange and application-specific actions.
    async fn handle<'r>(
        self: Arc<Self>,
        request: &'r Request<'_>,
        _data: Data,
    ) -> handler::Outcome<'r> {
        // Parse the query data.
        let query = rocket::try_outcome!(request.uri().query().into_outcome(Status::BadRequest));

        #[derive(FromForm)]
        struct CallbackQuery {
            code: String,
            state: String,
            // Nonstandard (but see below)
            scope: Option<String>,
        }

        let params = match CallbackQuery::from_form(&mut FormItems::from(query), false) {
            Ok(p) => p,
            Err(_) => return handler::Outcome::failure(Status::BadRequest),
        };

        {
            // Verify that the given state is the same one in the cookie.
            // Begin a new scope so that cookies is not kept around too long.
            let mut cookies = request
                .guard::<Cookies<'_>>()
                .await
                .expect("request cookies");
            match cookies.get_private(STATE_COOKIE_NAME) {
                Some(ref cookie) if cookie.value() == params.state => {
                    cookies.remove(cookie.clone());
                }
                _ => return handler::Outcome::failure(Status::BadRequest),
            }
        }

        // Have the adapter perform the token exchange.
        let token = match self
            .adapter
            .exchange_code(&self.config, TokenRequest::AuthorizationCode(params.code))
            .await
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
                token
            }
            Err(e) => {
                log::error!("Token exchange failed: {:?}", e);
                return handler::Outcome::failure(Status::BadRequest);
            }
        };

        // Run the callback.
        let responder = self.callback.callback(request, token).await;
        handler::Outcome::from(request, responder).await
    }
}

impl<C: fmt::Debug> fmt::Debug for OAuth2<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OAuth2")
            .field("adapter", &(..))
            .field("callback", &self.callback)
            .field("config", &self.config)
            .field("login_scopes", &self.login_scopes)
            .finish()
    }
}

// These cannot be closures becuase of the lifetime parameter.
// TODO: cross-reference rust-lang/rust issues.

/// Handles the OAuth redirect route
fn redirect_handler<'r, C: Callback>(
    request: &'r Request<'_>,
    data: Data,
) -> handler::HandlerFuture<'r> {
    Box::pin(async move {
        let oauth = match request.guard::<State<'_, Arc<OAuth2<C>>>>().await {
            Outcome::Success(oauth) => oauth.clone(),
            Outcome::Failure(_) => return handler::Outcome::failure(Status::InternalServerError),
            Outcome::Forward(()) => unreachable!(),
        };
        oauth.handle(request, data).await
    })
}

/// Handles a login route, performing a redirect
fn login_handler<'r, C: Callback>(
    request: &'r Request<'_>,
    _data: Data,
) -> handler::HandlerFuture<'r> {
    Box::pin(async move {
        let oauth = match request.guard::<State<'_, Arc<OAuth2<C>>>>().await {
            Outcome::Success(oauth) => oauth,
            Outcome::Failure(_) => return handler::Outcome::failure(Status::InternalServerError),
            Outcome::Forward(()) => unreachable!(),
        };
        let mut cookies = request
            .guard::<Cookies<'_>>()
            .await
            .expect("request cookies");
        let scopes: Vec<_> = oauth.login_scopes.iter().map(String::as_str).collect();
        handler::Outcome::try_from(request, oauth.get_redirect(&mut cookies, &scopes)).await
    })
}
