use std::convert::TryInto;
use std::io::Read;

use hyper::{
    header::{Accept, Authorization, Basic, ContentType},
    net::HttpsConnector,
    Client,
};
use rocket::http::ext::IntoOwned;
use rocket::http::uri::Absolute;
use url::form_urlencoded::Serializer as UrlSerializer;
use url::Url;

use super::{Adapter, Error, ErrorKind, OAuthConfig, TokenRequest, TokenResponse};

/// The default `Adapter` implementation. Uses `hyper` and `rustls` to perform the token exchange.
///
/// By defualt, this adapter will use HTTP Basic Authentication. If this is
/// not supported by your authorization server, the [`basic_auth`] method
/// can be used to change this behavior.
///
/// [`basic_auth`]: HyperSyncRustlsAdapter::basic_auth()
#[derive(Clone, Debug)]
pub struct HyperSyncRustlsAdapter {
    use_basic_auth: bool,
}

impl Default for HyperSyncRustlsAdapter {
    fn default() -> Self {
        Self {
            use_basic_auth: true,
        }
    }
}

impl HyperSyncRustlsAdapter {
    /// Sets whether or not this adapter will use HTTP Basic Authentication.
    /// Although servers are required to support it (RFC 6749 §2.3.1), not all
    /// do.
    ///
    /// If this is set to `false`, the `client_id` and `client_secret` will be
    /// sent as part of the request body instead of an `Authorization` header.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use rocket::fairing::AdHoc;
    /// use rocket_oauth2::{HyperSyncRustlsAdapter, OAuth2, OAuthConfig, StaticProvider};
    ///
    /// struct MyProvider;
    ///
    /// fn main() {
    ///     rocket::ignite()
    ///         .attach(AdHoc::on_attach("OAuth Config", |rocket| {
    ///             let config = OAuthConfig::from_config(rocket.config(), "my_provider").unwrap();
    ///             Ok(rocket.attach(OAuth2::<MyProvider>::custom(
    ///                 HyperSyncRustlsAdapter::default().basic_auth(false), config)
    ///             ))
    ///         }))
    ///         .launch();
    /// }
    /// ```
    pub fn basic_auth(self, use_basic_auth: bool) -> Self {
        Self {
            use_basic_auth,
            ..self
        }
    }
}

impl Adapter for HyperSyncRustlsAdapter {
    fn authorization_uri(
        &self,
        config: &OAuthConfig,
        state: &str,
        scopes: &[&str],
    ) -> Result<Absolute<'static>, Error> {
        let auth_uri = config.provider().auth_uri();

        let mut url = Url::parse(&auth_uri)
            .map_err(|e| Error::new_from(ErrorKind::InvalidUri(auth_uri.to_string()), e))?;

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", config.client_id())
            .append_pair("state", state);

        if let Some(redirect_uri) = config.redirect_uri() {
            url.query_pairs_mut().append_pair("redirect_uri", redirect_uri);
        }

        if !scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &scopes.join(" "));
        }

        Ok(Absolute::parse(url.as_ref())
            .map_err(|_| Error::new(ErrorKind::InvalidUri(url.to_string())))?
            .into_owned())
    }

    fn exchange_code(
        &self,
        config: &OAuthConfig,
        token: TokenRequest,
    ) -> Result<TokenResponse<()>, Error> {
        let https = HttpsConnector::new(hyper_sync_rustls::TlsClient::new());
        let client = Client::with_connector(https);

        let mut request = client
            .post(config.provider().token_uri().as_ref())
            .header(Accept::json())
            .header(ContentType::form_url_encoded());

        let mut ser = UrlSerializer::new(String::new());
        match token {
            TokenRequest::AuthorizationCode(code) => {
                ser.append_pair("grant_type", "authorization_code");
                ser.append_pair("code", &code);
                if let Some(redirect_uri) = config.redirect_uri() {
                    ser.append_pair("redirect_uri", redirect_uri);
                }
            }
            TokenRequest::RefreshToken(token) => {
                ser.append_pair("grant_type", "refresh_token");
                ser.append_pair("refresh_token", &token);
            }
        }

        if self.use_basic_auth {
            request = request
                .header(Authorization(Basic {
                    username: config.client_id().to_string(),
                    password: Some(config.client_secret().to_string()),
                }));
        } else {
            ser.append_pair("client_id", config.client_id());
            ser.append_pair("client_secret", config.client_secret());
        }

        let req_str = ser.finish();

        let request = request.body(&req_str);

        let response = request
            .send()
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;

        if !response.status.is_success() {
            return Err(Error::new(ErrorKind::ExchangeError(
                response.status.to_u16(),
            )));
        }

        let data: serde_json::Value = serde_json::from_reader(response.take(2 * 1024 * 1024))
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;
        Ok(data.try_into()?)
    }
}
