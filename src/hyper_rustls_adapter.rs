use std::convert::TryInto;

use hyper::{
    body::HttpBody,
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    Body, Client, Request,
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
/// [`basic_auth`]: HyperRustlsAdapter::basic_auth()

#[derive(Clone, Debug)]
pub struct HyperRustlsAdapter {
    use_basic_auth: bool,
    client: Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
}

impl Default for HyperRustlsAdapter {
    fn default() -> Self {
        Self {
            use_basic_auth: true,
            // TODO: consider making the root store configurable
            client: Client::builder().build(hyper_rustls::HttpsConnector::with_native_roots()),
        }
    }
}

impl HyperRustlsAdapter {
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
    /// use rocket_oauth2::{HyperRustlsAdapter, OAuth2, OAuthConfig, StaticProvider};
    ///
    /// struct MyProvider;
    ///
    /// #[rocket::launch]
    /// fn rocket() -> _ {
    ///     rocket::build()
    ///         .attach(AdHoc::on_ignite("OAuth Config", |mut rocket| async {
    ///             let config = OAuthConfig::from_figment(rocket.figment(), "my_provider").unwrap();
    ///             rocket.attach(OAuth2::<MyProvider>::custom(
    ///                 HyperRustlsAdapter::default().basic_auth(false), config)
    ///             )
    ///         }))
    /// }
    /// ```
    pub fn basic_auth(self, use_basic_auth: bool) -> Self {
        Self {
            use_basic_auth,
            ..self
        }
    }
}

#[async_trait::async_trait]
impl Adapter for HyperRustlsAdapter {
    fn authorization_uri(
        &self,
        config: &OAuthConfig,
        state: &str,
        scopes: &[&str],
        extra_params: &[(&str, &str)],
    ) -> Result<Absolute<'static>, Error> {
        let auth_uri = config.provider().auth_uri();

        let mut url = Url::parse(&auth_uri)
            .map_err(|e| Error::new_from(ErrorKind::InvalidUri(auth_uri.to_string()), e))?;

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", config.client_id())
            .append_pair("state", state);

        if let Some(redirect_uri) = config.redirect_uri() {
            url.query_pairs_mut()
                .append_pair("redirect_uri", redirect_uri);
        }

        if !scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &scopes.join(" "));
        }

        // Request parameters must not be included more than once. This
        // adapter chooses to ignore duplicates instead of overwriting.
        for (name, value) in extra_params {
            match *name {
                "response_type" | "client_id" | "state" => continue,
                "redirect_uri" if config.redirect_uri().is_some() => continue,
                "scope" if !scopes.is_empty() => continue,
                _ => url.query_pairs_mut().append_pair(name, value),
            };
        }

        Ok(Absolute::parse(url.as_ref())
            .map_err(|_| Error::new(ErrorKind::InvalidUri(url.to_string())))?
            .into_owned())
    }

    async fn exchange_code(
        &self,
        config: &OAuthConfig,
        token: TokenRequest,
    ) -> Result<TokenResponse<()>, Error> {
        let mut request = Request::post(&*config.provider().token_uri())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded");

        let req_str = {
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
                let encoded =
                    base64::encode(format!("{}:{}", config.client_id(), config.client_secret()));
                request = request.header(AUTHORIZATION, format!("Basic {}", encoded))
            } else {
                ser.append_pair("client_id", config.client_id());
                ser.append_pair("client_secret", config.client_secret());
            }

            ser.finish()
        };

        let request = request
            .body(Body::from(req_str))
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;
        if !response.status().is_success() {
            return Err(Error::new(ErrorKind::ExchangeError(
                response.status().as_u16(),
            )));
        }

        let mut body = response.into_body();
        let mut bytes = vec![];
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err(Error::new_from(
                    ErrorKind::ExchangeFailure,
                    "Response body was too large.",
                ));
            }
            bytes.extend(chunk);
        }

        let data: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;
        Ok(data.try_into()?)
    }
}
