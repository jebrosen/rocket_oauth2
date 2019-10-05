//! [Adapter] implemented using [`hyper-sync-rustls`](https://github.com/SergioBenitez/hyper-sync-rustls).

use hyper;
use hyper_sync_rustls;

use std::io::Read;

use rocket::http::ext::IntoOwned;
use rocket::http::uri::Absolute;
use url::form_urlencoded::Serializer as UrlSerializer;
use url::Url;

use self::hyper::{
    header::{Accept, ContentType},
    net::HttpsConnector,
    Client,
};
use super::{generate_state, Adapter, Error, ErrorKind, OAuthConfig, TokenResponse, TokenRequest};

/// `Adapter` implementation that uses `hyper` and `rustls` to perform the token exchange.
#[derive(Clone, Debug)]
pub struct HyperSyncRustlsAdapter;

impl Adapter for HyperSyncRustlsAdapter {
    fn authorization_uri(
        &self,
        config: &OAuthConfig,
        scopes: &[&str],
    ) -> Result<(Absolute<'static>, String), Error> {
        let state = generate_state();

        let mut url = Url::parse(&config.provider().auth_uri)
            .map_err(|e| Error::new_from(ErrorKind::InvalidUri(config.provider().auth_uri.to_string()), e))?;

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", config.client_id())
            .append_pair("redirect_uri", config.redirect_uri())
            .append_pair("state", &state);

        if !scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &scopes.join(" "));
        }

        Ok((
            Absolute::parse(url.as_ref())
                .map_err(|_| Error::new(ErrorKind::InvalidUri(url.to_string())))?
                .into_owned(),
            state,
        ))
    }

    fn exchange_code(
        &self,
        config: &OAuthConfig,
        token: TokenRequest
    ) -> Result<TokenResponse, Error> {
        let https = HttpsConnector::new(hyper_sync_rustls::TlsClient::new());
        let client = Client::with_connector(https);

        let mut ser = UrlSerializer::new(String::new());
        match token {
            TokenRequest::AuthorizationCode(code) => {
                ser.append_pair("grant_type", "authorization_code");
                ser.append_pair("code", &code);
                ser.append_pair("redirect_uri", config.redirect_uri());
            }
            TokenRequest::RefreshToken(token) => {
                ser.append_pair("grant_type", "refresh_token");
                ser.append_pair("refresh_token", &token);
            }
        }
        ser.append_pair("client_id", config.client_id());
        ser.append_pair("client_secret", config.client_secret());

        let req_str = ser.finish();

        let request = client
            .post(config.provider().token_uri.as_ref())
            .header(Accept::json())
            .header(ContentType::form_url_encoded())
            .body(&req_str);

        let response = request.send().map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;

        if !response.status.is_success() {
            return Err(Error::new(ErrorKind::ExchangeError(response.status.to_u16())))
        }

        let token =
            serde_json::from_reader(response.take(2 * 1024 * 1024))
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;
        Ok(token)
    }
}
