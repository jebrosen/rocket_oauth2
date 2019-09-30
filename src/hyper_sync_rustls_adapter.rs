//! [Adapter] implemented using [`hyper-sync-rustls`](https://github.com/SergioBenitez/hyper-sync-rustls).

use hyper;
use hyper_sync_rustls;

use std::io::Read;

use rocket::http::ext::IntoOwned;
use rocket::http::uri::{Absolute, Error as RocketUriError};
use serde_json::Error as SerdeJsonError;
use url::form_urlencoded::Serializer as UrlSerializer;
use url::{Url, ParseError};

use self::hyper::{
    header::{Accept, ContentType},
    net::HttpsConnector,
    status::StatusCode,
    Client, Error as HyperError,
};
use super::{generate_state, Adapter, OAuthConfig, TokenResponse};

#[derive(Debug)]
enum ErrorKind {
    /// An error in the provided authorization URI
    UriError(ParseError),
    /// An error in the completed authorization URI
    RocketUriError(RocketUriError<'static>),
    /// An error in the token exchange request
    RequestError(HyperError),
    /// A non-success response type
    UnsuccessfulRequest(StatusCode),
    /// An error in deserialization
    DeserializationError(SerdeJsonError),

    #[doc(hidden)]
    __Nonexhaustive,
}

/// Error type for HyperSyncRustlsAdapter
#[derive(Debug)]
pub struct Error { kind: ErrorKind }

impl From<ErrorKind> for Error {
    fn from(ek: ErrorKind) -> Error {
        Error { kind: ek }
    }
}

/// `Adapter` implementation that uses `hyper` and `rustls` to perform the token exchange.
pub struct HyperSyncRustlsAdapter;

impl Adapter for HyperSyncRustlsAdapter {
    type Error = Error;

    fn authorization_uri(
        &self,
        config: &OAuthConfig,
        scopes: &[&str],
    ) -> Result<(Absolute<'static>, String), Self::Error> {
        let state = generate_state();

        let mut url = Url::parse(&config.provider().auth_uri).map_err(ErrorKind::UriError)?;
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
                .map_err(|e| ErrorKind::RocketUriError(e.into_owned()))?
                .into_owned(),
            state,
        ))
    }

    fn exchange_code(
        &self,
        config: &OAuthConfig,
        code: &str,
    ) -> Result<TokenResponse, Self::Error> {
        let https = HttpsConnector::new(hyper_sync_rustls::TlsClient::new());
        let client = Client::with_connector(https);

        let mut ser = UrlSerializer::new(String::new());
        ser.append_pair("grant_type", "authorization_code");
        ser.append_pair("code", code);
        ser.append_pair("redirect_uri", config.redirect_uri());
        ser.append_pair("client_id", config.client_id());
        ser.append_pair("client_secret", config.client_secret());

        let req_str = ser.finish();

        let request = client
            .post(config.provider().token_uri.as_ref())
            .header(Accept::json())
            .header(ContentType::form_url_encoded())
            .body(&req_str);

        let response = request.send().map_err(ErrorKind::RequestError)?;
        if !response.status.is_success() {
            return Err(ErrorKind::UnsuccessfulRequest(response.status).into())
        }

        let token =
            serde_json::from_reader(response.take(2 * 1024 * 1024)).map_err(ErrorKind::DeserializationError)?;
        Ok(token)
    }
}
