//! [Adapter] implemented using [`hyper-rustls`](https://github.com/ctz/hyper-rustls).

use hyper;
use hyper_rustls;

use std::future::Future;
use std::pin::Pin;

use futures_util::try_stream::TryStreamExt;
use http::Error as HttpError;
use rocket::http::ext::IntoOwned;
use rocket::http::uri::{Absolute, Error as RocketUriError};
use serde_json::Error as SerdeJsonError;
use url::form_urlencoded::Serializer as UrlSerializer;
use url::{Url, ParseError};

use self::hyper::{
    header::{ACCEPT, CONTENT_TYPE},
    Body, Client, Error as HyperError,
    Request, StatusCode,
};
use self::hyper_rustls::HttpsConnector;
use super::{generate_state, Adapter, OAuthConfig, TokenResponse};

#[derive(Debug)]
enum ErrorKind {
    /// An error in the provided authorization URI
    UriError(ParseError),
    /// An error in the completed authorization URI
    RocketUriError(RocketUriError<'static>),
    /// An error in the token exchange URI building
    RequestUriError(HttpError),
    /// An error in the token exchange request
    RequestError(HyperError),
    /// A non-success response type
    UnsuccessfulRequest(StatusCode),
    /// Failure to stream or buffer response data, or too large
    UnsuccessfulStream,
    /// An error in deserialization
    DeserializationError(SerdeJsonError),

    #[doc(hidden)]
    __Nonexhaustive,
}

/// Error type for HyperRustlsAdapter
#[derive(Debug)]
pub struct Error { kind: ErrorKind }

impl From<ErrorKind> for Error {
    fn from(ek: ErrorKind) -> Error {
        Error { kind: ek }
    }
}

/// `Adapter` implementation that uses `hyper` and `rustls` to perform the token exchange.
#[derive(Clone, Debug)]
pub struct HyperRustlsAdapter;

impl Adapter for HyperRustlsAdapter {
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

    fn exchange_code<'a>(
        &'a self,
        config: &'a OAuthConfig,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output=Result<TokenResponse, Self::Error>> + Send + 'a>> {
        let mut ser = UrlSerializer::new(String::new());
        ser.append_pair("grant_type", "authorization_code");
        ser.append_pair("code", code);
        ser.append_pair("redirect_uri", config.redirect_uri());
        ser.append_pair("client_id", config.client_id());
        ser.append_pair("client_secret", config.client_secret());

        let req_str = ser.finish();

        Box::pin(async move {
            let https = HttpsConnector::new();
            let client: Client<_, Body> = Client::builder().build(https);

            let request = Request::post(config.provider().token_uri.as_ref())
                .header(ACCEPT, "application/json")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(req_str.into())
                .map_err(ErrorKind::RequestUriError)?;

            let response = client.request(request).await
                .map_err(ErrorKind::RequestError)?;

            if !response.status().is_success() {
                return Err(ErrorKind::UnsuccessfulRequest(response.status()).into())
            }

            let mut stream = response.into_body().map_err(|_| ErrorKind::UnsuccessfulStream);
            let mut body = Vec::with_capacity(1024);
            while let Some(chunk) = stream.try_next().await? {
                if body.len() + chunk.len() > 2 * 1024 * 1024 {
                    return Err(ErrorKind::UnsuccessfulStream.into());
                }
                body.extend(&chunk[..]);
            }

            let token = serde_json::from_slice(&body).map_err(ErrorKind::DeserializationError)?;
            Ok(token)
        })
    }
}
