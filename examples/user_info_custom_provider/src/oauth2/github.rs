use std::future::Future;
use std::pin::Pin;

use futures_util::stream::TryStreamExt;
use hyper::{
    header::{ACCEPT, AUTHORIZATION, USER_AGENT},
    Body, Client,
};
use hyper_rustls::HttpsConnector;
use rocket::fairing::Fairing;
use rocket::http::{Cookie, Cookies, SameSite, Status};
use rocket::request::Request;
use rocket::response::{self, Redirect, Responder, Response};
use rocket_oauth2::hyper_rustls_adapter::HyperRustlsAdapter;
use rocket_oauth2::{OAuth2, TokenResponse};
use serde_json;

/// User information to be retrieved from the GitHub API.
#[derive(serde::Deserialize)]
struct GitHubUserInfo {
    #[serde(default)]
    name: String,
}

/// Rocket fairing for managing the GitHub OAuth2 flow
///
/// The third argument passed into OAuth2::fairing is the
/// config_name which must match the key used in Rocket.toml
/// to specify the custom provider attributes.
pub fn fairing() -> impl Fairing {
    OAuth2::fairing(
        HyperRustlsAdapter,
        post_install_callback,
        "github",
        "/auth/github",
        Some(("/login/github", vec![String::from("user:read")])),
    )
}

/// Callback to handle the authenticated token recieved from GitHub
/// and store it as a private cookie
fn post_install_callback<'r>(
    request: &'r Request<'_>,
    token: TokenResponse,
) -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>> {
    Box::pin(async move {
        let result: Result<_, Box<dyn std::error::Error + Send + Sync>> = async {
            let https = HttpsConnector::new();
            let client = Client::builder().build(https);

            // Use the token to retrieve the user's GitHub account information.
            let req = hyper::Request::get("https://api.github.com/user")
                .header(AUTHORIZATION, format!("token {}", token.access_token()))
                .header(ACCEPT, "application/vnd.github.v3+json")
                .header(USER_AGENT, "rocket_oauth2 demo application")
                .body(Body::empty())?;

            let response = client.request(req).await?;

            if !response.status().is_success() {
                return Err(format!("got non-success status {}", response.status()).into());
            }

            let body = response
                .into_body()
                .try_fold(Vec::new(), |mut data, chunk| async move {
                    data.extend_from_slice(&chunk);
                    Ok(data)
                })
                .await?;

            let user_info: GitHubUserInfo = serde_json::from_slice(&body)?;

            // Set a private cookie with the user's name, and redirect to the home page.
            let mut cookies = request
                .guard::<Cookies<'_>>()
                .await
                .expect("request cookies");
            cookies.add_private(
                Cookie::build("username", user_info.name)
                    .same_site(SameSite::Lax)
                    .finish(),
            );
            Ok(Redirect::to("/"))
        }
        .await;
        result
            .map_err(response::Debug::from)
            .respond_to(request)
            .await
    })
}
