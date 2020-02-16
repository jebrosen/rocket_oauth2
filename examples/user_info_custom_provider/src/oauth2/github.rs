
use std::io::Read;

use hyper::{
    header::{qitem, Accept, Authorization, UserAgent},
    mime::Mime,
    net::HttpsConnector,
    Client,
};
use hyper_sync_rustls;
use rocket::http::{Cookie, Cookies, SameSite};
use rocket::request::Request;
use rocket::response::Redirect;
use rocket_oauth2::hyper_sync_rustls_adapter::HyperSyncRustlsAdapter;
use rocket_oauth2::{OAuth2, TokenResponse};
use serde_json;

use rocket::fairing::Fairing;

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
        HyperSyncRustlsAdapter,
        post_install_callback,
        "github",
        "/auth/github",
        Some(("/login/github", vec![String::from("user:read")])),
    )
}

/// Callback to handle the authenticated token recieved from GitHub
/// and store it as a private cookie
fn post_install_callback(
    request: &Request<'_>,
    token: TokenResponse,
) -> Result<Redirect, Box<dyn (::std::error::Error)>> {
    let https = HttpsConnector::new(hyper_sync_rustls::TlsClient::new());
    let client = Client::with_connector(https);

    // Use the token to retrieve the user's GitHub account information.
    let mime: Mime = "application/vnd.github.v3+json"
        .parse()
        .expect("parse GitHub MIME type");
    let response = client
        .get("https://api.github.com/user")
        .header(Authorization(format!("token {}", token.access_token())))
        .header(Accept(vec![qitem(mime)]))
        .header(UserAgent("rocket_oauth2 demo application".into()))
        .send()?;

    if !response.status.is_success() {
        return Err(format!("got non-success status {}", response.status).into());
    }

    let user_info: GitHubUserInfo = serde_json::from_reader(response.take(2 * 1024 * 1024))?;

    // Set a private cookie with the user's name, and redirect to the home page.
    let mut cookies = request.guard::<Cookies<'_>>().expect("request cookies");
    cookies.add_private(
        Cookie::build("username", user_info.name)
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}
