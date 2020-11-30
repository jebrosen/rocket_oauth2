use anyhow::{Context, Error};
use hyper::{
    body,
    header::{ACCEPT, AUTHORIZATION, USER_AGENT},
    Body,
    Client,
    Request,
};
use rocket::fairing::{AdHoc, Fairing};
use rocket::http::{Cookie, CookieJar, SameSite};
use rocket::response::{Debug, Redirect};
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
    AdHoc::on_attach("Github OAuth2", |rocket| async {
        Ok(rocket
            .mount("/", rocket::routes![github_login, post_install_callback])
            .attach(OAuth2::<GitHubUserInfo>::fairing("github")))
    })
}

#[rocket::get("/login/github")]
fn github_login(oauth2: OAuth2<GitHubUserInfo>, cookies: &CookieJar<'_>) -> Redirect {
    oauth2.get_redirect(cookies, &["user:read"]).unwrap()
}

/// Callback to handle the authenticated token recieved from GitHub
/// and store it as a private cookie
#[rocket::get("/auth/github")]
async fn post_install_callback(
    token: TokenResponse<GitHubUserInfo>,
    cookies: &CookieJar<'_>,
) -> Result<Redirect, Debug<Error>> {
    let client = Client::builder().build(hyper_rustls::HttpsConnector::new());

    // Use the token to retrieve the user's GitHub account information.
    let request = Request::get("https://api.github.com/user")
        .header(AUTHORIZATION, format!("token {}", token.access_token()))
        .header(ACCEPT, "application/vnd.github.v3+json")
        .header(USER_AGENT, "rocket_oauth2 demo application")
        .body(Body::empty())
        .expect("build GET request");

    let response = client.request(request).await.context("failed to send request to API")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "got non-success status {}",
            response.status()
        ))?;
    }

    let body = body::to_bytes(response.into_body()).await
        .context("failed to read response body")?;

    let user_info: GitHubUserInfo = serde_json::from_slice(&body)
        .context("failed to deserialize response")?;

    // Set a private cookie with the user's name, and redirect to the home page.
    cookies.add_private(
        Cookie::build("username", user_info.name)
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}
