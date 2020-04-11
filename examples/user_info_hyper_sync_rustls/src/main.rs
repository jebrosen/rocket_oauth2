#![feature(decl_macro, proc_macro_hygiene)]

use std::io::Read;

use hyper::{
    header::{qitem, Accept, Authorization, Bearer, UserAgent},
    mime::Mime,
    net::HttpsConnector,
    Client,
};
use hyper_sync_rustls;
use rocket::http::{Cookie, Cookies, SameSite};
use rocket::request::{self, FromRequest, Request};
use rocket::response::Redirect;
use rocket::{get, routes, Outcome};
use rocket_oauth2::{OAuth2, TokenResponse};
use serde_json::{self, Value};

struct User {
    pub username: String,
}

impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<User, ()> {
        let mut cookies = request.guard::<Cookies<'_>>().expect("request cookies");
        if let Some(cookie) = cookies.get_private("username") {
            return Outcome::Success(User {
                username: cookie.value().to_string(),
            });
        }

        Outcome::Forward(())
    }
}

/// User information to be retrieved from the GitHub API.
#[derive(serde::Deserialize)]
struct GitHubUserInfo {
    #[serde(default)]
    name: String,
}

#[get("/auth/github")]
fn github_callback(token: TokenResponse<GitHubUserInfo>, mut cookies: Cookies<'_>)
    -> Result<Redirect, Box<dyn (::std::error::Error)>>
{
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
    cookies.add_private(
        Cookie::build("username", user_info.name)
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

/// User information to be retrieved from the Google People API.
#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    names: Vec<Value>,
}

#[get("/auth/google")]
fn google_callback(token: TokenResponse<GoogleUserInfo>, mut cookies: Cookies<'_>)
    -> Result<Redirect, Box<dyn (::std::error::Error)>>
{
    let https = HttpsConnector::new(hyper_sync_rustls::TlsClient::new());
    let client = Client::with_connector(https);

    // Use the token to retrieve the user's Google account information.
    let response = client
        .get("https://people.googleapis.com/v1/people/me?personFields=names")
        .header(Authorization(Bearer {
            token: token.access_token().to_string(),
        }))
        .send()?;

    let user_info: GoogleUserInfo = serde_json::from_reader(response.take(2 * 1024 * 1024))?;

    let real_name = user_info
        .names
        .first()
        .and_then(|n| n.get("displayName"))
        .and_then(|s| s.as_str())
        .unwrap_or("");

    // Set a private cookie with the user's name, and redirect to the home page.
    cookies.add_private(
        Cookie::build("username", real_name.to_string())
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

/// User information to be retrieved from the Microsoft API.
#[derive(serde::Deserialize)]
struct MicrosoftUserInfo {
    #[serde(default, rename = "displayName")]
    display_name: String,
}

#[get("/auth/microsoft")]
fn microsoft_callback(token: TokenResponse<MicrosoftUserInfo>, mut cookies: Cookies<'_>)
    -> Result<Redirect, Box<dyn (::std::error::Error)>>
{
    let https = HttpsConnector::new(hyper_sync_rustls::TlsClient::new());
    let client = Client::with_connector(https);

    // Use the token to retrieve the user's Microsoft account information.
    let response = client
        .get("https://graph.microsoft.com/v1.0/me")
        .header(Authorization(Bearer {
            token: token.access_token().to_string(),
        }))
        .send()?;

    let user_info: MicrosoftUserInfo = serde_json::from_reader(response.take(2 * 1024 * 1024))?;

    // Set a private cookie with the user's name, and redirect to the home page.
    cookies.add_private(
        Cookie::build("username", user_info.display_name.to_string())
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

#[get("/")]
fn index(user: User) -> String {
    format!("Hi, {}!", user.username)
}

#[get("/", rank = 2)]
fn index_anonymous() -> &'static str {
    "Please login (/login/github or /login/google or /login/microsoft)"
}

#[get("/logout")]
fn logout(mut cookies: Cookies<'_>) -> Redirect {
    cookies.remove(Cookie::named("username"));
    Redirect::to("/")
}

fn main() {
    rocket::ignite()
        .mount("/", routes![
            index,
            index_anonymous,
            logout,
            github_callback,
            google_callback,
            microsoft_callback
        ])
        .attach(OAuth2::<GitHubUserInfo>::fairing(
            "github",
            Some(("/login/github", vec!["user:read".to_string()])),
        ))
        .attach(OAuth2::<GoogleUserInfo>::fairing(
            "google",
            Some(("/login/google", vec!["profile".to_string()])),
        ))
        .attach(OAuth2::<MicrosoftUserInfo>::fairing(
            "microsoft",
            Some(("/login/microsoft", vec!["user.read".to_string()])),
        ))
        .launch();
}
