#![feature(proc_macro_hygiene)]

use std::future::Future;
use std::pin::Pin;

use futures::stream::TryStreamExt;
use hyper::{
    header::{ACCEPT, AUTHORIZATION, USER_AGENT},
    Body, Client,
};
use hyper_rustls::HttpsConnector;
use rocket::http::{Cookie, Cookies, SameSite, Status};
use rocket::request::{self, FromRequest, Request};
use rocket::response::{self, Redirect, Responder, Response};
use rocket::{get, routes, Outcome};
use rocket_oauth2::hyper_rustls_adapter::HyperRustlsAdapter;
use rocket_oauth2::{OAuth2, TokenResponse};
use serde_json::{self, Value};

struct User {
    pub username: String,
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();

    async fn from_request(request: &'a Request<'r>) -> request::Outcome<User, ()> {
        let mut cookies = request
            .guard::<Cookies<'_>>()
            .await
            .expect("request cookies");
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

fn github_callback<'r>(
    request: &'r Request<'_>,
    token: TokenResponse,
) -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>> {
    Box::pin(async move {
        let result: Result<_, Box<dyn std::error::Error + Send + Sync>> = async {
            let https = HttpsConnector::new();
            let client: Client<_, Body> = Client::builder().build(https);

            let req = hyper::Request::get("https://api.github.com/user")
                .header(AUTHORIZATION, format!("token {}", token.access_token()))
                .header(ACCEPT, "application/vnd.github.v3+json")
                .header(USER_AGENT, "rocket_oauth2 demo application")
                .body(Body::empty())?;

            // Use the token to retrieve the user's GitHub account information.
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

/// User information to be retrieved from the Google People API.
#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    names: Vec<Value>,
}

fn google_callback<'r>(
    request: &'r Request<'_>,
    token: TokenResponse,
) -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>> {
    Box::pin(async move {
        let result: Result<_, Box<dyn std::error::Error + Send + Sync>> = async {
            let https = HttpsConnector::new();
            let client: Client<_, Body> = Client::builder().build(https);

            // Use the token to retrieve the user's GitHub account information.
            let req = hyper::Request::get(
                "https://people.googleapis.com/v1/people/me?personFields=names",
            )
            .header(AUTHORIZATION, format!("Bearer {}", token.access_token()))
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

            let user_info: GoogleUserInfo = serde_json::from_slice(&body)?;

            let real_name = user_info
                .names
                .first()
                .and_then(|n| n.get("displayName"))
                .and_then(|s| s.as_str())
                .unwrap_or("");

            // Set a private cookie with the user's name, and redirect to the home page.
            let mut cookies = request
                .guard::<Cookies<'_>>()
                .await
                .expect("request cookies");
            cookies.add_private(
                Cookie::build("username", real_name.to_string())
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

/// User information to be retrieved from the Microsoft Graph API.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MicrosoftUserInfo {
    display_name: String,
}

fn microsoft_callback<'r>(
    request: &'r Request<'_>,
    token: TokenResponse,
) -> Pin<Box<dyn Future<Output = Result<Response<'r>, Status>> + Send + 'r>> {
    Box::pin(async move {
        let result: Result<_, Box<dyn std::error::Error + Send + Sync>> = async {
            let https = HttpsConnector::new();
            let client: Client<_, Body> = Client::builder().build(https);

            // Use the token to retrieve the user's GitHub account information.
            let req = hyper::Request::get("https://graph.microsoft.com/v1.0/me")
                .header(AUTHORIZATION, format!("Bearer {}", token.access_token()))
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

            let user_info: MicrosoftUserInfo = serde_json::from_slice(&body)?;

            // Set a private cookie with the user's name, and redirect to the home page.
            let mut cookies = request
                .guard::<Cookies<'_>>()
                .await
                .expect("request cookies");
            cookies.add_private(
                Cookie::build("username", user_info.display_name)
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

#[get("/")]
fn index(user: User) -> String {
    format!("Hi, {}!", user.username)
}

#[get("/", rank = 2)]
fn index_anonymous() -> &'static str {
    "Please login (/login/github, /login/google or /login/microsoft)"
}

#[get("/logout")]
fn logout(mut cookies: Cookies<'_>) -> Redirect {
    cookies.remove(Cookie::named("username"));
    Redirect::to("/")
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, index_anonymous, logout])
        .attach(OAuth2::fairing(
            HyperRustlsAdapter,
            github_callback,
            "github",
            "/auth/github",
            Some(("/login/github", vec!["user:read".to_string()])),
        ))
        .attach(OAuth2::fairing(
            HyperRustlsAdapter,
            google_callback,
            "google",
            "/auth/google",
            Some(("/login/google", vec!["profile".to_string()])),
        ))
        .attach(OAuth2::fairing(
            HyperRustlsAdapter,
            microsoft_callback,
            "microsoft",
            "/auth/microsoft",
            Some(("/login/microsoft", vec!["user.read".to_string()])),
        ))
        .launch()
        .expect("server quit unexpectedly")
}
