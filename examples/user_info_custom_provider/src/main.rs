#![feature(decl_macro, proc_macro_hygiene)]

use rocket::http::{Cookie, Cookies};
use rocket::request::{self, FromRequest, Request};
use rocket::response::Redirect;
use rocket::{get, routes, Outcome};

mod oauth2;

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

#[get("/")]
fn index(user: User) -> String {
    format!("Hi, {}!", user.username)
}

#[get("/", rank = 2)]
fn index_anonymous() -> &'static str {
    "Please login (/login/github)"
}

#[get("/logout")]
fn logout(mut cookies: Cookies<'_>) -> Redirect {
    cookies.remove(Cookie::named("username"));
    Redirect::to("/")
}

fn main() {
    rocket::ignite()
        .mount("/", routes![index, index_anonymous, logout])
        .attach(oauth2::github::fairing())
        .launch();
}
