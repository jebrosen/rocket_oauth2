use rocket::http::{Cookie, CookieJar};
use rocket::request::{self, FromRequest, Request};
use rocket::response::Redirect;
use rocket::{get, routes};

mod oauth2;

struct User {
    pub username: String,
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();

    async fn from_request(request: &'a Request<'r>) -> request::Outcome<User, ()> {
        let cookies = request
            .guard::<&CookieJar<'_>>()
            .await
            .expect("request cookies");
        if let Some(cookie) = cookies.get_private("username") {
            return request::Outcome::Success(User {
                username: cookie.value().to_string(),
            });
        }

        request::Outcome::Forward(())
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
fn logout(cookies: &CookieJar<'_>) -> Redirect {
    cookies.remove(Cookie::named("username"));
    Redirect::to("/")
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::ignite()
        .mount("/", routes![index, index_anonymous, logout])
        .attach(oauth2::github::fairing())
}
