use std::borrow::Cow;
use std::fmt;

use rocket::figment::{self, Error, Figment};

/// Holds configuration for an OAuth application. This consists of the [Provider]
/// details, a `client_id` and `client_secret`, and an optional `redirect_uri`.
pub struct OAuthConfig {
    provider: Box<dyn Provider>,
    client_id: String,
    client_secret: String,
    redirect_uri: Option<String>,
}

impl OAuthConfig {
    /// Construct an OAuthConfig specifying all parameters manually.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_oauth2::{OAuthConfig, StaticProvider};
    ///
    /// let provider = StaticProvider::GitHub;
    /// let client_id = "...".to_string();
    /// let client_secret = "...".to_string();
    /// let redirect_uri = Some("http://localhost:8000/auth/github".to_string());
    ///
    /// let config = OAuthConfig::new(provider, client_id, client_secret, redirect_uri);
    /// ```
    pub fn new(
        provider: impl Provider,
        client_id: String,
        client_secret: String,
        redirect_uri: Option<String>,
    ) -> OAuthConfig {
        OAuthConfig {
            provider: Box::new(provider),
            client_id,
            client_secret,
            redirect_uri,
        }
    }

    /// Construct an OAuthConfig from Rocket configuration.
    ///
    /// # Example
    ///
    /// ## Rocket.toml
    ///
    /// ```toml
    /// [default.oauth.github]
    /// provider = "GitHub"
    /// client_id = "..."
    /// client_secret = "..."
    /// redirect_uri = "http://localhost:8000/auth/github"
    /// ```
    ///
    /// ## main.rs
    /// ```rust,no_run
    /// use rocket::fairing::AdHoc;
    /// use rocket_oauth2::{HyperRustlsAdapter, OAuth2, OAuthConfig};
    ///
    /// struct GitHub;
    ///
    /// #[rocket::launch]
    /// fn rocket() -> _ {
    ///     rocket::build()
    ///         .attach(AdHoc::on_ignite("OAuth Config", |mut rocket| async {
    ///             let config = OAuthConfig::from_figment(rocket.figment(), "github").unwrap();
    ///             rocket.attach(OAuth2::<GitHub>::custom(HyperRustlsAdapter::default(), config))
    ///         }))
    /// }
    /// ```
    pub fn from_figment(figment: &Figment, name: &str) -> Result<Self, Error> {
        #[derive(serde::Deserialize)]
        struct Config {
            provider: Option<String>,
            auth_uri: Option<String>,
            token_uri: Option<String>,
            client_id: String,
            client_secret: String,
            redirect_uri: Option<String>,
        }

        let conf: Config = figment.extract_inner(&format!("oauth.{}", name))?;

        let provider = match (conf.provider, conf.auth_uri, conf.token_uri) {
            (Some(provider_name), None, None) => StaticProvider::from_known_name(&provider_name)
                .ok_or_else(|| {
                    figment::error::Kind::InvalidValue(
                        figment::error::Actual::Str(provider_name),
                        "one of the predefined 'provider' names".into(),
                    )
                })?,
            (None, Some(auth_uri), Some(token_uri)) => StaticProvider {
                auth_uri: auth_uri.into(),
                token_uri: token_uri.into(),
            },
            _ => {
                return Err("either 'provider' or 'auth_uri'+'token_uri' should be specified, but not both".to_string().into());
            }
        };

        Ok(OAuthConfig::new(
            provider,
            conf.client_id,
            conf.client_secret,
            conf.redirect_uri,
        ))
    }

    /// Get the [`Provider`] for this configuration.
    pub fn provider(&self) -> &dyn Provider {
        &*self.provider
    }

    /// Get the client id for this configuration.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Get the client secret for this configuration.
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// Get the redirect URI for this configuration.
    pub fn redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }
}

impl fmt::Debug for OAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OAuthConfig")
            .field("provider", &(..))
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// A `Provider` can retrieve authorization and token exchange URIs specific to
/// an OAuth service provider.
///
/// In most cases, [`StaticProvider`] should be used instead of implementing
/// `Provider` manually. `Provider` should be implemented if the URIs will
/// change during runtime.
pub trait Provider: Send + Sync + 'static {
    /// Returns the authorization URI associated with the service provider.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_oauth2::{Provider, StaticProvider};
    ///
    /// assert_eq!(StaticProvider::GitHub.auth_uri(), "https://github.com/login/oauth/authorize");
    /// ```
    fn auth_uri(&self) -> Cow<'_, str>;
    /// Returns the token exchange URI associated with the service provider.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rocket_oauth2::{Provider, StaticProvider};
    ///
    /// assert_eq!(StaticProvider::GitHub.token_uri(), "https://github.com/login/oauth/access_token");
    /// ```
    fn token_uri(&self) -> Cow<'_, str>;
}

/// A `StaticProvider` contains authorization and token exchange URIs known in
/// advance, either at compile-time or early in initialization.
///
/// If the URIs will change during runtime, implement [`Provider`] for your own
/// type instead.
///
/// # Example
///
/// ```rust
/// use rocket_oauth2::StaticProvider;
///
/// let provider = StaticProvider {
///     auth_uri: "https://example.com/oauth2/authorize".into(),
///     token_uri: "https://example.com/oauth2/token".into(),
/// };
/// ```
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct StaticProvider {
    /// The authorization URI associated with the service provider.
    pub auth_uri: Cow<'static, str>,
    /// The token exchange URI associated with the service provider.
    pub token_uri: Cow<'static, str>,
}

impl Provider for StaticProvider {
    fn auth_uri(&self) -> Cow<'_, str> {
        Cow::Borrowed(&*self.auth_uri)
    }

    fn token_uri(&self) -> Cow<'_, str> {
        Cow::Borrowed(&*self.token_uri)
    }
}

macro_rules! providers {
    (@ $(($name:ident $docstr:expr) : $auth:expr, $token:expr),*) => {
        impl StaticProvider {
            $(
                #[doc = $docstr]
                #[allow(non_upper_case_globals)]
                pub const $name: StaticProvider = StaticProvider {
                    auth_uri: Cow::Borrowed($auth),
                    token_uri: Cow::Borrowed($token),
                };
            )*

            pub(crate) fn from_known_name(name: &str) -> Option<StaticProvider> {
                $(
                    if name.eq_ignore_ascii_case(stringify!($name)) {
                        return Some(StaticProvider::$name);
                    }
                )*
                None
            }
        }
    };
    ($($name:ident : $auth:expr, $token:expr),* $(,)*) => {
        providers!(@ $(($name concat!("A `Provider` suitable for authorizing users with ", stringify!($name), ".")) : $auth, $token),*);
    };
}

providers! {
    Discord: "https://discordapp.com/api/oauth2/authorize", "https://discordapp.com/api/oauth2/token",
    Facebook: "https://www.facebook.com/v3.1/dialog/oauth", "https://graph.facebook.com/v3.1/oauth/access_token",
    GitHub: "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token",
    Google: "https://accounts.google.com/o/oauth2/v2/auth", "https://www.googleapis.com/oauth2/v4/token",
    Microsoft: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    Reddit: "https://www.reddit.com/api/v1/authorize", "https://www.reddit.com/api/v1/access_token",
    Wikimedia: "https://meta.wikimedia.org/w/rest.php/oauth2/authorize", "https://meta.wikimedia.org/w/rest.php/oauth2/access_token",
    Yahoo: "https://api.login.yahoo.com/oauth2/request_auth", "https://api.login.yahoo.com/oauth2/get_token",
}
