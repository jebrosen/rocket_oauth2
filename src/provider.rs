use std::borrow::Cow;

/// A `Provider` can retrieve authorization and token exchange URIs specific to
/// an OAuth service provider.
///
/// In most cases, `StaticProvider` should be used instead of implementing
/// `Provider` manually.  Implementing `Provider` manually is mainly useful for
/// dynamically determined providers.
pub trait Provider: Send + Sync + 'static {
    /// Returns the authorization URI associated with the service provider.
    fn auth_uri(&self) -> Cow<'_, str>;
    /// Returns the token exchange URI associated with the service provider.
    fn token_uri(&self) -> Cow<'_, str>;
}

/// A `StaticProvider` contains authorization and token exchange URIs specific
/// to an OAuth service provider, that will not change after they are
/// determined.
///
/// If the service provider's URIs might change at runtime, implement
/// [`Provider`] for your own type instead.
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
        }

        impl StaticProvider {
            pub(crate) fn from_known_name(name: &str) -> Option<StaticProvider> {
                match name {
                    $(
                        stringify!($name) => Some(StaticProvider::$name),
                    )*
                    _ => None,
                }
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
    Yahoo: "https://api.login.yahoo.com/oauth2/request_auth", "https://api.login.yahoo.com/oauth2/get_token",
}
