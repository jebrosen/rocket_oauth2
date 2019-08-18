use std::borrow::Cow;

/// A `Provider` contains the authorization and token exchange URIs specific to
/// an OAuth service provider.
pub struct Provider {
    /// The authorization URI associated with the service provider.
    pub auth_uri: Cow<'static, str>,
    /// The token exchange URI associated with the service provider.
    pub token_uri: Cow<'static, str>,
}

macro_rules! providers {
    (@ $(($name:ident $docstr:expr) : $auth:expr, $token:expr),*) => {
        impl Provider {
            $(
                #[doc = $docstr]
                #[allow(non_upper_case_globals)]
                pub const $name: Provider = Provider {
                    auth_uri: Cow::Borrowed($auth),
                    token_uri: Cow::Borrowed($token),
                };
            )*
        }

        impl Provider {
            pub(crate) fn from_known_name(name: &str) -> Option<Provider> {
                match name {
                    $(
                        stringify!($name) => Some(Provider::$name),
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
