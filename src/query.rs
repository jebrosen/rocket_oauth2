//! Constants corresponding to standard HTTP names.

/// Common constants for HTTP headers
pub mod header {
    /// Common values of HTTP [`Accept`] header.
    ///
    /// [`Accept`]: https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.2
    pub mod accept {
        /// [JSON]-formatted data.
        ///
        /// [JSON]: https://datatracker.ietf.org/doc/html/rfc7159
        pub const ACCEPT_APPLICATION_JSON: &str = "application/json";
    }

    /// Common values of HTTP [`Content-Type`] header.
    ///
    /// [`Content-Type`]: https://datatracker.ietf.org/doc/html/rfc7231#section-3.1.1.5
    pub mod content_type {
        /// [Form-based] data encoded into a URL.
        ///
        /// [Form-based]: https://www.ietf.org/rfc/rfc1867
        pub const X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
    }
}

/// Constants corresponding to URL parameter names
/// and their common values for OAuth2 implementation.
pub mod param {
    /// The client identifier issued to the client during the registration process.
    pub const CLIENT_ID: &str = "client_id";

    /// The client secret.
    pub const CLIENT_SECRET: &str = "client_secret";

    /// The authorization code received from the authorization server.
    pub const CODE: &str = "code";

    /// Extension grant type.
    pub const GRANT_TYPE: &str = "grant_type";

    /// Common values of `grant_type` parameter.
    pub mod grant_type {
        /// Grant type for OAuth2 [Access Token Request].
        ///
        /// [Access Token Request]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        pub const AUTHORIZATION_CODE: &str = "authorization_code";

        /// Grant type for OAuth2 [Refreshing an Access Token].
        ///
        /// [Refreshing an Access Token]: https://datatracker.ietf.org/doc/html/rfc6749#section-6
        pub const REFRESH_TOKEN: &str = "refresh_token";
    }

    /// The endpoint to which the authorization server redirects the user-agent.
    pub const REDIRECT_URI: &str = "redirect_uri";

    /// The refresh token, which can be used to obtain
    /// new access tokens using the same authorization grant.
    pub const REFRESH_TOKEN: &str = "refresh_token";

    /// Type of response requested from the authorization server.
    pub const RESPONSE_TYPE: &str = "response_type";

    /// Common values of `response_type` parameter.
    pub mod response_type {

        /// Response type for OAuth2 [Authorization Request].
        /// [Authorization Request]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
        pub const CODE: &str = "code";
    }

    /// The scope of the access request.
    pub const SCOPE: &str = "scope";

    /// An opaque value used by the client to maintain state between the request and callback.
    pub const STATE: &str = "state";
}
