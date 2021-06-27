//! Constants for commonly used header and parameter names and values.

/// Constants for commonly used HTTP header values.
pub mod header {
    /// `application/json` value of the [`Accept`] header, corresponding to
    /// [JSON]-formatted data.
    ///
    /// [`Accept`]: https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.2
    /// [JSON]: https://datatracker.ietf.org/doc/html/rfc8259
    pub const APPLICATION_JSON: &str = "application/json";

    /// `application/x-www-form-urlencoded` value of the [`Content-Type`] header,
    /// corresponding to [urlencoded] data.
    ///
    /// [`Content-Type`]: https://datatracker.ietf.org/doc/html/rfc7231#section-3.1.1.5
    /// [urlencoded]: https://url.spec.whatwg.org/#application/x-www-form-urlencoded
    pub const X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
}

/// Constants for commonly used URL parameter names and values.
pub mod param {
    /// `client_id`, the client identifier issued to the client during the
    /// registration process.
    pub const CLIENT_ID: &str = "client_id";

    /// `client_secret`, the client secret.
    pub const CLIENT_SECRET: &str = "client_secret";

    /// `code`, the authorization code received from the authorization server.
    pub const CODE: &str = "code";

    /// `grant_type`, the type of grant being requested from the server.
    pub const GRANT_TYPE: &str = "grant_type";

    /// Common values of the `grant_type` parameter.
    pub mod grant_type {
        /// `authorization_code`, the grant type for an OAuth2 [Access Token Request].
        ///
        /// [Access Token Request]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
        pub const AUTHORIZATION_CODE: &str = "authorization_code";

        /// `refresh_token`, the grant type for [Refreshing an Access Token].
        ///
        /// [Refreshing an Access Token]: https://datatracker.ietf.org/doc/html/rfc6749#section-6
        pub const REFRESH_TOKEN: &str = "refresh_token";
    }

    /// `redirect_uri`, the endpoint to which the authorization server will
    /// redirect the user agent after authorization.
    pub const REDIRECT_URI: &str = "redirect_uri";

    /// `refresh_token`, the refresh token, which can be used to obtain
    /// new access tokens using the same authorization grant.
    pub const REFRESH_TOKEN: &str = "refresh_token";

    /// `response_type`, the type of response requested from the authorization
    /// server.
    pub const RESPONSE_TYPE: &str = "response_type";

    /// Common values of the `response_type` parameter.
    pub mod response_type {
        /// `code`, the response type for an OAuth2 [Authorization Request].
        ///
        /// [Authorization Request]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
        pub const CODE: &str = "code";
    }

    /// `scope`, the scope of the access request.
    pub const SCOPE: &str = "scope";

    /// `state`, an opaque value used by the client to maintain state between the
    /// request and callback.
    pub const STATE: &str = "state";
}
