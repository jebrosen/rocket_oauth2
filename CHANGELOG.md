# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Added the `query` module, including constants for some commonly used
  header and parameter values for use by `Adapter` implementations.

## 0.5.0-rc.1 - 2021-06-09
### Changed
- Updated the `rocket` dependency to `0.5.0-rc.1`
  - Refactored `rocket_oauth2` to support `async` and other changes in 0.5
    - Changed `Adapter` and impls to use `#[async_trait]`
    - Made `Adapter::exchange_code` and `OAuth2::refresh` into `async fn`s
  - Replaced `OAuthConfig::from_config` with `OAuthConfig::from_figment`
  - Replaced `HyperSyncRustlsAdapter` with `HyperRustlsAdapter`; the feature
    flag has also been replaced with `hyper_rustls_adapter`
  - Implemented `Sentinel` on request guards, so misconfiguration will be
    detected earlier at runtime.
- Rewrote the primary example with `reqwest` and renamed it to `user_info`

### Removed
- Removed support for specifying `provider` as a table with `auth_uri`
  and `token_uri` values. These values are no longer nested under `provider`.

### Migration Guide
* If you specified `provider` as a table with `auth_uri` and `token_uri`,
  remove the intermediate `provider` table and move `auth_uri` and `token_uri`
  to the level `provider` was at.
* Change references to `hyper_sync_rustls_adapter` to `hyper_rustls_adapter`,
  and `HyperSyncRustlsAdapter` with `HyperRustlsAdapter`.
* Change calls to `OAuthConfig::from_config` to `OAuthConfig::from_figment`.
* Add `#[async_trait::async_trait]` to `Adapter` implementations, and change
  `exchange_code` to an `async fn` using an `async` HTTP client or a
  synchronous HTTP client wrapped in a `spawn_blocking` call.
* Add `.await` after calls to `Adapter::exchange_code()` and
  `OAuth2::refresh()`.

## 0.4.1 - 2020-09-23
### Changed
- The version requirement for `hyper_sync_rustls` has been loosened, allowing
  up to `0.3.0-rc.17`.

## 0.4.0 - 2020-08-25
### Added
- `get_redirect_extras` method, which accepts "extra" query parameters to use in
  the authentication request.
### Changed
- Use HTTP basic authentication by default to pass `client_id` and
  `client_secret` to the authorization server, instead of placing them in the
  request body.

### Migration Notes

Previous versions of this library sent the `client_id` and `client_secret` in
the request body, which is an optional extension supported by many authorization
servers. The default is now to use HTTP Basic Authentication, which [servers
must support]. In the case of a server that *only* supports authentication
parameters in the request body, this functionality can be disabled.

* For servers that support HTTP Basic Authentication, use `OAuth2::fairing()` or
  `OAuth2::custom()` with `HyperSyncRustlsAdapter::default()`.
* For servers that **do not** support HTTP Basic Authentication, use
  `OAuth2::custom()` with `HyperSyncRustlsAdapter::default().basic_auth(false)`.
* Only `HyperSyncRustlsAdapter` is affected by this change; custom `Adapter`
  types are not affected.

[servers must support]: https://tools.ietf.org/html/rfc6749#section-2.3.1

## 0.3.1 - 2020-07-19
### Added
- Support for 'Wikimedia' as a known provider.

## 0.3.0 - 2020-07-03
### Added
- Documentation that TokenResponse guard must come before Cookies
### Changed
- More specific log message when the state cookie is missing or
  inaccessible
- Provider names are now case-insensitive, matching the documentation

## 0.3.0-rc.1 - 2020-06-15
### Added
- Log messages help pinpoint which part of the token exchange failed
- The `redirect_uri` is now optional
### Changed
- Removed the `A` type parameter from `OAuth2::fairing()`.
  To use a custom `Adapter`, use `OAuth2::custom()`.
- Removed the `Callback` trait. Callbacks are now implemented
  as regular routes that use the `TokenResponse` request guard.
- `OAuth2` is no longer placed in managed state. Instead, `OAuth2`
  implements `FromRequest`.
- `HyperSyncRustlsAdapter` is exported from the crate root instead
  of from a submodule.
### Removed
- Removed the automatic creation of login routes. Instead,
  `get_redirect()` can be called from a user-defined login route.

## 0.2.0 - 2020-04-11
### Added
- More complete documentation and examples of custom Provider usage

## 0.2.0-rc.1 - 2019-10-27
### Added
- Refresh tokens can be exchanged using `OAuth2::refresh()`

### Changed
- Restructured error handling in `Adapter`s.
- Removed the `A` type parameter from `OAuth2`.
- `TokenResponse` is redesigned and no longer uses `serde_derive`.
  Fields have been converted to methods, and `.as_value()` replaces
  the functionality of `.extras`.
- `Provider` is now a trait, allowing for dynamically determined `Provider`s.
- `Adapter` is now only responsible for *conveying* state in
  `authorization_uri()`; state is generated by the library itself.
- Added (direct) dependencies on 'ring' (0.13) and 'base64' (0.10); removed
  'rand' dependency

## 0.1.0 - 2019-10-01
### Added
- CHANGELOG.md.
- Support for 'Microsoft' (v2.0) as a known Provider and an example.
- A 'scope' can be specificied in the authorization callback as a
  fallback in case it is not present in the token response. This is
  the case with Strava, for example.
- Types derive more of the traits in `std`, such as `Clone` and `Debug`.

### Changed
- Update 'rand' dependency to 0.7.
- Update 'url' dependency to 2.1.

## 0.0.5 - 2018-12-06
