# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0-rc.1
### Added
- Refresh tokens can be exchanged using `OAuth2::refresh()`

### Changed
- Restructure error handling in `Adapter`s.
- Remove the `A` type parameter from `OAuth2`.
- `TokenResponse` is redesigned and no longer uses `serde_derive`.
  Fields have been converted to methods, and `.as_value()` replaces
  the functionality of `.extras`.
- `Provider` is now a trait, allowing for dynamically determined `Provider`s.

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
