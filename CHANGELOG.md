# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 - Unreleased
### Added
- CHANGELOG.md.
- Support for 'Microsoft' (v2.0) as a known Provider with example.
- A 'scope' can be specificied in the authorization callback as a
  fallback in case it is not present in the token response. This is
  the case with Strava, for example.
- Types derive more of the traits in `std`, such as `Clone` and `Debug`

### Changed
- Update 'rand' dependency to 0.7.
- Update 'url' dependency to 2.1.

## 0.0.5 - 2018-12-06
