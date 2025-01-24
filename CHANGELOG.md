# bedrock-oauth2-verifier ChangeLog

## 2.3.1 - 2025-01-dd

### Fixed
- Ensure `getBasicAuthorizationCredentials()` is synchronous.

## 2.3.0 - 2025-01-24

### Added
- Add `getBasicAuthorizationCredentials()` helper for parsing
  "Authorization: Basic <credentials>" from a request.

## 2.2.0 - 2025-01-23

### Added
- Add `checkTargetScopedAccessToken()` to enable commonly used oauth scope
  pattern based on request's target resource.
- Allow custom `typ` claim for access tokens.

## 2.1.1 - 2025-01-23

### Fixed
- Use `...cache.peek(key)` in cache record rotation management code to
  avoid extending record TTL when not actually accessing cache for use.
- Update dependencies.

## 2.1.0 - 2024-04-10

### Added
- Add optional `jwt` param to allow passing a JWT directly
  to `checkAccessToken`.

## 2.0.2 - 2023-10-19

### Fixed
- Simplify cache rotation promise code.

## 2.0.1 - 2023-10-19

### Fixed
- Fix unhandled promise rejection that could arise from fetching
  an uncached issuer config.

## 2.0.0 - 2023-09-15

### Changed
- **BREAKING**: Drop support for Node.js < 18.
- Use `@digitalbazaar/http-client@4`. This version required Node.js 18+.

## 1.0.2 - 2023-08-30

### Fixed
- Fix unhandled promise rejection that could occur during issuer config
  rotation.

## 1.0.1 - 2022-11-16

### Fixed
- Add missing dependencies `@digitalbazaar/http-client@3.2` and `jose@4.11`.
- Remove unused deps `@digitalbazaar/http-client`, `klona` and `sinon` from
  test.

## 1.0.0 - 2022-09-27

- See git history for changes.
