# bedrock-oauth2-verifier ChangeLog

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
