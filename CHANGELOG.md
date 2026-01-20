# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffolding
- TUI framework with Ratatui
- HTTP client with authentication support (Basic, Bearer, JWT, OAuth2, Digest)
- Intercepting proxy server with HTTPS support
- Passive scanner with security header, cookie, CORS, and information disclosure rules
- Active scanner with SQLi, XSS, path traversal, and command injection modules
- Web spider/crawler
- JavaScript scripting engine (Boa)
- Workspace management (collections, environments, sessions)
- Import support (Postman, cURL, OpenAPI, HAR)
- Scan policy management
- CI/CD pipeline (GitHub Actions)
- Cross-platform release builds

### Security
- TLS certificate generation for MITM proxy
- Secure credential storage
- Input validation on all user inputs

## [0.1.0] - TBD

### Added
- Initial release
- Core functionality for web application security testing
- Terminal-based user interface
- Basic scanning capabilities

---

[Unreleased]: https://github.com/example/ancarna/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/example/ancarna/releases/tag/v0.1.0
