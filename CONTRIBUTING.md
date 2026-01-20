# Contributing to Ancarna

Thank you for your interest in contributing to Ancarna! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Rust 1.82 or later
- Git
- A terminal emulator that supports modern features

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ancarna.git
   cd ancarna
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/ancarna.git
   ```

## Development Setup

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run the application
cargo run

# Run with arguments
cargo run -- --proxy-port 8081
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests for a specific module
cargo test --package ancarna --lib scanner
```

### Code Formatting

```bash
# Check formatting
cargo fmt -- --check

# Apply formatting
cargo fmt
```

### Linting

```bash
# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring
- `test/description` - Test additions/changes

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting, no code change
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add SSRF detection module

fix(proxy): handle connection timeout gracefully

docs(readme): update installation instructions
```

## Coding Standards

### Rust Style

- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting
- Address all `clippy` warnings
- Write documentation for public APIs

### Code Organization

```
src/
├── main.rs          # Entry point
├── app/             # Application core
├── tui/             # Terminal UI
├── http/            # HTTP client
├── proxy/           # Proxy server
├── scanner/         # Security scanning
│   ├── passive/     # Passive rules
│   └── active/      # Active attacks
├── spider/          # Web crawler
├── fuzzer/          # Fuzzing engine
├── scripting/       # JavaScript engine
├── workspace/       # Project management
└── reporting/       # Report generation
```

### Error Handling

- Use `anyhow::Result` for application errors
- Use `thiserror` for library errors
- Provide context with `.context()` or `.with_context()`
- Never use `.unwrap()` in production code (except in tests)

### Logging

- Use `tracing` for logging
- Use appropriate log levels:
  - `error!`: Unrecoverable errors
  - `warn!`: Recoverable issues
  - `info!`: Important events
  - `debug!`: Debugging information
  - `trace!`: Verbose tracing

### Documentation

- Document all public items
- Include examples in documentation
- Keep comments up to date with code

```rust
/// Performs an active scan on the target URL.
///
/// # Arguments
///
/// * `url` - The target URL to scan
/// * `policy` - The scan policy to use
///
/// # Returns
///
/// A vector of findings discovered during the scan.
///
/// # Examples
///
/// ```
/// let findings = scanner.scan("https://example.com", &policy).await?;
/// ```
pub async fn scan(&self, url: &str, policy: &ScanPolicy) -> Result<Vec<Finding>> {
    // ...
}
```

## Testing

### Test Organization

- Unit tests: In the same file as the code, in a `tests` module
- Integration tests: In the `tests/` directory
- Test utilities: In `tests/common/`

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Arrange
        let input = "test";

        // Act
        let result = function(input);

        // Assert
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_async_feature() {
        // ...
    }
}
```

### Test Coverage

- Aim for high coverage on critical paths
- Write tests for edge cases
- Include both positive and negative tests

## Submitting Changes

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commits
3. Ensure all tests pass
4. Update documentation if needed
5. Push to your fork
6. Open a Pull Request

### Pull Request Template

```markdown
## Description

Brief description of changes.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing

Describe testing performed.

## Checklist

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests pass
```

### Review Process

- PRs require at least one approval
- Address review feedback promptly
- Keep PRs focused and reasonably sized

## Release Process

### Versioning

We use [Semantic Versioning](https://semver.org/):
- MAJOR: Breaking changes
- MINOR: New features (backwards compatible)
- PATCH: Bug fixes (backwards compatible)

### Creating a Release

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create a git tag:
   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```
4. GitHub Actions will build and publish the release

## Getting Help

- Open an issue for bugs or feature requests
- Start a discussion for questions
- Check existing issues before creating new ones

## Recognition

Contributors are recognized in:
- The CONTRIBUTORS file
- Release notes
- Project documentation

Thank you for contributing to Ancarna!
