# Ancarna - Terminal Security Testing Platform

## Vision
A terminal-based web application security testing tool with OWASP ZAP feature parity, built on Ratatui and inspired by ATAC's architecture.

## Name
**Ancarna** - A tool of ancient power, forged for modern security testing.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              ANCARNA TUI                                 │
│  ┌─────────────┬─────────────┬──────────────┬─────────────────────────┐ │
│  │  Workspace  │   Request   │   Response   │      Scan Results       │ │
│  │  Navigator  │   Editor    │   Viewer     │      / Findings         │ │
│  └─────────────┴─────────────┴──────────────┴─────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │                    Status Bar / Proxy Status                        │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌──────────────┐ ┌─────────────┐ ┌─────────────┐
            │   Proxy      │ │   Scanner   │ │   Spider    │
            │   Engine     │ │   Engine    │ │   Engine    │
            └──────────────┘ └─────────────┘ └─────────────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    ▼
                        ┌───────────────────────┐
                        │   Core HTTP Client    │
                        │      (reqwest)        │
                        └───────────────────────┘
```

---

## Module Structure

```
ancarna/
├── Cargo.toml
├── src/
│   ├── main.rs                    # Entry point
│   ├── app/                       # Application state & lifecycle
│   │   ├── mod.rs
│   │   ├── state.rs               # Global app state
│   │   ├── config.rs              # Configuration management
│   │   └── events.rs              # Event handling
│   │
│   ├── tui/                       # Terminal UI layer
│   │   ├── mod.rs
│   │   ├── terminal.rs            # Terminal setup/teardown
│   │   ├── layout.rs              # Layout management
│   │   ├── theme.rs               # Color schemes & styling
│   │   └── widgets/               # Custom widgets
│   │       ├── mod.rs
│   │       ├── request_editor.rs
│   │       ├── response_viewer.rs
│   │       ├── tree_navigator.rs
│   │       ├── findings_panel.rs
│   │       └── proxy_log.rs
│   │
│   ├── http/                      # HTTP client layer
│   │   ├── mod.rs
│   │   ├── client.rs              # HTTP client wrapper
│   │   ├── request.rs             # Request types
│   │   ├── response.rs            # Response types
│   │   ├── auth/                  # Authentication handlers
│   │   │   ├── mod.rs
│   │   │   ├── basic.rs
│   │   │   ├── bearer.rs
│   │   │   ├── digest.rs
│   │   │   ├── oauth2.rs
│   │   │   └── jwt.rs
│   │   └── websocket.rs           # WebSocket client
│   │
│   ├── proxy/                     # Intercepting proxy
│   │   ├── mod.rs
│   │   ├── server.rs              # Proxy server
│   │   ├── intercept.rs           # Request/response interception
│   │   ├── tls.rs                 # TLS/HTTPS handling (MITM)
│   │   ├── rules.rs               # Intercept rules
│   │   └── history.rs             # Request history
│   │
│   ├── scanner/                   # Security scanning
│   │   ├── mod.rs
│   │   ├── engine.rs              # Scan orchestration
│   │   ├── passive/               # Passive scanning
│   │   │   ├── mod.rs
│   │   │   ├── analyzer.rs        # Traffic analyzer
│   │   │   └── rules/             # Passive scan rules
│   │   │       ├── mod.rs
│   │   │       ├── headers.rs     # Security headers check
│   │   │       ├── cookies.rs     # Cookie security
│   │   │       ├── disclosure.rs  # Information disclosure
│   │   │       └── ssl.rs         # SSL/TLS issues
│   │   ├── active/                # Active scanning
│   │   │   ├── mod.rs
│   │   │   ├── injector.rs        # Payload injection
│   │   │   └── attacks/           # Attack modules
│   │   │       ├── mod.rs
│   │   │       ├── sqli.rs        # SQL injection
│   │   │       ├── xss.rs         # Cross-site scripting
│   │   │       ├── path_traversal.rs
│   │   │       ├── command_injection.rs
│   │   │       ├── xxe.rs         # XML external entity
│   │   │       ├── ssrf.rs        # Server-side request forgery
│   │   │       └── lfi_rfi.rs     # File inclusion
│   │   ├── policies/              # Scan policies
│   │   │   ├── mod.rs
│   │   │   ├── default.rs
│   │   │   ├── api.rs             # API-focused policy
│   │   │   └── custom.rs          # User-defined policies
│   │   └── findings.rs            # Vulnerability findings
│   │
│   ├── spider/                    # Web crawler
│   │   ├── mod.rs
│   │   ├── crawler.rs             # Traditional spider
│   │   ├── ajax_spider.rs         # JavaScript-aware spider
│   │   ├── scope.rs               # Crawl scope management
│   │   └── sitemap.rs             # Site structure
│   │
│   ├── fuzzer/                    # Fuzzing engine
│   │   ├── mod.rs
│   │   ├── engine.rs              # Fuzzer core
│   │   ├── payloads/              # Payload management
│   │   │   ├── mod.rs
│   │   │   ├── wordlists.rs       # Wordlist loading
│   │   │   ├── generators.rs      # Payload generation
│   │   │   └── encoders.rs        # Encoding variants
│   │   └── analysis.rs            # Response analysis
│   │
│   ├── scripting/                 # Scripting engine
│   │   ├── mod.rs
│   │   ├── runtime.rs             # JavaScript runtime (boa)
│   │   ├── api.rs                 # Script API bindings
│   │   ├── hooks.rs               # Pre/post request hooks
│   │   └── stdlib/                # Standard library functions
│   │
│   ├── workspace/                 # Project/session management
│   │   ├── mod.rs
│   │   ├── project.rs             # Project structure
│   │   ├── collections.rs         # Request collections
│   │   ├── environments.rs        # Environment variables
│   │   ├── session.rs             # Session/cookie management
│   │   └── import/                # Import formats
│   │       ├── mod.rs
│   │       ├── postman.rs
│   │       ├── openapi.rs
│   │       ├── curl.rs
│   │       └── har.rs             # HTTP Archive format
│   │
│   ├── reporting/                 # Report generation
│   │   ├── mod.rs
│   │   ├── formats/
│   │   │   ├── mod.rs
│   │   │   ├── html.rs
│   │   │   ├── json.rs
│   │   │   ├── xml.rs
│   │   │   └── sarif.rs           # Static Analysis Results Format
│   │   └── templates/
│   │
│   ├── api/                       # External API (for automation)
│   │   ├── mod.rs
│   │   ├── server.rs              # REST API server
│   │   ├── routes.rs              # API endpoints
│   │   └── auth.rs                # API authentication
│   │
│   └── plugins/                   # Plugin system
│       ├── mod.rs
│       ├── loader.rs              # Plugin discovery/loading
│       ├── registry.rs            # Plugin registry
│       └── api.rs                 # Plugin API interface
│
├── plugins/                       # Built-in plugins
│   └── ...
│
├── payloads/                      # Default payload files
│   ├── sqli/
│   ├── xss/
│   ├── wordlists/
│   └── ...
│
├── config/                        # Default configurations
│   ├── default.toml
│   └── scan_policies/
│
└── tests/
    ├── integration/
    └── unit/
```

---

## Development Phases

### Phase 1: Foundation (MVP)
**Goal**: Basic HTTP client with TUI and proxy capability

- [ ] Project scaffolding with Cargo workspace
- [ ] Basic TUI framework with Ratatui
- [ ] HTTP client with reqwest
- [ ] Request/response viewer
- [ ] Collection management (JSON/YAML storage)
- [ ] Basic intercepting proxy (HTTP only)
- [ ] Request history

### Phase 2: Core Security Features
**Goal**: Passive scanning and basic active scanning

- [ ] Passive scanner framework
- [ ] Security header analysis
- [ ] Cookie security checks
- [ ] Information disclosure detection
- [ ] Basic active scanner (SQLi, XSS)
- [ ] Findings management & display
- [ ] TLS/HTTPS proxy support

### Phase 3: Advanced Scanning
**Goal**: Full active scanning suite

- [ ] Complete OWASP Top 10 attack modules
- [ ] Scan policy management
- [ ] Spider/crawler
- [ ] Fuzzer engine
- [ ] WebSocket testing
- [ ] Authentication handler (OAuth2, JWT, etc.)

### Phase 4: Automation & Integration
**Goal**: CI/CD integration and scripting

- [ ] JavaScript scripting engine
- [ ] REST API for automation
- [ ] CLI mode (headless operation)
- [ ] Report generation (HTML, JSON, SARIF)
- [ ] Import/export (Postman, OpenAPI, HAR)

### Phase 5: Advanced Features
**Goal**: Feature parity with ZAP

- [ ] AJAX Spider (headless browser)
- [ ] Plugin system
- [ ] Session management
- [ ] Scope management
- [ ] Breakpoints (request/response modification)
- [ ] Response diffing
- [ ] gRPC support

---

## Key Dependencies

```toml
[dependencies]
# TUI Framework
ratatui = "0.29"
crossterm = "0.28"
tui-textarea = "0.7"
tui-tree-widget = "0.23"

# HTTP Client
reqwest = { version = "0.12", features = ["cookies", "json", "multipart"] }
reqwest-middleware = "0.4"
hyper = "1.0"            # For proxy server
rustls = "0.23"          # TLS handling

# Async Runtime
tokio = { version = "1.48", features = ["full"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"
toml = "0.8"

# Scripting
boa_engine = "0.21"      # JavaScript runtime

# Security/Crypto
rcgen = "0.13"           # Certificate generation for MITM
rustls-pemfile = "2.0"

# Parsing
url = "2.5"
regex = "1.10"
scraper = "0.20"         # HTML parsing for spider

# Utilities
chrono = "0.4"
uuid = "1.19"
thiserror = "2.0"
tracing = "0.1"
```

---

## Comparison with OWASP ZAP

| Feature | ZAP | Ancarna (Planned) |
|---------|-----|-------------------|
| Intercepting Proxy | ✅ | Phase 1 |
| Passive Scanning | ✅ | Phase 2 |
| Active Scanning | ✅ | Phase 2-3 |
| Spider | ✅ | Phase 3 |
| AJAX Spider | ✅ | Phase 5 |
| Fuzzer | ✅ | Phase 3 |
| WebSocket | ✅ | Phase 3 |
| Scripting | ✅ (Multiple langs) | Phase 4 (JS) |
| API | ✅ | Phase 4 |
| Add-ons | ✅ | Phase 5 |
| GUI | Desktop (Java/Swing) | Terminal (Ratatui) |
| Resource Usage | Heavy | Lightweight |
| Offline Support | Partial | Full |

---

## Design Principles

1. **Offline-First**: No cloud dependency, all data local
2. **Keyboard-Driven**: Vim-like navigation, minimal mouse
3. **Lightweight**: Fast startup, minimal resource usage
4. **Scriptable**: Full automation capability
5. **Extensible**: Plugin architecture from the start
6. **Secure by Default**: No data leaves the machine unless explicitly requested

---

## Technical Decisions

### Why Rust?
- Memory safety for security tooling
- Excellent async performance
- Rich ecosystem (reqwest, tokio, ratatui)
- Single binary distribution

### Why Ratatui over other TUI frameworks?
- Active development and community
- Proven by ATAC and similar tools
- Rich widget ecosystem
- Good documentation

### Proxy Architecture
- Use `hyper` for high-performance proxy server
- `rcgen` for dynamic certificate generation (MITM)
- Maintain certificate cache for performance
- Support both HTTP and HTTPS interception

### Scanner Architecture
- Modular attack plugins
- Async scan execution with configurable concurrency
- Finding deduplication and correlation
- Risk scoring based on CVSS-like metrics
