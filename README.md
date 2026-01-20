# Ancarna

**Web Proxy Security in Your Terminal**

Ancarna is a TUI-based web application security testing tool with OWASP ZAP feature parity, built with Rust and Ratatui.

## Features (Roadmap)

### Phase 1: Foundation (MVP)
- [x] Project scaffolding
- [x] TUI framework (Ratatui)
- [x] HTTP client
- [x] Request/response viewer
- [x] Basic intercepting proxy
- [ ] Collection management

### Phase 2: Core Security
- [x] Passive scanner (headers, cookies, disclosure)
- [x] Active scanner (SQLi, XSS, path traversal, command injection)
- [x] Findings management
- [ ] TLS/HTTPS proxy (MITM)

### Phase 3: Advanced Scanning
- [x] Scan policies
- [x] Spider/crawler
- [ ] Fuzzer engine
- [ ] WebSocket testing
- [ ] Authentication handlers

### Phase 4: Automation
- [x] JavaScript scripting (Boa)
- [ ] REST API for automation
- [ ] CLI mode
- [ ] Report generation

### Phase 5: Advanced
- [ ] AJAX Spider
- [ ] Plugin system
- [ ] Session management
- [ ] gRPC support

## Installation

```bash
# Build from source
cargo build --release

# Install
cargo install --path .
```

## Usage

```bash
# Start with TUI
ancarna

# Start with custom proxy port
ancarna --proxy-port 8081

# Headless scan
ancarna --headless --target https://example.com

# Execute script
ancarna --headless --script scan.js
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `h/j/k/l` | Navigate |
| `Tab` | Cycle focus |
| `i` | Edit mode |
| `Esc` | Normal mode |
| `:` | Command palette |
| `?` | Help |
| `Ctrl+C` | Quit |

## Configuration

Configuration file: `~/.config/ancarna/config.toml`

```toml
[proxy]
listen_addr = "127.0.0.1"
default_port = 8080
https_intercept = true

[scanner]
max_threads = 10
request_timeout = 30

[tui]
theme = "default"
vim_mode = true
```

## Architecture

```
ancarna/
├── src/
│   ├── app/        # Application state
│   ├── tui/        # Terminal UI
│   ├── http/       # HTTP client
│   ├── proxy/      # Intercepting proxy
│   ├── scanner/    # Security scanning
│   ├── spider/     # Web crawler
│   ├── scripting/  # JS engine
│   └── workspace/  # Project management
└── config/         # Default configs
```

## Comparison with OWASP ZAP

| Feature | ZAP | Ancarna |
|---------|-----|---------|
| Intercepting Proxy | ✅ | ✅ |
| Passive Scanning | ✅ | ✅ |
| Active Scanning | ✅ | ✅ |
| Spider | ✅ | ✅ |
| Fuzzer | ✅ | 🚧 |
| Scripting | ✅ | ✅ |
| GUI | Desktop | Terminal |
| Resource Usage | Heavy | Light |

## License

MIT

## Credits

Inspired by:
- [ATAC](https://github.com/Julien-cpsn/ATAC) - Terminal API Client
- [resterm](https://github.com/unkn0wn-root/resterm) - Terminal REST Client
- [OWASP ZAP](https://www.zaproxy.org/) - Security Testing Tool
