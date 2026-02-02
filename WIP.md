# Work In Progress - Feature Status

This document catalogs the status of features in the codebase.

## What's Currently Working

### Core Features
- Basic proxy capture and history
- TUI navigation between tabs
- Manual request building and sending
- Response viewing
- Basic findings display
- **Passive scanning** - All 13 rules now wired to proxy traffic:
  - SecurityHeadersRule, CookieSecurityRule, InformationDisclosureRule
  - ContentTypeRule, CorsRule, CspRule, CacheControlRule
  - CsrfRule, PermissionsPolicyRule, ReferrerPolicyRule, ServerBannerRule
  - JwtRule (JWT token analysis, weak secret detection)
  - JsAnalysisRule (secrets, endpoints, vulnerable libraries)
- **Import UI** - Press 'I' on Workspace tab to import files
- **Browser/Carbonyl** - Press Enter on Browser tab to launch carbonyl
- **Active Scanner** - Press 's' on Scanner tab to run active scans (non-blocking)
- **Fuzzer** - Runs in background with progress events (non-blocking)
- **Intercept Flow** - Request interception with edit capabilities (f=forward, x=drop)
- **Session Persistence** - Auto-saves on exit, loads on startup

### Background Task Support
- Active scanner runs in tokio::spawn, sends ScanProgress/ScanComplete events
- Fuzzer runs in tokio::spawn, sends progress events
- UI shows SCANNING or FUZZING mode during operations

---

## Remaining Work (Lower Priority)

### 1. ParamMiner Integration
**Status:** Code exists, not wired to active scanner UI
- `ParamMiner` in `src/scanner/param_discovery.rs` can discover hidden parameters

### 2. CachePoisonTester Integration
**Status:** Code exists, not wired to active scanner UI
- `CachePoisonTester` in `src/scanner/param_discovery.rs`

### 3. WebSocket Message Inspection
**Status:** Infrastructure exists, no TUI view
- `WebSocketHistory`, `WebSocketMessage` in `src/proxy/websocket.rs`
- Needs TUI panel to view intercepted WebSocket messages

### 4. Scripting UI
**Status:** Runtime exists, no UI to enter scripts
- `PreRequestScript`, `PostRequestScript` in `src/scripting/mod.rs`
- JavaScript execution via `boa_engine` works

### 5. Fuzzer Control Methods
**Status:** Methods exist, no UI keybindings
- `stop()`, `pause()`, `resume()` exist in fuzzer but not wired to keybindings

### 6. Browser Scan State Fields
**Status:** Fields defined, not used
- `browser_scan_targets`, `browser_scanning`, etc. defined but not utilized

### 7. Unused Mode Variants
**Status:** Defined but redundant
- `AppMode::ViewResponse` - Not needed (response is always visible)
- `AppMode::Intercept` - Superseded by `ProxyDetails` mode

---

## Recently Completed

1. **Passive Scanner Rules** - All 13 rules wired to proxy traffic
2. **JWT Analysis** - Detects weak secrets, algorithm issues, expired tokens
3. **JavaScript Analysis** - Finds exposed secrets, vulnerable libraries, API endpoints
4. **Import UI** - 'I' key on Workspace tab opens import dialog
5. **Browser Launch** - Enter key on Browser tab opens URL dialog for carbonyl
6. **Non-blocking Active Scanner** - Runs in background task with events
7. **Non-blocking Fuzzer** - Runs in background task with events
8. **AppMode::Scanning/Fuzzing** - Set during operations for visual feedback

---

## Build Status

```
cargo build: 211 warnings, 0 errors
```

Warnings are mostly about unused helper methods and redundant mode variants that could be cleaned up in a future refactor.
