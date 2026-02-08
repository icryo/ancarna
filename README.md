# Ancarna

**Web Proxy in Your Terminal**

![Ancarna](example.png)

A lightweight terminal-based web security testing tool. Intercept, inspect, and analyze HTTP/HTTPS traffic without leaving your terminal.

## Features

- **HTTPS Intercepting Proxy** - MITM proxy with on-the-fly certificate generation
- **Request Editor** - Modify and replay requests with vim-style navigation
- **Passive Scanner** - Automatic detection of security issues (headers, cookies, CSP, CORS)
- **Findings View** - Tree view grouped by host with filtering (`!pattern` to exclude)
- **Intercept Mode** - Pause, edit, and forward/drop requests

## Install

```bash
cargo install --git https://github.com/icryo/ancarna
```

Or build from source:
```bash
git clone https://github.com/icryo/ancarna
cd ancarna
cargo build --release
```

## Quick Start

```bash
# Start ancarna
ancarna

# Configure your browser to use proxy at 127.0.0.1:8080
# Press 'C' to install the CA certificate for HTTPS interception
```

## Keybindings

### General

| Key | Action |
|-----|--------|
| `Ctrl+P` | **Command palette** - search all actions |
| `1-7` | Switch tabs |
| `Tab` | Cycle focus between panels |
| `?` | Show help dialog |
| `q` | Quit |
| `Ctrl+E` | Export report (HTML/JSON/CSV/Markdown) |
| `Ctrl+t` | New request tab |
| `Ctrl+w` | Close current tab |
| `>/<` | Next/previous request tab |

### Navigation

| Key | Action |
|-----|--------|
| `j/k` | Move down/up |
| `h/l` | Move left/right |
| `g/G` | Go to top/bottom |
| `Ctrl+d/u` | Half page down/up |
| `[/]` | Switch sub-tabs |

### Proxy Tab

| Key | Action |
|-----|--------|
| `I` | Toggle intercept mode |
| `f` | Forward intercepted request |
| `x` | Drop intercepted request |
| `d` | View request details |
| `/` | Filter history (`!pattern` to exclude) |
| `W` | View WebSocket messages |
| `Ctrl+C` | Install CA certificate |

### Scanner Tab

| Key | Action |
|-----|--------|
| `Enter` | Start/stop scan |
| `e` | Edit scan target URL |
| `S` | Open scripting panel |
| `p` | Configure scan policy |

### Request Editor

| Key | Action |
|-----|--------|
| `e` | Edit URL |
| `i` | Edit current field |
| `o` | Add new row |
| `d` | Delete row |
| `Space` | Toggle row enabled |
| `m` | Cycle HTTP method |
| `Enter` | Send request |
| `n` | New request |

### Response Viewer

| Key | Action |
|-----|--------|
| `/` | Search in response |
| `n/N` | Next/previous match |
| `y` | Copy to clipboard |
| `r` | Toggle raw/pretty view |

### Import/Export

| Key | Action |
|-----|--------|
| `E` | Select environment |
| `Ctrl+I` | Import from file (Postman/HAR/OpenAPI/cURL) |
| `I` | Import from clipboard |
| `C` | Export as cURL |
| `Ctrl+V` | Paste from clipboard |

### Collections

| Key | Action |
|-----|--------|
| `H` | Toggle history panel |
| `D` | Delete selected item |
| `R` | Rename selected item |

## Roadmap

### Planned Features

- **Interactsh/OOB Callback Integration** - Out-of-band vulnerability detection using callback servers for blind SSRF, XXE, and other injection detection. Will support custom Interactsh servers and automatic payload generation with correlation IDs.

- **HTTP/2 MITM Support** - Full HTTP/2 proxying for modern web applications

- **Extractors for Templates** - Capture regex groups from responses for evidence collection and chained attacks

- **Custom Template Loading** - Load external Nuclei-compatible templates from disk at runtime

## License

MIT
