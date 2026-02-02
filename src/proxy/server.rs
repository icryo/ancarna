//! Proxy server implementation

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::history::ProxyHistory;
use super::intercept::InterceptManager;
use super::tls::CertificateAuthority;
use super::websocket::WebSocketHistory;
use crate::app::{AppEvent, ProxyConfig};

/// Intercepting proxy server
pub struct ProxyServer {
    /// Configuration
    config: ProxyConfig,

    /// Listen port
    port: u16,

    /// Event sender
    event_tx: mpsc::Sender<AppEvent>,

    /// Request history
    history: Arc<ProxyHistory>,

    /// WebSocket history
    ws_history: Arc<WebSocketHistory>,

    /// Intercept manager
    intercept: Arc<parking_lot::RwLock<InterceptManager>>,

    /// Certificate authority
    ca: Arc<CertificateAuthority>,

    /// Server shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,

    /// Server running flag
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(
        config: &ProxyConfig,
        port: u16,
        event_tx: mpsc::Sender<AppEvent>,
    ) -> Result<Self> {
        // Initialize or load CA
        let ca = if let (Some(cert_path), Some(key_path)) = (&config.ca_cert_path, &config.ca_key_path) {
            CertificateAuthority::from_files(cert_path, key_path)?
        } else {
            CertificateAuthority::new()?
        };

        Ok(Self {
            config: config.clone(),
            port,
            event_tx,
            history: Arc::new(ProxyHistory::default()),
            ws_history: Arc::new(WebSocketHistory::default()),
            intercept: Arc::new(parking_lot::RwLock::new(InterceptManager::new())),
            ca: Arc::new(ca),
            shutdown_tx: None,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.listen_addr, self.port)
            .parse()
            .context("Invalid listen address")?;

        let listener = TcpListener::bind(addr)
            .await
            .context("Failed to bind proxy server")?;

        tracing::info!("Proxy server listening on {}", addr);

        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let history = self.history.clone();
        let ws_history = self.ws_history.clone();
        let intercept = self.intercept.clone();
        let ca = self.ca.clone();
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        let config = self.config.clone();

        // Spawn the accept loop
        tokio::spawn(async move {
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        tracing::info!("Proxy: new connection from {}", peer_addr);

                        let history = history.clone();
                        let ws_history = ws_history.clone();
                        let intercept = intercept.clone();
                        let ca = ca.clone();
                        let event_tx = event_tx.clone();
                        let config = config.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(
                                stream,
                                peer_addr,
                                history,
                                ws_history,
                                intercept,
                                ca,
                                event_tx,
                                config,
                            )
                            .await
                            {
                                tracing::warn!("Proxy connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the proxy server
    pub async fn stop(&self) -> Result<()> {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        tracing::info!("Proxy server stopped");
        Ok(())
    }

    /// Get the proxy history
    pub fn history(&self) -> Arc<ProxyHistory> {
        self.history.clone()
    }

    /// Get the intercept manager
    pub fn intercept(&self) -> Arc<parking_lot::RwLock<InterceptManager>> {
        self.intercept.clone()
    }

    /// Get the CA certificate PEM
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.ca_cert_pem()
    }

    /// Check if proxy is running
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Install the CA certificate to system/browser trust stores
    pub fn install_ca_cert(&self) -> (Vec<String>, Vec<String>) {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let cert_path = std::path::PathBuf::from(format!("{}/.ancarna/ca.crt", home));
        self.ca.install_ca_cert(&cert_path)
    }
}

/// Handle a single connection
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    history: Arc<ProxyHistory>,
    ws_history: Arc<WebSocketHistory>,
    intercept: Arc<parking_lot::RwLock<InterceptManager>>,
    ca: Arc<CertificateAuthority>,
    event_tx: mpsc::Sender<AppEvent>,
    config: ProxyConfig,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(anyhow::anyhow!("Invalid request line"));
    }

    let method = parts[0];
    let target = parts[1];
    let _version = parts[2];

    tracing::info!("Proxy: {} {} from {}", method, target, peer_addr);

    // Read headers
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
        headers.push(line);
    }

    if method == "CONNECT" {
        // HTTPS tunnel
        handle_connect(stream, target, history, ws_history, intercept, ca, event_tx, config).await
    } else {
        // HTTP request
        handle_http_request(
            stream,
            method,
            target,
            headers,
            history,
            intercept,
            event_tx,
            config,
        )
        .await
    }
}

/// Handle CONNECT method (HTTPS tunnel)
async fn handle_connect(
    mut stream: tokio::net::TcpStream,
    target: &str,
    history: Arc<ProxyHistory>,
    ws_history: Arc<WebSocketHistory>,
    intercept: Arc<parking_lot::RwLock<InterceptManager>>,
    ca: Arc<CertificateAuthority>,
    event_tx: mpsc::Sender<AppEvent>,
    config: ProxyConfig,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    tracing::info!("Proxy: handling CONNECT to {}", target);

    // Parse host:port
    let parts: Vec<&str> = target.split(':').collect();
    let host = parts[0];
    let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);

    // Record the CONNECT request in history (even if not intercepting)
    let url = format!("https://{}:{}/", host, port);
    let id = history.add_request("CONNECT", &url);
    tracing::info!("Proxy: recorded CONNECT request id={} to {}", id, url);

    // Send 200 Connection Established
    tracing::info!("Proxy: sending 200 Connection Established");
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    if config.https_intercept {
        tracing::info!("Proxy: MITM mode - generating cert for {}", host);
        // MITM: Generate certificate and upgrade to TLS
        let (cert_pem, key_pem) = ca.generate_cert(host)?;
        tracing::info!("Proxy: cert generated, parsing certificate");

        // Parse certificate and key using rustls-pki-types PEM support
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse certificate")?;
        tracing::info!("Proxy: parsed {} certs", certs.len());

        let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .context("Failed to parse private key")?;
        tracing::info!("Proxy: parsed private key");

        // Create TLS config with ALPN for HTTP/1.1 only
        tracing::info!("Proxy: creating TLS server config");
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Failed to create TLS config")?;

        // Force HTTP/1.1 - we don't support HTTP/2 MITM yet
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        tracing::info!("Proxy: TLS config created, accepting connection");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        // Upgrade connection to TLS
        let tls_stream = acceptor.accept(stream).await?;
        tracing::info!("Proxy: TLS handshake complete");

        // Now handle the decrypted traffic
        handle_tls_traffic(tls_stream, host, port, history, ws_history, intercept, event_tx, config).await
    } else {
        // Pure tunnel (no interception)
        tracing::info!("Proxy: tunnel mode - forwarding to {}:{}", host, port);
        tunnel_traffic(stream, host, port).await
    }
}

/// Handle decrypted TLS traffic
async fn handle_tls_traffic(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    host: &str,
    port: u16,
    history: Arc<ProxyHistory>,
    ws_history: Arc<WebSocketHistory>,
    intercept: Arc<parking_lot::RwLock<InterceptManager>>,
    event_tx: mpsc::Sender<AppEvent>,
    _config: ProxyConfig,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    loop {
        tracing::info!("Proxy: waiting for HTTPS request from client");
        let mut request_line = String::new();
        match reader.read_line(&mut request_line).await {
            Ok(0) => {
                tracing::info!("Proxy: client closed connection (EOF)");
                break;
            }
            Ok(n) => {
                tracing::info!("Proxy: read {} bytes request line: {:?}", n, request_line.trim());
            }
            Err(e) => {
                tracing::warn!("Proxy: error reading request line: {}", e);
                return Err(e.into());
            }
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            tracing::warn!("Proxy: invalid request line (parts={}): {:?}", parts.len(), request_line);
            break;
        }

        let method = parts[0];
        let path = parts[1];
        let url = format!("https://{}:{}{}", host, port, path);
        tracing::info!("Proxy: HTTPS {} {}", method, url);

        // Read headers
        let mut headers = std::collections::HashMap::new();
        let mut content_length = 0usize;
        let mut is_websocket_upgrade = false;
        let mut raw_headers = Vec::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            raw_headers.push(line.clone());
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                if key == "content-length" {
                    content_length = value.parse().unwrap_or(0);
                }
                // Detect WebSocket upgrade
                if key == "upgrade" && value.to_lowercase() == "websocket" {
                    is_websocket_upgrade = true;
                }
                headers.insert(key, value);
            }
        }

        // Handle WebSocket upgrade
        if is_websocket_upgrade {
            tracing::info!("WebSocket upgrade detected for {}", url);
            // Reassemble the stream for WebSocket handling
            let stream = reader.into_inner().unsplit(write_half);
            return handle_websocket_proxy(
                stream,
                host,
                port,
                path,
                &request_line,
                &raw_headers,
                &headers,
                ws_history,
            ).await;
        }

        // Read body if present
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).await?;
        }

        // Record in history
        let id = history.add_request(method, &url);

        // Store request headers and body
        history.update_request(
            id,
            headers.clone(),
            if body.is_empty() { None } else { Some(body.clone()) },
        );

        tracing::info!("HTTPS request: {} {} (body: {} bytes)", method, url, body.len());

        // Check if intercept is enabled
        let (should_intercept, _intercept_enabled) = {
            let mgr = intercept.read();
            (mgr.is_enabled(), mgr.is_enabled())
        };

        // Variables that may be modified by intercept
        let mut final_method = method.to_string();
        let mut final_url = url.clone();
        let mut final_headers = headers.clone();
        let mut final_body = body.clone();
        let mut should_drop = false;

        if should_intercept {
            // Create intercepted request
            let mut intercepted = super::InterceptedRequest::new_request(id, method, &url);
            intercepted.headers = headers.clone();
            if !body.is_empty() {
                intercepted.body = Some(body.clone());
            }

            // Create intercept channel and wait for decision
            let (intercept_id, request_to_send, rx) = {
                let mut mgr = intercept.write();
                mgr.create_intercept(intercepted)
            };

            // Send to app for user review
            if let Err(e) = event_tx.send(AppEvent::ProxyRequest(request_to_send)).await {
                tracing::warn!("Failed to send intercept event: {}", e);
            } else {
                tracing::info!("Intercept: waiting for user decision on request {}", intercept_id);

                // Wait for decision with timeout
                match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
                    Ok(Ok(decision)) => {
                        tracing::info!("Intercept: received decision - forward={}", decision.forward);
                        if decision.forward {
                            // Apply any modifications
                            final_method = decision.request.method.clone();
                            final_url = decision.request.url.clone();
                            final_headers = decision.request.headers.clone();
                            final_body = decision.request.body.clone().unwrap_or_default();
                        } else {
                            should_drop = true;
                        }
                    }
                    Ok(Err(_)) => {
                        tracing::warn!("Intercept: channel closed, forwarding original request");
                    }
                    Err(_) => {
                        tracing::warn!("Intercept: timeout waiting for decision, forwarding original request");
                    }
                }
            }
        }

        // If user decided to drop, send error response and continue
        if should_drop {
            tracing::info!("Intercept: dropping request {} {}", final_method, final_url);
            let error_response = "HTTP/1.1 444 Blocked by Proxy\r\nContent-Length: 27\r\nConnection: close\r\n\r\nRequest blocked by user.\r\n";
            write_half.write_all(error_response.as_bytes()).await?;
            continue;
        }

        // Forward to target server
        let target_addr = format!("{}:{}", host, port);
        tracing::info!("Proxy: connecting to target {}", target_addr);

        // Create TLS connection to target
        let tcp_stream = match tokio::net::TcpStream::connect(&target_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Proxy: failed to connect to {}: {}", target_addr, e);
                return Err(e.into());
            }
        };
        tracing::info!("Proxy: TCP connected to {}", target_addr);

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        tracing::info!("Proxy: TLS connecting to target");
        let mut target_stream = match connector.connect(server_name, tcp_stream).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Proxy: TLS connection to target failed: {}", e);
                return Err(e.into());
            }
        };
        tracing::info!("Proxy: TLS connected to target");

        // Start timing before sending request
        let request_start = std::time::Instant::now();

        // Send request to target (use potentially modified values from intercept)
        // Extract path from final_url if URL was modified
        let final_path = if final_url != url {
            url::Url::parse(&final_url)
                .map(|u| u.path().to_string())
                .unwrap_or_else(|_| path.to_string())
        } else {
            path.to_string()
        };

        let mut request_bytes = format!("{} {} HTTP/1.1\r\n", final_method, final_path);
        for (key, value) in &final_headers {
            request_bytes.push_str(&format!("{}: {}\r\n", key, value));
        }
        request_bytes.push_str("\r\n");
        target_stream.write_all(request_bytes.as_bytes()).await?;
        if !final_body.is_empty() {
            target_stream.write_all(&final_body).await?;
        }

        // Read response
        tracing::info!("Proxy: reading response from target");
        let mut response_reader = BufReader::new(&mut target_stream);
        let mut status_line = String::new();
        response_reader.read_line(&mut status_line).await?;
        tracing::info!("Proxy: target response: {}", status_line.trim());

        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        let status_code: u16 = status_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        // Read response headers
        let mut response_headers = std::collections::HashMap::new();
        let mut response_content_length = 0usize;
        let mut chunked = false;
        loop {
            let mut line = String::new();
            response_reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                if key == "content-length" {
                    response_content_length = value.parse().unwrap_or(0);
                }
                if key == "transfer-encoding" && value.contains("chunked") {
                    chunked = true;
                }
                response_headers.insert(key, value);
            }
        }

        // Read response body
        let mut response_body = Vec::new();
        if chunked {
            // Read chunked encoding
            loop {
                let mut size_line = String::new();
                response_reader.read_line(&mut size_line).await?;
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    break;
                }
                let mut chunk = vec![0u8; size];
                response_reader.read_exact(&mut chunk).await?;
                response_body.extend(chunk);
                // Read trailing CRLF
                let mut crlf = String::new();
                response_reader.read_line(&mut crlf).await?;
            }
        } else if response_content_length > 0 {
            response_body = vec![0u8; response_content_length];
            response_reader.read_exact(&mut response_body).await?;
        }

        // Calculate request duration
        let duration_ms = request_start.elapsed().as_millis() as u64;

        // Update history
        history.update_response(
            id,
            status_code,
            duration_ms,
            response_body.len(),
            response_headers.clone(),
            Some(response_body.clone()),
        );

        // Send ProxyComplete event for passive scanning
        if let Some(entry) = history.get(id) {
            if let Err(e) = event_tx.send(AppEvent::ProxyComplete(entry)).await {
                tracing::warn!("Failed to send ProxyComplete event: {}", e);
            }
        }

        // Forward response to client
        tracing::info!("Proxy: forwarding response {} ({} bytes) to client", status_code, response_body.len());
        write_half.write_all(status_line.as_bytes()).await?;
        for (key, value) in &response_headers {
            // Skip transfer-encoding since we dechunked; we'll add content-length instead
            if key == "transfer-encoding" {
                continue;
            }
            // Skip original content-length if we dechunked (length changed)
            if key == "content-length" && chunked {
                continue;
            }
            write_half
                .write_all(format!("{}: {}\r\n", key, value).as_bytes())
                .await?;
        }
        // Add correct content-length
        write_half
            .write_all(format!("content-length: {}\r\n", response_body.len()).as_bytes())
            .await?;
        write_half.write_all(b"\r\n").await?;
        write_half.write_all(&response_body).await?;
        write_half.flush().await?;
        tracing::info!("Proxy: response forwarded successfully");
    }

    Ok(())
}

/// Pure tunnel (no MITM)
async fn tunnel_traffic(
    mut client: tokio::net::TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    tracing::info!("Proxy: tunnel connecting to {}:{}", host, port);
    let mut server = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tracing::info!("Proxy: tunnel established, starting bidirectional copy");

    let (mut client_read, mut client_write) = client.split();
    let (mut server_read, mut server_write) = server.split();

    let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
    let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }

    Ok(())
}

/// Handle HTTP request (non-CONNECT)
async fn handle_http_request(
    mut stream: tokio::net::TcpStream,
    method: &str,
    target: &str,
    headers: Vec<String>,
    history: Arc<ProxyHistory>,
    _intercept: Arc<parking_lot::RwLock<InterceptManager>>,
    event_tx: mpsc::Sender<AppEvent>,
    _config: ProxyConfig,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tracing::info!("Proxy: handling HTTP request {} {}", method, target);

    // Record in history
    let id = history.add_request(method, target);

    // Parse headers into HashMap for storage
    let mut header_map = std::collections::HashMap::new();
    for header in &headers {
        if let Some((key, value)) = header.split_once(':') {
            header_map.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    // Store request headers (no body for now in simple HTTP handler)
    history.update_request(id, header_map, None);

    // Parse URL
    let url = url::Url::parse(target)?;
    let host = url.host_str().context("No host in URL")?;
    let port = url.port().unwrap_or(80);
    let path = url.path();

    // Connect to target
    tracing::info!("Proxy: connecting to {}:{}", host, port);
    let mut target_stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tracing::info!("Proxy: connected to target");

    // Forward request - use HTTP/1.0 to force connection close (simpler response handling)
    let mut request = format!("{} {} HTTP/1.0\r\n", method, path);
    // Add Host header if not present
    let has_host = headers.iter().any(|h| h.to_lowercase().starts_with("host:"));
    if !has_host {
        request.push_str(&format!("Host: {}\r\n", host));
    }
    for header in &headers {
        // Skip Proxy-Connection header
        if !header.to_lowercase().starts_with("proxy-connection:") {
            request.push_str(header);
        }
    }
    request.push_str("Connection: close\r\n");
    request.push_str("\r\n");

    // Start timing before sending request
    let request_start = std::time::Instant::now();

    tracing::info!("Proxy: forwarding request to target");
    target_stream.write_all(request.as_bytes()).await?;

    // Read response - HTTP/1.0 with Connection: close means server will close when done
    let mut response = Vec::new();
    target_stream.read_to_end(&mut response).await?;
    tracing::info!("Proxy: received {} bytes from target", response.len());

    // Calculate request duration
    let duration_ms = request_start.elapsed().as_millis() as u64;

    // Parse status code from response
    let response_str = String::from_utf8_lossy(&response);
    let status_code = response_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Update history
    history.update_response(
        id,
        status_code,
        duration_ms,
        response.len(),
        std::collections::HashMap::new(),
        Some(response.clone()),
    );

    // Send ProxyComplete event for passive scanning
    if let Some(entry) = history.get(id) {
        if let Err(e) = event_tx.send(AppEvent::ProxyComplete(entry)).await {
            tracing::warn!("Failed to send ProxyComplete event: {}", e);
        }
    }

    // Send response to client
    tracing::info!("Proxy: sending {} byte response (status {})", response.len(), status_code);
    stream.write_all(&response).await?;
    tracing::info!("Proxy: request complete");

    Ok(())
}

/// Handle WebSocket proxy connection
async fn handle_websocket_proxy(
    _client_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    host: &str,
    port: u16,
    path: &str,
    _request_line: &str,
    _raw_headers: &[String],
    headers: &std::collections::HashMap<String, String>,
    ws_history: Arc<WebSocketHistory>,
) -> Result<()> {
    let ws_url = format!("wss://{}:{}{}", host, port, path);
    tracing::info!("WebSocket upgrade detected: {}", ws_url);

    // Create session in history
    let session_id = ws_history.create_session(&ws_url, host);
    ws_history.update_session(session_id, |s| {
        s.origin = headers.get("origin").cloned();
        s.subprotocol = headers.get("sec-websocket-protocol").cloned();
    });

    // TODO: Full WebSocket MITM proxying requires complex stream handling
    // For now, just log the WebSocket connection attempt
    tracing::warn!("WebSocket proxy not yet fully implemented - connection to {} will be logged but not proxied", ws_url);

    // Mark session as closed since we can't proxy it yet
    ws_history.update_session(session_id, |s| s.mark_closed());

    // Return error to indicate WebSocket cannot be handled yet
    anyhow::bail!("WebSocket proxy not yet implemented")
}
