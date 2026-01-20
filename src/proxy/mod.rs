//! Intercepting proxy module
//!
//! Provides HTTP/HTTPS proxy functionality for intercepting and
//! analyzing web traffic.

mod history;
mod intercept;
mod server;
mod tls;
mod websocket;

pub use history::{HistoryEntry, ProxyHistory};
pub use intercept::{InterceptDecision, InterceptManager, InterceptRule, InterceptedRequest};
pub use server::ProxyServer;
pub use tls::CertificateAuthority;
pub use websocket::{
    MessageDirection, MessageType, SessionState, WebSocketFilter, WebSocketHistory,
    WebSocketMessage, WebSocketSession,
};
