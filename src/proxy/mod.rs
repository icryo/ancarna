//! Intercepting proxy module
//!
//! Provides HTTP/HTTPS proxy functionality for intercepting and
//! analyzing web traffic.

mod history;
mod intercept;
mod server;
mod tls;
mod websocket;

pub use history::HistoryEntry;
pub use intercept::{InterceptDecision, InterceptedRequest};
pub use server::ProxyServer;
