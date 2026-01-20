//! HTTP client module
//!
//! Provides HTTP client functionality for making requests,
//! handling authentication, and managing responses.

mod client;
mod request;
mod response;
pub mod auth;

pub use client::HttpClient;
pub use request::{AuthConfig, ContentType, OAuth2GrantType, Request, RequestBuilder};
pub use response::Response;
