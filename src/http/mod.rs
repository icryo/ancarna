//! HTTP client module
//!
//! Provides HTTP client functionality for making requests,
//! handling authentication, and managing responses.

#![allow(dead_code)]

mod client;
mod request;
mod response;
pub mod auth;

pub use client::HttpClient;
pub use request::{AuthConfig, Request};
pub use response::Response;
