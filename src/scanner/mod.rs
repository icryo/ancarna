//! Security scanner module
//!
//! Provides passive and active security scanning capabilities.

mod engine;
mod findings;
pub mod active;
pub mod js_analysis;
pub mod jwt;
pub mod param_discovery;
pub mod passive;
pub mod policies;

pub use engine::ScanEngine;
pub use findings::{Finding, Severity};
