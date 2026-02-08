//! Security scanner module
//!
//! Provides passive and active security scanning capabilities.

mod engine;
mod findings;
pub mod active;
pub mod authz;
pub mod graphql;
pub mod js_analysis;
pub mod jwt;
pub mod oob;
pub mod param_discovery;
pub mod passive;
pub mod policies;
pub mod templates;
pub mod upload;

pub use engine::ScanEngine;
pub use findings::{Finding, Severity};
pub use authz::{AuthzTester, UserSession, IdorTester};
pub use graphql::GraphQLScanner;
pub use oob::{OobManager, OobPayloadGenerator};
pub use templates::{Template, TemplateExecutor};
pub use upload::UploadScanner;
