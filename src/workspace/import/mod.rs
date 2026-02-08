//! Import formats for collections and requests

#![allow(dead_code)]

pub mod curl;
pub mod har;
pub mod openapi;
pub mod postman;

use anyhow::Result;

use super::collections::Collection;
use super::project::Project;

/// Detect format and import
pub fn import_auto(content: &str) -> Result<ImportResult> {
    // Try to detect format
    if content.starts_with("curl") || content.starts_with("curl ") {
        return curl::import(content);
    }

    // Try JSON-based formats
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        // Check for Postman collection
        if json.get("info").is_some() && json.get("item").is_some() {
            return postman::import(content);
        }

        // Check for HAR format
        if json.get("log").is_some() {
            return har::import(content);
        }

        // Check for OpenAPI
        if json.get("openapi").is_some() || json.get("swagger").is_some() {
            return openapi::import(content);
        }
    }

    // Try YAML-based formats
    if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content) {
        // Check for OpenAPI
        if yaml.get("openapi").is_some() || yaml.get("swagger").is_some() {
            return openapi::import(content);
        }
    }

    Err(anyhow::anyhow!("Unknown import format"))
}

/// Result of an import operation
pub enum ImportResult {
    /// Imported a single collection
    Collection(Collection),

    /// Imported multiple collections
    Collections(Vec<Collection>),

    /// Imported a project
    Project(Project),
}
