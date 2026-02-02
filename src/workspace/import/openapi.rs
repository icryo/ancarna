//! OpenAPI/Swagger import

use anyhow::{Context, Result};

use super::ImportResult;
use crate::http::Request;
use crate::workspace::collections::Collection;

/// Import an OpenAPI specification
pub fn import(content: &str) -> Result<ImportResult> {
    // Try JSON first, then YAML
    let spec: openapiv3::OpenAPI = if content.trim().starts_with('{') {
        serde_json::from_str(content).context("Failed to parse OpenAPI JSON")?
    } else {
        serde_yaml::from_str(content).context("Failed to parse OpenAPI YAML")?
    };

    let collection = convert_spec(&spec)?;
    Ok(ImportResult::Collection(collection))
}

fn convert_spec(spec: &openapiv3::OpenAPI) -> Result<Collection> {
    let name = spec
        .info
        .title
        .clone();

    let mut collection = Collection::new(&name);
    collection.description = spec.info.description.clone();

    // Get base URL
    let base_url = spec
        .servers
        .first()
        .map(|s| s.url.clone())
        .unwrap_or_else(|| "https://api.example.com".to_string());

    // Convert paths to requests
    for (path, path_item) in &spec.paths.paths {
        if let openapiv3::ReferenceOr::Item(item) = path_item {
            // Handle each HTTP method
            if let Some(op) = &item.get {
                let request = convert_operation("GET", &base_url, path, op);
                let name = op
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("GET {}", path));
                collection.add_request(&name, request);
            }

            if let Some(op) = &item.post {
                let request = convert_operation("POST", &base_url, path, op);
                let name = op
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("POST {}", path));
                collection.add_request(&name, request);
            }

            if let Some(op) = &item.put {
                let request = convert_operation("PUT", &base_url, path, op);
                let name = op
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("PUT {}", path));
                collection.add_request(&name, request);
            }

            if let Some(op) = &item.patch {
                let request = convert_operation("PATCH", &base_url, path, op);
                let name = op
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("PATCH {}", path));
                collection.add_request(&name, request);
            }

            if let Some(op) = &item.delete {
                let request = convert_operation("DELETE", &base_url, path, op);
                let name = op
                    .operation_id
                    .clone()
                    .unwrap_or_else(|| format!("DELETE {}", path));
                collection.add_request(&name, request);
            }
        }
    }

    Ok(collection)
}

fn convert_operation(
    method: &str,
    base_url: &str,
    path: &str,
    operation: &openapiv3::Operation,
) -> Request {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);

    let mut request = Request::new(method, &url);

    // Set description
    if let Some(desc) = &operation.description {
        request.name = desc.clone();
    } else if let Some(summary) = &operation.summary {
        request.name = summary.clone();
    }

    // Extract path parameters
    for param in &operation.parameters {
        if let openapiv3::ReferenceOr::Item(p) = param {
            match p {
                openapiv3::Parameter::Query { parameter_data, .. } => {
                    // Add as query param with placeholder
                    request.params.insert(
                        parameter_data.name.clone(),
                        format!("{{{{{}}}}}", parameter_data.name),
                    );
                }
                openapiv3::Parameter::Header { parameter_data, .. } => {
                    request.headers.insert(
                        parameter_data.name.clone(),
                        format!("{{{{{}}}}}", parameter_data.name),
                    );
                }
                _ => {}
            }
        }
    }

    // Add content-type for methods with body
    if method == "POST" || method == "PUT" || method == "PATCH" {
        if let Some(openapiv3::ReferenceOr::Item(b)) = &operation.request_body {
            if b.content.contains_key("application/json") {
                request
                    .headers
                    .insert("Content-Type".to_string(), "application/json".to_string());
                request.body = Some("{}".to_string());
            }
        }
    }

    request
}
