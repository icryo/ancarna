//! HAR (HTTP Archive) import

use anyhow::{Context, Result};
use serde::Deserialize;

use super::ImportResult;
use crate::http::Request;
use crate::workspace::collections::Collection;

/// Import a HAR file
pub fn import(content: &str) -> Result<ImportResult> {
    let har: HarFile = serde_json::from_str(content).context("Failed to parse HAR file")?;

    let mut collection = Collection::new("Imported from HAR");

    for entry in &har.log.entries {
        let request = convert_entry(entry)?;
        let name = format!("{} {}", entry.request.method, entry.request.url);
        collection.add_request(&name, request);
    }

    Ok(ImportResult::Collection(collection))
}

fn convert_entry(entry: &HarEntry) -> Result<Request> {
    let mut request = Request::new(&entry.request.method, &entry.request.url);

    // Convert headers
    for header in &entry.request.headers {
        // Skip pseudo-headers and cookies
        if !header.name.starts_with(':') && header.name.to_lowercase() != "cookie" {
            request.headers.insert(header.name.clone(), header.value.clone());
        }
    }

    // Convert query string
    if let Some(query_string) = &entry.request.query_string {
        for param in query_string {
            request.params.insert(param.name.clone(), param.value.clone());
        }
    }

    // Convert body
    if let Some(post_data) = &entry.request.post_data {
        request.body = Some(post_data.text.clone());
    }

    Ok(request)
}

// HAR file structures

#[derive(Debug, Deserialize)]
struct HarFile {
    log: HarLog,
}

#[derive(Debug, Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    request: HarRequest,
    #[serde(default)]
    response: Option<HarResponse>,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    method: String,
    url: String,
    headers: Vec<HarHeader>,
    #[serde(rename = "queryString")]
    query_string: Option<Vec<HarQueryParam>>,
    #[serde(rename = "postData")]
    post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
struct HarResponse {
    status: u16,
    #[serde(rename = "statusText")]
    status_text: String,
}

#[derive(Debug, Deserialize)]
struct HarHeader {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarQueryParam {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    #[serde(rename = "mimeType")]
    mime_type: String,
    text: String,
}
