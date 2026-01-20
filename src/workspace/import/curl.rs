//! cURL command import

use anyhow::{Context, Result};
use std::collections::HashMap;

use super::ImportResult;
use crate::http::Request;
use crate::workspace::collections::Collection;

/// Import a cURL command
pub fn import(content: &str) -> Result<ImportResult> {
    let request = parse_curl(content)?;

    let mut collection = Collection::new("Imported from cURL");
    collection.add_request("Imported Request", request);

    Ok(ImportResult::Collection(collection))
}

/// Parse a cURL command into a Request
pub fn parse_curl(curl: &str) -> Result<Request> {
    let args = parse_curl_args(curl)?;

    let mut method = "GET".to_string();
    let mut url = String::new();
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut body: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        match arg.as_str() {
            "curl" => {}
            "-X" | "--request" => {
                i += 1;
                if i < args.len() {
                    method = args[i].clone();
                }
            }
            "-H" | "--header" => {
                i += 1;
                if i < args.len() {
                    if let Some((key, value)) = args[i].split_once(':') {
                        headers.insert(key.trim().to_string(), value.trim().to_string());
                    }
                }
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" => {
                i += 1;
                if i < args.len() {
                    body = Some(args[i].clone());
                    if method == "GET" {
                        method = "POST".to_string();
                    }
                }
            }
            "-u" | "--user" => {
                i += 1;
                if i < args.len() {
                    let auth = &args[i];
                    let encoded = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        auth.as_bytes(),
                    );
                    headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
                }
            }
            "-A" | "--user-agent" => {
                i += 1;
                if i < args.len() {
                    headers.insert("User-Agent".to_string(), args[i].clone());
                }
            }
            "-e" | "--referer" => {
                i += 1;
                if i < args.len() {
                    headers.insert("Referer".to_string(), args[i].clone());
                }
            }
            "-b" | "--cookie" => {
                i += 1;
                if i < args.len() {
                    headers.insert("Cookie".to_string(), args[i].clone());
                }
            }
            "-L" | "--location" | "-k" | "--insecure" | "-v" | "--verbose" | "-s" | "--silent" => {
                // Flags we recognize but don't need to handle
            }
            _ if arg.starts_with("http://") || arg.starts_with("https://") => {
                url = arg.clone();
            }
            _ if arg.starts_with('-') => {
                // Unknown flag, skip
            }
            _ if url.is_empty() => {
                url = arg.clone();
            }
            _ => {}
        }

        i += 1;
    }

    if url.is_empty() {
        return Err(anyhow::anyhow!("No URL found in cURL command"));
    }

    let mut request = Request::new(&method, &url);
    request.headers = headers;
    request.body = body;

    Ok(request)
}

/// Parse cURL command into arguments, respecting quotes
fn parse_curl_args(curl: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    // Handle line continuations
    let normalized = curl.replace("\\\n", " ").replace("\\\r\n", " ");

    for c in normalized.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if !in_single_quote => {
                escape_next = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' | '\n' | '\r' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    args.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_curl() {
        let curl = "curl https://api.example.com/users";
        let request = parse_curl(curl).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "https://api.example.com/users");
    }

    #[test]
    fn test_curl_with_method() {
        let curl = "curl -X POST https://api.example.com/users";
        let request = parse_curl(curl).unwrap();
        assert_eq!(request.method, "POST");
    }

    #[test]
    fn test_curl_with_headers() {
        let curl = r#"curl -H "Content-Type: application/json" -H "Authorization: Bearer token" https://api.example.com"#;
        let request = parse_curl(curl).unwrap();
        assert_eq!(
            request.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );
        assert_eq!(
            request.headers.get("Authorization"),
            Some(&"Bearer token".to_string())
        );
    }

    #[test]
    fn test_curl_with_data() {
        let curl = r#"curl -d '{"name":"test"}' https://api.example.com"#;
        let request = parse_curl(curl).unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, Some(r#"{"name":"test"}"#.to_string()));
    }
}
