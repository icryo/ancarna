//! JavaScript scripting engine
//!
//! Provides scripting capabilities for pre/post request scripts
//! and custom automation.

#![allow(dead_code)]

use anyhow::Result;
use boa_engine::{Context as JsContext, JsValue, Source};
use std::collections::HashMap;

/// Script execution context
pub struct ScriptContext {
    /// JavaScript context
    js_context: JsContext,

    /// Script timeout in milliseconds
    timeout_ms: u64,
}

/// Result of script execution
#[derive(Debug, Clone)]
pub struct ScriptResult {
    /// Whether the script succeeded
    pub success: bool,

    /// Return value (if any)
    pub value: Option<String>,

    /// Console output
    pub console: Vec<String>,

    /// Variables set by the script
    pub variables: HashMap<String, String>,

    /// Error message (if failed)
    pub error: Option<String>,
}

impl ScriptContext {
    /// Create a new script context
    pub fn new(timeout_ms: u64) -> Self {
        let js_context = JsContext::default();

        Self {
            js_context,
            timeout_ms,
        }
    }

    /// Execute a script
    pub fn execute(&mut self, script: &str) -> Result<ScriptResult> {
        let source = Source::from_bytes(script);

        match self.js_context.eval(source) {
            Ok(value) => {
                let value_str = value.to_string(&mut self.js_context)
                    .map(|s| s.to_std_string_escaped())
                    .ok();

                Ok(ScriptResult {
                    success: true,
                    value: value_str,
                    console: Vec::new(),
                    variables: HashMap::new(),
                    error: None,
                })
            }
            Err(e) => Ok(ScriptResult {
                success: false,
                value: None,
                console: Vec::new(),
                variables: HashMap::new(),
                error: Some(e.to_string()),
            }),
        }
    }

    /// Set a variable in the context
    pub fn set_variable(&mut self, name: &str, value: &str) -> Result<()> {
        let js_value = JsValue::from(boa_engine::js_string!(value));
        self.js_context.register_global_property(
            boa_engine::js_string!(name),
            js_value,
            boa_engine::property::Attribute::all(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to set variable: {}", e))?;
        Ok(())
    }

    /// Set request object in context
    pub fn set_request(&mut self, request: &crate::http::Request) -> Result<()> {
        let json = serde_json::to_string(request)?;
        let script = format!("var request = {};", json);
        let source = Source::from_bytes(&script);
        self.js_context.eval(source)
            .map_err(|e| anyhow::anyhow!("Failed to set request: {}", e))?;
        Ok(())
    }

    /// Set response object in context
    pub fn set_response(&mut self, response: &crate::http::Response) -> Result<()> {
        // Create a simplified response object for JavaScript
        let response_obj = serde_json::json!({
            "status": response.status,
            "statusText": response.status_text,
            "headers": response.headers,
            "body": response.body_text(),
            "duration": response.duration_ms,
        });

        let script = format!("var response = {};", response_obj);
        let source = Source::from_bytes(&script);
        self.js_context.eval(source)
            .map_err(|e| anyhow::anyhow!("Failed to set response: {}", e))?;
        Ok(())
    }

    /// Set environment variables in context
    pub fn set_environment(&mut self, env: &HashMap<String, String>) -> Result<()> {
        let json = serde_json::to_string(env)?;
        let script = format!("var environment = {};", json);
        let source = Source::from_bytes(&script);
        self.js_context.eval(source)
            .map_err(|e| anyhow::anyhow!("Failed to set environment: {}", e))?;
        Ok(())
    }
}

/// Pre-request script runner
pub struct PreRequestScript {
    script: String,
}

impl PreRequestScript {
    pub fn new(script: &str) -> Self {
        Self {
            script: script.to_string(),
        }
    }

    /// Run the pre-request script
    pub fn run(
        &self,
        request: &mut crate::http::Request,
        environment: &HashMap<String, String>,
    ) -> Result<ScriptResult> {
        let mut context = ScriptContext::new(5000);

        // Set up context
        context.set_request(request)?;
        context.set_environment(environment)?;

        // Add helper functions
        let helpers = r#"
            var pm = {
                environment: {
                    get: function(name) { return environment[name]; },
                    set: function(name, value) { environment[name] = value; }
                },
                request: {
                    headers: request.headers
                }
            };
        "#;

        context.execute(helpers)?;

        // Execute script
        let result = context.execute(&self.script)?;

        // Apply changes from script back to request
        if result.success {
            // Read the modified request object back from JavaScript
            let get_request_script = r#"JSON.stringify(request)"#;
            if let Ok(modified_result) = context.execute(get_request_script) {
                if let Some(json_str) = modified_result.value {
                    // Parse the JSON back into a request-like structure
                    if let Ok(modified_req) = serde_json::from_str::<ModifiedRequest>(&json_str) {
                        // Apply changes to the original request
                        if let Some(url) = modified_req.url {
                            request.url = url;
                        }
                        if let Some(method) = modified_req.method {
                            request.method = method;
                        }
                        if let Some(headers) = modified_req.headers {
                            for (key, value) in headers {
                                request.headers.insert(key, value);
                            }
                        }
                        if let Some(params) = modified_req.params {
                            for (key, value) in params {
                                request.params.insert(key, value);
                            }
                        }
                        if let Some(body) = modified_req.body {
                            request.body = Some(body);
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

/// Struct for deserializing modified request from JavaScript
#[derive(Debug, serde::Deserialize)]
struct ModifiedRequest {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    params: Option<HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
}

/// Post-request script runner (tests)
pub struct PostRequestScript {
    script: String,
}

impl PostRequestScript {
    pub fn new(script: &str) -> Self {
        Self {
            script: script.to_string(),
        }
    }

    /// Run the post-request script
    pub fn run(
        &self,
        request: &crate::http::Request,
        response: &crate::http::Response,
        environment: &HashMap<String, String>,
    ) -> Result<ScriptResult> {
        let mut context = ScriptContext::new(5000);

        // Set up context
        context.set_request(request)?;
        context.set_response(response)?;
        context.set_environment(environment)?;

        // Add helper functions and test framework
        let helpers = r#"
            var tests = {};
            var pm = {
                environment: {
                    get: function(name) { return environment[name]; },
                    set: function(name, value) { environment[name] = value; }
                },
                response: {
                    code: response.status,
                    json: function() { return JSON.parse(response.body); },
                    text: function() { return response.body; },
                    headers: response.headers
                },
                test: function(name, fn) {
                    try {
                        fn();
                        tests[name] = { passed: true };
                    } catch (e) {
                        tests[name] = { passed: false, error: e.message };
                    }
                },
                expect: function(value) {
                    return {
                        to: {
                            equal: function(expected) {
                                if (value !== expected) {
                                    throw new Error('Expected ' + expected + ' but got ' + value);
                                }
                            },
                            be: {
                                a: function(type) {
                                    if (typeof value !== type) {
                                        throw new Error('Expected type ' + type);
                                    }
                                }
                            },
                            have: {
                                property: function(prop) {
                                    if (!(prop in value)) {
                                        throw new Error('Missing property: ' + prop);
                                    }
                                }
                            }
                        }
                    };
                }
            };
        "#;

        context.execute(helpers)?;

        // Execute script
        let result = context.execute(&self.script)?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_script() {
        let mut context = ScriptContext::new(5000);
        let result = context.execute("1 + 1").unwrap();
        assert!(result.success);
        assert_eq!(result.value, Some("2".to_string()));
    }

    #[test]
    fn test_script_error() {
        let mut context = ScriptContext::new(5000);
        // Use a syntax error to test error handling
        let result = context.execute("function { invalid syntax").unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
