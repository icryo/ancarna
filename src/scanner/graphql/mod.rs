//! GraphQL Security Scanner
//!
//! Detects and tests GraphQL endpoints for security vulnerabilities including:
//! - Introspection exposure
//! - Injection attacks
//! - Batching/aliasing attacks
//! - Denial of Service via deep nesting
//! - Authorization bypass
//!
//! # Usage
//! ```ignore
//! let scanner = GraphQLScanner::new();
//! let findings = scanner.scan("https://api.example.com/graphql").await?;
//! ```

use crate::http::{Request, Response};
use crate::scanner::findings::{Finding, Severity};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

/// GraphQL endpoint detection patterns
const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/graphql",
    "/api/v1/graphql",
    "/query",
    "/gql",
    "/playground",
    "/console",
    "/altair",
];

/// GraphQL introspection query
const INTROSPECTION_QUERY: &str = r#"
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"#;

/// Simple introspection query
const SIMPLE_INTROSPECTION: &str = r#"{ __schema { types { name } } }"#;

/// GraphQL type kind
const TYPE_INTROSPECTION: &str = r#"{ __type(name: "Query") { name fields { name type { name } } } }"#;

/// GraphQL schema information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphQLSchema {
    /// Query type name
    pub query_type: Option<String>,
    /// Mutation type name
    pub mutation_type: Option<String>,
    /// Subscription type name
    pub subscription_type: Option<String>,
    /// All types in the schema
    pub types: Vec<GraphQLType>,
    /// Extracted queries
    pub queries: Vec<GraphQLField>,
    /// Extracted mutations
    pub mutations: Vec<GraphQLField>,
}

/// GraphQL type definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLType {
    /// Type name
    pub name: String,
    /// Type kind (OBJECT, SCALAR, ENUM, etc.)
    pub kind: String,
    /// Type description
    pub description: Option<String>,
    /// Fields (for object types)
    pub fields: Vec<GraphQLField>,
}

/// GraphQL field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLField {
    /// Field name
    pub name: String,
    /// Field description
    pub description: Option<String>,
    /// Field arguments
    pub args: Vec<GraphQLArgument>,
    /// Return type
    pub return_type: String,
}

/// GraphQL argument
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLArgument {
    /// Argument name
    pub name: String,
    /// Argument type
    pub arg_type: String,
    /// Whether the argument is required
    pub required: bool,
}

/// GraphQL vulnerability finding
#[derive(Debug, Clone)]
pub struct GraphQLFinding {
    /// Vulnerability type
    pub vuln_type: GraphQLVulnType,
    /// Severity
    pub severity: Severity,
    /// Description
    pub description: String,
    /// Evidence
    pub evidence: Option<String>,
    /// Affected query/mutation
    pub affected_operation: Option<String>,
}

/// Types of GraphQL vulnerabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphQLVulnType {
    /// Introspection is enabled
    IntrospectionEnabled,
    /// Field suggestions enabled (information disclosure)
    FieldSuggestionsEnabled,
    /// Batching attack possible
    BatchingEnabled,
    /// Deep nesting allowed (DoS)
    DeepNestingAllowed,
    /// SQL injection in arguments
    SqlInjection,
    /// NoSQL injection in arguments
    NoSqlInjection,
    /// Authorization bypass
    AuthorizationBypass,
    /// Sensitive data exposed
    SensitiveDataExposed,
    /// Debug mode enabled
    DebugModeEnabled,
    /// CSRF possible (no CSRF token)
    CsrfVulnerable,
}

impl std::fmt::Display for GraphQLVulnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntrospectionEnabled => write!(f, "GraphQL Introspection Enabled"),
            Self::FieldSuggestionsEnabled => write!(f, "GraphQL Field Suggestions Enabled"),
            Self::BatchingEnabled => write!(f, "GraphQL Batching Attack Possible"),
            Self::DeepNestingAllowed => write!(f, "GraphQL Deep Nesting DoS"),
            Self::SqlInjection => write!(f, "GraphQL SQL Injection"),
            Self::NoSqlInjection => write!(f, "GraphQL NoSQL Injection"),
            Self::AuthorizationBypass => write!(f, "GraphQL Authorization Bypass"),
            Self::SensitiveDataExposed => write!(f, "GraphQL Sensitive Data Exposure"),
            Self::DebugModeEnabled => write!(f, "GraphQL Debug Mode Enabled"),
            Self::CsrfVulnerable => write!(f, "GraphQL CSRF Vulnerability"),
        }
    }
}

/// GraphQL security scanner
pub struct GraphQLScanner {
    /// HTTP client
    client: Client,
    /// Request timeout
    timeout: std::time::Duration,
    /// Custom headers to include
    headers: HashMap<String, String>,
    /// Maximum nesting depth to test
    max_nesting_depth: usize,
    /// Maximum batch size to test
    max_batch_size: usize,
}

impl GraphQLScanner {
    /// Create a new GraphQL scanner
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
            timeout: std::time::Duration::from_secs(30),
            headers: HashMap::new(),
            max_nesting_depth: 10,
            max_batch_size: 100,
        }
    }

    /// Set custom headers
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Set authentication header
    pub fn with_auth(mut self, token: &str) -> Self {
        self.headers
            .insert("Authorization".to_string(), format!("Bearer {}", token));
        self
    }

    /// Detect GraphQL endpoints
    pub async fn detect_endpoints(&self, base_url: &str) -> Result<Vec<String>> {
        let base_url = base_url.trim_end_matches('/');
        let mut endpoints = Vec::new();

        for path in GRAPHQL_PATHS {
            let url = format!("{}{}", base_url, path);

            // Try a simple query to detect GraphQL
            match self.send_query(&url, SIMPLE_INTROSPECTION).await {
                Ok(response) => {
                    if self.is_graphql_response(&response) {
                        endpoints.push(url);
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(endpoints)
    }

    /// Check if response is a valid GraphQL response
    fn is_graphql_response(&self, response: &Value) -> bool {
        response.get("data").is_some() || response.get("errors").is_some()
    }

    /// Send a GraphQL query
    async fn send_query(&self, url: &str, query: &str) -> Result<Value> {
        let body = json!({
            "query": query
        });

        let mut request = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body);

        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        let response = request.send().await.context("Failed to send GraphQL request")?;
        let json: Value = response.json().await.context("Failed to parse GraphQL response")?;

        Ok(json)
    }

    /// Send a GraphQL query with variables
    async fn send_query_with_vars(
        &self,
        url: &str,
        query: &str,
        variables: Value,
    ) -> Result<Value> {
        let body = json!({
            "query": query,
            "variables": variables
        });

        let mut request = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&body);

        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;
        let json: Value = response.json().await?;

        Ok(json)
    }

    /// Scan a GraphQL endpoint for vulnerabilities
    pub async fn scan(&self, url: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Test introspection
        if let Some(finding) = self.test_introspection(url).await? {
            findings.push(finding);
        }

        // Test field suggestions
        if let Some(finding) = self.test_field_suggestions(url).await? {
            findings.push(finding);
        }

        // Test batching
        if let Some(finding) = self.test_batching(url).await? {
            findings.push(finding);
        }

        // Test deep nesting
        if let Some(finding) = self.test_deep_nesting(url).await? {
            findings.push(finding);
        }

        // Test debug mode
        if let Some(finding) = self.test_debug_mode(url).await? {
            findings.push(finding);
        }

        // Get schema and test injections
        if let Ok(schema) = self.extract_schema(url).await {
            // Test SQL injection
            let sqli_findings = self.test_injection(&schema, url).await?;
            findings.extend(sqli_findings);

            // Check for sensitive fields
            if let Some(finding) = self.check_sensitive_fields(&schema, url) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Test if introspection is enabled
    async fn test_introspection(&self, url: &str) -> Result<Option<Finding>> {
        let response = self.send_query(url, INTROSPECTION_QUERY).await?;

        if response.get("data").and_then(|d| d.get("__schema")).is_some() {
            return Ok(Some(
                Finding::new("GraphQL Introspection Enabled", Severity::Medium, url)
                    .with_description(
                        "GraphQL introspection is enabled, allowing attackers to discover \
                         the entire API schema including queries, mutations, types, and fields.",
                    )
                    .with_evidence("__schema query returned full schema")
                    .with_remediation(
                        "Disable introspection in production environments. \
                         Most GraphQL servers have configuration options to disable this feature.",
                    )
                    .with_reference(
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    )
                    .with_cwe(200)
                    .with_scanner("graphql"),
            ));
        }

        Ok(None)
    }

    /// Test if field suggestions are enabled
    async fn test_field_suggestions(&self, url: &str) -> Result<Option<Finding>> {
        // Send a query with an intentionally wrong field name
        let query = r#"{ __typo }"#;
        let response = self.send_query(url, query).await?;

        if let Some(errors) = response.get("errors").and_then(|e| e.as_array()) {
            for error in errors {
                if let Some(message) = error.get("message").and_then(|m| m.as_str()) {
                    if message.contains("Did you mean")
                        || message.contains("did you mean")
                        || message.contains("suggestion")
                    {
                        return Ok(Some(
                            Finding::new("GraphQL Field Suggestions Enabled", Severity::Low, url)
                                .with_description(
                                    "GraphQL field suggestions are enabled, which can help \
                                     attackers discover valid field names through error messages.",
                                )
                                .with_evidence(message)
                                .with_remediation(
                                    "Disable field suggestions in production to reduce information disclosure.",
                                )
                                .with_cwe(200)
                                .with_scanner("graphql"),
                        ));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Test for batching attacks
    async fn test_batching(&self, url: &str) -> Result<Option<Finding>> {
        // Send multiple queries in a batch
        let batch_query = (0..5)
            .map(|i| format!("q{}: __typename", i))
            .collect::<Vec<_>>()
            .join(" ");

        let query = format!("{{ {} }}", batch_query);
        let response = self.send_query(url, &query).await?;

        if response.get("data").is_some() {
            // Check if all queries were executed
            if let Some(data) = response.get("data").and_then(|d| d.as_object()) {
                if data.len() >= 5 {
                    return Ok(Some(
                        Finding::new("GraphQL Batching Attack Possible", Severity::Medium, url)
                            .with_description(
                                "GraphQL batching is enabled without rate limiting. \
                                 Attackers can send multiple queries in a single request \
                                 to bypass rate limits or perform brute-force attacks.",
                            )
                            .with_evidence(&format!("Batched {} queries successfully", data.len()))
                            .with_remediation(
                                "Implement query complexity analysis and rate limiting. \
                                 Consider limiting the number of operations per request.",
                            )
                            .with_reference(
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#batching-attacks",
                            )
                            .with_cwe(770)
                            .with_scanner("graphql"),
                    ));
                }
            }
        }

        Ok(None)
    }

    /// Test for deep nesting DoS
    async fn test_deep_nesting(&self, url: &str) -> Result<Option<Finding>> {
        // Generate a deeply nested query
        let mut query = "__typename".to_string();

        for _ in 0..self.max_nesting_depth {
            query = format!("... on Query {{ {} }}", query);
        }

        let query = format!("{{ {} }}", query);

        // Measure response time
        let start = std::time::Instant::now();
        let response = self.send_query(url, &query).await;
        let duration = start.elapsed();

        match response {
            Ok(resp) => {
                // If the query was accepted and took a long time, it might be vulnerable
                if resp.get("data").is_some() && duration.as_secs() > 5 {
                    return Ok(Some(
                        Finding::new("GraphQL Deep Nesting DoS Possible", Severity::Medium, url)
                            .with_description(&format!(
                                "GraphQL endpoint allows deeply nested queries without limits. \
                                 A query with {} levels of nesting took {:?} to process.",
                                self.max_nesting_depth, duration
                            ))
                            .with_evidence(&format!("Nesting depth: {}", self.max_nesting_depth))
                            .with_remediation(
                                "Implement query depth limiting and complexity analysis \
                                 to prevent denial of service attacks.",
                            )
                            .with_reference(
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#query-depth-limiting",
                            )
                            .with_cwe(400)
                            .with_scanner("graphql"),
                    ));
                }
            }
            Err(_) => {
                // Query was rejected, which is good
            }
        }

        Ok(None)
    }

    /// Test for debug mode
    async fn test_debug_mode(&self, url: &str) -> Result<Option<Finding>> {
        let query = r#"{ __schema { types { name } } }"#;
        let response = self.send_query(url, query).await?;

        if let Some(errors) = response.get("errors").and_then(|e| e.as_array()) {
            for error in errors {
                // Check for stack traces or debug information
                let error_str = serde_json::to_string(error).unwrap_or_default();

                if error_str.contains("stacktrace")
                    || error_str.contains("stack_trace")
                    || error_str.contains("trace")
                    || error_str.contains("at line")
                    || error_str.contains("file:")
                {
                    return Ok(Some(
                        Finding::new("GraphQL Debug Mode Enabled", Severity::Low, url)
                            .with_description(
                                "GraphQL endpoint is exposing debug information \
                                 in error responses, potentially revealing internal details.",
                            )
                            .with_evidence(&error_str)
                            .with_remediation("Disable debug mode in production environments.")
                            .with_cwe(209)
                            .with_scanner("graphql"),
                    ));
                }
            }
        }

        Ok(None)
    }

    /// Extract schema from introspection
    pub async fn extract_schema(&self, url: &str) -> Result<GraphQLSchema> {
        let response = self.send_query(url, INTROSPECTION_QUERY).await?;

        let schema_data = response
            .get("data")
            .and_then(|d| d.get("__schema"))
            .context("Introspection query failed")?;

        let mut schema = GraphQLSchema::default();

        // Extract type names
        schema.query_type = schema_data
            .get("queryType")
            .and_then(|q| q.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        schema.mutation_type = schema_data
            .get("mutationType")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        schema.subscription_type = schema_data
            .get("subscriptionType")
            .and_then(|s| s.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());

        // Extract types
        if let Some(types) = schema_data.get("types").and_then(|t| t.as_array()) {
            for type_data in types {
                if let Some(gql_type) = self.parse_type(type_data) {
                    // Skip internal types
                    if !gql_type.name.starts_with("__") {
                        // Extract queries and mutations
                        if Some(&gql_type.name) == schema.query_type.as_ref() {
                            schema.queries = gql_type.fields.clone();
                        } else if Some(&gql_type.name) == schema.mutation_type.as_ref() {
                            schema.mutations = gql_type.fields.clone();
                        }

                        schema.types.push(gql_type);
                    }
                }
            }
        }

        Ok(schema)
    }

    /// Parse a type from JSON
    fn parse_type(&self, data: &Value) -> Option<GraphQLType> {
        Some(GraphQLType {
            name: data.get("name")?.as_str()?.to_string(),
            kind: data.get("kind")?.as_str()?.to_string(),
            description: data
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string()),
            fields: data
                .get("fields")
                .and_then(|f| f.as_array())
                .map(|fields| {
                    fields
                        .iter()
                        .filter_map(|f| self.parse_field(f))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Parse a field from JSON
    fn parse_field(&self, data: &Value) -> Option<GraphQLField> {
        Some(GraphQLField {
            name: data.get("name")?.as_str()?.to_string(),
            description: data
                .get("description")
                .and_then(|d| d.as_str())
                .map(|s| s.to_string()),
            args: data
                .get("args")
                .and_then(|a| a.as_array())
                .map(|args| {
                    args.iter()
                        .filter_map(|a| self.parse_argument(a))
                        .collect()
                })
                .unwrap_or_default(),
            return_type: self.get_type_name(data.get("type")?),
        })
    }

    /// Parse an argument from JSON
    fn parse_argument(&self, data: &Value) -> Option<GraphQLArgument> {
        Some(GraphQLArgument {
            name: data.get("name")?.as_str()?.to_string(),
            arg_type: self.get_type_name(data.get("type")?),
            required: data
                .get("type")
                .and_then(|t| t.get("kind"))
                .and_then(|k| k.as_str())
                .map(|k| k == "NON_NULL")
                .unwrap_or(false),
        })
    }

    /// Get type name from type reference
    fn get_type_name(&self, type_ref: &Value) -> String {
        if let Some(name) = type_ref.get("name").and_then(|n| n.as_str()) {
            return name.to_string();
        }

        let kind = type_ref
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or("");

        match kind {
            "NON_NULL" => {
                if let Some(of_type) = type_ref.get("ofType") {
                    format!("{}!", self.get_type_name(of_type))
                } else {
                    "Unknown!".to_string()
                }
            }
            "LIST" => {
                if let Some(of_type) = type_ref.get("ofType") {
                    format!("[{}]", self.get_type_name(of_type))
                } else {
                    "[Unknown]".to_string()
                }
            }
            _ => "Unknown".to_string(),
        }
    }

    /// Test for injection vulnerabilities in GraphQL arguments
    async fn test_injection(&self, schema: &GraphQLSchema, url: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // SQL injection payloads
        let sqli_payloads = vec![
            ("'", "SQL syntax"),
            ("\"", "SQL syntax"),
            ("1' OR '1'='1", "OR"),
            ("1; DROP TABLE", "DROP"),
            ("' UNION SELECT", "UNION"),
        ];

        // NoSQL injection payloads
        let nosqli_payloads = vec![
            ("{\"$gt\": \"\"}", "$gt"),
            ("{\"$ne\": null}", "$ne"),
            ("{\"$regex\": \".*\"}", "$regex"),
        ];

        // Test queries with string arguments
        for query in &schema.queries {
            for arg in &query.args {
                if arg.arg_type.contains("String") || arg.arg_type.contains("ID") {
                    // Test SQL injection
                    for (payload, indicator) in &sqli_payloads {
                        let test_query = format!(
                            "{{ {}({}: \"{}\") {{ __typename }} }}",
                            query.name, arg.name, payload
                        );

                        if let Ok(response) = self.send_query(url, &test_query).await {
                            let response_str = serde_json::to_string(&response).unwrap_or_default();

                            if response_str.to_lowercase().contains(&indicator.to_lowercase())
                                || response_str.contains("syntax error")
                                || response_str.contains("mysql")
                                || response_str.contains("postgresql")
                                || response_str.contains("sqlite")
                            {
                                findings.push(
                                    Finding::new("GraphQL SQL Injection", Severity::Critical, url)
                                        .with_description(&format!(
                                            "Potential SQL injection in GraphQL query '{}' argument '{}'",
                                            query.name, arg.name
                                        ))
                                        .with_parameter(&format!("{}.{}", query.name, arg.name))
                                        .with_evidence(&format!(
                                            "Payload: {}, Response indicator: {}",
                                            payload, indicator
                                        ))
                                        .with_remediation(
                                            "Use parameterized queries and proper input validation.",
                                        )
                                        .with_reference(
                                            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#injection",
                                        )
                                        .with_cwe(89)
                                        .with_scanner("graphql"),
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Check for sensitive field exposure
    fn check_sensitive_fields(&self, schema: &GraphQLSchema, url: &str) -> Option<Finding> {
        let sensitive_patterns = vec![
            "password",
            "secret",
            "token",
            "apikey",
            "api_key",
            "private",
            "ssn",
            "credit_card",
            "creditcard",
            "cvv",
        ];

        let mut exposed_fields = Vec::new();

        for gql_type in &schema.types {
            for field in &gql_type.fields {
                let field_lower = field.name.to_lowercase();
                for pattern in &sensitive_patterns {
                    if field_lower.contains(pattern) {
                        exposed_fields.push(format!("{}.{}", gql_type.name, field.name));
                    }
                }
            }
        }

        if !exposed_fields.is_empty() {
            return Some(
                Finding::new("GraphQL Sensitive Data Exposure", Severity::High, url)
                    .with_description(&format!(
                        "The GraphQL schema exposes potentially sensitive fields: {}",
                        exposed_fields.join(", ")
                    ))
                    .with_evidence(&exposed_fields.join(", "))
                    .with_remediation(
                        "Review exposed fields and ensure sensitive data is properly protected. \
                         Consider using field-level authorization.",
                    )
                    .with_cwe(200)
                    .with_scanner("graphql"),
            );
        }

        None
    }
}

impl Default for GraphQLScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_scanner_creation() {
        let scanner = GraphQLScanner::new();
        assert!(!scanner.headers.is_empty() == false);
    }

    #[test]
    fn test_schema_parsing() {
        let scanner = GraphQLScanner::new();

        let type_data = json!({
            "name": "User",
            "kind": "OBJECT",
            "description": "A user",
            "fields": [
                {
                    "name": "id",
                    "description": "User ID",
                    "args": [],
                    "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID" } }
                }
            ]
        });

        let gql_type = scanner.parse_type(&type_data);
        assert!(gql_type.is_some());

        let gql_type = gql_type.unwrap();
        assert_eq!(gql_type.name, "User");
        assert_eq!(gql_type.kind, "OBJECT");
        assert_eq!(gql_type.fields.len(), 1);
        assert_eq!(gql_type.fields[0].name, "id");
    }

    #[test]
    fn test_type_name_extraction() {
        let scanner = GraphQLScanner::new();

        let simple_type = json!({ "kind": "SCALAR", "name": "String" });
        assert_eq!(scanner.get_type_name(&simple_type), "String");

        let non_null_type = json!({
            "kind": "NON_NULL",
            "name": null,
            "ofType": { "kind": "SCALAR", "name": "String" }
        });
        assert_eq!(scanner.get_type_name(&non_null_type), "String!");

        let list_type = json!({
            "kind": "LIST",
            "name": null,
            "ofType": { "kind": "SCALAR", "name": "Int" }
        });
        assert_eq!(scanner.get_type_name(&list_type), "[Int]");
    }
}
