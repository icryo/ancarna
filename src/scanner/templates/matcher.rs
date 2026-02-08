//! Matcher execution
//!
//! Executes matchers against HTTP responses.

use regex::Regex;

use super::parser::{Matcher, MatcherCondition, MatcherPart, MatcherType};
use crate::http::{Request, Response};

/// Result of a match operation
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Whether the matcher matched
    pub matched: bool,
    /// Name of the matcher (if any)
    pub name: Option<String>,
    /// Extracted values from the match
    pub extracts: Vec<String>,
}

impl MatchResult {
    pub fn success(name: Option<String>) -> Self {
        Self {
            matched: true,
            name,
            extracts: Vec::new(),
        }
    }

    pub fn failure() -> Self {
        Self {
            matched: false,
            name: None,
            extracts: Vec::new(),
        }
    }

    pub fn with_extracts(mut self, extracts: Vec<String>) -> Self {
        self.extracts = extracts;
        self
    }
}

/// Execute a matcher against request/response
pub fn execute_matcher(
    matcher: &Matcher,
    request: &Request,
    response: &Response,
) -> MatchResult {
    // Handle compound matchers with sub_matchers
    let result = if !matcher.sub_matchers.is_empty() {
        execute_compound_matcher(matcher, request, response)
    } else {
        match matcher.matcher_type {
            MatcherType::Status => execute_status_matcher(matcher, response),
            MatcherType::Word => execute_word_matcher(matcher, request, response),
            MatcherType::Regex => execute_regex_matcher(matcher, request, response),
            MatcherType::Dsl => execute_dsl_matcher(matcher, request, response),
            MatcherType::Binary => MatchResult::failure(), // Not implemented
        }
    };

    // Apply negative logic
    if matcher.negative {
        MatchResult {
            matched: !result.matched,
            name: result.name,
            extracts: result.extracts,
        }
    } else {
        result
    }
}

/// Execute a compound matcher with sub_matchers
fn execute_compound_matcher(
    matcher: &Matcher,
    request: &Request,
    response: &Response,
) -> MatchResult {
    let results: Vec<MatchResult> = matcher
        .sub_matchers
        .iter()
        .map(|m| execute_matcher(m, request, response))
        .collect();

    let matched = match matcher.condition {
        MatcherCondition::And => results.iter().all(|r| r.matched),
        MatcherCondition::Or => results.iter().any(|r| r.matched),
    };

    if matched {
        let extracts: Vec<String> = results
            .into_iter()
            .filter(|r| r.matched)
            .flat_map(|r| r.extracts)
            .collect();
        MatchResult::success(matcher.name.clone()).with_extracts(extracts)
    } else {
        MatchResult::failure()
    }
}

/// Execute status code matcher
fn execute_status_matcher(matcher: &Matcher, response: &Response) -> MatchResult {
    let status = response.status;
    let matched = matcher.status.iter().any(|&s| s == status);

    if matched {
        MatchResult::success(matcher.name.clone())
    } else {
        MatchResult::failure()
    }
}

/// Execute word matcher
fn execute_word_matcher(
    matcher: &Matcher,
    request: &Request,
    response: &Response,
) -> MatchResult {
    // Empty word list should not match anything
    if matcher.words.is_empty() {
        return MatchResult::failure();
    }

    let text = get_match_text(matcher.part, request, response);
    let text_lower = text.to_lowercase();

    let matches: Vec<bool> = matcher.words.iter().map(|word| {
        if matcher.case_insensitive {
            text_lower.contains(&word.to_lowercase())
        } else {
            text.contains(word)
        }
    }).collect();

    let matched = match matcher.condition {
        MatcherCondition::And => matches.iter().all(|&m| m),
        MatcherCondition::Or => matches.iter().any(|&m| m),
    };

    if matched {
        let extracts: Vec<String> = matcher.words.iter()
            .filter(|word| {
                if matcher.case_insensitive {
                    text_lower.contains(&word.to_lowercase())
                } else {
                    text.contains(*word)
                }
            })
            .cloned()
            .collect();
        MatchResult::success(matcher.name.clone()).with_extracts(extracts)
    } else {
        MatchResult::failure()
    }
}

/// Execute regex matcher
fn execute_regex_matcher(
    matcher: &Matcher,
    request: &Request,
    response: &Response,
) -> MatchResult {
    let text = get_match_text(matcher.part, request, response);

    let patterns: Vec<Regex> = matcher.regex.iter()
        .filter_map(|pattern| {
            // Only add (?i) if case_insensitive is true AND pattern doesn't already have it
            let pattern = if matcher.case_insensitive && !pattern.contains("(?i)") {
                format!("(?i){}", pattern)
            } else {
                pattern.clone()
            };
            Regex::new(&pattern).ok()
        })
        .collect();

    if patterns.is_empty() {
        return MatchResult::failure();
    }

    let matches: Vec<bool> = patterns.iter().map(|re| re.is_match(&text)).collect();

    let matched = match matcher.condition {
        MatcherCondition::And => matches.iter().all(|&m| m),
        MatcherCondition::Or => matches.iter().any(|&m| m),
    };

    if matched {
        let extracts: Vec<String> = patterns.iter()
            .flat_map(|re| {
                re.find_iter(&text)
                    .take(5) // Limit extracts
                    .map(|m| m.as_str().to_string())
            })
            .collect();
        MatchResult::success(matcher.name.clone()).with_extracts(extracts)
    } else {
        MatchResult::failure()
    }
}

/// Execute DSL matcher (simplified implementation)
fn execute_dsl_matcher(
    matcher: &Matcher,
    request: &Request,
    response: &Response,
) -> MatchResult {
    // Simplified DSL evaluation - supports basic checks
    let header_text = format_headers(&response.headers);
    let body_text = response.body_text();
    let status_code = response.status;

    let matches: Vec<bool> = matcher.dsl.iter().map(|expr| {
        evaluate_dsl(expr, &header_text, &body_text, status_code, request)
    }).collect();

    let matched = match matcher.condition {
        MatcherCondition::And => matches.iter().all(|&m| m),
        MatcherCondition::Or => matches.iter().any(|&m| m),
    };

    if matched {
        MatchResult::success(matcher.name.clone())
    } else {
        MatchResult::failure()
    }
}

/// Get text to match based on part
fn get_match_text(part: MatcherPart, _request: &Request, response: &Response) -> String {
    match part {
        MatcherPart::Body => response.body_text(),
        MatcherPart::Header => format_headers(&response.headers),
        MatcherPart::All => {
            let headers = format_headers(&response.headers);
            let body = response.body_text();
            format!("{}\n\n{}", headers, body)
        }
    }
}

/// Format headers as text
fn format_headers(headers: &std::collections::HashMap<String, String>) -> String {
    headers.iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Evaluate a simple DSL expression
fn evaluate_dsl(
    expr: &str,
    headers: &str,
    body: &str,
    status_code: u16,
    _request: &Request,
) -> bool {
    let expr = expr.trim();

    // Handle negation
    let (is_negated, expr) = if expr.starts_with('!') {
        (true, expr[1..].trim())
    } else {
        (false, expr)
    };

    let result = if expr.starts_with("regex(") {
        // regex('pattern', header) or regex('pattern', body)
        evaluate_regex_dsl(expr, headers, body)
    } else if expr.starts_with("contains(") {
        // contains(header, 'value')
        evaluate_contains_dsl(expr, headers, body)
    } else if expr.contains("status_code") {
        // status_code == 200, status_code != 301
        evaluate_status_dsl(expr, status_code)
    } else if expr.contains("len(body)") || expr.contains("len(header)") {
        // len(body) > 0
        evaluate_len_dsl(expr, headers, body)
    } else {
        // Default: try as regex on headers
        if let Ok(re) = Regex::new(&format!("(?i){}", expr)) {
            re.is_match(headers) || re.is_match(body)
        } else {
            false
        }
    };

    if is_negated { !result } else { result }
}

fn evaluate_regex_dsl(expr: &str, headers: &str, body: &str) -> bool {
    // Parse regex('pattern', part) or regex("pattern", part)
    let inner = expr.trim_start_matches("regex(").trim_end_matches(')');

    // Find the pattern by looking for matching quotes
    let (pattern, part) = if let Some(result) = parse_quoted_arg(inner) {
        result
    } else {
        return false;
    };

    let text = if part.to_lowercase().contains("header") {
        headers
    } else {
        body
    };

    Regex::new(&format!("(?i){}", pattern))
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

/// Parse a quoted argument from DSL expression, handling commas inside quotes
/// Returns (pattern, remaining) or None if parsing fails
fn parse_quoted_arg(input: &str) -> Option<(String, String)> {
    let input = input.trim();

    // Determine quote character
    let quote_char = if input.starts_with('\'') {
        '\''
    } else if input.starts_with('"') {
        '"'
    } else {
        // No quotes, fall back to comma split (legacy behavior)
        let parts: Vec<&str> = input.splitn(2, ',').collect();
        if parts.len() == 2 {
            return Some((parts[0].trim().to_string(), parts[1].trim().to_string()));
        }
        return None;
    };

    // Find the closing quote (skip escaped quotes)
    let chars: Vec<char> = input.chars().collect();
    let mut i = 1; // Start after opening quote
    let mut pattern = String::new();

    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            // Escaped character
            pattern.push(chars[i + 1]);
            i += 2;
        } else if chars[i] == quote_char {
            // Found closing quote
            let remaining = &input[i + 1..];
            // Skip comma and whitespace to get the part
            let part = remaining.trim_start_matches(',').trim();
            return Some((pattern, part.to_string()));
        } else {
            pattern.push(chars[i]);
            i += 1;
        }
    }

    None // No closing quote found
}

fn evaluate_contains_dsl(expr: &str, headers: &str, body: &str) -> bool {
    // Parse contains(part, 'value')
    let inner = expr.trim_start_matches("contains(").trim_end_matches(')');

    // Split on first comma to get part, then parse the value
    let parts: Vec<&str> = inner.splitn(2, ',').collect();
    if parts.len() != 2 {
        return false;
    }

    let part = parts[0].trim().to_lowercase();
    let value_str = parts[1].trim();

    // Handle quoted values (which may contain commas)
    let value = if value_str.starts_with('\'') || value_str.starts_with('"') {
        let quote = value_str.chars().next().unwrap();
        value_str
            .trim_start_matches(quote)
            .trim_end_matches(quote)
            .to_lowercase()
    } else {
        value_str.to_lowercase()
    };

    let text = if part.contains("header") {
        headers.to_lowercase()
    } else {
        body.to_lowercase()
    };

    text.contains(&value)
}

fn evaluate_status_dsl(expr: &str, status_code: u16) -> bool {
    // Parse status_code comparisons: ==, !=, >=, <=, >, <
    let expr = expr.replace("status_code", &status_code.to_string());

    // Check operators in order of specificity (>= before >, etc.)
    if expr.contains("!=") {
        let parts: Vec<&str> = expr.split("!=").collect();
        if parts.len() == 2 {
            let left: u16 = parts[0].trim().parse().unwrap_or(0);
            let right: u16 = parts[1].trim().parse().unwrap_or(0);
            return left != right;
        }
    } else if expr.contains("==") {
        let parts: Vec<&str> = expr.split("==").collect();
        if parts.len() == 2 {
            let left: u16 = parts[0].trim().parse().unwrap_or(0);
            let right: u16 = parts[1].trim().parse().unwrap_or(0);
            return left == right;
        }
    } else if expr.contains(">=") {
        let parts: Vec<&str> = expr.split(">=").collect();
        if parts.len() == 2 {
            let left: u16 = parts[0].trim().parse().unwrap_or(0);
            let right: u16 = parts[1].trim().parse().unwrap_or(0);
            return left >= right;
        }
    } else if expr.contains("<=") {
        let parts: Vec<&str> = expr.split("<=").collect();
        if parts.len() == 2 {
            let left: u16 = parts[0].trim().parse().unwrap_or(0);
            let right: u16 = parts[1].trim().parse().unwrap_or(0);
            return left <= right;
        }
    } else if expr.contains('>') {
        let parts: Vec<&str> = expr.split('>').collect();
        if parts.len() == 2 {
            let left: u16 = parts[0].trim().parse().unwrap_or(0);
            let right: u16 = parts[1].trim().parse().unwrap_or(0);
            return left > right;
        }
    } else if expr.contains('<') {
        let parts: Vec<&str> = expr.split('<').collect();
        if parts.len() == 2 {
            let left: u16 = parts[0].trim().parse().unwrap_or(0);
            let right: u16 = parts[1].trim().parse().unwrap_or(0);
            return left < right;
        }
    }

    false
}

fn evaluate_len_dsl(expr: &str, headers: &str, body: &str) -> bool {
    // Parse len(body) comparisons: ==, !=, >=, <=, >, <
    let header_len = headers.len();
    let body_len = body.len();

    let expr = expr
        .replace("len(body)", &body_len.to_string())
        .replace("len(header)", &header_len.to_string());

    // Check operators in order of specificity (>= before >, etc.)
    if expr.contains("!=") {
        let parts: Vec<&str> = expr.split("!=").collect();
        if parts.len() == 2 {
            let left: usize = parts[0].trim().parse().unwrap_or(0);
            let right: usize = parts[1].trim().parse().unwrap_or(0);
            return left != right;
        }
    } else if expr.contains("==") {
        let parts: Vec<&str> = expr.split("==").collect();
        if parts.len() == 2 {
            let left: usize = parts[0].trim().parse().unwrap_or(0);
            let right: usize = parts[1].trim().parse().unwrap_or(0);
            return left == right;
        }
    } else if expr.contains(">=") {
        let parts: Vec<&str> = expr.split(">=").collect();
        if parts.len() == 2 {
            let left: usize = parts[0].trim().parse().unwrap_or(0);
            let right: usize = parts[1].trim().parse().unwrap_or(0);
            return left >= right;
        }
    } else if expr.contains("<=") {
        let parts: Vec<&str> = expr.split("<=").collect();
        if parts.len() == 2 {
            let left: usize = parts[0].trim().parse().unwrap_or(0);
            let right: usize = parts[1].trim().parse().unwrap_or(0);
            return left <= right;
        }
    } else if expr.contains('>') {
        let parts: Vec<&str> = expr.split('>').collect();
        if parts.len() == 2 {
            let left: usize = parts[0].trim().parse().unwrap_or(0);
            let right: usize = parts[1].trim().parse().unwrap_or(0);
            return left > right;
        }
    } else if expr.contains('<') {
        let parts: Vec<&str> = expr.split('<').collect();
        if parts.len() == 2 {
            let left: usize = parts[0].trim().parse().unwrap_or(0);
            let right: usize = parts[1].trim().parse().unwrap_or(0);
            return left < right;
        }
    }

    false
}

/// Execute multiple matchers with a condition
pub fn execute_matchers(
    matchers: &[Matcher],
    condition: MatcherCondition,
    request: &Request,
    response: &Response,
) -> Vec<MatchResult> {
    let results: Vec<MatchResult> = matchers.iter()
        .map(|m| execute_matcher(m, request, response))
        .collect();

    let all_matched = match condition {
        MatcherCondition::And => results.iter().all(|r| r.matched),
        MatcherCondition::Or => results.iter().any(|r| r.matched),
    };

    if all_matched {
        results
    } else {
        Vec::new()
    }
}
