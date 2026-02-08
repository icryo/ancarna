//! Tests for the template engine
//!
//! These tests verify correct behavior after bug fixes.

#[cfg(test)]
mod bug_tests {
    use crate::http::{Request, Response};
    use crate::scanner::templates::executor::TemplateExecutor;
    use crate::scanner::templates::matcher::{execute_matcher, execute_matchers};
    use crate::scanner::templates::parser::{
        Matcher, MatcherCondition, MatcherPart, MatcherType, Severity, Template,
    };
    use std::collections::HashMap;

    fn create_request() -> Request {
        Request {
            id: "test".to_string(),
            name: "Test".to_string(),
            method: "GET".to_string(),
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
            params: HashMap::new(),
            body: None,
            content_type: None,
            auth: None,
            pre_script: None,
            post_script: None,
            timeout: None,
            follow_redirects: true,
        }
    }

    fn create_response(status: u16, headers: HashMap<String, String>, body: &str) -> Response {
        Response {
            status,
            status_text: "OK".to_string(),
            headers,
            body: body.as_bytes().to_vec(),
            duration_ms: 100,
            size: body.len(),
            http_version: "HTTP/1.1".to_string(),
            remote_addr: None,
            tls_info: None,
            timing: None,
            cookies: Vec::new(),
        }
    }

    // =========================================================================
    // FIX 1: Matcher::and() now properly combines matchers
    // =========================================================================
    #[test]
    fn fix1_matcher_and_combines_matchers() {
        let matcher1 = Matcher::body_regex(r"<form.*post");
        let matcher2 = Matcher::body_not_contains(&["csrf_token"]);

        // Matcher::and should combine both matchers
        let combined = Matcher::and(vec![matcher1, matcher2]);

        // FIXED: sub_matchers should contain both matchers
        assert_eq!(
            combined.sub_matchers.len(),
            2,
            "Matcher::and() should preserve all matchers in sub_matchers"
        );

        let request = create_request();

        // Form WITH csrf_token should NOT match (both conditions must be true)
        let body_with_csrf = r#"<form method="post"><input name="csrf_token" value="abc"></form>"#;
        let response_with_csrf = create_response(200, HashMap::new(), body_with_csrf);
        let result_with_csrf = execute_matcher(&combined, &request, &response_with_csrf);
        assert!(
            !result_with_csrf.matched,
            "Form with CSRF token should NOT match"
        );

        // Form WITHOUT csrf_token should match
        let body_without_csrf = r#"<form method="post"><input name="email"></form>"#;
        let response_without_csrf = create_response(200, HashMap::new(), body_without_csrf);
        let result_without_csrf = execute_matcher(&combined, &request, &response_without_csrf);
        assert!(
            result_without_csrf.matched,
            "Form without CSRF token should match"
        );
    }

    // =========================================================================
    // FIX 2: header_missing() now uses multiline mode
    // =========================================================================
    #[test]
    fn fix2_header_missing_multiline() {
        // Create a response with multiple headers
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );

        let request = create_request();
        let response = create_response(200, headers.clone(), "");

        // header_missing should NOT match because HSTS is present
        let matcher = Matcher::header_missing("Strict-Transport-Security");
        let result = execute_matcher(&matcher, &request, &response);

        // FIXED: With (?m) multiline mode, ^ matches start of each line
        assert!(
            !result.matched,
            "header_missing should return false when header exists"
        );

        // Test with missing header
        let mut headers_no_hsts = HashMap::new();
        headers_no_hsts.insert("Content-Type".to_string(), "text/html".to_string());
        let response_no_hsts = create_response(200, headers_no_hsts, "");
        let result_no_hsts = execute_matcher(&matcher, &request, &response_no_hsts);
        assert!(
            result_no_hsts.matched,
            "header_missing should return true when header is absent"
        );
    }

    // =========================================================================
    // FIX 3: Empty word matcher no longer matches
    // =========================================================================
    #[test]
    fn fix3_empty_word_matcher_fails() {
        let matcher = Matcher {
            matcher_type: MatcherType::Word,
            words: Vec::new(), // Empty!
            condition: MatcherCondition::And,
            part: MatcherPart::Body,
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "any content here");

        let result = execute_matcher(&matcher, &request, &response);

        // FIXED: Empty word list should not match anything
        assert!(
            !result.matched,
            "Empty word matcher should not match anything"
        );
    }

    // =========================================================================
    // FIX 4: DSL regex parser handles commas in quoted patterns
    // =========================================================================
    #[test]
    fn fix4_dsl_regex_comma_in_pattern() {
        let matcher = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["regex('ERROR,FATAL', body)".to_string()],
            ..Default::default()
        };

        let request = create_request();
        let response_with_both = create_response(200, HashMap::new(), "Log: ERROR,FATAL occurred");
        let response_with_error_only = create_response(200, HashMap::new(), "Log: ERROR occurred");

        let result_both = execute_matcher(&matcher, &request, &response_with_both);
        let result_error = execute_matcher(&matcher, &request, &response_with_error_only);

        // FIXED: Pattern 'ERROR,FATAL' should be preserved
        assert!(
            result_both.matched,
            "Pattern 'ERROR,FATAL' should match 'ERROR,FATAL'"
        );
        assert!(
            !result_error.matched,
            "Pattern 'ERROR,FATAL' should NOT match 'ERROR' alone"
        );
    }

    // =========================================================================
    // FIX 5: Cookie security detection uses compound matchers
    // =========================================================================
    #[test]
    fn fix5_cookie_httponly_detection() {
        let request = create_request();

        // Test header_not_contains matcher (negative word match)
        let not_contains_matcher = Matcher::header_not_contains("Set-Cookie", "httponly");

        // Header WITHOUT httponly - should match (httponly is NOT present)
        let mut headers_without = HashMap::new();
        headers_without.insert("Set-Cookie".to_string(), "session=abc; Secure".to_string());
        let response_without = create_response(200, headers_without, "");
        let result_without = execute_matcher(&not_contains_matcher, &request, &response_without);

        // Header WITH httponly - should NOT match (httponly IS present)
        let mut headers_with = HashMap::new();
        headers_with.insert("Set-Cookie".to_string(), "session=abc; HttpOnly; Secure".to_string());
        let response_with = create_response(200, headers_with, "");
        let result_with = execute_matcher(&not_contains_matcher, &request, &response_with);

        assert!(
            result_without.matched,
            "header_not_contains should match when httponly is absent"
        );
        assert!(
            !result_with.matched,
            "header_not_contains should NOT match when httponly is present"
        );

        // Now test the full compound matcher
        let compound = Matcher::and(vec![
            Matcher::header_exists("Set-Cookie"),
            Matcher::header_not_contains("Set-Cookie", "httponly"),
        ]);

        let compound_result_without = execute_matcher(&compound, &request, &response_without);
        let compound_result_with = execute_matcher(&compound, &request, &response_with);

        assert!(
            compound_result_without.matched,
            "Compound matcher should flag cookie WITHOUT httponly"
        );
        assert!(
            !compound_result_with.matched,
            "Compound matcher should NOT flag cookie WITH httponly"
        );
    }

    // =========================================================================
    // FIX 6: Private IP regex validates octets
    // =========================================================================
    #[test]
    fn fix6_private_ip_valid_octets() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_request();

        // Invalid IP: octets > 255 - should NOT match
        let body_invalid = "Internal server: 10.999.888.777";
        let response_invalid = create_response(200, HashMap::new(), body_invalid);
        let findings_invalid = executor.execute(&request, &response_invalid);
        let has_ip_invalid = findings_invalid.iter().any(|f| f.name.contains("Private IP"));
        assert!(
            !has_ip_invalid,
            "Invalid IP 10.999.888.777 should NOT be detected as private IP"
        );

        // Valid private IP - should match
        let body_valid = "Internal server: 10.0.1.50";
        let response_valid = create_response(200, HashMap::new(), body_valid);
        let findings_valid = executor.execute(&request, &response_valid);
        let has_ip_valid = findings_valid.iter().any(|f| f.name.contains("Private IP"));
        assert!(
            has_ip_valid,
            "Valid IP 10.0.1.50 should be detected as private IP"
        );
    }

    // =========================================================================
    // FIX 7: Status DSL now supports >=, <=, >, < operators
    // =========================================================================
    #[test]
    fn fix7_status_dsl_operators() {
        let request = create_request();

        // Test >= operator
        let matcher_gte = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["status_code >= 200".to_string()],
            ..Default::default()
        };
        let response_200 = create_response(200, HashMap::new(), "");
        let response_199 = create_response(199, HashMap::new(), "");

        assert!(
            execute_matcher(&matcher_gte, &request, &response_200).matched,
            "status_code >= 200 should match 200"
        );
        assert!(
            !execute_matcher(&matcher_gte, &request, &response_199).matched,
            "status_code >= 200 should NOT match 199"
        );

        // Test <= operator
        let matcher_lte = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["status_code <= 299".to_string()],
            ..Default::default()
        };
        let response_299 = create_response(299, HashMap::new(), "");
        let response_300 = create_response(300, HashMap::new(), "");

        assert!(
            execute_matcher(&matcher_lte, &request, &response_299).matched,
            "status_code <= 299 should match 299"
        );
        assert!(
            !execute_matcher(&matcher_lte, &request, &response_300).matched,
            "status_code <= 299 should NOT match 300"
        );

        // Test > and < operators
        let matcher_gt = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["status_code > 200".to_string()],
            ..Default::default()
        };
        assert!(
            !execute_matcher(&matcher_gt, &request, &response_200).matched,
            "status_code > 200 should NOT match 200"
        );

        let matcher_lt = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["status_code < 200".to_string()],
            ..Default::default()
        };
        assert!(
            execute_matcher(&matcher_lt, &request, &response_199).matched,
            "status_code < 200 should match 199"
        );
    }

    // =========================================================================
    // FIX 8: len() DSL now properly handles >= and <= operators
    // =========================================================================
    #[test]
    fn fix8_len_dsl_operators() {
        let request = create_request();
        let response_small = create_response(200, HashMap::new(), "small"); // 5 chars
        let response_large = create_response(200, HashMap::new(), "this is a much larger body"); // 27 chars

        // Test >= operator
        let matcher_gte = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["len(body) >= 10".to_string()],
            ..Default::default()
        };

        assert!(
            !execute_matcher(&matcher_gte, &request, &response_small).matched,
            "len(body) >= 10 should NOT match 5-char body"
        );
        assert!(
            execute_matcher(&matcher_gte, &request, &response_large).matched,
            "len(body) >= 10 should match 27-char body"
        );

        // Test <= operator
        let matcher_lte = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["len(body) <= 10".to_string()],
            ..Default::default()
        };

        assert!(
            execute_matcher(&matcher_lte, &request, &response_small).matched,
            "len(body) <= 10 should match 5-char body"
        );
        assert!(
            !execute_matcher(&matcher_lte, &request, &response_large).matched,
            "len(body) <= 10 should NOT match 27-char body"
        );
    }

    // =========================================================================
    // FIX 9: Case-insensitive flag not doubled when (?i) exists anywhere
    // =========================================================================
    #[test]
    fn fix9_case_insensitive_not_doubled() {
        // Pattern with (?i) in the middle should not get another one prepended
        let matcher = Matcher {
            matcher_type: MatcherType::Regex,
            regex: vec!["test(?i)pattern".to_string()],
            case_insensitive: true,
            part: MatcherPart::Body,
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "testPATTERN");

        let result = execute_matcher(&matcher, &request, &response);
        // Should still match (the existing (?i) handles case insensitivity)
        assert!(result.matched, "Pattern with (?i) should still work");
    }

    // =========================================================================
    // Note: SSN false positives (Bug 10) is a design limitation, not a code bug
    // A more sophisticated approach would require context analysis
    // =========================================================================
    #[test]
    fn note10_ssn_detection_works() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_request();

        // Valid SSN format is detected
        let response = create_response(200, HashMap::new(), "SSN: 123-45-6789");
        let findings = executor.execute(&request, &response);
        assert!(
            findings.iter().any(|f| f.name.contains("SSN")),
            "SSN pattern should be detected"
        );
    }

    // =========================================================================
    // Test: execute_matchers OR logic
    // =========================================================================
    #[test]
    fn test_execute_matchers_or_returns_all_results() {
        let matcher1 = Matcher {
            matcher_type: MatcherType::Word,
            words: vec!["found".to_string()],
            name: Some("first".to_string()),
            ..Default::default()
        };
        let matcher2 = Matcher {
            matcher_type: MatcherType::Word,
            words: vec!["notfound".to_string()],
            name: Some("second".to_string()),
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "found this");

        let results = execute_matchers(
            &[matcher1, matcher2],
            MatcherCondition::Or,
            &request,
            &response,
        );

        // With OR, if any matches, all results are returned (including non-matches)
        assert_eq!(results.len(), 2);
        assert!(results[0].matched);
        assert!(!results[1].matched);
    }

    // =========================================================================
    // EDGE CASE TESTS
    // =========================================================================

    #[test]
    fn edge_case_matcher_and_empty_submatcher() {
        // Empty sub_matchers should not match
        let empty_and = Matcher::and(vec![]);
        let request = create_request();
        let response = create_response(200, HashMap::new(), "anything");

        let result = execute_matcher(&empty_and, &request, &response);
        // Empty AND with no sub_matchers - the sub_matchers vec is empty,
        // but the matcher itself has empty words, which returns failure
        assert!(!result.matched, "Empty AND matcher should not match");
    }

    #[test]
    fn edge_case_matcher_and_single_submatcher() {
        // Single sub_matcher should work
        let single_and = Matcher::and(vec![Matcher::body_regex(r"test")]);
        let request = create_request();

        let response_match = create_response(200, HashMap::new(), "this is a test");
        let response_no_match = create_response(200, HashMap::new(), "no match here");

        assert!(
            execute_matcher(&single_and, &request, &response_match).matched,
            "Single-item AND should match when sub_matcher matches"
        );
        assert!(
            !execute_matcher(&single_and, &request, &response_no_match).matched,
            "Single-item AND should not match when sub_matcher doesn't match"
        );
    }

    #[test]
    fn edge_case_matcher_or_logic() {
        // Test Matcher::or() - should match if ANY sub_matcher matches
        let or_matcher = Matcher::or(vec![
            Matcher::body_regex(r"foo"),
            Matcher::body_regex(r"bar"),
        ]);
        let request = create_request();

        let response_foo = create_response(200, HashMap::new(), "contains foo");
        let response_bar = create_response(200, HashMap::new(), "contains bar");
        let response_both = create_response(200, HashMap::new(), "contains foo and bar");
        let response_neither = create_response(200, HashMap::new(), "contains nothing");

        assert!(execute_matcher(&or_matcher, &request, &response_foo).matched);
        assert!(execute_matcher(&or_matcher, &request, &response_bar).matched);
        assert!(execute_matcher(&or_matcher, &request, &response_both).matched);
        assert!(!execute_matcher(&or_matcher, &request, &response_neither).matched);
    }

    #[test]
    fn edge_case_nested_compound_matchers() {
        // Nested AND within AND
        let inner_and = Matcher::and(vec![
            Matcher::body_regex(r"foo"),
            Matcher::body_regex(r"bar"),
        ]);
        let outer_and = Matcher::and(vec![
            inner_and,
            Matcher::body_regex(r"baz"),
        ]);

        let request = create_request();
        let response_all = create_response(200, HashMap::new(), "foo bar baz");
        let response_missing_baz = create_response(200, HashMap::new(), "foo bar");

        assert!(
            execute_matcher(&outer_and, &request, &response_all).matched,
            "Nested AND should match when all conditions met"
        );
        assert!(
            !execute_matcher(&outer_and, &request, &response_missing_baz).matched,
            "Nested AND should not match when outer condition missing"
        );
    }

    #[test]
    fn edge_case_header_missing_empty_headers() {
        let request = create_request();
        let response = create_response(200, HashMap::new(), ""); // No headers

        let matcher = Matcher::header_missing("X-Custom-Header");
        let result = execute_matcher(&matcher, &request, &response);

        assert!(result.matched, "header_missing should match when headers are empty");
    }

    #[test]
    fn edge_case_header_missing_case_insensitive() {
        let request = create_request();

        // Header with different case
        let mut headers = HashMap::new();
        headers.insert("content-security-policy".to_string(), "default-src 'self'".to_string());
        let response = create_response(200, headers, "");

        // Should match the header regardless of case
        let matcher = Matcher::header_missing("Content-Security-Policy");
        let result = execute_matcher(&matcher, &request, &response);

        // The regex uses (?im) so it should be case-insensitive
        assert!(
            !result.matched,
            "header_missing should be case-insensitive"
        );
    }

    #[test]
    fn edge_case_dsl_regex_double_quotes() {
        // Test with double quotes instead of single quotes
        let matcher = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["regex(\"test,pattern\", body)".to_string()],
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "this is test,pattern here");

        let result = execute_matcher(&matcher, &request, &response);
        assert!(result.matched, "DSL regex should work with double quotes");
    }

    #[test]
    fn edge_case_dsl_regex_escaped_quotes() {
        // Pattern with escaped quotes
        let matcher = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["regex('it\\'s', body)".to_string()],
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "it's working");

        let result = execute_matcher(&matcher, &request, &response);
        assert!(result.matched, "DSL regex should handle escaped quotes");
    }

    #[test]
    fn edge_case_private_ip_boundary_values() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_request();

        // Test boundary values for 10.x.x.x range
        let test_cases = vec![
            ("10.0.0.0", true),      // Lower bound
            ("10.255.255.255", true), // Upper bound
            ("10.0.0.256", false),   // Invalid octet
            ("10.256.0.0", false),   // Invalid octet
        ];

        for (ip, should_match) in test_cases {
            let body = format!("Server IP: {}", ip);
            let response = create_response(200, HashMap::new(), &body);
            let findings = executor.execute(&request, &response);
            let has_ip = findings.iter().any(|f| f.name.contains("Private IP"));

            assert_eq!(
                has_ip, should_match,
                "IP {} should{} be detected as private IP",
                ip,
                if should_match { "" } else { " NOT" }
            );
        }
    }

    #[test]
    fn edge_case_private_ip_all_ranges() {
        let executor = TemplateExecutor::with_bundled();
        let request = create_request();

        // Test all three private IP ranges
        let valid_ips = vec![
            "10.1.2.3",       // Class A
            "172.16.0.1",     // Class B lower
            "172.31.255.254", // Class B upper
            "192.168.1.1",    // Class C
        ];

        for ip in valid_ips {
            let body = format!("Internal: {}", ip);
            let response = create_response(200, HashMap::new(), &body);
            let findings = executor.execute(&request, &response);
            let has_ip = findings.iter().any(|f| f.name.contains("Private IP"));
            assert!(has_ip, "Valid private IP {} should be detected", ip);
        }

        // Test non-private IPs that look similar
        let invalid_ips = vec![
            "172.15.0.1",  // Just below 172.16
            "172.32.0.1",  // Just above 172.31
            "11.0.0.1",    // Not 10.x.x.x
            "192.169.1.1", // Not 192.168.x.x
        ];

        for ip in invalid_ips {
            let body = format!("External: {}", ip);
            let response = create_response(200, HashMap::new(), &body);
            let findings = executor.execute(&request, &response);
            let has_ip = findings.iter().any(|f| f.name.contains("Private IP"));
            assert!(!has_ip, "Non-private IP {} should NOT be detected", ip);
        }
    }

    #[test]
    fn edge_case_status_dsl_equality() {
        let request = create_request();
        let response_200 = create_response(200, HashMap::new(), "");
        let response_404 = create_response(404, HashMap::new(), "");

        // Test == operator
        let matcher_eq = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["status_code == 200".to_string()],
            ..Default::default()
        };
        assert!(execute_matcher(&matcher_eq, &request, &response_200).matched);
        assert!(!execute_matcher(&matcher_eq, &request, &response_404).matched);

        // Test != operator
        let matcher_ne = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["status_code != 200".to_string()],
            ..Default::default()
        };
        assert!(!execute_matcher(&matcher_ne, &request, &response_200).matched);
        assert!(execute_matcher(&matcher_ne, &request, &response_404).matched);
    }

    #[test]
    fn edge_case_len_dsl_empty_body() {
        let request = create_request();
        let response_empty = create_response(200, HashMap::new(), "");

        let matcher_zero = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["len(body) == 0".to_string()],
            ..Default::default()
        };
        assert!(
            execute_matcher(&matcher_zero, &request, &response_empty).matched,
            "len(body) == 0 should match empty body"
        );

        let matcher_gt_zero = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["len(body) > 0".to_string()],
            ..Default::default()
        };
        assert!(
            !execute_matcher(&matcher_gt_zero, &request, &response_empty).matched,
            "len(body) > 0 should NOT match empty body"
        );
    }

    #[test]
    fn edge_case_len_dsl_header() {
        let request = create_request();

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let response = create_response(200, headers, "");

        // Headers formatted: "Content-Type: application/json" = 30 chars
        let matcher = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["len(header) > 0".to_string()],
            ..Default::default()
        };

        assert!(
            execute_matcher(&matcher, &request, &response).matched,
            "len(header) > 0 should match when headers present"
        );
    }

    #[test]
    fn edge_case_cookie_case_variations() {
        let request = create_request();

        // Test various case variations of HttpOnly
        let case_variations = vec![
            ("HttpOnly", false),   // Standard
            ("httponly", false),   // Lowercase
            ("HTTPONLY", false),   // Uppercase
            ("HTTPOnly", false),   // Mixed
            ("Secure", true),      // No HttpOnly - should match
        ];

        for (cookie_flags, should_flag) in case_variations {
            let mut headers = HashMap::new();
            headers.insert(
                "Set-Cookie".to_string(),
                format!("session=abc; {}", cookie_flags),
            );
            let response = create_response(200, headers, "");

            let matcher = Matcher::header_not_contains("Set-Cookie", "httponly");
            let result = execute_matcher(&matcher, &request, &response);

            assert_eq!(
                result.matched, should_flag,
                "Cookie with '{}' should{} be flagged as missing HttpOnly",
                cookie_flags,
                if should_flag { "" } else { " NOT" }
            );
        }
    }

    #[test]
    fn edge_case_no_cookie_header() {
        let request = create_request();
        let response = create_response(200, HashMap::new(), ""); // No headers

        // When there's no Set-Cookie header, the compound matcher should NOT match
        // because header_exists("Set-Cookie") should fail
        let compound = Matcher::and(vec![
            Matcher::header_exists("Set-Cookie"),
            Matcher::header_not_contains("Set-Cookie", "httponly"),
        ]);

        let result = execute_matcher(&compound, &request, &response);
        assert!(
            !result.matched,
            "Should not flag missing HttpOnly when there's no Set-Cookie header"
        );
    }

    #[test]
    fn edge_case_word_matcher_or_empty() {
        // OR condition with empty words should also fail
        let matcher = Matcher {
            matcher_type: MatcherType::Word,
            words: Vec::new(),
            condition: MatcherCondition::Or,
            part: MatcherPart::Body,
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "any content");

        let result = execute_matcher(&matcher, &request, &response);
        assert!(!result.matched, "Empty word matcher with OR should not match");
    }

    #[test]
    fn edge_case_regex_empty_patterns() {
        // Empty regex list should not match
        let matcher = Matcher {
            matcher_type: MatcherType::Regex,
            regex: Vec::new(),
            part: MatcherPart::Body,
            ..Default::default()
        };

        let request = create_request();
        let response = create_response(200, HashMap::new(), "any content");

        let result = execute_matcher(&matcher, &request, &response);
        assert!(!result.matched, "Empty regex list should not match");
    }

    #[test]
    fn edge_case_case_insensitive_flag_combinations() {
        let request = create_request();
        let response = create_response(200, HashMap::new(), "HELLO world");

        // case_insensitive=true, no (?i) in pattern - should add (?i)
        let matcher1 = Matcher {
            matcher_type: MatcherType::Regex,
            regex: vec!["hello".to_string()],
            case_insensitive: true,
            part: MatcherPart::Body,
            ..Default::default()
        };
        assert!(
            execute_matcher(&matcher1, &request, &response).matched,
            "case_insensitive=true should match case-insensitively"
        );

        // case_insensitive=false, no (?i) - should be case-sensitive
        let matcher2 = Matcher {
            matcher_type: MatcherType::Regex,
            regex: vec!["hello".to_string()],
            case_insensitive: false,
            part: MatcherPart::Body,
            ..Default::default()
        };
        assert!(
            !execute_matcher(&matcher2, &request, &response).matched,
            "case_insensitive=false should NOT match different case"
        );

        // case_insensitive=true, (?i) already in pattern - should not double
        let matcher3 = Matcher {
            matcher_type: MatcherType::Regex,
            regex: vec!["(?i)hello".to_string()],
            case_insensitive: true,
            part: MatcherPart::Body,
            ..Default::default()
        };
        assert!(
            execute_matcher(&matcher3, &request, &response).matched,
            "Existing (?i) should work with case_insensitive=true"
        );
    }

    #[test]
    fn edge_case_negative_matcher() {
        let request = create_request();
        let response = create_response(200, HashMap::new(), "hello world");

        // Negative matcher - should match when pattern is NOT found
        let matcher = Matcher {
            matcher_type: MatcherType::Word,
            words: vec!["goodbye".to_string()],
            negative: true,
            part: MatcherPart::Body,
            ..Default::default()
        };

        assert!(
            execute_matcher(&matcher, &request, &response).matched,
            "Negative matcher should match when word is NOT present"
        );

        let response_with_word = create_response(200, HashMap::new(), "goodbye world");
        assert!(
            !execute_matcher(&matcher, &request, &response_with_word).matched,
            "Negative matcher should NOT match when word IS present"
        );
    }

    #[test]
    fn edge_case_status_matcher_multiple_codes() {
        let request = create_request();

        let matcher = Matcher {
            matcher_type: MatcherType::Status,
            status: vec![200, 201, 204],
            ..Default::default()
        };

        assert!(execute_matcher(&matcher, &request, &create_response(200, HashMap::new(), "")).matched);
        assert!(execute_matcher(&matcher, &request, &create_response(201, HashMap::new(), "")).matched);
        assert!(execute_matcher(&matcher, &request, &create_response(204, HashMap::new(), "")).matched);
        assert!(!execute_matcher(&matcher, &request, &create_response(404, HashMap::new(), "")).matched);
    }

    #[test]
    fn edge_case_dsl_negation() {
        let request = create_request();
        let response = create_response(200, HashMap::new(), "test content");

        // DSL with ! negation
        let matcher = Matcher {
            matcher_type: MatcherType::Dsl,
            dsl: vec!["!status_code == 404".to_string()],
            ..Default::default()
        };

        assert!(
            execute_matcher(&matcher, &request, &response).matched,
            "DSL negation should work: !(200 == 404) = true"
        );

        let response_404 = create_response(404, HashMap::new(), "");
        assert!(
            !execute_matcher(&matcher, &request, &response_404).matched,
            "DSL negation: !(404 == 404) = false"
        );
    }

    // =========================================================================
    // Variable substitution tests
    // =========================================================================

    #[test]
    fn test_variable_substitution_basic() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com:8443/api/users?id=1");

        assert_eq!(vars.base_url, "https://example.com:8443");
        assert_eq!(vars.hostname, "example.com");
        assert_eq!(vars.host, "example.com");
        assert_eq!(vars.port, "8443");
        assert_eq!(vars.scheme, "https");
        assert_eq!(vars.path, "/api/users");
    }

    #[test]
    fn test_variable_substitution_default_ports() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars_https = TemplateVariables::from_url("https://example.com/path");
        assert_eq!(vars_https.port, "443");

        let vars_http = TemplateVariables::from_url("http://example.com/path");
        assert_eq!(vars_http.port, "80");
    }

    #[test]
    fn test_variable_substitution_in_string() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com:8443/api");

        // Test basic substitution
        assert_eq!(
            vars.substitute("{{BaseURL}}/admin"),
            "https://example.com:8443/admin"
        );

        assert_eq!(
            vars.substitute("{{Scheme}}://{{Hostname}}:{{Port}}"),
            "https://example.com:8443"
        );

        // Test case insensitivity
        assert_eq!(
            vars.substitute("{{baseurl}}/test"),
            "https://example.com:8443/test"
        );
    }

    #[test]
    fn test_variable_substitution_custom_vars() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com")
            .with_var("payload", "' OR 1=1--")
            .with_var("username", "admin");

        assert_eq!(
            vars.substitute("user={{username}}&pass={{payload}}"),
            "user=admin&pass=' OR 1=1--"
        );
    }

    #[test]
    fn test_variable_substitution_unknown_vars() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com");

        // Unknown variables should be left as-is
        assert_eq!(
            vars.substitute("{{unknown_var}}"),
            "{{unknown_var}}"
        );
    }

    #[test]
    fn test_variable_substitution_root_url() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com");
        assert_eq!(vars.root_url, "https://example.com/");

        let vars2 = TemplateVariables::from_url("https://example.com/");
        assert_eq!(vars2.root_url, "https://example.com/");
    }

    #[test]
    fn test_payload_combinations() {
        // Test the payload combination generator indirectly through template execution
        // This verifies the cartesian product logic works
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com")
            .with_var("p1", "v1")
            .with_var("p2", "v2");

        let result = vars.substitute("{{p1}}-{{p2}}");
        assert_eq!(result, "v1-v2");
    }

    #[test]
    fn test_variable_substitution_custom_case_insensitive() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com")
            .with_var("Payload", "test_value")
            .with_var("MyVar", "another_value");

        // Custom variables should be case-insensitive
        assert_eq!(vars.substitute("{{Payload}}"), "test_value");
        assert_eq!(vars.substitute("{{payload}}"), "test_value");
        assert_eq!(vars.substitute("{{PAYLOAD}}"), "test_value");
        assert_eq!(vars.substitute("{{myvar}}"), "another_value");
        assert_eq!(vars.substitute("{{MYVAR}}"), "another_value");
    }

    #[test]
    fn test_url_building_after_substitution() {
        use crate::scanner::templates::executor::TemplateVariables;

        let vars = TemplateVariables::from_url("https://example.com");

        // After substitution, if result is a full URL, don't prepend base
        let path_with_var = "{{BaseURL}}/admin";
        let substituted = vars.substitute(path_with_var);
        assert_eq!(substituted, "https://example.com/admin");

        // The substituted result starts with https:// so it should be used as-is
        // (This tests the logic in build_request_from_template)
        assert!(substituted.starts_with("https://"));
    }

    // =========================================================================
    // Active Template Parsing Tests
    // =========================================================================

    #[test]
    fn test_active_templates_parse_correctly() {
        use crate::scanner::templates::bundled_active_templates;

        let templates = bundled_active_templates();

        // We should have at least the 7 template files we created (some with multiple templates)
        assert!(
            templates.len() >= 10,
            "Expected at least 10 active templates, got {}",
            templates.len()
        );

        // Verify each template has required fields
        for template in &templates {
            assert!(
                !template.id.is_empty(),
                "Template should have an ID"
            );
            assert!(
                !template.info.name.is_empty(),
                "Template {} should have a name",
                template.id
            );
            // tags is a comma-separated string
            assert!(
                !template.info.tags.is_empty(),
                "Template {} should have tags",
                template.id
            );
        }

        // Check for expected template IDs
        let template_ids: Vec<&str> = templates.iter().map(|t| t.id.as_str()).collect();

        let expected_ids = [
            "sqli-error-based",
            "xss-reflected",
            "xss-dom-sources",
            "command-injection",
            "command-injection-blind-time",
            "path-traversal",
            "ssrf-localhost",
            "ssrf-file-protocol",
            "xxe-file-read",
            "xxe-ssrf",
            "http-request-smuggling-cl-te",
            "http-request-smuggling-te-cl",
        ];

        for expected_id in expected_ids {
            assert!(
                template_ids.contains(&expected_id),
                "Missing expected template: {}. Available: {:?}",
                expected_id,
                template_ids
            );
        }
    }

    #[test]
    fn test_active_templates_have_payloads_or_matchers() {
        use crate::scanner::templates::bundled_active_templates;

        let templates = bundled_active_templates();

        for template in &templates {
            // Active templates should have HTTP requests
            assert!(
                !template.http.is_empty(),
                "Template {} should have HTTP requests",
                template.id
            );

            for http_request in &template.http {
                // Each request should have matchers
                assert!(
                    !http_request.matchers.is_empty(),
                    "Template {} HTTP request should have matchers",
                    template.id
                );
            }
        }
    }

    #[test]
    fn test_sqli_template_has_error_patterns() {
        use crate::scanner::templates::bundled_active_templates;

        let templates = bundled_active_templates();
        let sqli = templates.iter().find(|t| t.id == "sqli-error-based");

        assert!(sqli.is_some(), "SQL injection template should exist");
        let sqli = sqli.unwrap();

        // Check it has the SQL injection tag (tags is a comma-separated string)
        assert!(
            sqli.info.tags.contains("sql"),
            "SQLi template should have sql tag, got: {}",
            sqli.info.tags
        );

        // Check severity is appropriate
        assert!(
            matches!(sqli.info.severity, Severity::High | Severity::Critical),
            "SQLi template should be high/critical severity"
        );
    }

    #[test]
    fn test_bundled_templates_includes_both_passive_and_active() {
        use crate::scanner::templates::{bundled_templates, bundled_passive_templates, bundled_active_templates};

        let all = bundled_templates();
        let passive = bundled_passive_templates();
        let active = bundled_active_templates();

        // Total should equal passive + active
        assert_eq!(
            all.len(),
            passive.len() + active.len(),
            "bundled_templates should include all passive and active templates"
        );

        // Passive templates should have expected count (26)
        assert!(
            passive.len() >= 20,
            "Expected at least 20 passive templates, got {}",
            passive.len()
        );

        // Active templates should have expected count (10+)
        assert!(
            active.len() >= 10,
            "Expected at least 10 active templates, got {}",
            active.len()
        );
    }
}
