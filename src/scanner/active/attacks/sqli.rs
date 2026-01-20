//! SQL Injection testing

use anyhow::Result;
use regex::Regex;

use crate::http::{HttpClient, Request};
use crate::scanner::findings::{Finding, Severity};

/// SQL error patterns
const SQL_ERROR_PATTERNS: &[(&str, &str)] = &[
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysql_", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"MySqlClient\.", "MySQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"Warning.*\Wpg_", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"Driver.*SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.*SQL Server", "MSSQL"),
    (r"\bSQL Server\b.*Driver", "MSSQL"),
    (r"Warning.*mssql_", "MSSQL"),
    (r"\bSQL Server\b.*\d", "MSSQL"),
    (r"(?s)Exception.*\bSystem\.Data\.SqlClient\.", "MSSQL"),
    (r"Unclosed quotation mark after", "MSSQL"),
    (r"CLI Driver.*DB2", "DB2"),
    (r"DB2 SQL error", "DB2"),
    (r"\bdb2_\w+\(", "DB2"),
    (r"ODBC.*SQL Server", "ODBC"),
    (r"ORA-\d{5}", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"Warning.*\Woci_", "Oracle"),
    (r"Warning.*\Wora_", "Oracle"),
    (r"oracle.*error", "Oracle"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLite\.Exception", "SQLite"),
    (r"System\.Data\.SQLite\.SQLiteException", "SQLite"),
    (r"Warning.*sqlite_", "SQLite"),
    (r"Warning.*SQLite3::", "SQLite"),
    (r"\[SQLITE_ERROR\]", "SQLite"),
    (r"SQL error.*POS([0-9]+)", "Generic"),
    (r"(?i)quoted string not properly terminated", "Generic"),
    (r"(?i)syntax error", "Generic"),
];

/// SQLi test payloads
const SQLI_PAYLOADS: &[&str] = &[
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' OR 1=1 --",
    "1 OR 1=1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "1; SELECT 1--",
    "'; DROP TABLE test--",
    "1' AND '1'='1",
    "1' AND SLEEP(5)--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
];

/// Scan for SQL injection vulnerabilities
pub async fn scan(client: &HttpClient, target_url: &str) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Parse URL to extract parameters
    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if params.is_empty() {
        return Ok(findings);
    }

    // Compile error patterns
    let error_patterns: Vec<(Regex, &str)> = SQL_ERROR_PATTERNS
        .iter()
        .filter_map(|(pattern, db)| {
            Regex::new(pattern).ok().map(|r| (r, *db))
        })
        .collect();

    // Test each parameter with each payload
    for (param_name, original_value) in &params {
        for payload in SQLI_PAYLOADS {
            // Build URL with payload
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, payload);
                    } else {
                        pairs.append_pair(k, v);
                    }
                }
            }

            // Send request
            let request = Request::new("GET", test_url.as_str());
            let response = match client.execute(&request).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            let body = response.body_text();

            // Check for SQL error patterns
            for (pattern, db_type) in &error_patterns {
                if pattern.is_match(&body) {
                    findings.push(
                        Finding::new("SQL Injection", Severity::High, target_url)
                            .with_description(&format!(
                                "SQL injection vulnerability detected in parameter '{}'. Database type: {}",
                                param_name, db_type
                            ))
                            .with_parameter(param_name)
                            .with_evidence(&format!("Payload: {}", payload))
                            .with_scanner("active/sqli")
                            .with_cwe(89)
                            .with_owasp("A03:2021 – Injection")
                            .with_remediation(
                                "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
                            )
                            .with_request(&format!("GET {}", test_url)),
                    );

                    // Found vulnerability, no need to test more payloads for this param
                    break;
                }
            }
        }
    }

    Ok(findings)
}

/// Check for time-based SQL injection
pub async fn scan_time_based(
    client: &HttpClient,
    target_url: &str,
    delay_seconds: u64,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    let time_payloads = vec![
        format!("' AND SLEEP({})--", delay_seconds),
        format!("' WAITFOR DELAY '0:0:{}'--", delay_seconds),
        format!("'; SELECT SLEEP({})--", delay_seconds),
        format!("1' AND (SELECT * FROM (SELECT(SLEEP({})))a)--", delay_seconds),
    ];

    let url = url::Url::parse(target_url)?;
    let params: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    for (param_name, _) in &params {
        for payload in &time_payloads {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &params {
                    if k == param_name {
                        pairs.append_pair(k, payload);
                    } else {
                        pairs.append_pair(k, v);
                    }
                }
            }

            let request = Request::new("GET", test_url.as_str());
            let start = std::time::Instant::now();

            if let Ok(response) = client.execute(&request).await {
                let elapsed = start.elapsed();

                // If response took significantly longer, potential time-based SQLi
                if elapsed.as_secs() >= delay_seconds {
                    findings.push(
                        Finding::new("Time-Based SQL Injection", Severity::High, target_url)
                            .with_description(&format!(
                                "Time-based SQL injection detected in parameter '{}'. Response delayed by {}s.",
                                param_name, elapsed.as_secs()
                            ))
                            .with_parameter(param_name)
                            .with_evidence(&format!("Payload: {}, Delay: {}s", payload, elapsed.as_secs()))
                            .with_scanner("active/sqli-time")
                            .with_cwe(89)
                            .with_owasp("A03:2021 – Injection")
                            .with_remediation(
                                "Use parameterized queries or prepared statements."
                            ),
                    );
                    break;
                }
            }
        }
    }

    Ok(findings)
}
