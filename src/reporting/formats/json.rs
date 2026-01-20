//! JSON Report Generator
//!
//! Generates machine-readable JSON security reports.

use anyhow::Result;
use serde_json;

use crate::reporting::ScanReport;

/// Generate JSON report
pub fn generate(report: &ScanReport) -> Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    Ok(json)
}

/// Generate minified JSON report
pub fn generate_minified(report: &ScanReport) -> Result<String> {
    let json = serde_json::to_string(report)?;
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::ReportMetadata;
    use crate::scanner::{Finding, Severity};

    #[test]
    fn test_generate_json_report() {
        let findings = vec![
            Finding::new("SQL Injection", Severity::Critical, "https://example.com/api"),
        ];
        let metadata = ReportMetadata::default();
        let report = ScanReport::new(findings, metadata);

        let json = generate(&report).unwrap();
        assert!(json.contains("SQL Injection"));
        assert!(json.contains("Critical"));
    }

    #[test]
    fn test_generate_minified_json() {
        let findings = vec![
            Finding::new("Test", Severity::Low, "https://example.com"),
        ];
        let metadata = ReportMetadata::default();
        let report = ScanReport::new(findings, metadata);

        let json = generate_minified(&report).unwrap();
        assert!(!json.contains('\n'));
    }
}
