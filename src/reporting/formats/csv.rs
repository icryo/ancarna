//! CSV Report Generator
//!
//! Generates spreadsheet-compatible CSV security reports.

use anyhow::Result;

use crate::reporting::ScanReport;

/// Generate CSV report
pub fn generate(report: &ScanReport) -> Result<String> {
    let mut csv = String::new();

    // Header row
    csv.push_str("ID,Severity,Title,URL,Description,CWE,OWASP,Scanner,Confidence,Evidence,Remediation\n");

    // Data rows
    for (idx, finding) in report.findings.iter().enumerate() {
        let row = vec![
            (idx + 1).to_string(),
            finding.severity_level().name().to_string(),
            csv_escape(&finding.name),
            csv_escape(&finding.url),
            csv_escape(&finding.description),
            finding.cwe_id.map(|c| format!("CWE-{}", c)).unwrap_or_default(),
            csv_escape(finding.owasp_category.as_deref().unwrap_or("")),
            csv_escape(&finding.scanner),
            format!("{:.2}", finding.confidence),
            csv_escape(finding.evidence.as_deref().unwrap_or("")),
            csv_escape(finding.remediation.as_deref().unwrap_or("")),
        ];

        csv.push_str(&row.join(","));
        csv.push('\n');
    }

    Ok(csv)
}

/// Generate summary-only CSV
pub fn generate_summary(report: &ScanReport) -> Result<String> {
    let mut csv = String::new();

    // Summary header
    csv.push_str("Metric,Value\n");

    csv.push_str(&format!("Total Findings,{}\n", report.summary.total_findings));
    csv.push_str(&format!("Risk Score,{}\n", report.summary.risk_score));
    csv.push_str(&format!("Unique Hosts,{}\n", report.summary.unique_hosts));
    csv.push_str(&format!("Unique URLs,{}\n", report.summary.unique_urls));
    csv.push_str(&format!("Scan Duration (seconds),{}\n", report.summary.duration_secs));

    csv.push_str("\nSeverity,Count\n");
    for (severity, count) in &report.summary.by_severity {
        csv.push_str(&format!("{},{}\n", severity, count));
    }

    csv.push_str("\nCategory,Count\n");
    for (category, count) in &report.summary.by_category {
        csv.push_str(&format!("{},{}\n", csv_escape(category), count));
    }

    Ok(csv)
}

/// Escape a value for CSV (handle commas, quotes, newlines)
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        // Escape quotes by doubling them and wrap in quotes
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::ReportMetadata;
    use crate::scanner::{Finding, Severity};

    #[test]
    fn test_csv_escape() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("with,comma"), "\"with,comma\"");
        assert_eq!(csv_escape("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(csv_escape("with\nnewline"), "\"with\nnewline\"");
    }

    #[test]
    fn test_generate_csv_report() {
        let findings = vec![
            Finding::new("SQL Injection", Severity::Critical, "https://example.com/api")
                .with_description("Test description"),
        ];
        let metadata = ReportMetadata::default();
        let report = ScanReport::new(findings, metadata);

        let csv = generate(&report).unwrap();
        assert!(csv.contains("ID,Severity,Title"));
        assert!(csv.contains("SQL Injection"));
        assert!(csv.contains("Critical"));
    }

    #[test]
    fn test_generate_summary_csv() {
        let findings = vec![
            Finding::new("Test", Severity::High, "https://example.com"),
        ];
        let metadata = ReportMetadata::default();
        let report = ScanReport::new(findings, metadata);

        let csv = generate_summary(&report).unwrap();
        assert!(csv.contains("Metric,Value"));
        assert!(csv.contains("Total Findings"));
    }
}
