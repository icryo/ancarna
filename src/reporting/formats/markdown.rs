//! Markdown Report Generator
//!
//! Generates documentation-friendly Markdown security reports.

use anyhow::Result;

use crate::reporting::ScanReport;
use crate::scanner::Severity;

/// Generate Markdown report
pub fn generate(report: &ScanReport) -> Result<String> {
    let mut md = String::new();

    // Title
    md.push_str(&format!("# {}\n\n", report.metadata.title));

    // Metadata
    md.push_str("## Report Information\n\n");
    md.push_str(&format!("- **Target:** {}\n", report.metadata.target));
    md.push_str(&format!(
        "- **Scan Period:** {} to {}\n",
        report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
        report.metadata.end_time.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    md.push_str(&format!(
        "- **Generated:** {}\n",
        report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    md.push_str(&format!(
        "- **Scanner Version:** {}\n\n",
        report.metadata.scanner_version
    ));

    if let Some(notes) = &report.metadata.notes {
        md.push_str(&format!("> {}\n\n", notes));
    }

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str("| Metric | Value |\n|--------|-------|\n");
    md.push_str(&format!(
        "| Total Findings | {} |\n",
        report.summary.total_findings
    ));
    md.push_str(&format!(
        "| Risk Score | {}/100 |\n",
        report.summary.risk_score
    ));
    md.push_str(&format!(
        "| Unique Hosts | {} |\n",
        report.summary.unique_hosts
    ));
    md.push_str(&format!(
        "| Unique URLs | {} |\n",
        report.summary.unique_urls
    ));
    md.push_str(&format!(
        "| Scan Duration | {}s |\n\n",
        report.summary.duration_secs
    ));

    // Severity Breakdown
    md.push_str("### Findings by Severity\n\n");
    md.push_str("| Severity | Count |\n|----------|-------|\n");

    let severities = ["Critical", "High", "Medium", "Low", "Informational"];
    for sev in severities {
        let count = report.summary.by_severity.get(sev).unwrap_or(&0);
        let emoji = match sev {
            "Critical" => "🔴",
            "High" => "🟠",
            "Medium" => "🟡",
            "Low" => "🟢",
            "Informational" => "🔵",
            _ => "⚪",
        };
        md.push_str(&format!("| {} {} | {} |\n", emoji, sev, count));
    }
    md.push('\n');

    // OWASP Mapping
    md.push_str("## OWASP Top 10 Coverage\n\n");
    md.push_str("| Category | Findings |\n|----------|----------|\n");

    let categories = [
        ("A01:2021", "Broken Access Control"),
        ("A02:2021", "Cryptographic Failures"),
        ("A03:2021", "Injection"),
        ("A04:2021", "Insecure Design"),
        ("A05:2021", "Security Misconfiguration"),
        ("A06:2021", "Vulnerable Components"),
        ("A07:2021", "Auth Failures"),
        ("A08:2021", "Data Integrity Failures"),
        ("A09:2021", "Security Logging Failures"),
        ("A10:2021", "Server-Side Request Forgery"),
    ];

    for (code, name) in categories {
        let full_key = format!("{} – {}", code, name);
        let count = report
            .owasp_mapping
            .get(&full_key)
            .map(|v| v.len())
            .unwrap_or(0);
        md.push_str(&format!("| {} - {} | {} |\n", code, name, count));
    }
    md.push('\n');

    // Findings Table
    md.push_str("## Findings Overview\n\n");
    md.push_str("| # | Severity | Title | URL |\n");
    md.push_str("|---|----------|-------|-----|\n");

    for (idx, finding) in report.findings.iter().enumerate() {
        let severity = finding.severity_level();
        let severity_emoji = match severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Informational => "🔵",
        };

        let url_truncated = if finding.url.len() > 50 {
            format!("{}...", &finding.url[..47])
        } else {
            finding.url.clone()
        };

        md.push_str(&format!(
            "| {} | {} {} | {} | `{}` |\n",
            idx + 1,
            severity_emoji,
            severity.name(),
            md_escape(&finding.name),
            url_truncated
        ));
    }
    md.push('\n');

    // Detailed Findings
    md.push_str("## Detailed Findings\n\n");

    for (idx, finding) in report.findings.iter().enumerate() {
        let severity = finding.severity_level();
        let severity_emoji = match severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Informational => "🔵",
        };

        md.push_str(&format!(
            "### {} Finding #{}: {}\n\n",
            severity_emoji,
            idx + 1,
            md_escape(&finding.name)
        ));

        md.push_str(&format!("**Severity:** {}\n\n", severity.name()));
        md.push_str(&format!("**URL:** `{}`\n\n", finding.url));

        if !finding.description.is_empty() {
            md.push_str("**Description:**\n\n");
            md.push_str(&format!("{}\n\n", finding.description));
        }

        if let Some(evidence) = &finding.evidence {
            md.push_str("**Evidence:**\n\n```\n");
            md.push_str(evidence);
            md.push_str("\n```\n\n");
        }

        if let Some(remediation) = &finding.remediation {
            md.push_str("**Remediation:**\n\n");
            md.push_str(&format!("{}\n\n", remediation));
        }

        // References
        let mut refs = Vec::new();
        if let Some(cwe) = finding.cwe_id {
            refs.push(format!("[CWE-{}](https://cwe.mitre.org/data/definitions/{}.html)", cwe, cwe));
        }
        if let Some(owasp) = &finding.owasp_category {
            refs.push(format!("OWASP: {}", owasp));
        }

        if !refs.is_empty() {
            md.push_str("**References:** ");
            md.push_str(&refs.join(" | "));
            md.push_str("\n\n");
        }

        md.push_str("---\n\n");
    }

    // Footer
    md.push_str(&format!(
        "\n*Report generated by Ancarna v{} on {}*\n",
        report.metadata.scanner_version,
        report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    Ok(md)
}

/// Escape special Markdown characters
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('*', "\\*")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::ReportMetadata;
    use crate::scanner::Finding;

    #[test]
    fn test_md_escape() {
        assert_eq!(md_escape("test|pipe"), "test\\|pipe");
        assert_eq!(md_escape("[link]"), "\\[link\\]");
    }

    #[test]
    fn test_generate_markdown_report() {
        let findings = vec![
            Finding::new("SQL Injection", Severity::Critical, "https://example.com/api")
                .with_description("Test description")
                .with_cwe(89),
        ];
        let metadata = ReportMetadata::default();
        let report = ScanReport::new(findings, metadata);

        let md = generate(&report).unwrap();
        assert!(md.contains("# Security Scan Report"));
        assert!(md.contains("SQL Injection"));
        assert!(md.contains("🔴"));
        assert!(md.contains("CWE-89"));
    }
}
