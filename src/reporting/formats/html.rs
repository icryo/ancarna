//! HTML Report Generator
//!
//! Generates styled, interactive HTML security reports.

use anyhow::Result;

use crate::reporting::ScanReport;
use crate::scanner::Severity;

/// Generate HTML report
pub fn generate(report: &ScanReport) -> Result<String> {
    let mut html = String::new();

    // HTML header
    html.push_str(&generate_header(&report.metadata.title));

    // Body start
    html.push_str("<body>\n");
    html.push_str("<div class=\"container\">\n");

    // Report header
    html.push_str(&generate_report_header(report));

    // Executive summary
    html.push_str(&generate_executive_summary(report));

    // Risk overview
    html.push_str(&generate_risk_overview(report));

    // OWASP mapping
    html.push_str(&generate_owasp_section(report));

    // Findings table
    html.push_str(&generate_findings_section(report));

    // Detailed findings
    html.push_str(&generate_detailed_findings(report));

    // Footer
    html.push_str(&generate_footer(report));

    html.push_str("</div>\n</body>\n</html>");

    Ok(html)
}

fn generate_header(title: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }}

        * {{ box-sizing: border-box; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        h1, h2, h3 {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }}

        h1 {{ color: #58a6ff; }}
        h2 {{ color: var(--text-primary); margin-top: 2rem; }}
        h3 {{ color: var(--text-secondary); }}

        .header {{
            text-align: center;
            padding: 2rem 0;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 2rem;
        }}

        .header h1 {{ border: none; margin-bottom: 0.5rem; }}
        .header .meta {{ color: var(--text-secondary); }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }}

        .summary-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}

        .summary-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}

        .summary-card .label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .severity-critical {{ color: var(--critical); }}
        .severity-high {{ color: var(--high); }}
        .severity-medium {{ color: var(--medium); }}
        .severity-low {{ color: var(--low); }}
        .severity-info {{ color: var(--info); }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: var(--critical); color: white; }}
        .badge-high {{ background: var(--high); color: white; }}
        .badge-medium {{ background: var(--medium); color: black; }}
        .badge-low {{ background: var(--low); color: black; }}
        .badge-info {{ background: var(--info); color: black; }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}

        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--bg-secondary);
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}

        tr:hover {{ background: var(--bg-tertiary); }}

        .finding {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }}

        .finding-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
            margin: 0;
        }}

        .finding-meta {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }}

        .finding-section {{
            margin: 1rem 0;
        }}

        .finding-section h4 {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }}

        .finding-section pre {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 1rem;
            overflow-x: auto;
            font-size: 0.85rem;
        }}

        .risk-meter {{
            background: var(--bg-secondary);
            border-radius: 8px;
            height: 24px;
            overflow: hidden;
            position: relative;
        }}

        .risk-meter-fill {{
            height: 100%;
            transition: width 0.3s ease;
        }}

        .risk-meter-label {{
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            font-weight: bold;
            font-size: 0.85rem;
        }}

        .owasp-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }}

        .owasp-item {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
        }}

        .owasp-item .count {{
            font-size: 1.5rem;
            font-weight: bold;
        }}

        .footer {{
            text-align: center;
            padding: 2rem;
            margin-top: 3rem;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
        }}

        @media print {{
            body {{ background: white; color: black; }}
            .container {{ max-width: none; }}
            .finding {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
"#)
}

fn generate_report_header(report: &ScanReport) -> String {
    format!(
        r#"<div class="header">
    <h1>{}</h1>
    <div class="meta">
        <p><strong>Target:</strong> {}</p>
        <p><strong>Scan Period:</strong> {} to {}</p>
        <p><strong>Generated:</strong> {}</p>
    </div>
</div>
"#,
        html_escape(&report.metadata.title),
        html_escape(&report.metadata.target),
        report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
        report.metadata.end_time.format("%Y-%m-%d %H:%M:%S UTC"),
        report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    )
}

fn generate_executive_summary(report: &ScanReport) -> String {
    let critical = report.summary.by_severity.get("Critical").unwrap_or(&0);
    let high = report.summary.by_severity.get("High").unwrap_or(&0);
    let medium = report.summary.by_severity.get("Medium").unwrap_or(&0);
    let low = report.summary.by_severity.get("Low").unwrap_or(&0);
    let info = report.summary.by_severity.get("Informational").unwrap_or(&0);

    format!(
        r#"<h2>Executive Summary</h2>
<div class="summary-grid">
    <div class="summary-card">
        <div class="value">{}</div>
        <div class="label">Total Findings</div>
    </div>
    <div class="summary-card">
        <div class="value severity-critical">{}</div>
        <div class="label">Critical</div>
    </div>
    <div class="summary-card">
        <div class="value severity-high">{}</div>
        <div class="label">High</div>
    </div>
    <div class="summary-card">
        <div class="value severity-medium">{}</div>
        <div class="label">Medium</div>
    </div>
    <div class="summary-card">
        <div class="value severity-low">{}</div>
        <div class="label">Low</div>
    </div>
    <div class="summary-card">
        <div class="value severity-info">{}</div>
        <div class="label">Info</div>
    </div>
</div>
"#,
        report.summary.total_findings,
        critical,
        high,
        medium,
        low,
        info
    )
}

fn generate_risk_overview(report: &ScanReport) -> String {
    let risk = report.summary.risk_score;
    let (color, label) = match risk {
        0..=20 => ("#3fb950", "Low Risk"),
        21..=40 => ("#d29922", "Medium Risk"),
        41..=60 => ("#db6d28", "Elevated Risk"),
        61..=80 => ("#f85149", "High Risk"),
        _ => ("#f85149", "Critical Risk"),
    };

    format!(
        r#"<h2>Risk Assessment</h2>
<div class="summary-grid">
    <div class="summary-card" style="grid-column: span 2;">
        <div class="label">Overall Risk Score</div>
        <div class="risk-meter" style="margin: 1rem 0;">
            <div class="risk-meter-fill" style="width: {}%; background: {};"></div>
            <div class="risk-meter-label">{}/100 - {}</div>
        </div>
    </div>
    <div class="summary-card">
        <div class="value">{}</div>
        <div class="label">Unique Hosts</div>
    </div>
    <div class="summary-card">
        <div class="value">{}</div>
        <div class="label">Unique URLs</div>
    </div>
</div>
"#,
        risk,
        color,
        risk,
        label,
        report.summary.unique_hosts,
        report.summary.unique_urls
    )
}

fn generate_owasp_section(report: &ScanReport) -> String {
    let mut html = String::from("<h2>OWASP Top 10 Coverage</h2>\n<div class=\"owasp-grid\">\n");

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
        let count = report.owasp_mapping
            .get(&full_key)
            .map(|v| v.len())
            .unwrap_or(0);

        let color = if count > 0 { "var(--critical)" } else { "var(--text-secondary)" };

        html.push_str(&format!(
            r#"    <div class="owasp-item">
        <div class="count" style="color: {};">{}</div>
        <div><strong>{}</strong></div>
        <div style="color: var(--text-secondary); font-size: 0.85rem;">{}</div>
    </div>
"#,
            color, count, code, name
        ));
    }

    html.push_str("</div>\n");
    html
}

fn generate_findings_section(report: &ScanReport) -> String {
    let mut html = String::from(
        r#"<h2>Findings Overview</h2>
<table>
    <thead>
        <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Title</th>
            <th>URL</th>
            <th>CWE</th>
        </tr>
    </thead>
    <tbody>
"#,
    );

    for (idx, finding) in report.findings.iter().enumerate() {
        let severity = finding.severity_level();
        let badge_class = match severity {
            Severity::Critical => "badge-critical",
            Severity::High => "badge-high",
            Severity::Medium => "badge-medium",
            Severity::Low => "badge-low",
            Severity::Informational => "badge-info",
        };

        let cwe = finding.cwe_id.map(|c| format!("CWE-{}", c)).unwrap_or_else(|| "-".to_string());

        html.push_str(&format!(
            r##"        <tr>
            <td>{}</td>
            <td><span class="badge {}">{}</span></td>
            <td><a href="#finding-{}">{}</a></td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{}</td>
            <td>{}</td>
        </tr>
"##,
            idx + 1,
            badge_class,
            severity.name(),
            idx,
            html_escape(&finding.name),
            html_escape(&finding.url),
            cwe
        ));
    }

    html.push_str("    </tbody>\n</table>\n");
    html
}

fn generate_detailed_findings(report: &ScanReport) -> String {
    let mut html = String::from("<h2>Detailed Findings</h2>\n");

    for (idx, finding) in report.findings.iter().enumerate() {
        let severity = finding.severity_level();
        let badge_class = match severity {
            Severity::Critical => "badge-critical",
            Severity::High => "badge-high",
            Severity::Medium => "badge-medium",
            Severity::Low => "badge-low",
            Severity::Informational => "badge-info",
        };

        html.push_str(&format!(
            r##"<div class="finding" id="finding-{}">
    <div class="finding-header">
        <div>
            <h3 class="finding-title">{}</h3>
            <div class="finding-meta">
                <strong>URL:</strong> {}
            </div>
        </div>
        <span class="badge {}">{}</span>
    </div>
"##,
            idx,
            html_escape(&finding.name),
            html_escape(&finding.url),
            badge_class,
            severity.name()
        ));

        // Description
        if !finding.description.is_empty() {
            html.push_str(&format!(
                r#"    <div class="finding-section">
        <h4>Description</h4>
        <p>{}</p>
    </div>
"#,
                html_escape(&finding.description)
            ));
        }

        // Evidence
        if let Some(evidence) = &finding.evidence {
            html.push_str(&format!(
                r#"    <div class="finding-section">
        <h4>Evidence</h4>
        <pre>{}</pre>
    </div>
"#,
                html_escape(evidence)
            ));
        }

        // Remediation
        if let Some(remediation) = &finding.remediation {
            html.push_str(&format!(
                r#"    <div class="finding-section">
        <h4>Remediation</h4>
        <p>{}</p>
    </div>
"#,
                html_escape(remediation)
            ));
        }

        // Metadata
        let mut meta_items = Vec::new();
        if let Some(cwe) = finding.cwe_id {
            meta_items.push(format!("CWE-{}", cwe));
        }
        if let Some(owasp) = &finding.owasp_category {
            meta_items.push(owasp.clone());
        }
        if !finding.scanner.is_empty() {
            meta_items.push(format!("Scanner: {}", finding.scanner));
        }

        if !meta_items.is_empty() {
            html.push_str(&format!(
                r#"    <div class="finding-section">
        <h4>References</h4>
        <p>{}</p>
    </div>
"#,
                meta_items.join(" | ")
            ));
        }

        html.push_str("</div>\n");
    }

    html
}

fn generate_footer(report: &ScanReport) -> String {
    format!(
        r#"<div class="footer">
    <p>Generated by Ancarna v{}</p>
    <p>Report generated at {}</p>
</div>
"#,
        report.metadata.scanner_version,
        report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::ReportMetadata;
    use crate::scanner::Finding;

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn test_generate_html_report() {
        let findings = vec![
            Finding::new("Test Finding", Severity::High, "https://example.com"),
        ];
        let metadata = ReportMetadata::default();
        let report = ScanReport::new(findings, metadata);

        let html = generate(&report).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test Finding"));
        assert!(html.contains("High"));
    }
}
