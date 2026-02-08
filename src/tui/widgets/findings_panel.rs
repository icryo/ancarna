//! Findings panel for displaying scan results

#![allow(dead_code)]

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::scanner::Finding;
use crate::tui::Theme;

/// Findings panel widget
pub struct FindingsPanel<'a> {
    /// Findings to display
    findings: &'a [Finding],

    /// Selected index
    selected: usize,

    /// Whether focused
    focused: bool,

    /// Theme
    theme: &'a Theme,

    /// Show details for selected finding
    show_details: bool,
}

impl<'a> FindingsPanel<'a> {
    pub fn new(findings: &'a [Finding], theme: &'a Theme) -> Self {
        Self {
            findings,
            selected: 0,
            focused: false,
            theme,
            show_details: false,
        }
    }

    pub fn selected(mut self, index: usize) -> Self {
        self.selected = index;
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn show_details(mut self, show: bool) -> Self {
        self.show_details = show;
        self
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        use ratatui::style::Modifier;

        let border_style = if self.focused {
            Style::default().fg(self.theme.accent)
        } else {
            Style::default().fg(self.theme.border)
        };

        // Title with position indicator
        let title = if self.findings.is_empty() {
            " Findings (0) ".to_string()
        } else {
            format!(
                " Findings ({}/{}) ",
                self.selected + 1,
                self.findings.len()
            )
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(title);

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.findings.is_empty() {
            let empty_lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No findings yet",
                    Style::default().fg(self.theme.muted),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Run a scan to detect vulnerabilities:",
                    Style::default().fg(self.theme.fg),
                )),
                Line::from(Span::styled(
                    "  • Press 's' to start a scan",
                    Style::default().fg(self.theme.muted),
                )),
                Line::from(Span::styled(
                    "  • Configure target URL first",
                    Style::default().fg(self.theme.muted),
                )),
            ];
            frame.render_widget(Paragraph::new(empty_lines), inner);
            return;
        }

        let lines: Vec<Line> = self
            .findings
            .iter()
            .enumerate()
            .map(|(i, finding)| {
                let is_selected = i == self.selected;
                let severity_color = self.theme.severity_color(&finding.severity);

                // Different shapes for different severities (accessibility)
                // Critical: ◆ (diamond), High: ▲ (triangle), Medium: ■ (square), Low: ● (circle)
                let severity_indicator = match finding.severity.as_str() {
                    "critical" => "◆",
                    "high" => "▲",
                    "medium" => "■",
                    "low" => "●",
                    _ => "○",
                };

                // Selection marker
                let marker = if is_selected && self.focused {
                    Span::styled("▸ ", Style::default().fg(self.theme.accent))
                } else {
                    Span::raw("  ")
                };

                let style = if is_selected {
                    Style::default().fg(self.theme.accent).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                Line::from(vec![
                    marker,
                    Span::styled(
                        format!("{} ", severity_indicator),
                        Style::default().fg(severity_color),
                    ),
                    Span::styled(&finding.name, style),
                ])
            })
            .collect();

        frame.render_widget(Paragraph::new(lines), inner);
    }

    /// Render detailed view of selected finding
    pub fn render_details(&self, frame: &mut Frame, area: Rect) {
        if self.findings.is_empty() || self.selected >= self.findings.len() {
            return;
        }

        let finding = &self.findings[self.selected];
        let severity_color = self.theme.severity_color(&finding.severity);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.theme.border))
            .title(" Finding Details ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let lines = vec![
            Line::from(vec![
                Span::styled("Name: ", Style::default().fg(self.theme.muted)),
                Span::raw(&finding.name),
            ]),
            Line::from(vec![
                Span::styled("Severity: ", Style::default().fg(self.theme.muted)),
                Span::styled(&finding.severity, Style::default().fg(severity_color)),
            ]),
            Line::from(vec![
                Span::styled("URL: ", Style::default().fg(self.theme.muted)),
                Span::raw(&finding.url),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Description:", Style::default().fg(self.theme.muted)),
            ]),
            Line::from(&finding.description as &str),
            Line::from(""),
            Line::from(vec![
                Span::styled("Evidence:", Style::default().fg(self.theme.muted)),
            ]),
            Line::from(finding.evidence.as_deref().unwrap_or("N/A")),
            Line::from(""),
            Line::from(vec![
                Span::styled("Remediation:", Style::default().fg(self.theme.muted)),
            ]),
            Line::from(finding.remediation.as_deref().unwrap_or("N/A")),
        ];

        frame.render_widget(Paragraph::new(lines), inner);
    }
}
