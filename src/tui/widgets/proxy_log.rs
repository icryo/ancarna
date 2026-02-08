//! Proxy request/response log widget

#![allow(dead_code)]

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::proxy::HistoryEntry;
use crate::tui::Theme;

/// Proxy log widget showing intercepted requests
pub struct ProxyLog<'a> {
    /// History entries
    entries: &'a [HistoryEntry],

    /// Selected index
    selected: usize,

    /// Whether focused
    focused: bool,

    /// Theme
    theme: &'a Theme,

    /// Scroll offset
    scroll: usize,
}

impl<'a> ProxyLog<'a> {
    pub fn new(entries: &'a [HistoryEntry], theme: &'a Theme) -> Self {
        Self {
            entries,
            selected: 0,
            focused: false,
            theme,
            scroll: 0,
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

    pub fn scroll(mut self, offset: usize) -> Self {
        self.scroll = offset;
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
        let title = if self.entries.is_empty() {
            " Proxy History (0) ".to_string()
        } else {
            format!(
                " Proxy History ({}/{}) ",
                self.selected + 1,
                self.entries.len()
            )
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(title);

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.entries.is_empty() {
            let empty_lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No requests captured",
                    Style::default().fg(self.theme.muted),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Configure your browser to use proxy:",
                    Style::default().fg(self.theme.fg),
                )),
                Line::from(Span::styled(
                    "  HTTP/HTTPS: 127.0.0.1:8080",
                    Style::default().fg(self.theme.muted),
                )),
            ];
            frame.render_widget(Paragraph::new(empty_lines), inner);
            return;
        }

        // Build table rows with selection marker
        let rows: Vec<Line> = self
            .entries
            .iter()
            .skip(self.scroll)
            .take(inner.height as usize)
            .enumerate()
            .map(|(i, entry)| {
                let is_selected = i + self.scroll == self.selected;
                let method_color = self.theme.method_color(&entry.method);
                let status_color = entry
                    .status
                    .map(|s| self.theme.status_color(s))
                    .unwrap_or(self.theme.muted);

                // Selection marker
                let marker = if is_selected && self.focused {
                    Span::styled("▸ ", Style::default().fg(self.theme.accent))
                } else {
                    Span::raw("  ")
                };

                // Base style for selected items
                let base_style = if is_selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                let (truncated_url, was_truncated) = truncate_url_with_indicator(&entry.url, 48);
                let url_span = if was_truncated {
                    Span::styled(
                        format!("{} ", truncated_url),
                        base_style.fg(self.theme.fg),
                    )
                } else {
                    Span::styled(truncated_url, base_style.fg(self.theme.fg))
                };

                let truncation_indicator = if was_truncated {
                    Span::styled("[+]", Style::default().fg(self.theme.muted))
                } else {
                    Span::raw("")
                };

                let spans = vec![
                    marker,
                    Span::styled(
                        format!("{:>3} ", entry.id),
                        base_style.fg(self.theme.muted),
                    ),
                    Span::styled(
                        format!("{:7} ", entry.method),
                        base_style.fg(method_color),
                    ),
                    Span::styled(
                        format!("{:4} ", entry.status.map(|s| s.to_string()).unwrap_or_else(|| "...".to_string())),
                        base_style.fg(status_color),
                    ),
                    url_span,
                    truncation_indicator,
                ];

                Line::from(spans)
            })
            .collect();

        frame.render_widget(Paragraph::new(rows), inner);
    }
}

fn truncate_url_with_indicator(url: &str, max_len: usize) -> (String, bool) {
    if url.len() <= max_len {
        (url.to_string(), false)
    } else {
        let target = max_len.saturating_sub(3);
        let mut end = target;
        while end > 0 && !url.is_char_boundary(end) {
            end -= 1;
        }
        (format!("{}...", &url[..end]), true)
    }
}

#[allow(dead_code)]
fn truncate_url(url: &str, max_len: usize) -> String {
    truncate_url_with_indicator(url, max_len).0
}
