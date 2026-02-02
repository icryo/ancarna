//! Proxy request/response log widget

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
        let border_style = if self.focused {
            Style::default().fg(self.theme.accent)
        } else {
            Style::default().fg(self.theme.border)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(format!(" Proxy History ({}) ", self.entries.len()));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.entries.is_empty() {
            let empty = Paragraph::new("No requests captured")
                .style(Style::default().fg(self.theme.muted));
            frame.render_widget(empty, inner);
            return;
        }

        // Build table rows
        let rows: Vec<Line> = self
            .entries
            .iter()
            .skip(self.scroll)
            .take(inner.height as usize)
            .enumerate()
            .map(|(i, entry)| {
                let _is_selected = i + self.scroll == self.selected;
                let method_color = self.theme.method_color(&entry.method);
                let status_color = entry
                    .status
                    .map(|s| self.theme.status_color(s))
                    .unwrap_or(self.theme.muted);

                let spans = vec![
                    Span::styled(
                        format!("{:>3} ", entry.id),
                        Style::default().fg(self.theme.muted),
                    ),
                    Span::styled(
                        format!("{:7} ", entry.method),
                        Style::default().fg(method_color),
                    ),
                    Span::styled(
                        format!("{:4} ", entry.status.map(|s| s.to_string()).unwrap_or_else(|| "...".to_string())),
                        Style::default().fg(status_color),
                    ),
                    Span::raw(truncate_url(&entry.url, 50)),
                ];

                Line::from(spans)
            })
            .collect();

        frame.render_widget(Paragraph::new(rows), inner);
    }
}

fn truncate_url(url: &str, max_len: usize) -> String {
    if url.len() <= max_len {
        url.to_string()
    } else {
        let target = max_len.saturating_sub(3);
        let mut end = target;
        while end > 0 && !url.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &url[..end])
    }
}
