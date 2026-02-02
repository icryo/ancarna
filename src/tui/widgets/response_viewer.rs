//! Response viewer widget

use ratatui::{
    layout::Rect,
    style::Style,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::http::Response;
use crate::tui::Theme;

/// Response viewer widget
pub struct ResponseViewer<'a> {
    /// The response to display
    response: Option<&'a Response>,

    /// Whether the viewer is focused
    focused: bool,

    /// Theme
    theme: &'a Theme,

    /// Current tab
    active_tab: ResponseTab,

    /// Scroll offset
    scroll: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseTab {
    #[default]
    Body,
    Headers,
    Cookies,
    Timing,
}

impl<'a> ResponseViewer<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self {
            response: None,
            focused: false,
            theme,
            active_tab: ResponseTab::default(),
            scroll: 0,
        }
    }

    pub fn response(mut self, response: &'a Response) -> Self {
        self.response = Some(response);
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn scroll(mut self, scroll: u16) -> Self {
        self.scroll = scroll;
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
            .title(" Response ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if let Some(resp) = self.response {
            self.render_response(frame, inner, resp);
        } else {
            let placeholder = Paragraph::new("No response yet")
                .style(Style::default().fg(self.theme.muted));
            frame.render_widget(placeholder, inner);
        }
    }

    fn render_response(&self, frame: &mut Frame, area: Rect, response: &Response) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::text::{Line, Span};

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // Status line
                Constraint::Length(1), // Tabs
                Constraint::Min(1),    // Content
            ])
            .split(area);

        // Status line
        let status_color = self.theme.status_color(response.status);
        let status_line = Line::from(vec![
            Span::styled(
                format!("{} {}", response.status, response.status_text),
                Style::default().fg(status_color),
            ),
            Span::raw(format!(
                " • {}ms • {}",
                response.duration_ms,
                format_size(response.body.len())
            )),
        ]);
        frame.render_widget(Paragraph::new(status_line), chunks[0]);

        // Tabs
        let tabs = ["Body", "Headers", "Cookies", "Timing"];
        let tab_line: Vec<Span> = tabs
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                let is_active = i == self.active_tab as usize;
                if is_active {
                    Span::styled(format!(" {} ", tab), Style::default().fg(self.theme.accent))
                } else {
                    Span::styled(format!(" {} ", tab), Style::default().fg(self.theme.muted))
                }
            })
            .collect();
        frame.render_widget(Paragraph::new(Line::from(tab_line)), chunks[1]);

        // Content based on active tab
        match self.active_tab {
            ResponseTab::Body => self.render_body(frame, chunks[2], response),
            ResponseTab::Headers => self.render_headers(frame, chunks[2], response),
            _ => {}
        }
    }

    fn render_body(&self, frame: &mut Frame, area: Rect, response: &Response) {
        let body = String::from_utf8_lossy(&response.body);

        // Try to format JSON
        let formatted = if response
            .headers
            .get("content-type")
            .map(|ct| ct.contains("json"))
            .unwrap_or(false)
        {
            jsonxf::pretty_print(&body).unwrap_or_else(|_| body.to_string())
        } else {
            body.to_string()
        };

        let paragraph = Paragraph::new(formatted)
            .scroll((self.scroll, 0));
        frame.render_widget(paragraph, area);
    }

    fn render_headers(&self, frame: &mut Frame, area: Rect, response: &Response) {
        use ratatui::text::Line;

        let lines: Vec<Line> = response
            .headers
            .iter()
            .map(|(k, v)| Line::from(format!("{}: {}", k, v)))
            .collect();

        frame.render_widget(Paragraph::new(lines), area);
    }
}

fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;

    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
