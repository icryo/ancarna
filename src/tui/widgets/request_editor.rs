//! Request editor widget

use ratatui::{
    layout::Rect,
    style::Style,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::http::Request;
use crate::tui::Theme;

/// Request editor widget for composing HTTP requests
pub struct RequestEditor<'a> {
    /// The request being edited
    request: Option<&'a Request>,

    /// Whether the editor is focused
    focused: bool,

    /// Theme
    theme: &'a Theme,

    /// Current tab (params, headers, body, auth, pre-script, post-script)
    active_tab: RequestTab,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestTab {
    #[default]
    Params,
    Headers,
    Body,
    Auth,
    PreScript,
    PostScript,
}

impl<'a> RequestEditor<'a> {
    pub fn new(theme: &'a Theme) -> Self {
        Self {
            request: None,
            focused: false,
            theme,
            active_tab: RequestTab::default(),
        }
    }

    pub fn request(mut self, request: &'a Request) -> Self {
        self.request = Some(request);
        self
    }

    pub fn focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn active_tab(mut self, tab: RequestTab) -> Self {
        self.active_tab = tab;
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
            .title(" Request ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if let Some(req) = self.request {
            self.render_request(frame, inner, req);
        } else {
            let placeholder = Paragraph::new("No request selected")
                .style(Style::default().fg(self.theme.muted));
            frame.render_widget(placeholder, inner);
        }
    }

    fn render_request(&self, frame: &mut Frame, area: Rect, request: &Request) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::text::{Line, Span};

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2), // Method + URL
                Constraint::Length(1), // Tabs
                Constraint::Min(1),    // Content
            ])
            .split(area);

        // Method and URL
        let method_color = self.theme.method_color(&request.method);
        let url_line = Line::from(vec![
            Span::styled(format!("{} ", request.method), Style::default().fg(method_color)),
            Span::raw(&request.url),
        ]);
        frame.render_widget(Paragraph::new(url_line), chunks[0]);

        // Tabs
        let tabs = ["Params", "Headers", "Body", "Auth", "Pre", "Post"];
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
        let content = match self.active_tab {
            RequestTab::Headers => self.render_headers(request),
            RequestTab::Body => self.render_body(request),
            _ => Paragraph::new(""),
        };
        frame.render_widget(content, chunks[2]);
    }

    fn render_headers(&self, request: &Request) -> Paragraph<'static> {
        use ratatui::text::Line;

        let lines: Vec<Line> = request
            .headers
            .iter()
            .map(|(k, v)| Line::from(format!("{}: {}", k, v)))
            .collect();

        Paragraph::new(lines)
    }

    fn render_body(&self, request: &Request) -> Paragraph<'static> {
        let body = request.body.as_deref().unwrap_or("");
        Paragraph::new(body.to_string())
    }
}
