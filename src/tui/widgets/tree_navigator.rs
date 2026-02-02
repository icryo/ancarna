//! Tree navigator widget for workspace/collection browsing

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::tui::Theme;

/// A node in the navigation tree
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Display name
    pub name: String,

    /// Node type
    pub node_type: NodeType,

    /// Children nodes
    pub children: Vec<TreeNode>,

    /// Whether the node is expanded
    pub expanded: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Collection,
    Folder,
    Request,
    Environment,
}

/// Tree navigator widget
pub struct TreeNavigator<'a> {
    /// Root nodes
    nodes: &'a [TreeNode],

    /// Selected index
    selected: usize,

    /// Whether focused
    focused: bool,

    /// Theme
    theme: &'a Theme,
}

impl<'a> TreeNavigator<'a> {
    pub fn new(nodes: &'a [TreeNode], theme: &'a Theme) -> Self {
        Self {
            nodes,
            selected: 0,
            focused: false,
            theme,
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

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let border_style = if self.focused {
            Style::default().fg(self.theme.accent)
        } else {
            Style::default().fg(self.theme.border)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Collections ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let lines = self.build_lines(self.nodes, 0);
        let content = Paragraph::new(lines);
        frame.render_widget(content, inner);
    }

    fn build_lines(&self, nodes: &[TreeNode], depth: usize) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        let indent = "  ".repeat(depth);

        for node in nodes.iter() {
            let icon = match node.node_type {
                NodeType::Collection => "📁",
                NodeType::Folder => if node.expanded { "📂" } else { "📁" },
                NodeType::Request => "📄",
                NodeType::Environment => "⚙️",
            };

            let expand_icon = if !node.children.is_empty() {
                if node.expanded { "▼ " } else { "▶ " }
            } else {
                "  "
            };

            let line = format!("{}{}{} {}", indent, expand_icon, icon, node.name);
            lines.push(Line::from(Span::raw(line)));

            if node.expanded {
                lines.extend(self.build_lines(&node.children, depth + 1));
            }
        }

        lines
    }
}
