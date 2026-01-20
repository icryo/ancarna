//! Layout utilities for the TUI

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Layout presets for different views
pub struct Layouts;

impl Layouts {
    /// Three-column workspace layout
    pub fn workspace(area: Rect) -> Vec<Rect> {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(40),
                Constraint::Percentage(40),
            ])
            .split(area)
            .to_vec()
    }

    /// Two-column proxy view
    pub fn proxy_view(area: Rect) -> Vec<Rect> {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(area)
            .to_vec()
    }

    /// Scanner results view (tree + details)
    pub fn scanner_view(area: Rect) -> Vec<Rect> {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Percentage(70),
            ])
            .split(area)
            .to_vec()
    }

    /// Vertical split for request/response in proxy
    pub fn request_response(area: Rect) -> Vec<Rect> {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(area)
            .to_vec()
    }

    /// Header area split (method/url + tabs)
    pub fn request_header(area: Rect) -> Vec<Rect> {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Method + URL
                Constraint::Length(2), // Tabs
                Constraint::Min(1),    // Content
            ])
            .split(area)
            .to_vec()
    }

    /// Create a centered popup
    pub fn centered_popup(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ])
            .split(area);

        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ])
            .split(popup_layout[1])[1]
    }

    /// Create a popup anchored to bottom of screen
    pub fn bottom_popup(height: u16, area: Rect) -> Rect {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(height),
            ])
            .split(area)[1]
    }
}
