//! Layout utilities for the TUI

#![allow(dead_code)]

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Layout presets for different views
pub struct Layouts;

impl Layouts {
    /// Adaptive three-column workspace layout based on terminal width
    /// Returns constraints for [Collections, Request, Response]
    pub fn workspace_constraints(width: u16) -> [Constraint; 3] {
        if width >= 120 {
            // Wide: give collections more room
            [
                Constraint::Percentage(25),
                Constraint::Percentage(38),
                Constraint::Percentage(37),
            ]
        } else if width >= 100 {
            // Medium: balanced
            [
                Constraint::Percentage(28),
                Constraint::Percentage(36),
                Constraint::Percentage(36),
            ]
        } else {
            // Compact: collections gets 30% for better readability
            [
                Constraint::Percentage(30),
                Constraint::Percentage(35),
                Constraint::Percentage(35),
            ]
        }
    }

    /// Three-column workspace layout (adaptive)
    pub fn workspace(area: Rect) -> Vec<Rect> {
        let constraints = Self::workspace_constraints(area.width);
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints(constraints)
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
