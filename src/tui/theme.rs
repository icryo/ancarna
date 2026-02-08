//! Theme and color definitions

#![allow(dead_code)]

use ratatui::style::Color;

/// Color theme for the TUI
#[derive(Debug, Clone)]
pub struct Theme {
    /// Primary foreground color
    pub fg: Color,

    /// Primary background color
    pub bg: Color,

    /// Accent color for highlights
    pub accent: Color,

    /// Secondary accent
    pub accent_secondary: Color,

    /// Border color
    pub border: Color,

    /// Muted text color
    pub muted: Color,

    /// Success color (green)
    pub success: Color,

    /// Warning color (yellow)
    pub warning: Color,

    /// Error color (red)
    pub error: Color,

    /// Info color (blue)
    pub info: Color,

    /// HTTP method colors
    pub http_get: Color,
    pub http_post: Color,
    pub http_put: Color,
    pub http_patch: Color,
    pub http_delete: Color,
    pub http_options: Color,
    pub http_head: Color,

    /// Severity colors
    pub severity_critical: Color,
    pub severity_high: Color,
    pub severity_medium: Color,
    pub severity_low: Color,
    pub severity_info: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    /// Dark theme (default)
    pub fn dark() -> Self {
        Self {
            fg: Color::Rgb(220, 220, 220),
            bg: Color::Rgb(30, 30, 30),
            accent: Color::Rgb(86, 156, 214),      // Blue
            accent_secondary: Color::Rgb(78, 201, 176), // Teal
            border: Color::Rgb(80, 80, 80),
            muted: Color::Rgb(128, 128, 128),
            success: Color::Rgb(78, 201, 176),     // Teal/Green
            warning: Color::Rgb(220, 180, 50),     // Yellow/Orange
            error: Color::Rgb(244, 71, 71),        // Red
            info: Color::Rgb(86, 156, 214),        // Blue

            // HTTP methods
            http_get: Color::Rgb(78, 201, 176),    // Green
            http_post: Color::Rgb(86, 156, 214),   // Blue
            http_put: Color::Rgb(220, 180, 50),    // Orange
            http_patch: Color::Rgb(200, 150, 80),  // Brown/Orange
            http_delete: Color::Rgb(244, 71, 71),  // Red
            http_options: Color::Rgb(180, 140, 220), // Purple
            http_head: Color::Rgb(128, 128, 128),  // Gray

            // Severity
            severity_critical: Color::Rgb(180, 0, 0),
            severity_high: Color::Rgb(244, 71, 71),
            severity_medium: Color::Rgb(220, 180, 50),
            severity_low: Color::Rgb(86, 156, 214),
            severity_info: Color::Rgb(128, 128, 128),
        }
    }

    /// Light theme
    pub fn light() -> Self {
        Self {
            fg: Color::Rgb(30, 30, 30),
            bg: Color::Rgb(250, 250, 250),
            accent: Color::Rgb(0, 102, 204),
            accent_secondary: Color::Rgb(0, 128, 96),
            border: Color::Rgb(200, 200, 200),
            muted: Color::Rgb(100, 100, 100),
            success: Color::Rgb(0, 128, 96),
            warning: Color::Rgb(200, 140, 0),
            error: Color::Rgb(200, 0, 0),
            info: Color::Rgb(0, 102, 204),

            http_get: Color::Rgb(0, 128, 96),
            http_post: Color::Rgb(0, 102, 204),
            http_put: Color::Rgb(200, 140, 0),
            http_patch: Color::Rgb(160, 100, 40),
            http_delete: Color::Rgb(200, 0, 0),
            http_options: Color::Rgb(120, 80, 180),
            http_head: Color::Rgb(100, 100, 100),

            severity_critical: Color::Rgb(140, 0, 0),
            severity_high: Color::Rgb(200, 0, 0),
            severity_medium: Color::Rgb(200, 140, 0),
            severity_low: Color::Rgb(0, 102, 204),
            severity_info: Color::Rgb(100, 100, 100),
        }
    }

    /// Get color for HTTP method
    pub fn method_color(&self, method: &str) -> Color {
        match method.to_uppercase().as_str() {
            "GET" => self.http_get,
            "POST" => self.http_post,
            "PUT" => self.http_put,
            "PATCH" => self.http_patch,
            "DELETE" => self.http_delete,
            "OPTIONS" => self.http_options,
            "HEAD" => self.http_head,
            _ => self.muted,
        }
    }

    /// Get color for finding severity
    pub fn severity_color(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" => self.severity_critical,
            "high" => self.severity_high,
            "medium" => self.severity_medium,
            "low" => self.severity_low,
            "info" | "informational" => self.severity_info,
            _ => self.muted,
        }
    }

    /// Get color for HTTP status code
    pub fn status_color(&self, status: u16) -> Color {
        match status {
            100..=199 => self.info,
            200..=299 => self.success,
            300..=399 => self.warning,
            400..=499 => self.error,
            500..=599 => self.severity_critical,
            _ => self.muted,
        }
    }
}
