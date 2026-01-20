//! Text input widget with cursor, selection, and editing support

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, StatefulWidget, Widget},
};

/// State for the text input widget
#[derive(Debug, Clone)]
pub struct TextInputState {
    /// Current text content
    pub value: String,
    /// Cursor position (character index)
    pub cursor: usize,
    /// Selection start (if any)
    pub selection_start: Option<usize>,
    /// Horizontal scroll offset
    pub scroll_offset: usize,
    /// Whether the input is focused
    pub focused: bool,
    /// Placeholder text
    pub placeholder: String,
}

impl Default for TextInputState {
    fn default() -> Self {
        Self {
            value: String::new(),
            cursor: 0,
            selection_start: None,
            scroll_offset: 0,
            focused: false,
            placeholder: String::new(),
        }
    }
}

impl TextInputState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = value.into();
        self.cursor = self.value.len();
        self
    }

    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = placeholder.into();
        self
    }

    /// Insert a character at cursor position
    pub fn insert(&mut self, c: char) {
        self.delete_selection();
        if self.cursor >= self.value.len() {
            self.value.push(c);
        } else {
            self.value.insert(self.cursor, c);
        }
        self.cursor += 1;
    }

    /// Insert a string at cursor position
    pub fn insert_str(&mut self, s: &str) {
        self.delete_selection();
        if self.cursor >= self.value.len() {
            self.value.push_str(s);
        } else {
            self.value.insert_str(self.cursor, s);
        }
        self.cursor += s.len();
    }

    /// Delete character before cursor (backspace)
    pub fn backspace(&mut self) {
        if self.selection_start.is_some() {
            self.delete_selection();
        } else if self.cursor > 0 {
            self.cursor -= 1;
            self.value.remove(self.cursor);
        }
    }

    /// Delete character at cursor (delete)
    pub fn delete(&mut self) {
        if self.selection_start.is_some() {
            self.delete_selection();
        } else if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
        }
    }

    /// Delete selected text
    fn delete_selection(&mut self) {
        if let Some(start) = self.selection_start.take() {
            let (from, to) = if start < self.cursor {
                (start, self.cursor)
            } else {
                (self.cursor, start)
            };
            self.value.drain(from..to);
            self.cursor = from;
        }
    }

    /// Move cursor left
    pub fn move_left(&mut self) {
        self.selection_start = None;
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

    /// Move cursor right
    pub fn move_right(&mut self) {
        self.selection_start = None;
        if self.cursor < self.value.len() {
            self.cursor += 1;
        }
    }

    /// Move cursor to start
    pub fn move_home(&mut self) {
        self.selection_start = None;
        self.cursor = 0;
    }

    /// Move cursor to end
    pub fn move_end(&mut self) {
        self.selection_start = None;
        self.cursor = self.value.len();
    }

    /// Move cursor to previous word boundary
    pub fn move_word_left(&mut self) {
        self.selection_start = None;
        if self.cursor == 0 {
            return;
        }
        // Skip whitespace
        while self.cursor > 0 && self.value.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // Skip word
        while self.cursor > 0 && self.value.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
    }

    /// Move cursor to next word boundary
    pub fn move_word_right(&mut self) {
        self.selection_start = None;
        let len = self.value.len();
        if self.cursor >= len {
            return;
        }
        // Skip current word
        while self.cursor < len && self.value.chars().nth(self.cursor) != Some(' ') {
            self.cursor += 1;
        }
        // Skip whitespace
        while self.cursor < len && self.value.chars().nth(self.cursor) == Some(' ') {
            self.cursor += 1;
        }
    }

    /// Delete word before cursor
    pub fn delete_word_back(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let end = self.cursor;
        // Skip whitespace
        while self.cursor > 0 && self.value.chars().nth(self.cursor - 1) == Some(' ') {
            self.cursor -= 1;
        }
        // Skip word
        while self.cursor > 0 && self.value.chars().nth(self.cursor - 1) != Some(' ') {
            self.cursor -= 1;
        }
        self.value.drain(self.cursor..end);
    }

    /// Delete from cursor to end
    pub fn delete_to_end(&mut self) {
        self.value.truncate(self.cursor);
    }

    /// Select all text
    pub fn select_all(&mut self) {
        self.selection_start = Some(0);
        self.cursor = self.value.len();
    }

    /// Clear the input
    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
        self.selection_start = None;
    }

    /// Get selected text
    pub fn selected_text(&self) -> Option<&str> {
        self.selection_start.map(|start| {
            let (from, to) = if start < self.cursor {
                (start, self.cursor)
            } else {
                (self.cursor, start)
            };
            &self.value[from..to]
        })
    }

    /// Handle keyboard input, returns true if input was consumed
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::{KeyCode, KeyModifiers};

        match (key.modifiers, key.code) {
            // Navigation
            (KeyModifiers::NONE, KeyCode::Left) => self.move_left(),
            (KeyModifiers::NONE, KeyCode::Right) => self.move_right(),
            (KeyModifiers::NONE, KeyCode::Home) => self.move_home(),
            (KeyModifiers::NONE, KeyCode::End) => self.move_end(),
            (KeyModifiers::CONTROL, KeyCode::Left) => self.move_word_left(),
            (KeyModifiers::CONTROL, KeyCode::Right) => self.move_word_right(),
            (KeyModifiers::CONTROL, KeyCode::Char('a')) => self.move_home(),
            (KeyModifiers::CONTROL, KeyCode::Char('e')) => self.move_end(),
            (KeyModifiers::CONTROL, KeyCode::Char('b')) => self.move_left(),
            (KeyModifiers::CONTROL, KeyCode::Char('f')) => self.move_right(),

            // Deletion
            (KeyModifiers::NONE, KeyCode::Backspace) => self.backspace(),
            (KeyModifiers::NONE, KeyCode::Delete) => self.delete(),
            (KeyModifiers::CONTROL, KeyCode::Char('h')) => self.backspace(),
            (KeyModifiers::CONTROL, KeyCode::Char('w')) => self.delete_word_back(),
            (KeyModifiers::CONTROL, KeyCode::Char('k')) => self.delete_to_end(),
            (KeyModifiers::CONTROL, KeyCode::Char('u')) => self.clear(),

            // Selection (Shift variants handled by selection_start)
            // Text input
            (KeyModifiers::NONE | KeyModifiers::SHIFT, KeyCode::Char(c)) => self.insert(c),

            _ => return false,
        }
        true
    }

    /// Update scroll offset to keep cursor visible
    fn update_scroll(&mut self, visible_width: usize) {
        if visible_width == 0 {
            return;
        }
        // Ensure cursor is visible
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset + visible_width {
            self.scroll_offset = self.cursor - visible_width + 1;
        }
    }
}

/// Text input widget
pub struct TextInput<'a> {
    /// Block wrapper
    block: Option<Block<'a>>,
    /// Style for the input text
    style: Style,
    /// Style when focused
    focus_style: Style,
    /// Cursor style
    cursor_style: Style,
    /// Placeholder style
    placeholder_style: Style,
}

impl<'a> Default for TextInput<'a> {
    fn default() -> Self {
        Self {
            block: None,
            style: Style::default(),
            focus_style: Style::default().fg(Color::Cyan),
            cursor_style: Style::default().bg(Color::White).fg(Color::Black),
            placeholder_style: Style::default().fg(Color::DarkGray),
        }
    }
}

impl<'a> TextInput<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    pub fn focus_style(mut self, style: Style) -> Self {
        self.focus_style = style;
        self
    }

    pub fn cursor_style(mut self, style: Style) -> Self {
        self.cursor_style = style;
        self
    }

    pub fn placeholder_style(mut self, style: Style) -> Self {
        self.placeholder_style = style;
        self
    }
}

impl<'a> StatefulWidget for TextInput<'a> {
    type State = TextInputState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Calculate inner area
        let inner_area = if let Some(ref block) = self.block {
            let inner = block.inner(area);
            // Render block with appropriate border style
            let styled_block = if state.focused {
                block.clone().border_style(self.focus_style)
            } else {
                block.clone()
            };
            styled_block.render(area, buf);
            inner
        } else {
            area
        };

        if inner_area.width == 0 || inner_area.height == 0 {
            return;
        }

        let visible_width = inner_area.width as usize;

        // Update scroll to keep cursor visible
        state.update_scroll(visible_width.saturating_sub(1));

        let base_style = if state.focused {
            self.focus_style
        } else {
            self.style
        };

        // Render content
        if state.value.is_empty() && !state.focused {
            // Show placeholder
            let placeholder: String = state
                .placeholder
                .chars()
                .take(visible_width)
                .collect();
            buf.set_string(inner_area.x, inner_area.y, &placeholder, self.placeholder_style);
        } else {
            // Show value with cursor
            let visible_text: String = state
                .value
                .chars()
                .skip(state.scroll_offset)
                .take(visible_width)
                .collect();

            let cursor_pos_in_view = state.cursor.saturating_sub(state.scroll_offset);

            for (i, c) in visible_text.chars().enumerate() {
                let style = if state.focused && i == cursor_pos_in_view {
                    self.cursor_style
                } else {
                    base_style
                };
                buf.set_string(inner_area.x + i as u16, inner_area.y, c.to_string(), style);
            }

            // Render cursor at end if cursor is at end
            if state.focused && cursor_pos_in_view >= visible_text.len() && cursor_pos_in_view < visible_width {
                buf.set_string(
                    inner_area.x + cursor_pos_in_view as u16,
                    inner_area.y,
                    " ",
                    self.cursor_style,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_input_insert() {
        let mut state = TextInputState::new();
        state.insert('h');
        state.insert('e');
        state.insert('l');
        state.insert('l');
        state.insert('o');
        assert_eq!(state.value, "hello");
        assert_eq!(state.cursor, 5);
    }

    #[test]
    fn test_text_input_backspace() {
        let mut state = TextInputState::new().with_value("hello");
        state.backspace();
        assert_eq!(state.value, "hell");
        assert_eq!(state.cursor, 4);
    }

    #[test]
    fn test_text_input_cursor_movement() {
        let mut state = TextInputState::new().with_value("hello world");
        state.move_home();
        assert_eq!(state.cursor, 0);
        state.move_end();
        assert_eq!(state.cursor, 11);
        state.move_left();
        assert_eq!(state.cursor, 10);
        state.move_right();
        assert_eq!(state.cursor, 11);
    }

    #[test]
    fn test_text_input_word_navigation() {
        let mut state = TextInputState::new().with_value("hello world test");
        state.move_home();
        state.move_word_right();
        assert_eq!(state.cursor, 6); // After "hello "
        state.move_word_right();
        assert_eq!(state.cursor, 12); // After "world "
        state.move_word_left();
        assert_eq!(state.cursor, 6); // Back to "world"
    }

    #[test]
    fn test_text_input_delete_word() {
        let mut state = TextInputState::new().with_value("hello world");
        state.delete_word_back();
        assert_eq!(state.value, "hello ");
        state.delete_word_back();
        assert_eq!(state.value, "");
    }
}
