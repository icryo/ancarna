//! Key-value editor widget for headers, params, form data

#![allow(dead_code)]

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, StatefulWidget, Widget},
};

use super::text_input::TextInputState;

/// A single key-value row
#[derive(Debug, Clone)]
pub struct KeyValueRow {
    /// Row key
    pub key: TextInputState,
    /// Row value
    pub value: TextInputState,
    /// Whether the row is enabled
    pub enabled: bool,
    /// Row description (optional)
    pub description: Option<String>,
}

impl KeyValueRow {
    pub fn new() -> Self {
        Self {
            key: TextInputState::new().with_placeholder("Key"),
            value: TextInputState::new().with_placeholder("Value"),
            enabled: true,
            description: None,
        }
    }

    pub fn with_key_value(key: &str, value: &str) -> Self {
        Self {
            key: TextInputState::new().with_value(key),
            value: TextInputState::new().with_value(value),
            enabled: true,
            description: None,
        }
    }
}

impl Default for KeyValueRow {
    fn default() -> Self {
        Self::new()
    }
}

/// Which column is being edited
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditColumn {
    Key,
    Value,
}

/// State for the key-value editor
#[derive(Debug, Clone)]
pub struct KeyValueEditorState {
    /// All rows
    pub rows: Vec<KeyValueRow>,
    /// Currently selected row index
    pub selected_row: usize,
    /// Which column is being edited (if editing)
    pub edit_column: Option<EditColumn>,
    /// Scroll offset for rendering
    pub scroll_offset: usize,
    /// Whether the widget is focused
    pub focused: bool,
}

impl Default for KeyValueEditorState {
    fn default() -> Self {
        Self {
            rows: vec![KeyValueRow::new()], // Start with one empty row
            selected_row: 0,
            edit_column: None,
            scroll_offset: 0,
            focused: false,
        }
    }
}

impl KeyValueEditorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rows(rows: Vec<KeyValueRow>) -> Self {
        let mut state = Self::default();
        if rows.is_empty() {
            state.rows = vec![KeyValueRow::new()];
        } else {
            state.rows = rows;
        }
        state
    }

    /// Create from a vec of (key, value) tuples
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        let rows: Vec<KeyValueRow> = pairs
            .into_iter()
            .map(|(k, v)| KeyValueRow::with_key_value(&k, &v))
            .collect();
        Self::with_rows(rows)
    }

    /// Convert to a vec of (key, value) tuples (only enabled rows with non-empty keys)
    pub fn to_pairs(&self) -> Vec<(String, String)> {
        self.rows
            .iter()
            .filter(|r| r.enabled && !r.key.value.is_empty())
            .map(|r| (r.key.value.clone(), r.value.value.clone()))
            .collect()
    }

    /// Move selection up
    pub fn move_up(&mut self) {
        if self.selected_row > 0 {
            self.selected_row -= 1;
        }
    }

    /// Move selection down
    pub fn move_down(&mut self) {
        if self.selected_row < self.rows.len().saturating_sub(1) {
            self.selected_row += 1;
        }
    }

    /// Add a new row below current
    pub fn add_row(&mut self) {
        let new_row = KeyValueRow::new();
        if self.selected_row >= self.rows.len() {
            self.rows.push(new_row);
            self.selected_row = self.rows.len() - 1;
        } else {
            self.rows.insert(self.selected_row + 1, new_row);
            self.selected_row += 1;
        }
    }

    /// Delete current row
    pub fn delete_row(&mut self) {
        if self.rows.len() > 1 {
            self.rows.remove(self.selected_row);
            if self.selected_row >= self.rows.len() {
                self.selected_row = self.rows.len() - 1;
            }
        } else {
            // Don't delete last row, just clear it
            self.rows[0] = KeyValueRow::new();
        }
    }

    /// Toggle current row enabled state
    pub fn toggle_enabled(&mut self) {
        if let Some(row) = self.rows.get_mut(self.selected_row) {
            row.enabled = !row.enabled;
        }
    }

    /// Enter edit mode on key column
    pub fn edit_key(&mut self) {
        self.edit_column = Some(EditColumn::Key);
        if let Some(row) = self.rows.get_mut(self.selected_row) {
            row.key.focused = true;
            row.key.cursor = row.key.value.len();
        }
    }

    /// Enter edit mode on value column
    pub fn edit_value(&mut self) {
        self.edit_column = Some(EditColumn::Value);
        if let Some(row) = self.rows.get_mut(self.selected_row) {
            row.value.focused = true;
            row.value.cursor = row.value.value.len();
        }
    }

    /// Exit edit mode
    pub fn exit_edit(&mut self) {
        if let Some(row) = self.rows.get_mut(self.selected_row) {
            row.key.focused = false;
            row.value.focused = false;
        }
        self.edit_column = None;

        // If we just edited the last row and it has content, add a new empty row
        if self.selected_row == self.rows.len() - 1 {
            let last = &self.rows[self.selected_row];
            if !last.key.value.is_empty() || !last.value.value.is_empty() {
                self.rows.push(KeyValueRow::new());
            }
        }
    }

    /// Switch between key and value columns while editing
    pub fn toggle_column(&mut self) {
        if let Some(col) = self.edit_column {
            if let Some(row) = self.rows.get_mut(self.selected_row) {
                match col {
                    EditColumn::Key => {
                        row.key.focused = false;
                        row.value.focused = true;
                        self.edit_column = Some(EditColumn::Value);
                    }
                    EditColumn::Value => {
                        row.value.focused = false;
                        row.key.focused = true;
                        self.edit_column = Some(EditColumn::Key);
                    }
                }
            }
        }
    }

    /// Handle key input in edit mode
    pub fn handle_edit_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;

        if self.edit_column.is_none() {
            return false;
        }

        match key.code {
            KeyCode::Esc => {
                self.exit_edit();
                return true;
            }
            KeyCode::Tab => {
                self.toggle_column();
                return true;
            }
            KeyCode::Enter => {
                self.exit_edit();
                self.move_down();
                return true;
            }
            _ => {}
        }

        // Forward to the active text input
        if let Some(row) = self.rows.get_mut(self.selected_row) {
            match self.edit_column {
                Some(EditColumn::Key) => row.key.handle_key(key),
                Some(EditColumn::Value) => row.value.handle_key(key),
                None => false,
            }
        } else {
            false
        }
    }

    /// Handle key input in navigation mode
    pub fn handle_nav_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        use crossterm::event::KeyCode;

        if self.edit_column.is_some() {
            return false;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_down();
                true
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_up();
                true
            }
            KeyCode::Char('i') | KeyCode::Enter => {
                self.edit_key();
                true
            }
            KeyCode::Tab => {
                self.edit_value();
                true
            }
            KeyCode::Char('o') => {
                self.add_row();
                self.edit_key();
                true
            }
            KeyCode::Char('d') => {
                self.delete_row();
                true
            }
            KeyCode::Char(' ') => {
                self.toggle_enabled();
                true
            }
            _ => false,
        }
    }

    /// Update scroll offset to keep selection visible
    fn update_scroll(&mut self, visible_rows: usize) {
        if visible_rows == 0 {
            return;
        }
        if self.selected_row < self.scroll_offset {
            self.scroll_offset = self.selected_row;
        } else if self.selected_row >= self.scroll_offset + visible_rows {
            self.scroll_offset = self.selected_row - visible_rows + 1;
        }
    }
}

/// Key-value editor widget
pub struct KeyValueEditor<'a> {
    /// Block wrapper
    block: Option<Block<'a>>,
    /// Style for normal rows
    row_style: Style,
    /// Style for selected row
    selected_style: Style,
    /// Style for disabled rows
    disabled_style: Style,
    /// Style for the key column
    key_style: Style,
    /// Style for the value column
    value_style: Style,
    /// Column divider character
    divider: &'a str,
}

impl<'a> Default for KeyValueEditor<'a> {
    fn default() -> Self {
        Self {
            block: None,
            row_style: Style::default(),
            selected_style: Style::default().bg(Color::DarkGray),
            disabled_style: Style::default().fg(Color::DarkGray),
            key_style: Style::default().fg(Color::Cyan),
            value_style: Style::default(),
            divider: " : ",
        }
    }
}

impl<'a> KeyValueEditor<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn selected_style(mut self, style: Style) -> Self {
        self.selected_style = style;
        self
    }

    pub fn key_style(mut self, style: Style) -> Self {
        self.key_style = style;
        self
    }

    pub fn value_style(mut self, style: Style) -> Self {
        self.value_style = style;
        self
    }
}

impl<'a> StatefulWidget for KeyValueEditor<'a> {
    type State = KeyValueEditorState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        // Calculate inner area
        let inner = if let Some(ref block) = self.block {
            let inner = block.inner(area);
            block.clone().render(area, buf);
            inner
        } else {
            area
        };

        if inner.height == 0 || inner.width == 0 {
            return;
        }

        let visible_rows = inner.height as usize;
        state.update_scroll(visible_rows);

        let key_width = (inner.width.saturating_sub(3) / 2) as usize; // Half minus divider
        let divider_width = self.divider.len();

        for (i, row) in state
            .rows
            .iter()
            .skip(state.scroll_offset)
            .take(visible_rows)
            .enumerate()
        {
            let y = inner.y + i as u16;
            let row_idx = state.scroll_offset + i;
            let is_selected = row_idx == state.selected_row;

            // Base style for the row
            let base_style = if !row.enabled {
                self.disabled_style
            } else if is_selected {
                self.selected_style
            } else {
                self.row_style
            };

            // Clear row with base style
            for x in inner.x..inner.x + inner.width {
                buf[(x, y)].set_style(base_style).set_char(' ');
            }

            // Checkbox for enabled state
            let checkbox = if row.enabled { "[x]" } else { "[ ]" };
            buf.set_string(inner.x, y, checkbox, base_style);

            // Key column
            let key_start = inner.x + 4;
            let key_display: String = row.key.value.chars().take(key_width.saturating_sub(4)).collect();
            let key_text = if key_display.is_empty() && !is_selected {
                "Key".to_string()
            } else {
                key_display
            };

            let key_style = if is_selected && state.edit_column == Some(EditColumn::Key) {
                self.key_style.add_modifier(Modifier::REVERSED)
            } else if row.enabled {
                self.key_style
            } else {
                self.disabled_style
            };
            buf.set_string(key_start, y, &key_text, key_style);

            // Divider
            let div_x = key_start + key_width as u16;
            buf.set_string(div_x, y, self.divider, base_style);

            // Value column
            let val_start = div_x + divider_width as u16;
            let val_width = (inner.x + inner.width).saturating_sub(val_start) as usize;
            let val_display: String = row.value.value.chars().take(val_width).collect();
            let val_text = if val_display.is_empty() && !is_selected {
                "Value".to_string()
            } else {
                val_display
            };

            let val_style = if is_selected && state.edit_column == Some(EditColumn::Value) {
                self.value_style.add_modifier(Modifier::REVERSED)
            } else if row.enabled {
                self.value_style
            } else {
                self.disabled_style
            };
            buf.set_string(val_start, y, &val_text, val_style);

            // Show cursor if editing
            if is_selected && state.focused {
                if let Some(edit_col) = state.edit_column {
                    let (cursor_x, cursor_state) = match edit_col {
                        EditColumn::Key => (key_start + row.key.cursor as u16, &row.key),
                        EditColumn::Value => (val_start + row.value.cursor as u16, &row.value),
                    };
                    if cursor_x < inner.x + inner.width {
                        let cursor_char = cursor_state
                            .value
                            .chars()
                            .nth(cursor_state.cursor)
                            .unwrap_or(' ');
                        buf[(cursor_x, y)]
                            .set_char(cursor_char)
                            .set_style(Style::default().bg(Color::White).fg(Color::Black));
                    }
                }
            }
        }

        // Show hint at bottom if there's space
        if visible_rows > state.rows.len() + 1 {
            let hint_y = inner.y + state.rows.len() as u16;
            let hint = if state.edit_column.is_some() {
                "Tab: switch column | Enter: done | Esc: cancel"
            } else {
                "i: edit | o: new row | d: delete | Space: toggle"
            };
            buf.set_string(
                inner.x,
                hint_y,
                hint,
                Style::default().fg(Color::DarkGray),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_value_editor_add_row() {
        let mut state = KeyValueEditorState::new();
        assert_eq!(state.rows.len(), 1);
        state.add_row();
        assert_eq!(state.rows.len(), 2);
        assert_eq!(state.selected_row, 1);
    }

    #[test]
    fn test_key_value_editor_navigation() {
        let mut state = KeyValueEditorState::with_rows(vec![
            KeyValueRow::with_key_value("a", "1"),
            KeyValueRow::with_key_value("b", "2"),
            KeyValueRow::with_key_value("c", "3"),
        ]);
        assert_eq!(state.selected_row, 0);
        state.move_down();
        assert_eq!(state.selected_row, 1);
        state.move_down();
        assert_eq!(state.selected_row, 2);
        state.move_down();
        assert_eq!(state.selected_row, 2); // Can't go past end
        state.move_up();
        assert_eq!(state.selected_row, 1);
    }

    #[test]
    fn test_key_value_editor_to_pairs() {
        let state = KeyValueEditorState::with_rows(vec![
            KeyValueRow::with_key_value("Content-Type", "application/json"),
            KeyValueRow::with_key_value("", "ignored"),
            KeyValueRow::with_key_value("Auth", "Bearer token"),
        ]);
        let pairs = state.to_pairs();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("Content-Type".to_string(), "application/json".to_string()));
        assert_eq!(pairs[1], ("Auth".to_string(), "Bearer token".to_string()));
    }
}
