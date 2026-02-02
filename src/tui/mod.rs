//! Terminal User Interface module
//!
//! Handles all TUI rendering and layout using Ratatui.

mod layout;
mod terminal;
mod theme;
pub mod widgets;

pub use terminal::{Tui, MIN_HEIGHT, MIN_WIDTH};
pub use theme::Theme;

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs},
    Frame,
};

use crate::app::{App, AppMode, Focus, MainTab, ProxyDetailsTab};

/// Safely truncate a string at a character boundary
fn safe_truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    // Find the last valid char boundary at or before max_len
    let mut end = max_len.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Main UI rendering
pub fn render(frame: &mut Frame, app: &App) {
    let state = app.state.read();
    let theme = Theme::default();

    // Check terminal size
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_size_warning(frame, area, &theme);
        return;
    }

    // Main layout: header, body, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/tabs
            Constraint::Min(10),   // Main content
            Constraint::Length(1), // Status bar
        ])
        .split(frame.area());

    // Render header with tabs
    render_header(frame, chunks[0], &state.current_tab, &theme);

    // Render main content based on current tab
    match state.current_tab {
        MainTab::Workspace => render_workspace_view(frame, chunks[1], app, &theme),
        MainTab::Proxy => render_proxy_view(frame, chunks[1], app, &theme),
        MainTab::Scanner => render_scanner_view(frame, chunks[1], app, &theme),
        MainTab::Spider => render_spider_view(frame, chunks[1], app, &theme),
        MainTab::Fuzzer => render_fuzzer_view(frame, chunks[1], app, &theme),
        MainTab::Browser => render_browser_view(frame, chunks[1], app, &theme),
        MainTab::Settings => render_settings_view(frame, chunks[1], app, &theme),
    }

    // Render status bar
    render_status_bar(frame, chunks[2], app, &theme);

    // Render modal dialogs if any
    drop(state); // Release lock before rendering modals
    let state = app.state.read();
    if state.mode == AppMode::Help {
        render_help_dialog(frame, &theme);
    } else if state.mode == AppMode::Command {
        render_command_palette(frame, &theme);
    } else if state.mode == AppMode::ConfirmDelete {
        render_confirm_delete_dialog(frame, app, &theme);
    } else if state.mode == AppMode::Rename {
        render_rename_dialog(frame, app, &theme);
    } else if state.mode == AppMode::BrowserUrl {
        render_browser_url_dialog(frame, app, &theme);
    } else if state.mode == AppMode::ImportFile {
        render_import_file_dialog(frame, app, &theme);
    } else if state.mode == AppMode::EditScannerTarget {
        render_scanner_target_dialog(frame, app, &theme);
    } else if state.mode == AppMode::ProxyDetails {
        drop(state);
        render_proxy_details_dialog(frame, app, &theme);
    } else if state.mode == AppMode::FindingDetails {
        drop(state);
        render_finding_details_dialog(frame, app, &theme);
    }
}

fn render_size_warning(frame: &mut Frame, area: Rect, _theme: &Theme) {
    let msg = format!(
        "Terminal too small: {}x{}\nMinimum required: {}x{}",
        area.width, area.height, MIN_WIDTH, MIN_HEIGHT
    );
    let warning = Paragraph::new(msg)
        .style(Style::default().fg(Color::Red))
        .block(Block::default().borders(Borders::ALL).title(" Warning "));
    frame.render_widget(warning, area);
}

fn render_header(frame: &mut Frame, area: Rect, current_tab: &MainTab, theme: &Theme) {
    // Show numbered shortcuts: "1:Workspace", "2:Proxy", etc.
    let titles: Vec<String> = MainTab::all()
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{}:{}", i + 1, t.name()))
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .title(Span::styled(" Ancarna ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)))
                .title_style(Style::default().fg(theme.accent)),
        )
        .style(Style::default().fg(theme.muted))
        .highlight_style(Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
        .select(current_tab.index())
        .divider(Span::styled(" │ ", Style::default().fg(theme.border)));

    frame.render_widget(tabs, area);
}

/// Render the workspace view (collections, request, response)
fn render_workspace_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let state = app.state.read();

    // Layout: URL bar at top, then three columns
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // URL bar
            Constraint::Min(5),    // Main panels
        ])
        .split(area);

    // Render URL bar
    render_url_bar(frame, vertical[0], app, theme);

    // Three-column layout for panels
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // Collections
            Constraint::Percentage(40), // Request
            Constraint::Percentage(40), // Response
        ])
        .split(vertical[1]);

    render_collections_panel(frame, columns[0], app, state.focus == Focus::Workspace, theme);
    render_request_panel(frame, columns[1], app, state.focus == Focus::RequestEditor, theme);
    render_response_panel(frame, columns[2], app, state.focus == Focus::ResponseViewer, theme);
}

fn render_url_bar(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    use crate::app::AppMode;
    let state = app.state.read();

    let is_editing = state.mode == AppMode::EditUrl;

    // Get environment name
    let env_name = if state.selected_environment == 0 {
        "No Env".to_string()
    } else {
        let envs = app.workspace.environments();
        envs.get(state.selected_environment - 1)
            .map(|e| e.name.clone())
            .unwrap_or_else(|| "No Env".to_string())
    };

    let method_style = Style::default()
        .fg(method_color(&state.request_method))
        .add_modifier(Modifier::BOLD);

    let url_display = if state.url_input.is_empty() {
        if is_editing {
            Span::styled("", Style::default())
        } else {
            Span::styled("Enter URL (press 'e' to edit)", Style::default().fg(theme.muted))
        }
    } else {
        Span::styled(&state.url_input, Style::default().fg(theme.fg))
    };

    // Cursor for edit mode
    let cursor = if is_editing {
        Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK))
    } else {
        Span::raw("")
    };

    let right_indicator = if state.is_loading {
        Span::styled(" ⟳ Sending... ", Style::default().fg(Color::Yellow))
    } else if is_editing {
        Span::styled(" ESC:cancel ", Style::default().fg(theme.muted))
    } else {
        Span::styled(" ⏎ Send ", Style::default().fg(theme.muted))
    };

    // Environment indicator
    let env_style = if state.selected_environment == 0 {
        Style::default().fg(theme.muted)
    } else {
        Style::default().fg(theme.success)
    };

    let content = Line::from(vec![
        Span::styled(format!(" {} ", state.request_method), method_style),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::raw(" "),
        url_display,
        cursor,
        Span::raw(" "),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::styled(format!(" {} ", env_name), env_style),
        right_indicator,
    ]);

    let border_style = if is_editing {
        Style::default().fg(theme.accent)
    } else {
        Style::default().fg(theme.border)
    };

    let title = if is_editing {
        " Request [EDITING] "
    } else {
        " Request "
    };

    let url_bar = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(title),
        );

    frame.render_widget(url_bar, area);

    // Render environment selector popup if open
    if state.env_selector_open {
        drop(state);
        render_env_selector_popup(frame, app, theme);
    }
}

fn render_env_selector_popup(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();
    let envs = app.workspace.environments();

    let area = centered_rect(40, 50, frame.area());

    let mut items = vec![Line::from(vec![
        if state.selected_environment == 0 {
            Span::styled("▸ ", Style::default().fg(theme.accent))
        } else {
            Span::raw("  ")
        },
        Span::styled("No Environment", if state.selected_environment == 0 {
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.fg)
        }),
    ])];

    for (i, env) in envs.iter().enumerate() {
        let is_selected = state.selected_environment == i + 1;
        items.push(Line::from(vec![
            if is_selected {
                Span::styled("▸ ", Style::default().fg(theme.accent))
            } else {
                Span::raw("  ")
            },
            Span::styled(&env.name, if is_selected {
                Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.fg)
            }),
            Span::styled(format!(" ({} vars)", env.variables.len()), Style::default().fg(theme.muted)),
        ]));
    }

    items.push(Line::from(""));
    items.push(Line::from(Span::styled(
        "j/k:select  Enter:confirm  Esc:cancel",
        Style::default().fg(theme.muted),
    )));

    let popup = Paragraph::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .title(" Select Environment "),
        );

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(popup, area);
}

fn render_collections_panel(frame: &mut Frame, area: Rect, app: &App, focused: bool, theme: &Theme) {
    use crate::app::CollectionItemType;

    let border_style = if focused {
        Style::default().fg(theme.accent)
    } else {
        Style::default().fg(theme.border)
    };

    let state = app.state.read();

    // Get flattened collection items for navigation
    let nav_items = app.get_collection_items();

    // Build collection tree display
    let mut lines = Vec::new();

    if nav_items.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Welcome to Ancarna!",
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  No collections yet",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Quick Start:",
            Style::default().fg(theme.fg),
        )));
        lines.push(Line::from(Span::styled(
            "  • Press 'l' to go to request editor",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  • Enter a URL and press Enter to send",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  • Press '?' for keyboard help",
            Style::default().fg(theme.muted),
        )));
    } else {
        for (idx, item) in nav_items.iter().enumerate() {
            let is_selected = idx == state.selected_collection_item;
            let indent = "  ".repeat(item.depth);

            let line = match item.item_type {
                CollectionItemType::Collection => {
                    let prefix = if is_selected { "▸" } else { "▾" };
                    let style = if is_selected {
                        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)
                    };
                    Line::from(Span::styled(format!("{}{} {}", indent, prefix, item.name), style))
                }
                CollectionItemType::Folder => {
                    let prefix = if is_selected { "▸" } else { " " };
                    let style = if is_selected {
                        Style::default().fg(theme.accent)
                    } else {
                        Style::default().fg(theme.fg)
                    };
                    Line::from(Span::styled(format!("{}{}📁 {}", indent, prefix, item.name), style))
                }
                CollectionItemType::Request => {
                    let prefix = if is_selected { "▸" } else { " " };
                    let method = item.request.as_ref().map(|r| r.method.as_str()).unwrap_or("???");
                    let m_color = method_color(method);

                    let _bg = if is_selected {
                        Some(theme.accent)
                    } else {
                        None
                    };

                    let mut spans = vec![
                        Span::raw(format!("{}{}", indent, prefix)),
                    ];

                    if is_selected {
                        spans.push(Span::styled(
                            format!("{:6}", method),
                            Style::default().fg(Color::Black).bg(theme.accent),
                        ));
                        spans.push(Span::styled(
                            format!(" {}", item.name),
                            Style::default().fg(Color::Black).bg(theme.accent),
                        ));
                    } else {
                        spans.push(Span::styled(
                            format!("{:6}", method),
                            Style::default().fg(m_color),
                        ));
                        spans.push(Span::styled(
                            format!(" {}", item.name),
                            Style::default().fg(theme.muted),
                        ));
                    }

                    Line::from(spans)
                }
            };
            lines.push(line);
        }

        // Clamp selected index
        let max_idx = nav_items.len().saturating_sub(1);
        if state.selected_collection_item > max_idx {
            // Note: Can't modify state here, but we'll handle it in the key handler
        }
    }

    // Add history section if there are history items
    if !state.request_history.is_empty() {
        lines.push(Line::from(""));
        let history_header_style = if state.history_focused {
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.muted)
        };
        lines.push(Line::from(Span::styled(
            if state.history_focused { "  ─── History (active) ───" } else { "  ─── History ───" },
            history_header_style,
        )));

        // Show history items (most recent first)
        let display_count = if state.history_focused { 10 } else { 5 };
        for (i, entry) in state.request_history.iter().rev().take(display_count).enumerate() {
            let method = &entry.method;
            let m_color = method_color(method);
            let is_selected = state.history_focused && i == state.selected_history_item;

            // Parse URL to show just path
            let display_url = if let Ok(parsed) = url::Url::parse(&entry.url) {
                parsed.path().to_string()
            } else {
                entry.url.clone()
            };

            // Truncate URL if too long
            let max_url_len = 25;
            let truncated_url = if display_url.len() > max_url_len {
                safe_truncate(&display_url, max_url_len)
            } else {
                display_url
            };

            let status_str = entry
                .status
                .map(|s| format!("{}", s))
                .unwrap_or_else(|| "ERR".to_string());

            let status_color = entry.status.map(|s| {
                if s < 300 { theme.success }
                else if s < 400 { Color::Yellow }
                else { theme.error }
            }).unwrap_or(theme.error);

            let prefix = if is_selected { "▸ " } else { "  " };

            if is_selected {
                lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(theme.accent)),
                    Span::styled(format!("{} ", method), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(truncated_url, Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(" ", Style::default().bg(theme.accent)),
                    Span::styled(status_str, Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(format!(" {}ms", entry.duration_ms), Style::default().fg(Color::Black).bg(theme.accent)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw(prefix),
                    Span::styled(format!("{} ", method), Style::default().fg(m_color)),
                    Span::styled(truncated_url, Style::default().fg(theme.fg)),
                    Span::raw(" "),
                    Span::styled(status_str, Style::default().fg(status_color)),
                    Span::styled(format!(" {}ms", entry.duration_ms), Style::default().fg(theme.muted)),
                ]));
            }
        }

        if state.request_history.len() > display_count {
            lines.push(Line::from(Span::styled(
                format!("  ... and {} more (H:toggle)", state.request_history.len() - display_count),
                Style::default().fg(theme.muted),
            )));
        }

        if state.history_focused {
            lines.push(Line::from(Span::styled(
                "  j/k:nav  Enter:load  H:back",
                Style::default().fg(theme.muted),
            )));
        }
    }

    let visible_height = area.height.saturating_sub(2) as usize;
    let total_lines = lines.len();
    let scroll_offset = state.collection_scroll.min(total_lines.saturating_sub(visible_height));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(" Collections ", Style::default().fg(if focused { theme.accent } else { theme.fg })));

    let content = Paragraph::new(lines)
        .block(block)
        .scroll((scroll_offset as u16, 0));

    frame.render_widget(content, area);

    // Render scrollbar if needed
    if total_lines > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut scrollbar_state = ScrollbarState::new(total_lines)
            .position(scroll_offset);

        let scrollbar_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 1,
            width: 1,
            height: area.height - 2,
        };
        frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
    }
}

fn render_request_panel(frame: &mut Frame, area: Rect, app: &App, focused: bool, theme: &Theme) {
    use crate::app::RequestEditorTab;

    let border_style = if focused {
        Style::default().fg(theme.accent)
    } else {
        Style::default().fg(theme.border)
    };

    let state = app.state.read();

    // Main block
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(" Request ", Style::default().fg(if focused { theme.accent } else { theme.fg })));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.height < 4 {
        return;
    }

    // Layout: tabs (1 line), content (rest)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Tabs
            Constraint::Min(1),    // Content
        ])
        .split(inner);

    // Render tabs
    let tabs: Vec<Span> = RequestEditorTab::all()
        .iter()
        .map(|tab| {
            let is_active = *tab == state.request_editor_tab;
            if is_active {
                Span::styled(
                    format!(" {} ", tab.name()),
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD).add_modifier(Modifier::UNDERLINED),
                )
            } else {
                Span::styled(
                    format!(" {} ", tab.name()),
                    Style::default().fg(theme.muted),
                )
            }
        })
        .collect();

    let tab_line = Line::from(tabs);
    frame.render_widget(Paragraph::new(tab_line), chunks[0]);

    // Render content based on active tab
    let content_area = chunks[1];

    match state.request_editor_tab {
        RequestEditorTab::Params => {
            render_params_tab(frame, content_area, &state, theme);
        }
        RequestEditorTab::Headers => {
            render_headers_tab(frame, content_area, &state, theme);
        }
        RequestEditorTab::Body => {
            render_body_tab(frame, content_area, &state, theme);
        }
        RequestEditorTab::Auth => {
            render_auth_tab(frame, content_area, &state, theme);
        }
    }
}

fn render_params_tab(frame: &mut Frame, area: Rect, state: &crate::app::AppState, theme: &Theme) {
    use crate::app::AppMode;
    use crate::tui::widgets::EditColumn;

    let mut lines = Vec::new();
    let is_editing = state.mode == AppMode::EditKeyValue;

    lines.push(Line::from(Span::styled(
        "Query Parameters",
        Style::default().fg(theme.muted),
    )));
    lines.push(Line::from(""));

    // Always show rows, including empty placeholder row
    for (i, row) in state.query_params.rows.iter().enumerate() {
        let is_selected = i == state.query_params.selected_row;
        let checkbox = if row.enabled { "[x]" } else { "[ ]" };

        // Determine styles based on editing state
        let (key_style, val_style, row_bg) = if is_editing && is_selected {
            let key_editing = state.query_params.edit_column == Some(EditColumn::Key);
            let val_editing = state.query_params.edit_column == Some(EditColumn::Value);
            (
                if key_editing {
                    Style::default().fg(Color::Black).bg(theme.accent)
                } else {
                    Style::default().fg(theme.info)
                },
                if val_editing {
                    Style::default().fg(Color::Black).bg(theme.accent)
                } else {
                    Style::default().fg(theme.fg)
                },
                Some(Color::DarkGray),
            )
        } else if is_selected && is_editing {
            (
                Style::default().fg(theme.info),
                Style::default().fg(theme.fg),
                Some(Color::DarkGray),
            )
        } else {
            (
                Style::default().fg(theme.info),
                Style::default().fg(theme.fg),
                None,
            )
        };

        let checkbox_style = if let Some(bg) = row_bg {
            Style::default().bg(bg)
        } else {
            Style::default()
        };

        // Selection indicator
        let indicator = if is_selected && is_editing { "▸" } else { " " };

        let key_display = if row.key.value.is_empty() {
            "key".to_string()
        } else {
            row.key.value.clone()
        };
        let val_display = if row.value.value.is_empty() {
            "value".to_string()
        } else {
            row.value.value.clone()
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{} {} ", indicator, checkbox), checkbox_style),
            Span::styled(key_display, key_style),
            Span::styled(" = ", Style::default().fg(theme.muted)),
            Span::styled(val_display, val_style),
        ]));
    }

    lines.push(Line::from(""));
    let hint = if is_editing {
        "  j/k:nav  i:edit  Tab:column  o:add  d:del  Esc:done"
    } else {
        "  i:edit  o:add  d:delete  Space:toggle"
    };
    lines.push(Line::from(Span::styled(hint, Style::default().fg(theme.muted))));

    let content = Paragraph::new(lines);
    frame.render_widget(content, area);
}

fn render_headers_tab(frame: &mut Frame, area: Rect, state: &crate::app::AppState, theme: &Theme) {
    use crate::app::AppMode;
    use crate::tui::widgets::EditColumn;

    let mut lines = Vec::new();
    let is_editing = state.mode == AppMode::EditKeyValue;

    lines.push(Line::from(Span::styled(
        "Request Headers",
        Style::default().fg(theme.muted),
    )));
    lines.push(Line::from(""));

    // Always show rows, including empty placeholder row
    for (i, row) in state.headers.rows.iter().enumerate() {
        let is_selected = i == state.headers.selected_row;
        let checkbox = if row.enabled { "[x]" } else { "[ ]" };

        // Determine styles based on editing state
        let (key_style, val_style, row_bg) = if is_editing && is_selected {
            let key_editing = state.headers.edit_column == Some(EditColumn::Key);
            let val_editing = state.headers.edit_column == Some(EditColumn::Value);
            (
                if key_editing {
                    Style::default().fg(Color::Black).bg(theme.accent)
                } else {
                    Style::default().fg(theme.info)
                },
                if val_editing {
                    Style::default().fg(Color::Black).bg(theme.accent)
                } else {
                    Style::default().fg(theme.fg)
                },
                Some(Color::DarkGray),
            )
        } else if is_selected && is_editing {
            (
                Style::default().fg(theme.info),
                Style::default().fg(theme.fg),
                Some(Color::DarkGray),
            )
        } else {
            (
                Style::default().fg(theme.info),
                Style::default().fg(theme.fg),
                None,
            )
        };

        let checkbox_style = if let Some(bg) = row_bg {
            Style::default().bg(bg)
        } else {
            Style::default()
        };

        // Selection indicator
        let indicator = if is_selected && is_editing { "▸" } else { " " };

        let key_display = if row.key.value.is_empty() {
            "Header-Name".to_string()
        } else {
            row.key.value.clone()
        };

        // Mask sensitive values when not editing
        let val_display = if row.value.value.is_empty() {
            "value".to_string()
        } else if !is_editing && (row.key.value.to_lowercase().contains("auth")
            || row.key.value.to_lowercase().contains("token")
            || row.key.value.to_lowercase().contains("key")
            || row.key.value.to_lowercase().contains("secret"))
        {
            "••••••••".to_string()
        } else {
            row.value.value.clone()
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{} {} ", indicator, checkbox), checkbox_style),
            Span::styled(key_display, key_style),
            Span::styled(": ", Style::default().fg(theme.muted)),
            Span::styled(val_display, val_style),
        ]));
    }

    lines.push(Line::from(""));
    let hint = if is_editing {
        "  j/k:nav  i:edit  Tab:column  o:add  d:del  Esc:done"
    } else {
        "  i:edit  o:add  d:delete  Space:toggle"
    };
    lines.push(Line::from(Span::styled(hint, Style::default().fg(theme.muted))));

    let content = Paragraph::new(lines);
    frame.render_widget(content, area);
}

fn render_body_tab(frame: &mut Frame, area: Rect, state: &crate::app::AppState, theme: &Theme) {
    use crate::app::{AppMode, BodyContentType};

    let mut lines = Vec::new();
    let is_editing = state.mode == AppMode::EditBody;

    // Content type selector
    let type_names = ["none", "json", "form", "multipart", "raw"];
    let type_line: Vec<Span> = type_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let is_selected = matches!(
                (i, state.body_content_type),
                (0, BodyContentType::None)
                    | (1, BodyContentType::Json)
                    | (2, BodyContentType::FormUrlEncoded)
                    | (3, BodyContentType::FormData)
                    | (4, BodyContentType::Raw)
            );
            if is_selected {
                Span::styled(format!("[{}]", name), Style::default().fg(theme.accent))
            } else {
                Span::styled(format!(" {} ", name), Style::default().fg(theme.muted))
            }
        })
        .collect();

    lines.push(Line::from(type_line));
    lines.push(Line::from(""));

    if state.body_content.is_empty() && !is_editing {
        lines.push(Line::from(Span::styled(
            "  No body content",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Press 'i' to edit body",
            Style::default().fg(theme.muted),
        )));
    } else {
        // Show body with syntax highlighting for JSON
        let display_content = if is_editing {
            // Show cursor in edit mode
            format!("{}█", state.body_content)
        } else {
            state.body_content.clone()
        };

        let formatted = format_json_body(&display_content);
        let max_lines = area.height.saturating_sub(4) as usize;
        for line in formatted.lines().take(max_lines) {
            if is_editing {
                // In edit mode, just show the text without JSON highlighting
                lines.push(Line::from(Span::raw(format!("  {}", line))));
            } else {
                lines.push(colorize_json_line(&format!("  {}", line), theme));
            }
        }
        if formatted.lines().count() > max_lines {
            lines.push(Line::from(Span::styled(
                "  ... (scroll for more)",
                Style::default().fg(theme.muted),
            )));
        }
    }

    lines.push(Line::from(""));
    let hint = if is_editing {
        "  Type to edit | Esc:done"
    } else {
        "  i:edit  Tab:type"
    };
    lines.push(Line::from(Span::styled(hint, Style::default().fg(theme.muted))));

    let content = Paragraph::new(lines);
    frame.render_widget(content, area);
}

fn render_auth_tab(frame: &mut Frame, area: Rect, state: &crate::app::AppState, theme: &Theme) {
    use crate::app::AuthType;

    let mut lines = Vec::new();

    // Auth type selector
    lines.push(Line::from(Span::styled("Authentication Type", Style::default().fg(theme.muted))));
    lines.push(Line::from(""));

    let type_line: Vec<Span> = AuthType::all()
        .iter()
        .map(|t| {
            if *t == state.auth_type {
                Span::styled(format!("[{}]", t.name()), Style::default().fg(theme.accent))
            } else {
                Span::styled(format!(" {} ", t.name()), Style::default().fg(theme.muted))
            }
        })
        .collect();
    lines.push(Line::from(type_line));
    lines.push(Line::from(""));

    // Show auth-specific fields
    match state.auth_type {
        AuthType::None => {
            lines.push(Line::from(Span::styled(
                "  No authentication configured",
                Style::default().fg(theme.muted),
            )));
        }
        AuthType::Basic => {
            lines.push(Line::from(Span::styled("  Basic Authentication", Style::default().fg(theme.fg))));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Username: ", Style::default().fg(theme.info)),
                Span::styled(
                    if state.auth_username.is_empty() { "(not set)" } else { &state.auth_username },
                    Style::default().fg(theme.fg),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Password: ", Style::default().fg(theme.info)),
                Span::styled(
                    if state.auth_password.is_empty() { "(not set)" } else { "••••••••" },
                    Style::default().fg(theme.fg),
                ),
            ]));
        }
        AuthType::Bearer => {
            lines.push(Line::from(Span::styled("  Bearer Token", Style::default().fg(theme.fg))));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Token: ", Style::default().fg(theme.info)),
                Span::styled(
                    if state.auth_token.is_empty() { "(not set)" } else { "••••••••" },
                    Style::default().fg(theme.fg),
                ),
            ]));
        }
        AuthType::ApiKey => {
            lines.push(Line::from(Span::styled("  API Key", Style::default().fg(theme.fg))));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  Key Name: ", Style::default().fg(theme.info)),
                Span::styled(
                    if state.auth_api_key_name.is_empty() { "(not set)" } else { &state.auth_api_key_name },
                    Style::default().fg(theme.fg),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Key Value: ", Style::default().fg(theme.info)),
                Span::styled(
                    if state.auth_api_key_value.is_empty() { "(not set)" } else { "••••••••" },
                    Style::default().fg(theme.fg),
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled("  Location: ", Style::default().fg(theme.info)),
                Span::styled(
                    match state.auth_api_key_location {
                        crate::app::ApiKeyLocation::Header => "Header",
                        crate::app::ApiKeyLocation::Query => "Query Parameter",
                    },
                    Style::default().fg(theme.fg),
                ),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Tab:cycle type  i:edit fields",
        Style::default().fg(theme.muted),
    )));

    let content = Paragraph::new(lines);
    frame.render_widget(content, area);
}

fn render_response_panel(frame: &mut Frame, area: Rect, app: &App, focused: bool, theme: &Theme) {
    use crate::app::ResponseTab;

    let border_style = if focused {
        Style::default().fg(theme.accent)
    } else {
        Style::default().fg(theme.border)
    };

    let state = app.state.read();
    let mut lines = Vec::new();

    if let Some(response) = &state.current_response {
        // Status line
        let status_color = status_color(response.status);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{}", response.status),
                Style::default().fg(status_color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(&response.status_text, Style::default().fg(status_color)),
            Span::styled(" • ", Style::default().fg(theme.border)),
            Span::styled(format!("{}ms", response.duration_ms), Style::default().fg(theme.muted)),
            Span::styled(" • ", Style::default().fg(theme.border)),
            Span::styled(format_size(response.size), Style::default().fg(theme.muted)),
        ]));

        // Tab bar
        let tab_line: Vec<Span> = ResponseTab::all()
            .iter()
            .map(|tab| {
                if *tab == state.response_tab {
                    Span::styled(
                        format!(" [{}] ", tab.name()),
                        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled(
                        format!("  {}  ", tab.name()),
                        Style::default().fg(theme.muted),
                    )
                }
            })
            .collect();
        lines.push(Line::from(tab_line));
        lines.push(Line::from(Span::styled(
            "─".repeat(area.width.saturating_sub(4) as usize),
            Style::default().fg(theme.border),
        )));

        // Content based on selected tab
        match state.response_tab {
            ResponseTab::Body => {
                if response.body.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "  (empty response body)",
                        Style::default().fg(theme.muted),
                    )));
                } else if state.response_raw_mode {
                    // Raw mode - no formatting
                    for line in response.body.lines() {
                        lines.push(Line::from(Span::raw(line)));
                    }
                } else {
                    // Formatted mode
                    let formatted = format_json_body(&response.body);
                    for line in formatted.lines() {
                        lines.push(colorize_json_line(line, theme));
                    }
                }

                // Show search results if any
                if !state.response_search.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        format!(
                            "  Search: \"{}\" ({} matches)",
                            state.response_search,
                            state.response_search_matches.len()
                        ),
                        Style::default().fg(theme.info),
                    )));
                }
            }
            ResponseTab::Headers => {
                lines.push(Line::from(Span::styled(
                    format!("  {} headers", response.headers.len()),
                    Style::default().fg(theme.muted),
                )));
                lines.push(Line::from(""));

                let mut sorted_headers: Vec<_> = response.headers.iter().collect();
                sorted_headers.sort_by(|a, b| a.0.cmp(b.0));

                for (key, value) in sorted_headers {
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {}", key), Style::default().fg(theme.info)),
                        Span::styled(": ", Style::default().fg(theme.muted)),
                        Span::raw(value.to_string()),
                    ]));
                }
            }
            ResponseTab::Cookies => {
                // Extract cookies from headers
                let cookies: Vec<&str> = response
                    .headers
                    .iter()
                    .filter(|(k, _)| k.to_lowercase() == "set-cookie")
                    .map(|(_, v)| v.as_str())
                    .collect();

                if cookies.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "  No cookies in response",
                        Style::default().fg(theme.muted),
                    )));
                } else {
                    lines.push(Line::from(Span::styled(
                        format!("  {} cookies", cookies.len()),
                        Style::default().fg(theme.muted),
                    )));
                    lines.push(Line::from(""));

                    for cookie in cookies {
                        // Parse cookie name=value
                        if let Some((name_val, _attrs)) = cookie.split_once(';') {
                            if let Some((name, value)) = name_val.split_once('=') {
                                lines.push(Line::from(vec![
                                    Span::styled(format!("  {}", name.trim()), Style::default().fg(theme.info)),
                                    Span::styled(" = ", Style::default().fg(theme.muted)),
                                    Span::raw(value.trim()),
                                ]));
                            }
                        } else {
                            lines.push(Line::from(Span::raw(format!("  {}", cookie))));
                        }
                    }
                }
            }
        }

        // Keyboard hints
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  [/]:tabs  /:search  y:copy  r:raw/pretty",
            Style::default().fg(theme.muted),
        )));
    } else if state.is_loading {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  ⟳ Sending request...",
            Style::default().fg(Color::Yellow),
        )));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  No response yet",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  To send a request:",
            Style::default().fg(theme.fg),
        )));
        lines.push(Line::from(Span::styled(
            "  1. Press 'e' to edit URL",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  2. Type the URL",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  3. Press Enter to send",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Shortcuts:",
            Style::default().fg(theme.fg),
        )));
        lines.push(Line::from(Span::styled(
            "  • 'm' - change HTTP method",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  • 'n' - new request",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  • 'I' - import from clipboard",
            Style::default().fg(theme.muted),
        )));
        lines.push(Line::from(Span::styled(
            "  • 'E' - select environment",
            Style::default().fg(theme.muted),
        )));
    }

    let visible_height = area.height.saturating_sub(2) as usize;
    let total_lines = lines.len();
    let scroll_offset = state.response_scroll.min(total_lines.saturating_sub(visible_height));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(Span::styled(" Response ", Style::default().fg(if focused { theme.accent } else { theme.fg })));

    let content = Paragraph::new(lines)
        .block(block)
        .scroll((scroll_offset as u16, 0));

    frame.render_widget(content, area);

    // Render scrollbar if needed
    if total_lines > visible_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut scrollbar_state = ScrollbarState::new(total_lines)
            .position(scroll_offset);

        let scrollbar_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 1,
            width: 1,
            height: area.height - 2,
        };
        frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
    }
}

/// Render proxy history view
fn render_proxy_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let state = app.state.read();
    let proxy_port = app.config.proxy.default_port;
    let proxy_addr = format!("127.0.0.1:{}", proxy_port);

    // Split area: status bar at top, history list, details at bottom if enabled
    let chunks = if state.show_proxy_details && !state.proxy_history.is_empty() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Status bar
                Constraint::Min(10),    // History list
                Constraint::Length(10), // Details panel
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Status bar
                Constraint::Min(10),    // History list
            ])
            .split(area)
    };

    // Status bar - show proxy server history count (direct from proxy object)
    let proxy_history_count = app.proxy.as_ref().map(|p| p.history().get_all().len()).unwrap_or(0);

    let proxy_status = if state.proxy_running {
        Span::styled(format!("● Proxy: {} [srv:{}/ui:{}] ", proxy_addr, proxy_history_count, state.proxy_history.len()), Style::default().fg(theme.success))
    } else {
        Span::styled("○ Proxy stopped ", Style::default().fg(theme.muted))
    };

    // Pre-filter count for display
    let filter = state.proxy_filter.to_lowercase();
    let filtered_count = if filter.is_empty() {
        state.proxy_history.len()
    } else {
        state.proxy_history.iter()
            .filter(|entry| {
                entry.host.to_lowercase().contains(&filter)
                    || entry.url.to_lowercase().contains(&filter)
                    || entry.method.to_lowercase().contains(&filter)
                    || entry.path.to_lowercase().contains(&filter)
                    || entry.status.map(|s| s.to_string().contains(&filter)).unwrap_or(false)
            })
            .count()
    };

    let title = if state.proxy_filter.is_empty() {
        format!(" Proxy ({} requests) ", state.proxy_history.len())
    } else {
        format!(" Proxy ({}/{} filtered) ", filtered_count, state.proxy_history.len())
    };

    let status_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(title);

    // Intercept status
    let intercept_status = if state.intercept_enabled {
        Span::styled(" [INTERCEPT ON] ", Style::default().fg(Color::Black).bg(Color::Yellow))
    } else {
        Span::styled(" I:intercept ", Style::default().fg(theme.muted))
    };

    let is_filtering = state.mode == crate::app::AppMode::FilterProxy;
    let filter_display = if is_filtering {
        Line::from(vec![
            Span::raw("  "),
            proxy_status,
            Span::raw("  "),
            intercept_status,
            Span::raw("  "),
            Span::styled("Filter: ", Style::default().fg(theme.accent)),
            Span::styled(&state.proxy_filter, Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK)),
            Span::styled(" (Enter:apply  Esc:cancel)", Style::default().fg(theme.muted)),
        ])
    } else {
        Line::from(vec![
            Span::raw("  "),
            proxy_status,
            Span::raw("  "),
            intercept_status,
            Span::raw("  "),
            Span::styled(
                format!("Filter: {} ", if state.proxy_filter.is_empty() { "<none>" } else { &state.proxy_filter }),
                Style::default().fg(theme.muted)
            ),
        ])
    };

    let status_content = Paragraph::new(filter_display).block(status_block);
    frame.render_widget(status_content, chunks[0]);

    // History list
    let history_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if state.focus == Focus::ProxyHistory { theme.accent } else { theme.border }))
        .title(" History (j/k:nav  d:details  /:filter) ");

    if state.proxy_history.is_empty() {
        let empty_msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No requests captured yet", Style::default().fg(theme.muted))),
            Line::from(""),
            Line::from(Span::styled("  1. Configure browser proxy:", Style::default().fg(theme.fg))),
            Line::from(Span::styled(format!("     HTTP/HTTPS Proxy: {}", proxy_addr), Style::default().fg(theme.info))),
            Line::from(""),
            Line::from(Span::styled("  2. For HTTPS, install CA certificate:", Style::default().fg(theme.fg))),
            Line::from(Span::styled("     ~/.ancarna/ca.crt", Style::default().fg(theme.info))),
            Line::from(""),
            Line::from(Span::styled("  3. Or use curl:", Style::default().fg(theme.fg))),
            Line::from(Span::styled(format!("     curl -x {} -k https://example.com", proxy_addr), Style::default().fg(theme.info))),
            Line::from(""),
            Line::from(Span::styled("  Keys: C=install cert  I=intercept  d=details  /=filter", Style::default().fg(theme.muted))),
        ])
        .block(history_block);
        frame.render_widget(empty_msg, chunks[1]);
    } else {
        // Filter history entries with regex support and !pattern for exclusion
        let filter = &state.proxy_filter;

        // Parse filter into include and exclude patterns
        let mut include_patterns: Vec<regex::Regex> = Vec::new();
        let mut exclude_patterns: Vec<regex::Regex> = Vec::new();

        for part in filter.split_whitespace() {
            if let Some(pattern) = part.strip_prefix('!') {
                if !pattern.is_empty() {
                    if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex::escape(pattern))) {
                        exclude_patterns.push(re);
                    }
                }
            } else if !part.is_empty() {
                if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex::escape(part))) {
                    include_patterns.push(re);
                }
            }
        }

        let filtered_entries: Vec<_> = state.proxy_history.iter().enumerate()
            .filter(|(_, entry)| {
                if filter.is_empty() {
                    return true;
                }

                let searchable = format!("{} {} {} {} {}",
                    entry.host, entry.url, entry.method, entry.path,
                    entry.status.map(|s| s.to_string()).unwrap_or_default());

                // Check exclusions first
                for re in &exclude_patterns {
                    if re.is_match(&searchable) {
                        return false;
                    }
                }

                // Check inclusions (if any patterns specified)
                if include_patterns.is_empty() {
                    true
                } else {
                    include_patterns.iter().any(|re| re.is_match(&searchable))
                }
            })
            .collect();

        // Build history list as lines (simpler than table for now)
        let mut lines = Vec::new();

        for (display_idx, (_original_idx, entry)) in filtered_entries.iter().enumerate() {
            let is_selected = display_idx == state.selected_proxy_item && state.focus == Focus::ProxyHistory;
            let m_color = method_color(&entry.method);

            let status_str = entry.status.map(|s| format!("{}", s)).unwrap_or_else(|| "...".to_string());
            let status_color = entry.status.map(|s| {
                if s < 300 { theme.success }
                else if s < 400 { Color::Yellow }
                else { theme.error }
            }).unwrap_or(theme.muted);

            let size_str = entry.response_size.map(format_size).unwrap_or_else(|| "-".to_string());
            let time_str = entry.duration_ms.map(|t| format!("{}ms", t)).unwrap_or_else(|| "-".to_string());

            // Truncate path for display
            let path_display = if entry.path.len() > 25 {
                safe_truncate(&entry.path, 22)
            } else {
                entry.path.clone()
            };

            let prefix = if is_selected { "▸ " } else { "  " };

            if is_selected {
                lines.push(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(theme.accent)),
                    Span::styled(format!("{:4} ", entry.id), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(format!("{:7} ", entry.method), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(format!("{:20} ", if entry.host.len() > 20 { safe_truncate(&entry.host, 17) } else { entry.host.clone() }), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(format!("{:25} ", path_display), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(format!("{:4} ", status_str), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(format!("{:8} ", size_str), Style::default().fg(Color::Black).bg(theme.accent)),
                    Span::styled(time_str, Style::default().fg(Color::Black).bg(theme.accent)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::raw(prefix),
                    Span::styled(format!("{:4} ", entry.id), Style::default().fg(theme.muted)),
                    Span::styled(format!("{:7} ", entry.method), Style::default().fg(m_color)),
                    Span::styled(format!("{:20} ", if entry.host.len() > 20 { safe_truncate(&entry.host, 17) } else { entry.host.clone() }), Style::default().fg(theme.fg)),
                    Span::styled(format!("{:25} ", path_display), Style::default().fg(theme.fg)),
                    Span::styled(format!("{:4} ", status_str), Style::default().fg(status_color)),
                    Span::styled(format!("{:8} ", size_str), Style::default().fg(theme.muted)),
                    Span::styled(time_str, Style::default().fg(theme.muted)),
                ]));
            }
        }

        let history_content = Paragraph::new(lines)
            .block(history_block)
            .scroll((state.proxy_history_scroll as u16, 0));

        frame.render_widget(history_content, chunks[1]);
    }

    // Details panel (if enabled and has selection)
    if state.show_proxy_details && !state.proxy_history.is_empty() && chunks.len() > 2 {
        if let Some(entry) = state.proxy_history.get(state.selected_proxy_item) {
            // Split details area into request and response sections
            let detail_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(chunks[2]);

            // Request details block
            let request_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(" Request ");

            let protocol = if entry.is_https { "HTTPS" } else { "HTTP" };
            let mut request_lines = vec![
                Line::from(vec![
                    Span::styled(format!("{} ", entry.method), Style::default().fg(theme.accent).add_modifier(ratatui::style::Modifier::BOLD)),
                    Span::styled(&entry.path, Style::default().fg(theme.fg)),
                    Span::styled(format!(" {}", protocol), Style::default().fg(theme.muted)),
                ]),
                Line::from(vec![
                    Span::styled("Host: ", Style::default().fg(theme.muted)),
                    Span::styled(&entry.host, Style::default().fg(theme.info)),
                ]),
            ];

            // Show request headers
            if !entry.request_headers.is_empty() {
                request_lines.push(Line::from(""));
                request_lines.push(Line::from(Span::styled("Headers:", Style::default().fg(theme.muted))));
                let mut sorted_headers: Vec<_> = entry.request_headers.iter().collect();
                sorted_headers.sort_by_key(|(k, _)| k.as_str());
                for (key, value) in sorted_headers.iter().take(6) {
                    let display_value = if value.len() > 40 {
                        safe_truncate(value, 40)
                    } else {
                        value.to_string()
                    };
                    request_lines.push(Line::from(vec![
                        Span::styled(format!("  {}: ", key), Style::default().fg(theme.muted)),
                        Span::styled(display_value, Style::default().fg(theme.fg)),
                    ]));
                }
                if entry.request_headers.len() > 6 {
                    request_lines.push(Line::from(Span::styled(
                        format!("  ... ({} more)", entry.request_headers.len() - 6),
                        Style::default().fg(theme.muted),
                    )));
                }
            }

            // Show request body if present
            if let Some(body) = &entry.request_body {
                request_lines.push(Line::from(""));
                request_lines.push(Line::from(Span::styled("Body:", Style::default().fg(theme.muted))));
                // Show first few lines of body
                for line in body.lines().take(5) {
                    let display_line = if line.len() > 55 {
                        safe_truncate(line, 55)
                    } else {
                        line.to_string()
                    };
                    request_lines.push(Line::from(Span::styled(
                        format!("  {}", display_line),
                        Style::default().fg(theme.fg),
                    )));
                }
                if body.lines().count() > 5 {
                    request_lines.push(Line::from(Span::styled(
                        format!("  ... ({} more lines)", body.lines().count() - 5),
                        Style::default().fg(theme.muted),
                    )));
                }
            }

            let request_content = Paragraph::new(request_lines).block(request_block);
            frame.render_widget(request_content, detail_chunks[0]);

            // Response details block
            let response_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(" Response ");

            let status_color = match entry.status {
                Some(s) if (200..300).contains(&s) => theme.success,
                Some(s) if (300..400).contains(&s) => theme.info,
                Some(s) if (400..500).contains(&s) => theme.warning,
                Some(s) if s >= 500 => theme.error,
                _ => theme.muted,
            };

            let mut response_lines = vec![
                Line::from(vec![
                    Span::styled("Status: ", Style::default().fg(theme.muted)),
                    Span::styled(
                        entry.status.map(|s| s.to_string()).unwrap_or_else(|| "pending".to_string()),
                        Style::default().fg(status_color).add_modifier(ratatui::style::Modifier::BOLD),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Size: ", Style::default().fg(theme.muted)),
                    Span::styled(
                        entry.response_size.map(format_size).unwrap_or_else(|| "-".to_string()),
                        Style::default().fg(theme.fg),
                    ),
                    Span::styled("  Time: ", Style::default().fg(theme.muted)),
                    Span::styled(
                        entry.duration_ms.map(|d| format!("{}ms", d)).unwrap_or_else(|| "-".to_string()),
                        Style::default().fg(theme.fg),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Type: ", Style::default().fg(theme.muted)),
                    Span::styled(
                        entry.content_type.as_deref().unwrap_or("unknown"),
                        Style::default().fg(theme.fg),
                    ),
                ]),
            ];

            // Show response headers
            if let Some(headers) = &entry.response_headers {
                if !headers.is_empty() {
                    response_lines.push(Line::from(""));
                    response_lines.push(Line::from(Span::styled("Headers:", Style::default().fg(theme.muted))));
                    let mut sorted_headers: Vec<_> = headers.iter().collect();
                    sorted_headers.sort_by_key(|(k, _)| k.as_str());
                    for (key, value) in sorted_headers.iter().take(5) {
                        let display_value = if value.len() > 40 {
                            safe_truncate(value, 40)
                        } else {
                            value.to_string()
                        };
                        response_lines.push(Line::from(vec![
                            Span::styled(format!("  {}: ", key), Style::default().fg(theme.muted)),
                            Span::styled(display_value, Style::default().fg(theme.fg)),
                        ]));
                    }
                    if headers.len() > 5 {
                        response_lines.push(Line::from(Span::styled(
                            format!("  ... ({} more)", headers.len() - 5),
                            Style::default().fg(theme.muted),
                        )));
                    }
                }
            }

            // Show response body if present
            if let Some(body) = &entry.response_body {
                response_lines.push(Line::from(""));
                response_lines.push(Line::from(Span::styled("Body:", Style::default().fg(theme.muted))));
                // Show first few lines of body
                for line in body.lines().take(5) {
                    let display_line = if line.len() > 55 {
                        safe_truncate(line, 55)
                    } else {
                        line.to_string()
                    };
                    response_lines.push(Line::from(Span::styled(
                        format!("  {}", display_line),
                        Style::default().fg(theme.fg),
                    )));
                }
                if body.lines().count() > 5 {
                    response_lines.push(Line::from(Span::styled(
                        format!("  ... ({} more lines)", body.lines().count() - 5),
                        Style::default().fg(theme.muted),
                    )));
                }
            } else {
                response_lines.push(Line::from(Span::styled("(no body)", Style::default().fg(theme.muted))));
            }

            let response_content = Paragraph::new(response_lines).block(response_block);
            frame.render_widget(response_content, detail_chunks[1]);
        }
    }
}

/// Extract hostname from URL
fn extract_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Group findings by hostname, applying filter
/// Returns (sorted_hosts, findings_by_host)
pub fn group_findings_by_host<'a>(
    findings: &'a [crate::scanner::Finding],
    filter: &str,
) -> (Vec<String>, std::collections::HashMap<String, Vec<&'a crate::scanner::Finding>>) {
    use std::collections::HashMap;

    // Parse filter into include and exclude patterns
    let mut include_patterns: Vec<regex::Regex> = Vec::new();
    let mut exclude_patterns: Vec<regex::Regex> = Vec::new();

    for part in filter.split_whitespace() {
        if let Some(pattern) = part.strip_prefix('!') {
            if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex::escape(pattern))) {
                exclude_patterns.push(re);
            }
        } else if !part.is_empty() {
            if let Ok(re) = regex::Regex::new(&format!("(?i){}", regex::escape(part))) {
                include_patterns.push(re);
            }
        }
    }

    let mut by_host: HashMap<String, Vec<&crate::scanner::Finding>> = HashMap::new();

    for finding in findings {
        let host = extract_host(&finding.url);

        // Check exclusions first
        let excluded = exclude_patterns.iter().any(|re| re.is_match(&host));
        if excluded {
            continue;
        }

        // Check inclusions (if any patterns specified)
        let included = include_patterns.is_empty()
            || include_patterns.iter().any(|re| re.is_match(&host));
        if !included {
            continue;
        }

        by_host.entry(host).or_default().push(finding);
    }

    // Sort hosts by finding count (descending), then alphabetically
    let mut hosts: Vec<String> = by_host.keys().cloned().collect();
    hosts.sort_by(|a, b| {
        let count_a = by_host.get(a).map(|v| v.len()).unwrap_or(0);
        let count_b = by_host.get(b).map(|v| v.len()).unwrap_or(0);
        count_b.cmp(&count_a).then_with(|| a.cmp(b))
    });

    (hosts, by_host)
}

/// Render scanner view
fn render_scanner_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let state = app.state.read();

    // Determine if we need a filter bar
    let has_filter = !state.findings_filter.is_empty() || state.mode == AppMode::FilterFindings;

    // Split area into status, filter (optional), and findings
    let chunks = if has_filter {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),  // Status
                Constraint::Length(3),  // Filter bar
                Constraint::Min(10),    // Findings
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),  // Status
                Constraint::Min(10),    // Findings
            ])
            .split(area)
    };

    // Status block
    let status_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(format!(" Scanner ({} findings) ", state.findings.len()));

    let mut status_lines = vec![Line::from("")];

    if let Some(progress) = state.scan_progress {
        let bar_width = 30;
        let filled = (progress * bar_width as f64) as usize;
        let empty = bar_width - filled;

        status_lines.push(Line::from(vec![
            Span::styled("  Scanning: ", Style::default().fg(theme.fg)),
            Span::styled("█".repeat(filled), Style::default().fg(theme.accent)),
            Span::styled("░".repeat(empty), Style::default().fg(theme.muted)),
            Span::styled(format!(" {:.0}%", progress * 100.0), Style::default().fg(theme.fg)),
        ]));
    } else {
        status_lines.push(Line::from(vec![
            Span::styled("  Passive scanning: ", Style::default().fg(theme.muted)),
            Span::styled(if state.proxy_running { "Active (via proxy)" } else { "Inactive" },
                Style::default().fg(if state.proxy_running { theme.success } else { theme.muted })),
        ]));
    }

    let status_content = Paragraph::new(status_lines).block(status_block);
    frame.render_widget(status_content, chunks[0]);

    // Filter bar (if visible)
    let findings_chunk_idx = if has_filter {
        let filter_editing = state.mode == AppMode::FilterFindings;
        let filter_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if filter_editing { theme.accent } else { theme.border }))
            .title(" Filter (use !pattern to exclude) ");

        let filter_text = if filter_editing {
            // Show cursor
            let cursor_pos = state.findings_filter_cursor;
            let (before, after) = state.findings_filter.split_at(cursor_pos.min(state.findings_filter.len()));
            Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(before, Style::default().fg(theme.fg)),
                Span::styled("▎", Style::default().fg(theme.accent)),
                Span::styled(after, Style::default().fg(theme.fg)),
            ])
        } else if state.findings_filter.is_empty() {
            Line::from(Span::styled(" Press / to filter...", Style::default().fg(theme.muted)))
        } else {
            Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(&state.findings_filter, Style::default().fg(theme.fg)),
            ])
        };

        let filter_content = Paragraph::new(filter_text).block(filter_block);
        frame.render_widget(filter_content, chunks[1]);
        2 // findings are in chunk 2
    } else {
        1 // findings are in chunk 1
    };

    // Group findings by host
    let (hosts, findings_by_host) = group_findings_by_host(&state.findings, &state.findings_filter);

    // Findings block - tree view
    let total_filtered = hosts.iter()
        .filter_map(|h| findings_by_host.get(h))
        .map(|v| v.len())
        .sum::<usize>();

    let title = if state.findings_filter.is_empty() {
        format!(" Findings ({} hosts, {} total) ", hosts.len(), state.findings.len())
    } else {
        format!(" Findings ({} hosts, {} matching) ", hosts.len(), total_filtered)
    };

    let findings_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if state.focus == Focus::Findings { theme.accent } else { theme.border }))
        .title(format!("{}  /:filter  Enter:expand  d:details ", title));

    let findings_area = chunks[findings_chunk_idx];

    if hosts.is_empty() {
        let empty_msg = if state.findings.is_empty() {
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled("  No security findings yet", Style::default().fg(theme.muted))),
                Line::from(""),
                Line::from(Span::styled("  Findings will appear here when:", Style::default().fg(theme.muted))),
                Line::from(Span::styled("    • Proxy traffic is analyzed (passive scanning)", Style::default().fg(theme.muted))),
                Line::from(Span::styled("    • Active scans are run (Ctrl+S)", Style::default().fg(theme.muted))),
            ])
        } else {
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled("  No findings match filter", Style::default().fg(theme.muted))),
                Line::from(Span::styled("  Press Esc or clear filter to show all", Style::default().fg(theme.muted))),
            ])
        };
        frame.render_widget(empty_msg.block(findings_block), findings_area);
        return;
    }

    // Build tree view lines
    let mut lines = Vec::new();
    let visible_height = findings_area.height.saturating_sub(2) as usize;

    // Calculate which line is selected for scrolling
    let mut current_line = 0usize;
    let mut selected_line = 0usize;

    // First pass: find selected line for scroll calculation
    for (host_idx, host) in hosts.iter().enumerate() {
        let is_host_selected = host_idx == state.findings_selected_host && state.findings_selected_within_host.is_none();
        if is_host_selected {
            selected_line = current_line;
        }
        current_line += 1;

        if state.findings_expanded_hosts.contains(host) {
            if let Some(host_findings) = findings_by_host.get(host) {
                for (finding_idx, _) in host_findings.iter().enumerate() {
                    let is_finding_selected = host_idx == state.findings_selected_host
                        && state.findings_selected_within_host == Some(finding_idx);
                    if is_finding_selected {
                        selected_line = current_line;
                    }
                    current_line += 1;
                }
            }
        }
    }

    // Calculate scroll offset
    let scroll_offset = if selected_line >= visible_height {
        selected_line - visible_height + 1
    } else {
        0
    };

    // Second pass: render visible lines
    current_line = 0;
    for (host_idx, host) in hosts.iter().enumerate() {
        let is_expanded = state.findings_expanded_hosts.contains(host);
        let is_host_selected = state.focus == Focus::Findings
            && host_idx == state.findings_selected_host
            && state.findings_selected_within_host.is_none();

        let host_findings = findings_by_host.get(host);
        let finding_count = host_findings.map(|v| v.len()).unwrap_or(0);

        // Skip if before scroll window
        if current_line >= scroll_offset && lines.len() < visible_height {
            let expand_icon = if is_expanded { "▼" } else { "▶" };
            let host_display = if host.len() > 40 {
                safe_truncate(host, 37)
            } else {
                host.clone()
            };

            if is_host_selected {
                lines.push(Line::from(vec![
                    Span::styled(format!(" {} ", expand_icon), Style::default().fg(theme.accent)),
                    Span::styled(
                        format!("{} ({})", host_display, finding_count),
                        Style::default().fg(Color::Black).bg(theme.accent).add_modifier(Modifier::BOLD)
                    ),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(format!(" {} ", expand_icon), Style::default().fg(theme.muted)),
                    Span::styled(
                        format!("{} ", host_display),
                        Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)
                    ),
                    Span::styled(format!("({})", finding_count), Style::default().fg(theme.muted)),
                ]));
            }
        }
        current_line += 1;

        // Render findings under expanded host
        if is_expanded {
            if let Some(host_findings) = host_findings {
                for (finding_idx, finding) in host_findings.iter().enumerate() {
                    if current_line >= scroll_offset && lines.len() < visible_height {
                        let is_finding_selected = state.focus == Focus::Findings
                            && host_idx == state.findings_selected_host
                            && state.findings_selected_within_host == Some(finding_idx);

                        let severity_color = match finding.severity.to_lowercase().as_str() {
                            "critical" => Color::Magenta,
                            "high" => theme.error,
                            "medium" => Color::Yellow,
                            "low" => Color::Cyan,
                            _ => theme.muted,
                        };

                        let severity_char = match finding.severity.to_lowercase().as_str() {
                            "critical" => "C",
                            "high" => "H",
                            "medium" => "M",
                            "low" => "L",
                            _ => "?",
                        };

                        // Extract path from URL for display
                        let path = url::Url::parse(&finding.url)
                            .ok()
                            .map(|u| u.path().to_string())
                            .unwrap_or_else(|| finding.url.clone());

                        let name_display = if finding.name.len() > 30 {
                            safe_truncate(&finding.name, 27)
                        } else {
                            finding.name.clone()
                        };

                        let path_display = if path.len() > 25 {
                            safe_truncate(&path, 22)
                        } else {
                            path
                        };

                        if is_finding_selected {
                            lines.push(Line::from(vec![
                                Span::styled("   ", Style::default()),
                                Span::styled(format!("[{}]", severity_char), Style::default().fg(Color::Black).bg(severity_color)),
                                Span::styled(" ", Style::default()),
                                Span::styled(
                                    format!("{:<30} {}", name_display, path_display),
                                    Style::default().fg(Color::Black).bg(theme.accent)
                                ),
                            ]));
                        } else {
                            lines.push(Line::from(vec![
                                Span::styled("   ", Style::default()),
                                Span::styled(format!("[{}]", severity_char), Style::default().fg(severity_color)),
                                Span::styled(" ", Style::default()),
                                Span::styled(format!("{:<30} ", name_display), Style::default().fg(theme.fg)),
                                Span::styled(path_display, Style::default().fg(theme.muted)),
                            ]));
                        }
                    }
                    current_line += 1;
                }
            }
        }
    }

    let findings_content = Paragraph::new(lines).block(findings_block);
    frame.render_widget(findings_content, findings_area);
}

/// Render placeholder for unimplemented views
fn render_fuzzer_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    use crate::app::{FuzzerFocus, FuzzerSortBy};
    use crate::fuzzer::FuzzerState;

    let state = app.state.read();

    // Layout: top row (request + config), bottom row (results + details)
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40), // Top: request template + config
            Constraint::Percentage(60), // Bottom: results + details
        ])
        .split(area);

    // Top row: request template (left) + payload config (right)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60), // Request template
            Constraint::Percentage(40), // Payload config
        ])
        .split(main_chunks[0]);

    // Bottom row: results (left) + result details (right)
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), // Results table
            Constraint::Percentage(50), // Result details
        ])
        .split(main_chunks[1]);

    // ========== Request Template Panel ==========
    let template_focus = state.fuzzer_focus == FuzzerFocus::RequestTemplate;
    let template_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if template_focus { theme.accent } else { theme.border }))
        .title(" Request Template (use §markers§ for payloads) ");

    let template_text = if state.fuzzer_request_template.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled("  Paste or type a raw HTTP request here", Style::default().fg(theme.muted))),
            Line::from(""),
            Line::from(Span::styled("  Use §markers§ around values to fuzz:", Style::default().fg(theme.muted))),
            Line::from(Span::styled("    GET /api/user/§id§ HTTP/1.1", Style::default().fg(theme.info))),
            Line::from(Span::styled("    Authorization: Bearer §token§", Style::default().fg(theme.info))),
            Line::from(""),
            Line::from(Span::styled("  Press 'i' to edit, 'p' to paste from clipboard", Style::default().fg(theme.muted))),
        ]
    } else {
        // Highlight markers in template
        let mut lines = Vec::new();
        let marker_char = '§';
        let marker_len = marker_char.len_utf8(); // 2 bytes for §
        for line in state.fuzzer_request_template.lines() {
            let mut spans = Vec::new();
            let mut remaining = line;
            while let Some(start) = remaining.find(marker_char) {
                if start > 0 {
                    spans.push(Span::styled(&remaining[..start], Style::default().fg(theme.fg)));
                }
                remaining = &remaining[start..];
                if let Some(end) = remaining[marker_len..].find(marker_char) {
                    let marker = &remaining[..end + marker_len * 2];
                    spans.push(Span::styled(marker, Style::default().fg(theme.warning).add_modifier(Modifier::BOLD)));
                    remaining = &remaining[end + marker_len * 2..];
                } else {
                    break;
                }
            }
            if !remaining.is_empty() {
                spans.push(Span::styled(remaining, Style::default().fg(theme.fg)));
            }
            lines.push(Line::from(spans));
        }
        lines
    };
    let template_para = Paragraph::new(template_text).block(template_block);
    frame.render_widget(template_para, top_chunks[0]);

    // ========== Payload Config Panel ==========
    let config_focus = state.fuzzer_focus == FuzzerFocus::PayloadConfig;
    let config_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if config_focus { theme.accent } else { theme.border }))
        .title(" Payload Configuration ");

    let state_indicator = match state.fuzzer_state {
        FuzzerState::Idle => Span::styled("● Idle", Style::default().fg(theme.muted)),
        FuzzerState::Running => Span::styled("● Running", Style::default().fg(theme.success)),
        FuzzerState::Paused => Span::styled("● Paused", Style::default().fg(theme.warning)),
        FuzzerState::Stopped => Span::styled("● Stopped", Style::default().fg(theme.error)),
        FuzzerState::Completed => Span::styled("● Completed", Style::default().fg(theme.info)),
    };

    let config_lines = vec![
        Line::from(vec![
            Span::styled("  Status: ", Style::default().fg(theme.muted)),
            state_indicator,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Attack Mode: ", Style::default().fg(theme.muted)),
            Span::styled(state.fuzzer_attack_mode.name(), Style::default().fg(theme.accent)),
            Span::styled(" (m to cycle)", Style::default().fg(theme.muted)),
        ]),
        Line::from(vec![
            Span::styled("  Payload Set: ", Style::default().fg(theme.muted)),
            Span::styled(state.fuzzer_payload_set.name(), Style::default().fg(theme.accent)),
            Span::styled(" (w to cycle)", Style::default().fg(theme.muted)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Concurrency: ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}", state.fuzzer_concurrency), Style::default().fg(theme.fg)),
            Span::styled(" (+/- to adjust)", Style::default().fg(theme.muted)),
        ]),
        Line::from(vec![
            Span::styled("  Delay: ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}ms", state.fuzzer_delay_ms), Style::default().fg(theme.fg)),
            Span::styled(" (d to adjust)", Style::default().fg(theme.muted)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [Enter] Start  [Space] Pause  [Esc] Stop", Style::default().fg(theme.muted)),
        ]),
    ];

    let config_para = Paragraph::new(config_lines).block(config_block);
    frame.render_widget(config_para, top_chunks[1]);

    // ========== Results Panel ==========
    let results_focus = state.fuzzer_focus == FuzzerFocus::Results;
    let stats = &state.fuzzer_stats;
    let results_title = format!(
        " Results: {} sent, {} interesting (s to sort by: {}) ",
        stats.requests_sent,
        stats.interesting_count,
        state.fuzzer_sort_by.name()
    );
    let results_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if results_focus { theme.accent } else { theme.border }))
        .title(results_title);

    if state.fuzzer_results.is_empty() {
        let empty_lines = vec![
            Line::from(""),
            Line::from(Span::styled("  No results yet", Style::default().fg(theme.muted))),
            Line::from(""),
            Line::from(Span::styled("  Configure payloads and press Enter to start fuzzing", Style::default().fg(theme.muted))),
        ];
        let empty_para = Paragraph::new(empty_lines).block(results_block);
        frame.render_widget(empty_para, bottom_chunks[0]);
    } else {
        let mut result_lines = Vec::new();

        // Header
        result_lines.push(Line::from(vec![
            Span::styled("   #  ", Style::default().fg(theme.muted)),
            Span::styled("Status ", Style::default().fg(theme.muted)),
            Span::styled("Length   ", Style::default().fg(theme.muted)),
            Span::styled("Time    ", Style::default().fg(theme.muted)),
            Span::styled("Payload", Style::default().fg(theme.muted)),
        ]));

        // Get sorted results
        let mut sorted_results: Vec<_> = state.fuzzer_results.iter().enumerate().collect();
        match state.fuzzer_sort_by {
            FuzzerSortBy::RequestNum => sorted_results.sort_by_key(|(_, r)| r.request_num),
            FuzzerSortBy::StatusCode => sorted_results.sort_by_key(|(_, r)| r.status_code),
            FuzzerSortBy::Length => sorted_results.sort_by_key(|(_, r)| std::cmp::Reverse(r.response_length)),
            FuzzerSortBy::Time => sorted_results.sort_by_key(|(_, r)| std::cmp::Reverse(r.response_time)),
            FuzzerSortBy::Interesting => sorted_results.sort_by_key(|(_, r)| if r.interesting { 0 } else { 1 }),
        }

        // Visible area (accounting for header and block borders)
        let visible_height = bottom_chunks[0].height.saturating_sub(4) as usize;
        let scroll_offset = if state.fuzzer_selected_result >= visible_height {
            state.fuzzer_selected_result - visible_height + 1
        } else {
            0
        };

        for (_display_idx, (original_idx, result)) in sorted_results.iter().enumerate().skip(scroll_offset).take(visible_height) {
            let is_selected = *original_idx == state.fuzzer_selected_result && results_focus;

            let status_color = match result.status_code {
                200..=299 => theme.success,
                300..=399 => theme.info,
                400..=499 => theme.warning,
                500..=599 => theme.error,
                _ => theme.muted,
            };

            let prefix = if is_selected { "▸" } else { " " };
            let interesting_marker = if result.interesting { "!" } else { " " };

            let payload_display = if !result.payloads.is_empty() {
                result.payloads.join(", ")
            } else {
                String::new()
            };
            let payload_truncated = if payload_display.len() > 30 {
                safe_truncate(&payload_display, 27)
            } else {
                payload_display
            };

            let line_style = if is_selected {
                Style::default().bg(Color::Rgb(60, 60, 80))
            } else if result.interesting {
                Style::default().fg(theme.warning)
            } else {
                Style::default()
            };

            result_lines.push(Line::from(vec![
                Span::styled(format!("{}{} ", prefix, interesting_marker), line_style),
                Span::styled(format!("{:4} ", result.request_num), line_style.fg(theme.fg)),
                Span::styled(format!("{:6} ", result.status_code), line_style.fg(status_color)),
                Span::styled(format!("{:8} ", result.response_length), line_style.fg(theme.fg)),
                Span::styled(format!("{:6}ms ", result.response_time.as_millis()), line_style.fg(theme.fg)),
                Span::styled(payload_truncated, line_style.fg(theme.muted)),
            ]));
        }

        let results_para = Paragraph::new(result_lines).block(results_block);
        frame.render_widget(results_para, bottom_chunks[0]);
    }

    // ========== Result Details Panel ==========
    let details_focus = state.fuzzer_focus == FuzzerFocus::ResultDetails;
    let details_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if details_focus { theme.accent } else { theme.border }))
        .title(" Result Details ");

    if let Some(result) = state.fuzzer_results.get(state.fuzzer_selected_result) {
        let mut detail_lines = Vec::new();

        detail_lines.push(Line::from(vec![
            Span::styled("Request #", Style::default().fg(theme.muted)),
            Span::styled(format!("{}", result.request_num), Style::default().fg(theme.fg)),
        ]));

        let status_color = match result.status_code {
            200..=299 => theme.success,
            300..=399 => theme.info,
            400..=499 => theme.warning,
            500..=599 => theme.error,
            _ => theme.muted,
        };
        detail_lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}", result.status_code), Style::default().fg(status_color)),
        ]));

        detail_lines.push(Line::from(vec![
            Span::styled("Length: ", Style::default().fg(theme.muted)),
            Span::styled(format!("{} bytes", result.response_length), Style::default().fg(theme.fg)),
        ]));

        detail_lines.push(Line::from(vec![
            Span::styled("Time: ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}ms", result.response_time.as_millis()), Style::default().fg(theme.fg)),
        ]));

        detail_lines.push(Line::from(""));

        if result.interesting {
            detail_lines.push(Line::from(vec![
                Span::styled("⚠ INTERESTING: ", Style::default().fg(theme.warning).add_modifier(Modifier::BOLD)),
                Span::styled(result.interesting_reason.as_deref().unwrap_or("Unknown"), Style::default().fg(theme.warning)),
            ]));
            detail_lines.push(Line::from(""));
        }

        detail_lines.push(Line::from(Span::styled("Payloads:", Style::default().fg(theme.muted))));
        for (i, payload) in result.payloads.iter().enumerate() {
            let pos_name = result.positions.get(i).map(|s| s.as_str()).unwrap_or("?");
            detail_lines.push(Line::from(vec![
                Span::styled(format!("  {}: ", pos_name), Style::default().fg(theme.info)),
                Span::styled(payload, Style::default().fg(theme.fg)),
            ]));
        }

        if let Some(error) = &result.error {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(vec![
                Span::styled("Error: ", Style::default().fg(theme.error)),
                Span::styled(error, Style::default().fg(theme.error)),
            ]));
        }

        // Response body preview (first few lines)
        if !result.response_body.is_empty() {
            detail_lines.push(Line::from(""));
            detail_lines.push(Line::from(Span::styled("Response (preview):", Style::default().fg(theme.muted))));
            for line in result.response_body.lines().take(8) {
                let truncated = if line.len() > 50 { safe_truncate(line, 47) } else { line.to_string() };
                detail_lines.push(Line::from(Span::styled(format!("  {}", truncated), Style::default().fg(theme.fg))));
            }
        }

        let details_para = Paragraph::new(detail_lines).block(details_block);
        frame.render_widget(details_para, bottom_chunks[1]);
    } else {
        let empty_lines = vec![
            Line::from(""),
            Line::from(Span::styled("  Select a result to view details", Style::default().fg(theme.muted))),
        ];
        let empty_para = Paragraph::new(empty_lines).block(details_block);
        frame.render_widget(empty_para, bottom_chunks[1]);
    }
}

fn render_browser_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let state = app.state.read();

    // Single content area
    let info_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(" Carbonyl Terminal Browser ");

    let carbonyl_available = crate::browser::carbonyl_available();
    let status_icon = if carbonyl_available { "✓" } else { "✗" };
    let status_color = if carbonyl_available { theme.success } else { theme.error };
    let status_text = if carbonyl_available { "Carbonyl installed" } else { "Carbonyl not found - install from https://github.com/fathyb/carbonyl" };

    let in_tmux = std::env::var("TMUX").is_ok();
    let tmux_icon = if in_tmux { "✓" } else { "✗" };
    let tmux_color = if in_tmux { theme.success } else { theme.error };
    let tmux_text = if in_tmux { "Running in tmux" } else { "Not in tmux - browser requires tmux" };

    let info_text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Carbonyl", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled(" - Full Terminal Web Browser", Style::default().fg(theme.fg)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(format!("{} ", status_icon), Style::default().fg(status_color)),
            Span::styled(status_text, Style::default().fg(theme.fg)),
        ]),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(format!("{} ", tmux_icon), Style::default().fg(tmux_color)),
            Span::styled(tmux_text, Style::default().fg(theme.fg)),
        ]),
        Line::from(vec![
            Span::raw("    "),
            Span::styled("✓ ", Style::default().fg(theme.success)),
            Span::styled("Traffic routed through ancarna proxy", Style::default().fg(theme.fg)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(theme.muted)),
            Span::styled("Enter", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled(" to launch browser in new tmux window", Style::default().fg(theme.muted)),
        ]),
        Line::from(vec![
            Span::styled("  Use ", Style::default().fg(theme.muted)),
            Span::styled("Ctrl-b n", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::styled(" to switch between windows", Style::default().fg(theme.muted)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::raw("    "),
            Span::styled(
                format!("Proxy: 127.0.0.1:{}", state.settings_proxy_port),
                Style::default().fg(theme.info)
            ),
        ]),
        Line::from(""),
    ];

    frame.render_widget(Paragraph::new(info_text).block(info_block), area);
}

fn render_settings_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    use crate::app::SettingsSection;

    let state = app.state.read();

    // Layout: left sidebar (sections) + right content
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(20), // Sidebar
            Constraint::Min(40),    // Content
        ])
        .split(area);

    // ========== Sidebar (sections) ==========
    let sidebar_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(" Settings ");

    let mut section_lines = Vec::new();
    for section in SettingsSection::all() {
        let is_selected = *section == state.settings_section;
        let prefix = if is_selected { "▸ " } else { "  " };
        let style = if is_selected {
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.fg)
        };
        section_lines.push(Line::from(Span::styled(format!("{}{}", prefix, section.name()), style)));
    }

    let sidebar = Paragraph::new(section_lines).block(sidebar_block);
    frame.render_widget(sidebar, chunks[0]);

    // ========== Content (based on selected section) ==========
    let content_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent))
        .title(format!(" {} Settings (j/k:nav, Enter:toggle, +/-:adjust) ", state.settings_section.name()));

    let content_lines = match state.settings_section {
        SettingsSection::Proxy => vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Proxy Port: ", Style::default().fg(theme.muted)),
                Span::styled(format!("{}", state.settings_proxy_port), Style::default().fg(theme.accent)),
                Span::styled(" (+/- to adjust)", Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Intercept Mode: ", Style::default().fg(theme.muted)),
                Span::styled(
                    if state.intercept_enabled { "Enabled" } else { "Disabled" },
                    Style::default().fg(if state.intercept_enabled { theme.success } else { theme.muted }),
                ),
                Span::styled(" (i to toggle on Proxy tab)", Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Proxy Status: ", Style::default().fg(theme.muted)),
                Span::styled(
                    if state.proxy_running { "Running" } else { "Stopped" },
                    Style::default().fg(if state.proxy_running { theme.success } else { theme.error }),
                ),
                Span::styled(" (P to start/stop on Proxy tab)", Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(Span::styled("  TLS Interception: ", Style::default().fg(theme.muted))),
            Line::from(Span::styled("    Auto-generates certificates for HTTPS sites", Style::default().fg(theme.muted))),
            Line::from(Span::styled("    Press 'X' on Proxy tab to export CA cert", Style::default().fg(theme.info))),
        ],
        SettingsSection::Scanner => vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Scanner Concurrency: ", Style::default().fg(theme.muted)),
                Span::styled(format!("{}", state.settings_scanner_concurrency), Style::default().fg(theme.accent)),
                Span::styled(" (+/- to adjust)", Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(Span::styled("  Passive Scanning: ", Style::default().fg(theme.muted))),
            Line::from(vec![
                Span::styled("    Status: ", Style::default().fg(theme.muted)),
                Span::styled(
                    if state.proxy_running { "Active (via proxy)" } else { "Inactive" },
                    Style::default().fg(if state.proxy_running { theme.success } else { theme.muted }),
                ),
            ]),
            Line::from(""),
            Line::from(Span::styled("  Enabled Passive Rules:", Style::default().fg(theme.muted))),
            Line::from(Span::styled("    - Security Headers", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Cookie Security", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - CORS Analysis", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - CSP Analysis", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Cache Control", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Server Disclosure", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - CSRF Protection", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Referrer Policy", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Permissions Policy", Style::default().fg(theme.info))),
        ],
        SettingsSection::General => vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  Auto-save: ", Style::default().fg(theme.muted)),
                Span::styled(
                    if state.settings_auto_save { "Enabled" } else { "Disabled" },
                    Style::default().fg(if state.settings_auto_save { theme.success } else { theme.muted }),
                ),
                Span::styled(" (Enter to toggle)", Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Auto-save Interval: ", Style::default().fg(theme.muted)),
                Span::styled(format!("{}s", state.settings_auto_save_interval), Style::default().fg(theme.accent)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Theme: ", Style::default().fg(theme.muted)),
                Span::styled(
                    if state.settings_dark_theme { "Dark" } else { "Light" },
                    Style::default().fg(theme.accent),
                ),
                Span::styled(" (t to toggle)", Style::default().fg(theme.muted)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Show Request Timing: ", Style::default().fg(theme.muted)),
                Span::styled(
                    if state.settings_show_timing { "Yes" } else { "No" },
                    Style::default().fg(if state.settings_show_timing { theme.success } else { theme.muted }),
                ),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Max History Entries: ", Style::default().fg(theme.muted)),
                Span::styled(format!("{}", state.settings_max_history), Style::default().fg(theme.accent)),
            ]),
        ],
        SettingsSection::About => vec![
            Line::from(""),
            Line::from(Span::styled("  Ancarna", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))),
            Line::from(Span::styled("  Terminal Security Testing Platform", Style::default().fg(theme.muted))),
            Line::from(""),
            Line::from(vec![
                Span::styled("  Version: ", Style::default().fg(theme.muted)),
                Span::styled("0.1.0", Style::default().fg(theme.fg)),
            ]),
            Line::from(""),
            Line::from(Span::styled("  Features:", Style::default().fg(theme.muted))),
            Line::from(Span::styled("    - HTTP/HTTPS Proxy with TLS interception", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Passive & Active Security Scanning", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Parameter Fuzzing (Turbo Intruder style)", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - JWT Token Analysis", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - JavaScript Analysis", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - WebSocket Support", Style::default().fg(theme.info))),
            Line::from(Span::styled("    - Report Generation (HTML/JSON/CSV/MD)", Style::default().fg(theme.info))),
            Line::from(""),
            Line::from(Span::styled("  Keyboard Shortcuts:", Style::default().fg(theme.muted))),
            Line::from(Span::styled("    1-6      Switch tabs", Style::default().fg(theme.fg))),
            Line::from(Span::styled("    H/L      Previous/Next tab", Style::default().fg(theme.fg))),
            Line::from(Span::styled("    ?        Show help", Style::default().fg(theme.fg))),
            Line::from(Span::styled("    q        Quit", Style::default().fg(theme.fg))),
        ],
    };

    let content = Paragraph::new(content_lines).block(content_block);
    frame.render_widget(content, chunks[1]);
}

/// Render the spider/crawler view
fn render_spider_view(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    use crate::app::SpiderFocus;
    use crate::spider::SpiderState;

    let state = app.state.read();

    // Layout: left (url input + config), right (results)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40), // Left: URL input + config
            Constraint::Percentage(60), // Right: discovered URLs
        ])
        .split(area);

    // Left column: URL input on top, config below
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // URL input
            Constraint::Min(10),    // Config + controls
        ])
        .split(main_chunks[0]);

    // ========== URL Input Panel ==========
    let url_focus = state.spider_focus == SpiderFocus::UrlInput;
    let is_editing = state.mode == crate::app::AppMode::EditUrl && state.current_tab == MainTab::Spider;

    let url_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if is_editing || url_focus { theme.accent } else { theme.border }))
        .title(if is_editing { " Target URL [EDITING] " } else { " Target URL " });

    // When editing, show url_input (the edit buffer), otherwise show spider_url_input
    let display_url = if is_editing {
        &state.url_input
    } else {
        &state.spider_url_input
    };

    let url_content = if display_url.is_empty() && !is_editing {
        vec![
            Line::from(""),
            Line::from(Span::styled("  Enter a URL to start crawling (press 'i' to edit)", Style::default().fg(theme.muted))),
            Line::from(Span::styled("  Example: https://example.com", Style::default().fg(theme.info))),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(display_url, Style::default().fg(theme.fg)),
                if is_editing {
                    Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK))
                } else {
                    Span::raw("")
                },
            ]),
            if is_editing {
                Line::from(Span::styled("  [Enter] Save  [Esc] Cancel", Style::default().fg(theme.muted)))
            } else {
                Line::from("")
            },
        ]
    };
    let url_para = Paragraph::new(url_content).block(url_block);
    frame.render_widget(url_para, left_chunks[0]);

    // ========== Config & Controls Panel ==========
    let config_focus = state.spider_focus == SpiderFocus::Config;
    let config_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if config_focus { theme.accent } else { theme.border }))
        .title(" Configuration ");

    let state_indicator = match state.spider_state {
        SpiderState::Idle => Span::styled("● Idle", Style::default().fg(theme.muted)),
        SpiderState::Running => Span::styled("● Running", Style::default().fg(theme.success)),
        SpiderState::Paused => Span::styled("● Paused", Style::default().fg(theme.warning)),
        SpiderState::Stopped => Span::styled("● Stopped", Style::default().fg(theme.error)),
    };

    let config_lines = vec![
        Line::from(vec![
            Span::styled("  Status: ", Style::default().fg(theme.muted)),
            state_indicator,
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Max Depth:  ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}", state.spider_max_depth), Style::default().fg(theme.fg)),
        ]),
        Line::from(vec![
            Span::styled("  Max Pages:  ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}", state.spider_max_pages), Style::default().fg(theme.fg)),
        ]),
        Line::from(vec![
            Span::styled("  Delay:      ", Style::default().fg(theme.muted)),
            Span::styled(format!("{}ms", state.spider_delay_ms), Style::default().fg(theme.fg)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Stats: ", Style::default().fg(theme.muted)),
            Span::styled(format!("{} visited", state.spider_stats.visited), Style::default().fg(theme.info)),
            Span::styled(", ", Style::default().fg(theme.muted)),
            Span::styled(format!("{} queued", state.spider_stats.queued), Style::default().fg(theme.warning)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  [Enter] Start  [Space] Pause  [Esc] Stop", Style::default().fg(theme.muted))),
        Line::from(Span::styled("  [i] Edit URL  [Tab] Next panel", Style::default().fg(theme.muted))),
    ];

    let config_para = Paragraph::new(config_lines).block(config_block);
    frame.render_widget(config_para, left_chunks[1]);

    // ========== Results Panel ==========
    let results_focus = state.spider_focus == SpiderFocus::Results;
    let results_title = format!(
        " Discovered URLs ({}) ",
        state.spider_discovered.len()
    );
    let results_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if results_focus { theme.accent } else { theme.border }))
        .title(results_title);

    if state.spider_discovered.is_empty() {
        let empty_lines = vec![
            Line::from(""),
            Line::from(Span::styled("  No URLs discovered yet", Style::default().fg(theme.muted))),
            Line::from(""),
            Line::from(Span::styled("  Enter a target URL and press Enter to start", Style::default().fg(theme.muted))),
        ];
        let empty_para = Paragraph::new(empty_lines).block(results_block);
        frame.render_widget(empty_para, main_chunks[1]);
    } else {
        let mut result_lines = Vec::new();

        // Header
        result_lines.push(Line::from(vec![
            Span::styled("  Depth  ", Style::default().fg(theme.muted)),
            Span::styled("URL", Style::default().fg(theme.muted)),
        ]));

        // Visible area
        let visible_height = main_chunks[1].height.saturating_sub(4) as usize;
        let scroll_offset = if state.spider_selected_url >= visible_height {
            state.spider_selected_url - visible_height + 1
        } else {
            0
        };

        for (idx, discovered) in state.spider_discovered.iter().enumerate().skip(scroll_offset).take(visible_height) {
            let is_selected = idx == state.spider_selected_url && results_focus;

            let depth_str = format!("  {:^5}  ", discovered.depth);
            let url_display = if discovered.url.len() > 60 {
                safe_truncate(&discovered.url, 57)
            } else {
                discovered.url.clone()
            };

            let style = if is_selected {
                Style::default().bg(theme.accent).fg(theme.bg)
            } else {
                Style::default().fg(theme.fg)
            };

            result_lines.push(Line::from(vec![
                Span::styled(depth_str, style),
                Span::styled(url_display, style),
            ]));
        }

        let results_para = Paragraph::new(result_lines).block(results_block);
        frame.render_widget(results_para, main_chunks[1]);
    }
}

fn render_placeholder_view(frame: &mut Frame, area: Rect, title: &str, message: &str, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border))
        .title(format!(" {} ", title));

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(format!("  {}", message), Style::default().fg(theme.muted))),
    ])
    .block(block);

    frame.render_widget(content, area);
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let state = app.state.read();

    let mode_str = match state.mode {
        AppMode::Normal => "NORMAL",
        AppMode::EditUrl => "EDIT URL",
        AppMode::EditKeyValue => "EDIT",
        AppMode::EditBody => "EDIT BODY",
        AppMode::EditAuth => "EDIT AUTH",
        AppMode::SelectEnvironment => "ENV",
        AppMode::SearchResponse => "SEARCH",
        AppMode::ViewResponse => "VIEW",
        AppMode::Intercept => "INTERCEPT",
        AppMode::Scanning => "SCAN",
        AppMode::Fuzzing => "FUZZ",
        AppMode::Command => "CMD",
        AppMode::Help => "HELP",
        AppMode::ConfirmDelete => "DELETE?",
        AppMode::Rename => "RENAME",
        AppMode::FilterProxy => "FILTER",
        AppMode::BrowserUrl => "URL",
        AppMode::ProxyDetails => "DETAILS",
        AppMode::EditInterceptUrl => "EDIT URL",
        AppMode::EditInterceptMethod => "EDIT METHOD",
        AppMode::EditInterceptHeaders => "EDIT HEADERS",
        AppMode::EditInterceptBody => "EDIT BODY",
        AppMode::FindingDetails => "FINDING",
        AppMode::FilterFindings => "FILTER",
        AppMode::ImportFile => "IMPORT",
        AppMode::EditScannerTarget => "SCAN TARGET",
        AppMode::Scanning => "SCANNING",
        AppMode::Fuzzing => "FUZZING",
        AppMode::ViewResponse => "RESPONSE",
        AppMode::Intercept => "INTERCEPT",
    };

    let proxy_indicator = if state.proxy_running {
        Span::styled("●", Style::default().fg(Color::Green))
    } else {
        Span::styled("○", Style::default().fg(theme.muted))
    };

    let status_msg = state
        .status_message
        .as_deref()
        .unwrap_or("");

    // Shortcuts hint based on current focus
    let shortcuts = match state.focus {
        Focus::Workspace => "j/k:nav  Enter:select  n:new",
        Focus::RequestEditor => "i:edit  Enter:send  Tab:next",
        Focus::ResponseViewer => "j/k:scroll  y:copy  Tab:next",
        _ => "?:help  Tab:focus  q:quit",
    };

    let status = Line::from(vec![
        Span::styled(
            format!(" {} ", mode_str),
            Style::default().fg(Color::Black).bg(theme.accent),
        ),
        Span::raw(" "),
        proxy_indicator,
        Span::styled(" Proxy ", Style::default().fg(theme.muted)),
        Span::styled("│", Style::default().fg(theme.border)),
        Span::raw(" "),
        Span::raw(status_msg),
        Span::raw(" "),
        // Right-aligned shortcuts
        Span::styled(
            format!("{:>width$}", shortcuts, width = (area.width as usize).saturating_sub(30)),
            Style::default().fg(theme.muted),
        ),
    ]);

    let status_bar = Paragraph::new(status)
        .style(Style::default().bg(theme.bg));

    frame.render_widget(status_bar, area);
}

fn render_help_dialog(frame: &mut Frame, theme: &Theme) {
    let area = centered_rect(70, 85, frame.area());

    let help_text = vec![
        Line::from(Span::styled(
            "Ancarna Keyboard Shortcuts",
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled("General", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  Tab       ", Style::default().fg(theme.info)),
            Span::raw("Cycle focus between panels"),
        ]),
        Line::from(vec![
            Span::styled("  1-6       ", Style::default().fg(theme.info)),
            Span::raw("Switch tab (Workspace/Proxy/Scanner/...)"),
        ]),
        Line::from(vec![
            Span::styled("  ?         ", Style::default().fg(theme.info)),
            Span::raw("Toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("  q         ", Style::default().fg(theme.info)),
            Span::raw("Quit application"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Navigation", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  j/k       ", Style::default().fg(theme.info)),
            Span::raw("Move down/up"),
        ]),
        Line::from(vec![
            Span::styled("  h/l       ", Style::default().fg(theme.info)),
            Span::raw("Move focus left/right"),
        ]),
        Line::from(vec![
            Span::styled("  [/]       ", Style::default().fg(theme.info)),
            Span::raw("Switch sub-tabs"),
        ]),
        Line::from(vec![
            Span::styled("  g/G       ", Style::default().fg(theme.info)),
            Span::raw("Go to top/bottom"),
        ]),
        Line::from(vec![
            Span::styled("  Ctrl+d/u  ", Style::default().fg(theme.info)),
            Span::raw("Half page down/up"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Request Editing", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  e         ", Style::default().fg(theme.info)),
            Span::raw("Edit URL"),
        ]),
        Line::from(vec![
            Span::styled("  i         ", Style::default().fg(theme.info)),
            Span::raw("Edit current field (params/headers/body)"),
        ]),
        Line::from(vec![
            Span::styled("  o         ", Style::default().fg(theme.info)),
            Span::raw("Add new row (params/headers)"),
        ]),
        Line::from(vec![
            Span::styled("  d         ", Style::default().fg(theme.info)),
            Span::raw("Delete row"),
        ]),
        Line::from(vec![
            Span::styled("  Space     ", Style::default().fg(theme.info)),
            Span::raw("Toggle row enabled"),
        ]),
        Line::from(vec![
            Span::styled("  m         ", Style::default().fg(theme.info)),
            Span::raw("Cycle HTTP method"),
        ]),
        Line::from(vec![
            Span::styled("  Enter     ", Style::default().fg(theme.info)),
            Span::raw("Send request"),
        ]),
        Line::from(vec![
            Span::styled("  n         ", Style::default().fg(theme.info)),
            Span::raw("New request"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Response", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  [/]       ", Style::default().fg(theme.info)),
            Span::raw("Switch Body/Headers/Cookies"),
        ]),
        Line::from(vec![
            Span::styled("  /         ", Style::default().fg(theme.info)),
            Span::raw("Search in response"),
        ]),
        Line::from(vec![
            Span::styled("  n/N       ", Style::default().fg(theme.info)),
            Span::raw("Next/previous match"),
        ]),
        Line::from(vec![
            Span::styled("  y         ", Style::default().fg(theme.info)),
            Span::raw("Copy to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("  r         ", Style::default().fg(theme.info)),
            Span::raw("Toggle raw/pretty"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Environment & Import/Export", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  E         ", Style::default().fg(theme.info)),
            Span::raw("Select environment"),
        ]),
        Line::from(vec![
            Span::styled("  I         ", Style::default().fg(theme.info)),
            Span::raw("Import from clipboard (cURL/URL)"),
        ]),
        Line::from(vec![
            Span::styled("  C         ", Style::default().fg(theme.info)),
            Span::raw("Export as cURL to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("  Ctrl+V    ", Style::default().fg(theme.info)),
            Span::raw("Paste from clipboard"),
        ]),
        Line::from(""),
        Line::from(Span::styled("Collection Management", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled("  H         ", Style::default().fg(theme.info)),
            Span::raw("Toggle history focus"),
        ]),
        Line::from(vec![
            Span::styled("  D         ", Style::default().fg(theme.info)),
            Span::raw("Delete selected request"),
        ]),
        Line::from(vec![
            Span::styled("  R         ", Style::default().fg(theme.info)),
            Span::raw("Rename selected item"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Press Esc or ? to close",
            Style::default().fg(theme.muted),
        )),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .title(Span::styled(" Help ", Style::default().fg(theme.accent))),
        )
        .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(help, area);
}

fn render_command_palette(frame: &mut Frame, theme: &Theme) {
    let area = centered_rect(50, 15, frame.area());

    let command = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(":", Style::default().fg(theme.accent)),
            Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(" Command "),
    )
    .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(command, area);
}

fn render_confirm_delete_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();
    let area = centered_rect(50, 25, frame.area());

    let item_name = if let Some(idx) = state.delete_target {
        let items = app.get_collection_items();
        items.get(idx).map(|i| i.name.clone()).unwrap_or_else(|| "Unknown".to_string())
    } else {
        "Unknown".to_string()
    };

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Are you sure you want to delete?",
            Style::default().fg(theme.fg),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  \"{}\"", item_name),
            Style::default().fg(theme.error).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  This action cannot be undone.",
            Style::default().fg(theme.muted),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  y/Enter", Style::default().fg(theme.error)),
            Span::styled(" Delete  ", Style::default().fg(theme.fg)),
            Span::styled("  n/Esc", Style::default().fg(theme.success)),
            Span::styled(" Cancel", Style::default().fg(theme.fg)),
        ]),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.error))
            .title(Span::styled(" Confirm Delete ", Style::default().fg(theme.error))),
    )
    .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(content, area);
}

fn render_rename_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();
    let area = centered_rect(50, 20, frame.area());

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Enter new name:",
            Style::default().fg(theme.fg),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(theme.accent)),
            Span::styled(&state.rename_buffer, Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter:confirm  Esc:cancel",
            Style::default().fg(theme.muted),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(Span::styled(" Rename ", Style::default().fg(theme.accent))),
    )
    .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(content, area);
}

fn render_browser_url_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();
    let area = centered_rect(60, 25, frame.area());

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Enter URL to open in browser:",
            Style::default().fg(theme.fg),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(theme.accent)),
            Span::styled(&state.browser_url_input, Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter:launch  Esc:cancel",
            Style::default().fg(theme.muted),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(Span::styled(" Browser ", Style::default().fg(theme.accent))),
    )
    .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(content, area);
}

fn render_import_file_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();
    let area = centered_rect(70, 35, frame.area());

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Enter file path to import:",
            Style::default().fg(theme.fg),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  Supported formats: Postman, HAR, OpenAPI, curl",
            Style::default().fg(theme.muted),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(theme.accent)),
            Span::styled(&state.import_path_input, Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter:import  Esc:cancel",
            Style::default().fg(theme.muted),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(Span::styled(" Import Collection ", Style::default().fg(theme.accent))),
    )
    .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(content, area);
}

fn render_scanner_target_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();
    let area = centered_rect(70, 35, frame.area());

    let content = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Enter target URL for active scan:",
            Style::default().fg(theme.fg),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  e.g., https://example.com or https://api.example.com/v1",
            Style::default().fg(theme.muted),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", Style::default().fg(theme.accent)),
            Span::styled(&state.scanner_target_url, Style::default().fg(theme.fg)),
            Span::styled("█", Style::default().fg(theme.accent).add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Enter:scan  Esc:cancel",
            Style::default().fg(theme.muted),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(Span::styled(" Active Scanner ", Style::default().fg(theme.accent))),
    )
    .style(Style::default().fg(theme.fg));

    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(content, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Render the proxy details dialog (full request/response view)
fn render_proxy_details_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();

    // Check if we're viewing an intercepted request
    let is_intercepted = state.intercepted_request.is_some();
    let is_editing = matches!(
        state.mode,
        AppMode::EditInterceptUrl | AppMode::EditInterceptMethod |
        AppMode::EditInterceptHeaders | AppMode::EditInterceptBody
    );

    // Get the selected proxy entry (for non-intercepted view)
    // When viewing intercepted request, we still need a reference to entry for response tab
    let entry_opt = state.proxy_history.get(state.selected_proxy_item);
    if entry_opt.is_none() && !is_intercepted {
        return;
    }

    // Create a large centered dialog (90% x 90%)
    let area = centered_rect(90, 90, frame.area());

    // Clear background
    frame.render_widget(ratatui::widgets::Clear, area);

    // Build the content based on selected tab
    let (title, content_lines) = match state.proxy_details_tab {
        ProxyDetailsTab::Request => {
            let mut lines = Vec::new();

            // If viewing intercepted request, show that data with edit support
            if let Some(ref intercepted) = state.intercepted_request {
                // Method line (editable)
                let method_display = if state.mode == AppMode::EditInterceptMethod {
                    // Show edit buffer with cursor
                    let mut s = state.intercept_method_input.clone();
                    s.insert(state.intercept_method_cursor, '▊');
                    s
                } else {
                    intercepted.method.clone()
                };
                let method_style = if state.mode == AppMode::EditInterceptMethod {
                    Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(method_color(&intercepted.method)).add_modifier(Modifier::BOLD)
                };

                // URL line (editable)
                let url_display = if state.mode == AppMode::EditInterceptUrl {
                    let mut s = state.intercept_url_input.clone();
                    let cursor_pos = state.intercept_url_cursor.min(s.len());
                    s.insert(cursor_pos, '▊');
                    s
                } else {
                    intercepted.url.clone()
                };
                let url_style = if state.mode == AppMode::EditInterceptUrl {
                    Style::default().fg(theme.accent)
                } else {
                    Style::default().fg(theme.fg)
                };

                lines.push(Line::from(vec![
                    Span::styled("Method: ", Style::default().fg(theme.muted)),
                    Span::styled(method_display, method_style),
                    if state.mode != AppMode::EditInterceptMethod && is_intercepted {
                        Span::styled(" (m to edit)", Style::default().fg(theme.muted).add_modifier(Modifier::DIM))
                    } else {
                        Span::raw("")
                    },
                ]));

                lines.push(Line::from(vec![
                    Span::styled("URL: ", Style::default().fg(theme.muted)),
                    Span::styled(url_display, url_style),
                    if state.mode != AppMode::EditInterceptUrl && is_intercepted {
                        Span::styled(" (e to edit)", Style::default().fg(theme.muted).add_modifier(Modifier::DIM))
                    } else {
                        Span::raw("")
                    },
                ]));

                if intercepted.modified {
                    lines.push(Line::from(Span::styled(
                        "  [MODIFIED]",
                        Style::default().fg(theme.warning),
                    )));
                }

                lines.push(Line::from(""));

                // Headers section
                let headers_style = if state.mode == AppMode::EditInterceptHeaders {
                    Style::default().fg(theme.accent)
                } else {
                    Style::default().fg(theme.muted)
                };
                lines.push(Line::from(vec![
                    Span::styled("─── Headers ───", headers_style),
                    if state.mode != AppMode::EditInterceptHeaders && is_intercepted {
                        Span::styled(" (i to edit)", Style::default().fg(theme.muted).add_modifier(Modifier::DIM))
                    } else {
                        Span::raw("")
                    },
                ]));

                if state.mode == AppMode::EditInterceptHeaders {
                    // Show headers from editor with selection
                    for (idx, row) in state.intercept_headers_editor.rows.iter().enumerate() {
                        let is_selected = idx == state.intercept_headers_editor.selected_row;
                        let prefix = if is_selected { "▸ " } else { "  " };
                        let enabled_indicator = if row.enabled { "" } else { "[off] " };

                        let key_style = if is_selected && state.intercept_headers_editor.edit_column == Some(crate::tui::widgets::EditColumn::Key) {
                            Style::default().fg(theme.accent).add_modifier(Modifier::UNDERLINED)
                        } else if is_selected {
                            Style::default().fg(theme.info).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(theme.info)
                        };

                        let value_style = if is_selected && state.intercept_headers_editor.edit_column == Some(crate::tui::widgets::EditColumn::Value) {
                            Style::default().fg(theme.accent).add_modifier(Modifier::UNDERLINED)
                        } else if is_selected {
                            Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(theme.fg)
                        };

                        lines.push(Line::from(vec![
                            Span::styled(prefix, Style::default().fg(if is_selected { theme.accent } else { theme.muted })),
                            Span::styled(enabled_indicator, Style::default().fg(theme.warning)),
                            Span::styled(format!("{}: ", row.key.value), key_style),
                            Span::styled(&row.value.value, value_style),
                        ]));
                    }
                    lines.push(Line::from(Span::styled(
                        "  (o:add  d:delete  space:toggle  Enter:edit  Esc:done)",
                        Style::default().fg(theme.muted),
                    )));
                } else {
                    // Show headers read-only
                    let mut sorted_headers: Vec<_> = intercepted.headers.iter().collect();
                    sorted_headers.sort_by_key(|(k, _)| k.as_str());
                    for (key, value) in sorted_headers {
                        lines.push(Line::from(vec![
                            Span::styled(format!("{}: ", key), Style::default().fg(theme.info)),
                            Span::styled(value, Style::default().fg(theme.fg)),
                        ]));
                    }
                }

                // Body section
                let body_text = if state.mode == AppMode::EditInterceptBody {
                    state.intercept_body_input.clone()
                } else {
                    intercepted.body_text().unwrap_or_default()
                };

                if !body_text.is_empty() || state.mode == AppMode::EditInterceptBody {
                    lines.push(Line::from(""));
                    let body_style = if state.mode == AppMode::EditInterceptBody {
                        Style::default().fg(theme.accent)
                    } else {
                        Style::default().fg(theme.muted)
                    };
                    lines.push(Line::from(vec![
                        Span::styled("─── Body ───", body_style),
                        if state.mode != AppMode::EditInterceptBody && is_intercepted {
                            Span::styled(" (b to edit)", Style::default().fg(theme.muted).add_modifier(Modifier::DIM))
                        } else {
                            Span::raw("")
                        },
                    ]));

                    if state.mode == AppMode::EditInterceptBody {
                        // Show body with cursor
                        let mut display = state.intercept_body_input.clone();
                        let cursor_pos = state.intercept_body_cursor.min(display.len());
                        display.insert(cursor_pos, '▊');
                        for line in display.lines() {
                            lines.push(Line::from(line.to_string()));
                        }
                        lines.push(Line::from(Span::styled(
                            "  (Esc to finish editing)",
                            Style::default().fg(theme.muted),
                        )));
                    } else {
                        // Pretty print if JSON
                        let display_body = if body_text.trim().starts_with('{') || body_text.trim().starts_with('[') {
                            format_json_body(&body_text)
                        } else {
                            body_text.clone()
                        };

                        for line in display_body.lines() {
                            if body_text.trim().starts_with('{') || body_text.trim().starts_with('[') {
                                lines.push(colorize_json_line(line, theme));
                            } else {
                                lines.push(Line::from(line.to_string()));
                            }
                        }
                    }
                }

                (" Intercepted Request ", lines)
            } else if let Some(entry) = entry_opt {
                // Normal view from history entry
                let protocol = if entry.is_https { "HTTPS" } else { "HTTP" };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{} ", entry.method),
                        Style::default().fg(method_color(&entry.method)).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&entry.path, Style::default().fg(theme.fg)),
                    Span::styled(format!(" {} /1.1", protocol), Style::default().fg(theme.muted)),
                ]));

                lines.push(Line::from(vec![
                    Span::styled("Host: ", Style::default().fg(theme.muted)),
                    Span::styled(&entry.host, Style::default().fg(theme.info)),
                ]));

                lines.push(Line::from(""));

                // Headers
                lines.push(Line::from(Span::styled(
                    "─── Headers ───",
                    Style::default().fg(theme.muted),
                )));

                let mut sorted_headers: Vec<_> = entry.request_headers.iter().collect();
                sorted_headers.sort_by_key(|(k, _)| k.as_str());
                for (key, value) in sorted_headers {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}: ", key), Style::default().fg(theme.info)),
                        Span::styled(value, Style::default().fg(theme.fg)),
                    ]));
                }

                // Body
                if let Some(body) = &entry.request_body {
                    if !body.is_empty() {
                        lines.push(Line::from(""));
                        lines.push(Line::from(Span::styled(
                            "─── Body ───",
                            Style::default().fg(theme.muted),
                        )));

                        // Try to pretty-print JSON
                        let display_body = if body.trim().starts_with('{') || body.trim().starts_with('[') {
                            format_json_body(body)
                        } else {
                            body.clone()
                        };

                        for line in display_body.lines() {
                            if body.trim().starts_with('{') || body.trim().starts_with('[') {
                                lines.push(colorize_json_line(line, theme));
                            } else {
                                lines.push(Line::from(line.to_string()));
                            }
                        }
                    }
                }

                (" Request ", lines)
            } else {
                // No entry available
                (" Request ", vec![Line::from("No request selected")])
            }
        }
        ProxyDetailsTab::Response => {
            let mut lines = Vec::new();

            // Need an entry for response view
            let Some(entry) = entry_opt else {
                return;
            };

            // Status line
            let status = entry.status.unwrap_or(0);
            let status_color = match status {
                s if (200..300).contains(&s) => theme.success,
                s if (300..400).contains(&s) => theme.info,
                s if (400..500).contains(&s) => theme.warning,
                s if s >= 500 => theme.error,
                _ => theme.muted,
            };
            let status_text = match status {
                200 => "OK",
                201 => "Created",
                204 => "No Content",
                301 => "Moved Permanently",
                302 => "Found",
                304 => "Not Modified",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                500 => "Internal Server Error",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                _ => "Unknown",
            };

            lines.push(Line::from(vec![
                Span::styled("HTTP/1.1 ", Style::default().fg(theme.muted)),
                Span::styled(
                    format!("{} {}", status, status_text),
                    Style::default().fg(status_color).add_modifier(Modifier::BOLD),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("Size: ", Style::default().fg(theme.muted)),
                Span::styled(
                    entry.response_size.map(format_size).unwrap_or_else(|| "-".to_string()),
                    Style::default().fg(theme.fg),
                ),
                Span::styled("  Time: ", Style::default().fg(theme.muted)),
                Span::styled(
                    entry.duration_ms.map(|d| format!("{}ms", d)).unwrap_or_else(|| "-".to_string()),
                    Style::default().fg(theme.fg),
                ),
            ]));

            lines.push(Line::from(""));

            // Headers
            if let Some(headers) = &entry.response_headers {
                lines.push(Line::from(Span::styled(
                    "─── Headers ───",
                    Style::default().fg(theme.muted),
                )));

                let mut sorted_headers: Vec<_> = headers.iter().collect();
                sorted_headers.sort_by_key(|(k, _)| k.as_str());
                for (key, value) in sorted_headers {
                    lines.push(Line::from(vec![
                        Span::styled(format!("{}: ", key), Style::default().fg(theme.info)),
                        Span::styled(value, Style::default().fg(theme.fg)),
                    ]));
                }
            }

            // Body
            if let Some(body) = &entry.response_body {
                if !body.is_empty() {
                    lines.push(Line::from(""));
                    lines.push(Line::from(Span::styled(
                        "─── Body ───",
                        Style::default().fg(theme.muted),
                    )));

                    // Try to pretty-print JSON
                    let is_json = entry.content_type.as_ref()
                        .map(|ct| ct.contains("json"))
                        .unwrap_or(false)
                        || body.trim().starts_with('{')
                        || body.trim().starts_with('[');

                    let display_body = if is_json {
                        format_json_body(body)
                    } else {
                        body.clone()
                    };

                    for line in display_body.lines() {
                        if is_json {
                            lines.push(colorize_json_line(line, theme));
                        } else {
                            lines.push(Line::from(line.to_string()));
                        }
                    }
                }
            } else {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled("(no body)", Style::default().fg(theme.muted))));
            }

            (" Response ", lines)
        }
    };

    // Apply scroll
    let scroll_offset = state.proxy_details_scroll.min(content_lines.len().saturating_sub(1));
    let visible_lines: Vec<Line> = content_lines
        .into_iter()
        .skip(scroll_offset)
        .collect();

    // Create tabs
    let tabs = vec![
        if state.proxy_details_tab == ProxyDetailsTab::Request {
            Span::styled(" [Request] ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" Request ", Style::default().fg(theme.muted))
        },
        Span::styled(" | ", Style::default().fg(theme.border)),
        if state.proxy_details_tab == ProxyDetailsTab::Response {
            Span::styled("[Response] ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("Response ", Style::default().fg(theme.muted))
        },
    ];

    // Build title with tabs and keybindings
    let title_line = Line::from(vec![
        Span::styled(title, Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(theme.border)),
    ]).patch_style(Style::default());

    // Create block with tabs in title - use different hints for intercept mode
    let bottom_hints = if is_intercepted && !is_editing {
        Line::from(vec![
            Span::styled(" e", Style::default().fg(theme.info)),
            Span::styled(":url ", Style::default().fg(theme.muted)),
            Span::styled("m", Style::default().fg(theme.info)),
            Span::styled(":method ", Style::default().fg(theme.muted)),
            Span::styled("i", Style::default().fg(theme.info)),
            Span::styled(":headers ", Style::default().fg(theme.muted)),
            Span::styled("b", Style::default().fg(theme.info)),
            Span::styled(":body ", Style::default().fg(theme.muted)),
            Span::styled("f", Style::default().fg(theme.success)),
            Span::styled(":forward ", Style::default().fg(theme.muted)),
            Span::styled("x", Style::default().fg(theme.error)),
            Span::styled(":drop ", Style::default().fg(theme.muted)),
            Span::styled("Esc", Style::default().fg(theme.info)),
            Span::styled(":close ", Style::default().fg(theme.muted)),
        ])
    } else if is_editing {
        Line::from(vec![
            Span::styled(" Editing... ", Style::default().fg(theme.accent)),
            Span::styled("Esc", Style::default().fg(theme.info)),
            Span::styled(":done ", Style::default().fg(theme.muted)),
            Span::styled("Enter", Style::default().fg(theme.info)),
            Span::styled(":confirm ", Style::default().fg(theme.muted)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" Tab", Style::default().fg(theme.info)),
            Span::styled(":switch ", Style::default().fg(theme.muted)),
            Span::styled("r", Style::default().fg(theme.info)),
            Span::styled(":workspace ", Style::default().fg(theme.muted)),
            Span::styled("c", Style::default().fg(theme.info)),
            Span::styled(":curl ", Style::default().fg(theme.muted)),
            Span::styled("y", Style::default().fg(theme.info)),
            Span::styled(":copy ", Style::default().fg(theme.muted)),
            Span::styled("j/k", Style::default().fg(theme.info)),
            Span::styled(":scroll ", Style::default().fg(theme.muted)),
            Span::styled("Esc", Style::default().fg(theme.info)),
            Span::styled(":close ", Style::default().fg(theme.muted)),
        ])
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if is_intercepted { theme.warning } else { theme.accent }))
        .title(title_line)
        .title_bottom(bottom_hints);

    // Create inner area for tabs
    let inner = block.inner(area);

    // Split inner into tabs bar and content
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Tab bar
            Constraint::Min(0),    // Content
        ])
        .split(inner);

    // Render block
    frame.render_widget(block, area);

    // Render tab bar
    let tab_bar = Paragraph::new(Line::from(tabs));
    frame.render_widget(tab_bar, chunks[0]);

    // Render content with scroll
    let content = Paragraph::new(visible_lines)
        .wrap(ratatui::widgets::Wrap { trim: false });
    frame.render_widget(content, chunks[1]);

    // Render scrollbar if content overflows
    let content_height = chunks[1].height as usize;
    let total_lines = state.proxy_details_scroll + content_height;
    if total_lines > content_height {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut scrollbar_state = ScrollbarState::new(total_lines)
            .position(scroll_offset);
        frame.render_stateful_widget(scrollbar, chunks[1], &mut scrollbar_state);
    }
}

/// Render finding details dialog
fn render_finding_details_dialog(frame: &mut Frame, app: &App, theme: &Theme) {
    let state = app.state.read();

    // Get the selected finding
    let finding = match state.findings.get(state.selected_finding) {
        Some(f) => f,
        None => return,
    };

    // Create a centered dialog (80% x 80%)
    let area = centered_rect(80, 80, frame.area());

    // Clear background
    frame.render_widget(ratatui::widgets::Clear, area);

    // Severity color
    let severity_color = match finding.severity.to_lowercase().as_str() {
        "critical" => Color::Magenta,
        "high" => theme.error,
        "medium" => Color::Yellow,
        "low" => Color::Cyan,
        _ => theme.muted,
    };

    // Build content
    let mut lines = vec![
        // Header with severity
        Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(theme.muted)),
            Span::styled(
                finding.severity.to_uppercase(),
                Style::default().fg(severity_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Name: ", Style::default().fg(theme.muted)),
            Span::styled(&finding.name, Style::default().fg(theme.fg).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("URL: ", Style::default().fg(theme.muted)),
            Span::styled(&finding.url, Style::default().fg(theme.info)),
        ]),
        Line::from(""),
        // Description
        Line::from(Span::styled(
            "─── Description ───",
            Style::default().fg(theme.muted),
        )),
    ];
    for line in finding.description.lines() {
        lines.push(Line::from(line.to_string()));
    }

    lines.push(Line::from(""));

    // Evidence
    lines.push(Line::from(Span::styled(
        "─── Evidence ───",
        Style::default().fg(theme.muted),
    )));
    if let Some(evidence) = &finding.evidence {
        for line in evidence.lines() {
            lines.push(Line::from(Span::styled(line, Style::default().fg(theme.warning))));
        }
    } else {
        lines.push(Line::from(Span::styled("No evidence", Style::default().fg(theme.muted))));
    }

    lines.push(Line::from(""));

    // Remediation
    lines.push(Line::from(Span::styled(
        "─── Remediation ───",
        Style::default().fg(theme.muted),
    )));
    if let Some(remediation) = &finding.remediation {
        for line in remediation.lines() {
            lines.push(Line::from(Span::styled(line, Style::default().fg(theme.success))));
        }
    } else {
        lines.push(Line::from(Span::styled("No remediation info", Style::default().fg(theme.muted))));
    }

    // Create block
    let title = format!(" Finding {}/{} ", state.selected_finding + 1, state.findings.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(severity_color))
        .title(title)
        .title_bottom(Line::from(vec![
            Span::styled(" j/k", Style::default().fg(theme.info)),
            Span::styled(":prev/next ", Style::default().fg(theme.muted)),
            Span::styled("Esc", Style::default().fg(theme.info)),
            Span::styled(":close ", Style::default().fg(theme.muted)),
        ]));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Render content
    let content = Paragraph::new(lines)
        .wrap(ratatui::widgets::Wrap { trim: false });
    frame.render_widget(content, inner);
}

/// Format JSON body with pretty printing
fn format_json_body(body: &str) -> String {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        serde_json::to_string_pretty(&json).unwrap_or_else(|_| body.to_string())
    } else {
        body.to_string()
    }
}

/// Colorize a single JSON line for syntax highlighting
fn colorize_json_line(line: &str, theme: &Theme) -> Line<'static> {
    let line = line.to_string();
    let trimmed = line.trim();

    // Simple JSON syntax highlighting
    if trimmed.starts_with('"') && trimmed.contains(':') {
        // Key-value pair
        if let Some(colon_pos) = line.find(':') {
            let (key_part, value_part) = line.split_at(colon_pos);
            return Line::from(vec![
                Span::styled(key_part.to_string(), Style::default().fg(theme.info)),
                Span::styled(value_part.to_string(), Style::default().fg(theme.fg)),
            ]);
        }
    } else if trimmed.starts_with('"') {
        // String value
        return Line::from(Span::styled(line, Style::default().fg(theme.success)));
    } else if trimmed.parse::<f64>().is_ok() || trimmed.trim_end_matches(',').parse::<f64>().is_ok() {
        // Number
        return Line::from(Span::styled(line, Style::default().fg(theme.warning)));
    } else if trimmed == "true" || trimmed == "false" || trimmed == "true," || trimmed == "false,"
            || trimmed == "null" || trimmed == "null," {
        // Boolean/null
        return Line::from(Span::styled(line, Style::default().fg(theme.error)));
    }

    Line::from(line)
}

fn method_color(method: &str) -> Color {
    match method.to_uppercase().as_str() {
        "GET" => Color::Green,
        "POST" => Color::Blue,
        "PUT" => Color::Yellow,
        "PATCH" => Color::Rgb(255, 165, 0), // Orange
        "DELETE" => Color::Red,
        "HEAD" => Color::Cyan,
        "OPTIONS" => Color::Magenta,
        _ => Color::White,
    }
}

fn status_color(status: u16) -> Color {
    match status {
        200..=299 => Color::Green,
        300..=399 => Color::Cyan,
        400..=499 => Color::Yellow,
        500..=599 => Color::Red,
        _ => Color::White,
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
