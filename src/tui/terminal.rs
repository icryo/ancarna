//! Terminal setup and teardown

#![allow(dead_code)]

use anyhow::{bail, Result};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};

use crate::app::App;

/// Minimum terminal width
pub const MIN_WIDTH: u16 = 80;
/// Minimum terminal height
pub const MIN_HEIGHT: u16 = 24;

/// Terminal wrapper for TUI operations
pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    mouse_enabled: bool,
}

impl Tui {
    /// Create a new TUI instance
    pub fn new() -> Result<Self> {
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;

        Ok(Self {
            terminal,
            mouse_enabled: false,
        })
    }

    /// Check if terminal size meets minimum requirements
    pub fn check_size(&self) -> Result<()> {
        let size = self.terminal.size()?;
        if size.width < MIN_WIDTH || size.height < MIN_HEIGHT {
            bail!(
                "Terminal too small: {}x{} (minimum: {}x{})",
                size.width,
                size.height,
                MIN_WIDTH,
                MIN_HEIGHT
            );
        }
        Ok(())
    }

    /// Enter the TUI (setup terminal)
    pub fn enter(&mut self) -> Result<()> {
        // Check size before entering
        self.check_size()?;

        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;

        // Note: Panic hook is set up in main.rs - don't duplicate it here
        // as that would cause issues if enter() is called multiple times

        self.terminal.hide_cursor()?;
        self.terminal.clear()?;

        Ok(())
    }

    /// Enable mouse support
    pub fn enable_mouse(&mut self) -> Result<()> {
        if !self.mouse_enabled {
            execute!(io::stdout(), EnableMouseCapture)?;
            self.mouse_enabled = true;
        }
        Ok(())
    }

    /// Disable mouse support
    pub fn disable_mouse(&mut self) -> Result<()> {
        if self.mouse_enabled {
            execute!(io::stdout(), DisableMouseCapture)?;
            self.mouse_enabled = false;
        }
        Ok(())
    }

    /// Exit the TUI (restore terminal)
    pub fn exit(&mut self) -> Result<()> {
        if self.mouse_enabled {
            execute!(io::stdout(), DisableMouseCapture)?;
        }
        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;

        Ok(())
    }

    /// Draw the UI
    pub fn draw(&mut self, app: &App) -> Result<()> {
        self.terminal.draw(|frame| {
            super::render(frame, app);
        })?;

        Ok(())
    }

    /// Get terminal size
    pub fn size(&self) -> Result<(u16, u16)> {
        let size = self.terminal.size()?;
        Ok((size.width, size.height))
    }

    /// Check if size is valid
    pub fn is_size_valid(&self) -> bool {
        self.terminal
            .size()
            .map(|s| s.width >= MIN_WIDTH && s.height >= MIN_HEIGHT)
            .unwrap_or(false)
    }

    /// Force a full redraw
    pub fn force_redraw(&mut self) -> Result<()> {
        self.terminal.clear()?;
        Ok(())
    }

    /// Suspend the TUI to allow external programs to take over the terminal
    ///
    /// This properly exits the TUI state while keeping the Terminal alive.
    /// Call `resume()` to restore TUI after the external program exits.
    pub fn suspend(&mut self) -> Result<()> {
        // Disable mouse first if enabled
        if self.mouse_enabled {
            execute!(io::stdout(), DisableMouseCapture)?;
        }

        // Show cursor before leaving alternate screen
        self.terminal.show_cursor()?;

        // Leave alternate screen and disable raw mode
        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen)?;

        // Flush stdout to ensure terminal state is applied
        io::Write::flush(&mut io::stdout())?;

        Ok(())
    }

    /// Resume the TUI after an external program has finished
    ///
    /// This restores the TUI state and clears ratatui's internal buffers
    /// to ensure the next draw is a full redraw.
    pub fn resume(&mut self) -> Result<()> {
        // Re-enter alternate screen and enable raw mode
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;

        // Hide cursor
        self.terminal.hide_cursor()?;

        // Re-enable mouse if it was enabled before suspend
        if self.mouse_enabled {
            execute!(io::stdout(), EnableMouseCapture)?;
        }

        // CRITICAL: Clear ratatui's internal buffer state to force full redraw
        // This resets both the front and back buffers
        self.terminal.clear()?;

        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        // Best effort cleanup - try to restore terminal to normal state
        // This handles both normal exit and if we're in suspended state
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        if self.mouse_enabled {
            let _ = execute!(io::stdout(), DisableMouseCapture);
        }
        let _ = self.terminal.show_cursor();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_size_constants() {
        assert!(MIN_WIDTH >= 80);
        assert!(MIN_HEIGHT >= 24);
    }
}
