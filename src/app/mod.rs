//! Application core module
//!
//! Handles application lifecycle, state management, and coordination
//! between the TUI, proxy, scanner, and other subsystems.

mod config;
mod events;
mod state;

pub use config::{Config, GeneralConfig, ProxyConfig, ScannerConfig, ScriptingConfig, TuiConfig};
pub use events::{AppEvent, EventHandler};
pub use state::{App, ApiKeyLocation, AppMode, AppState, AuthType, BodyContentType, CollectionItemType, CollectionNavigationItem, CurrentResponse, Focus, FuzzerFocus, FuzzerPayloadSet, FuzzerSortBy, HistoryEntry, MainTab, ProxyDetailsTab, ProxyHistoryItem, BrowserFocus, BrowserMode, RequestEditorTab, ResponseTab, SettingsSection, SpiderFocus};
