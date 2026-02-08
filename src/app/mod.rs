//! Application core module
//!
//! Handles application lifecycle, state management, and coordination
//! between the TUI, proxy, scanner, and other subsystems.

mod config;
mod events;
mod state;

pub use config::{Config, ProxyConfig};
pub use events::AppEvent;
pub use state::{App, ApiKeyLocation, AppMode, AppState, AuthType, BodyContentType, CollectionItemType, Focus, FuzzerFocus, FuzzerPayloadSet, FuzzerSortBy, MainTab, ProxyDetailsTab, RequestEditorTab, RequestTabs, ResponseTab, SettingsSection, SpiderFocus};
