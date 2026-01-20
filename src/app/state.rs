//! Application state management

use anyhow::{Context, Result};
use crossterm::{execute, terminal};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::config::Config;
use super::events::{AppEvent, EventHandler};
use crate::http::HttpClient;
use crate::proxy::ProxyServer;
use crate::reporting::{ReportMetadata, ScanReport};
use crate::scanner::ScanEngine;
use crate::scope::ScopeManager;
use crate::tui::Tui;
use crate::workspace::Workspace;

/// Application running mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// Normal browsing/editing mode
    Normal,
    /// Editing URL in the URL bar
    EditUrl,
    /// Editing params/headers in key-value editor
    EditKeyValue,
    /// Editing request body
    EditBody,
    /// Editing auth fields
    EditAuth,
    /// Environment selector open
    SelectEnvironment,
    /// Response search mode
    SearchResponse,
    /// Viewing response
    ViewResponse,
    /// Proxy intercept mode (paused on request/response)
    Intercept,
    /// Running a scan
    Scanning,
    /// Fuzzing
    Fuzzing,
    /// Command palette open
    Command,
    /// Help dialog
    Help,
    /// Confirm delete dialog
    ConfirmDelete,
    /// Rename request/collection
    Rename,
    /// Filtering proxy history
    FilterProxy,
    /// Browser URL input dialog
    BrowserUrl,
    /// Proxy details dialog (full request/response view)
    ProxyDetails,
    /// Editing intercepted request URL
    EditInterceptUrl,
    /// Editing intercepted request method
    EditInterceptMethod,
    /// Editing intercepted request headers
    EditInterceptHeaders,
    /// Editing intercepted request body
    EditInterceptBody,
    /// Finding details dialog
    FindingDetails,
    /// Filtering findings with regex
    FilterFindings,
}

/// Current focus within the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    /// Workspace/collection tree
    Workspace,
    /// Request editor
    RequestEditor,
    /// Response viewer
    ResponseViewer,
    /// Proxy history
    ProxyHistory,
    /// Scan results/findings
    Findings,
    /// Fuzzer results
    FuzzerResults,
}

/// Main tab views
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MainTab {
    #[default]
    Browser,
    Workspace,
    Proxy,
    Scanner,
    Spider,
    Fuzzer,
    Settings,
}

impl MainTab {
    pub fn all() -> &'static [MainTab] {
        &[
            MainTab::Browser,
            MainTab::Workspace,
            MainTab::Proxy,
            MainTab::Scanner,
            MainTab::Spider,
            MainTab::Fuzzer,
            MainTab::Settings,
        ]
    }

    pub fn index(&self) -> usize {
        match self {
            MainTab::Browser => 0,
            MainTab::Workspace => 1,
            MainTab::Proxy => 2,
            MainTab::Scanner => 3,
            MainTab::Spider => 4,
            MainTab::Fuzzer => 5,
            MainTab::Settings => 6,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MainTab::Browser => "Browser",
            MainTab::Workspace => "Workspace",
            MainTab::Proxy => "Proxy",
            MainTab::Scanner => "Scanner",
            MainTab::Spider => "Spider",
            MainTab::Fuzzer => "Fuzzer",
            MainTab::Settings => "Settings",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            MainTab::Browser => MainTab::Workspace,
            MainTab::Workspace => MainTab::Proxy,
            MainTab::Proxy => MainTab::Scanner,
            MainTab::Scanner => MainTab::Spider,
            MainTab::Spider => MainTab::Fuzzer,
            MainTab::Fuzzer => MainTab::Settings,
            MainTab::Settings => MainTab::Browser,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            MainTab::Browser => MainTab::Settings,
            MainTab::Workspace => MainTab::Browser,
            MainTab::Proxy => MainTab::Workspace,
            MainTab::Scanner => MainTab::Proxy,
            MainTab::Spider => MainTab::Scanner,
            MainTab::Fuzzer => MainTab::Spider,
            MainTab::Settings => MainTab::Fuzzer,
        }
    }
}

/// Tab selection in proxy details dialog
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyDetailsTab {
    #[default]
    Request,
    Response,
}

/// Which section of an intercepted request is being edited
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterceptEditSection {
    #[default]
    Url,
    Method,
    Headers,
    Body,
}

/// Shared application state
pub struct AppState {
    /// Current application mode
    pub mode: AppMode,

    /// Current main tab
    pub current_tab: MainTab,

    /// Current TUI focus
    pub focus: Focus,

    /// Whether the application should quit
    pub should_quit: bool,

    /// Status message to display
    pub status_message: Option<String>,

    /// Status message timestamp (for auto-clear)
    pub status_timestamp: Option<std::time::Instant>,

    /// Proxy running state
    pub proxy_running: bool,

    /// Current scan progress (0.0 - 1.0)
    pub scan_progress: Option<f64>,

    /// Current request being edited/viewed
    pub current_request: Option<crate::http::Request>,

    /// Current response from last request
    pub current_response: Option<CurrentResponse>,

    /// Selected collection item index
    pub selected_collection_item: usize,

    /// Collection panel scroll offset
    pub collection_scroll: usize,

    /// Request panel scroll offset
    pub request_scroll: usize,

    /// Response panel scroll offset
    pub response_scroll: usize,

    /// Proxy history scroll position
    pub proxy_history_scroll: usize,

    /// URL input buffer (when editing)
    pub url_input: String,

    /// Cursor position in URL input (byte offset)
    pub url_cursor: usize,

    /// Command palette input buffer
    pub command_input: String,

    /// HTTP method for current request
    pub request_method: String,

    /// Is currently sending a request
    pub is_loading: bool,

    /// Request editor active tab
    pub request_editor_tab: RequestEditorTab,

    /// Query parameters editor state
    pub query_params: crate::tui::widgets::KeyValueEditorState,

    /// Headers editor state
    pub headers: crate::tui::widgets::KeyValueEditorState,

    /// Request body content
    pub body_content: String,

    /// Body content type
    pub body_content_type: BodyContentType,

    /// Selected environment index (0 = No Environment)
    pub selected_environment: usize,

    /// Whether environment selector popup is open
    pub env_selector_open: bool,

    /// Auth type for current request
    pub auth_type: AuthType,

    /// Auth credentials
    pub auth_username: String,
    pub auth_password: String,
    pub auth_token: String,
    pub auth_api_key_name: String,
    pub auth_api_key_value: String,
    pub auth_api_key_location: ApiKeyLocation,

    /// Currently focused auth field (0-based index within the auth type's fields)
    pub auth_field_index: usize,

    /// Request history (last N requests)
    pub request_history: Vec<HistoryEntry>,

    /// Selected history item
    pub selected_history_item: usize,

    /// Search query for response
    pub response_search: String,

    /// Search matches in response
    pub response_search_matches: Vec<(usize, usize)>, // (line, col)

    /// Current search match index
    pub current_search_match: usize,

    /// Response viewer tab
    pub response_tab: ResponseTab,

    /// Whether to show raw response (no formatting)
    pub response_raw_mode: bool,

    /// Whether history panel is focused (vs collection)
    pub history_focused: bool,

    /// Rename buffer
    pub rename_buffer: String,

    /// Item being renamed (collection index or history index)
    pub rename_target: Option<usize>,

    /// Delete confirmation target
    pub delete_target: Option<usize>,

    /// Proxy history entries (synced from proxy server)
    pub proxy_history: Vec<ProxyHistoryItem>,

    /// Selected proxy entry index
    pub selected_proxy_item: usize,

    /// Proxy filter text
    pub proxy_filter: String,

    /// Whether to show proxy details panel
    pub show_proxy_details: bool,

    /// Proxy details dialog state
    pub proxy_details_tab: ProxyDetailsTab,  // Request or Response
    pub proxy_details_scroll: usize,         // Scroll position within content

    /// Security findings from passive/active scanning
    pub findings: Vec<crate::scanner::Finding>,

    /// Selected finding index
    pub selected_finding: usize,

    /// Findings scroll offset
    pub findings_scroll: usize,

    /// Findings filter input (regex pattern, `!pattern` for exclusion)
    pub findings_filter: String,

    /// Cursor position in findings filter
    pub findings_filter_cursor: usize,

    /// Set of expanded host names in findings tree
    pub findings_expanded_hosts: std::collections::HashSet<String>,

    /// Currently selected host index (in filtered/sorted host list)
    pub findings_selected_host: usize,

    /// Currently selected finding index within the selected host (-1 means host itself is selected)
    pub findings_selected_within_host: Option<usize>,

    /// Whether intercept mode is enabled
    pub intercept_enabled: bool,

    /// Current intercepted request/response (if any)
    pub intercepted_request: Option<crate::proxy::InterceptedRequest>,

    /// Intercept queue count (pending requests)
    pub intercept_queue_count: usize,

    // ============ Intercept Editing State ============
    /// Current section being edited in intercept dialog
    pub intercept_edit_section: InterceptEditSection,

    /// Intercept URL edit buffer
    pub intercept_url_input: String,

    /// Cursor position in intercept URL
    pub intercept_url_cursor: usize,

    /// Intercept method edit buffer
    pub intercept_method_input: String,

    /// Cursor position in intercept method
    pub intercept_method_cursor: usize,

    /// Intercept headers editor state
    pub intercept_headers_editor: crate::tui::widgets::KeyValueEditorState,

    /// Intercept body edit buffer
    pub intercept_body_input: String,

    /// Cursor position in intercept body
    pub intercept_body_cursor: usize,

    // ============ Fuzzer UI State ============
    /// Raw request template with §markers§ for payload positions
    pub fuzzer_request_template: String,

    /// Selected attack mode
    pub fuzzer_attack_mode: crate::fuzzer::AttackMode,

    /// Selected built-in payload set
    pub fuzzer_payload_set: FuzzerPayloadSet,

    /// Custom payloads (one per line)
    pub fuzzer_custom_payloads: String,

    /// Fuzzer results
    pub fuzzer_results: Vec<crate::fuzzer::FuzzResult>,

    /// Selected result index
    pub fuzzer_selected_result: usize,

    /// Fuzzer results scroll offset
    pub fuzzer_results_scroll: usize,

    /// Current fuzzer state
    pub fuzzer_state: crate::fuzzer::FuzzerState,

    /// Fuzzer statistics
    pub fuzzer_stats: crate::fuzzer::FuzzerStats,

    /// How to sort results
    pub fuzzer_sort_by: FuzzerSortBy,

    /// Fuzzer focus area
    pub fuzzer_focus: FuzzerFocus,

    /// Max concurrent requests
    pub fuzzer_concurrency: usize,

    /// Delay between requests (ms)
    pub fuzzer_delay_ms: u64,

    // ============ Settings UI State ============
    /// Settings section focus
    pub settings_section: SettingsSection,

    /// Settings: Proxy port
    pub settings_proxy_port: u16,

    /// Settings: Scanner concurrency
    pub settings_scanner_concurrency: usize,

    /// Settings: Auto-save enabled
    pub settings_auto_save: bool,

    /// Settings: Auto-save interval (seconds)
    pub settings_auto_save_interval: u64,

    /// Settings: Theme (dark/light)
    pub settings_dark_theme: bool,

    /// Settings: Show request timing
    pub settings_show_timing: bool,

    /// Settings: Max history entries
    pub settings_max_history: usize,

    // ============ Scope State ============
    /// Scope manager for target scope enforcement
    pub scope_manager: ScopeManager,

    /// Whether to enforce scope on proxy
    pub scope_enforce_proxy: bool,

    /// Whether to enforce scope on scanner
    pub scope_enforce_scanner: bool,

    // ============ Browser UI State ============
    /// Browser capture results
    pub browser_captures: Vec<crate::browser::CaptureResult>,

    /// Selected capture index
    pub browser_selected_capture: usize,

    /// URL input for new capture
    pub browser_url_input: String,

    /// Current recon mode
    pub browser_mode: BrowserMode,

    /// Scan targets (hosts/CIDRs to scan)
    pub browser_scan_targets: String,

    /// Whether a scan is in progress
    pub browser_scanning: bool,

    /// Scan progress (current / total)
    pub browser_scan_progress: (usize, usize),

    /// Resolution preset index
    pub browser_resolution_idx: usize,

    /// Focus within recon view
    pub browser_focus: BrowserFocus,

    /// Last browsed URL (for display purposes)
    pub browser_last_url: Option<String>,

    /// Pending browser navigation URL (processed in main loop)
    pub browser_pending_navigation: Option<String>,

    // ============ Spider UI State ============
    /// Spider target URL input
    pub spider_url_input: String,

    /// Discovered URLs from spider
    pub spider_discovered: Vec<crate::spider::DiscoveredUrl>,

    /// Spider running state
    pub spider_state: crate::spider::SpiderState,

    /// Spider statistics
    pub spider_stats: crate::spider::SpiderStats,

    /// Selected discovered URL index
    pub spider_selected_url: usize,

    /// Focus within spider view
    pub spider_focus: SpiderFocus,

    /// Spider configuration (for UI display)
    pub spider_max_depth: usize,

    /// Spider max pages
    pub spider_max_pages: usize,

    /// Spider delay between requests (ms)
    pub spider_delay_ms: u64,
}

/// Browser mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserMode {
    Browse,
    #[default]
    InputUrl,
    InputScan,
}

/// Browser panel focus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserFocus {
    #[default]
    CapturesList,
    Details,
}

/// Spider panel focus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpiderFocus {
    #[default]
    UrlInput,
    Config,
    Results,
}

impl SpiderFocus {
    pub fn next(&self) -> Self {
        match self {
            SpiderFocus::UrlInput => SpiderFocus::Config,
            SpiderFocus::Config => SpiderFocus::Results,
            SpiderFocus::Results => SpiderFocus::UrlInput,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            SpiderFocus::UrlInput => SpiderFocus::Results,
            SpiderFocus::Config => SpiderFocus::UrlInput,
            SpiderFocus::Results => SpiderFocus::Config,
        }
    }
}

/// Settings section for navigation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsSection {
    #[default]
    Proxy,
    Scanner,
    General,
    About,
}

impl SettingsSection {
    pub fn all() -> &'static [SettingsSection] {
        &[
            SettingsSection::Proxy,
            SettingsSection::Scanner,
            SettingsSection::General,
            SettingsSection::About,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            SettingsSection::Proxy => "Proxy",
            SettingsSection::Scanner => "Scanner",
            SettingsSection::General => "General",
            SettingsSection::About => "About",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            SettingsSection::Proxy => SettingsSection::Scanner,
            SettingsSection::Scanner => SettingsSection::General,
            SettingsSection::General => SettingsSection::About,
            SettingsSection::About => SettingsSection::Proxy,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            SettingsSection::Proxy => SettingsSection::About,
            SettingsSection::Scanner => SettingsSection::Proxy,
            SettingsSection::General => SettingsSection::Scanner,
            SettingsSection::About => SettingsSection::General,
        }
    }
}

/// Simplified proxy history item for UI display
#[derive(Debug, Clone)]
pub struct ProxyHistoryItem {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub duration_ms: Option<u64>,
    pub response_size: Option<usize>,
    pub is_https: bool,
    pub content_type: Option<String>,
    pub request_headers: std::collections::HashMap<String, String>,
    pub request_body: Option<String>,
    pub response_headers: Option<std::collections::HashMap<String, String>>,
    pub response_body: Option<String>,
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthType {
    #[default]
    None,
    Basic,
    Bearer,
    ApiKey,
}

impl AuthType {
    pub fn all() -> &'static [AuthType] {
        &[AuthType::None, AuthType::Basic, AuthType::Bearer, AuthType::ApiKey]
    }

    pub fn name(&self) -> &'static str {
        match self {
            AuthType::None => "None",
            AuthType::Basic => "Basic",
            AuthType::Bearer => "Bearer",
            AuthType::ApiKey => "API Key",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            AuthType::None => AuthType::Basic,
            AuthType::Basic => AuthType::Bearer,
            AuthType::Bearer => AuthType::ApiKey,
            AuthType::ApiKey => AuthType::None,
        }
    }
}

/// API Key location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApiKeyLocation {
    #[default]
    Header,
    Query,
}

/// Response viewer tabs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseTab {
    #[default]
    Body,
    Headers,
    Cookies,
}

impl ResponseTab {
    pub fn all() -> &'static [ResponseTab] {
        &[ResponseTab::Body, ResponseTab::Headers, ResponseTab::Cookies]
    }

    pub fn name(&self) -> &'static str {
        match self {
            ResponseTab::Body => "Body",
            ResponseTab::Headers => "Headers",
            ResponseTab::Cookies => "Cookies",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ResponseTab::Body => ResponseTab::Headers,
            ResponseTab::Headers => ResponseTab::Cookies,
            ResponseTab::Cookies => ResponseTab::Body,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ResponseTab::Body => ResponseTab::Cookies,
            ResponseTab::Headers => ResponseTab::Body,
            ResponseTab::Cookies => ResponseTab::Headers,
        }
    }
}

/// Built-in payload set selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FuzzerPayloadSet {
    #[default]
    Custom,
    CommonPasswords,
    CommonUsernames,
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    DirectoryBruteforce,
}

impl FuzzerPayloadSet {
    pub fn all() -> &'static [FuzzerPayloadSet] {
        &[
            FuzzerPayloadSet::Custom,
            FuzzerPayloadSet::CommonPasswords,
            FuzzerPayloadSet::CommonUsernames,
            FuzzerPayloadSet::SqlInjection,
            FuzzerPayloadSet::Xss,
            FuzzerPayloadSet::PathTraversal,
            FuzzerPayloadSet::CommandInjection,
            FuzzerPayloadSet::DirectoryBruteforce,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            FuzzerPayloadSet::Custom => "Custom",
            FuzzerPayloadSet::CommonPasswords => "Common Passwords",
            FuzzerPayloadSet::CommonUsernames => "Common Usernames",
            FuzzerPayloadSet::SqlInjection => "SQL Injection",
            FuzzerPayloadSet::Xss => "XSS Payloads",
            FuzzerPayloadSet::PathTraversal => "Path Traversal",
            FuzzerPayloadSet::CommandInjection => "Command Injection",
            FuzzerPayloadSet::DirectoryBruteforce => "Directory Bruteforce",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            FuzzerPayloadSet::Custom => FuzzerPayloadSet::CommonPasswords,
            FuzzerPayloadSet::CommonPasswords => FuzzerPayloadSet::CommonUsernames,
            FuzzerPayloadSet::CommonUsernames => FuzzerPayloadSet::SqlInjection,
            FuzzerPayloadSet::SqlInjection => FuzzerPayloadSet::Xss,
            FuzzerPayloadSet::Xss => FuzzerPayloadSet::PathTraversal,
            FuzzerPayloadSet::PathTraversal => FuzzerPayloadSet::CommandInjection,
            FuzzerPayloadSet::CommandInjection => FuzzerPayloadSet::DirectoryBruteforce,
            FuzzerPayloadSet::DirectoryBruteforce => FuzzerPayloadSet::Custom,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            FuzzerPayloadSet::Custom => FuzzerPayloadSet::DirectoryBruteforce,
            FuzzerPayloadSet::CommonPasswords => FuzzerPayloadSet::Custom,
            FuzzerPayloadSet::CommonUsernames => FuzzerPayloadSet::CommonPasswords,
            FuzzerPayloadSet::SqlInjection => FuzzerPayloadSet::CommonUsernames,
            FuzzerPayloadSet::Xss => FuzzerPayloadSet::SqlInjection,
            FuzzerPayloadSet::PathTraversal => FuzzerPayloadSet::Xss,
            FuzzerPayloadSet::CommandInjection => FuzzerPayloadSet::PathTraversal,
            FuzzerPayloadSet::DirectoryBruteforce => FuzzerPayloadSet::CommandInjection,
        }
    }
}

/// How to sort fuzzer results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FuzzerSortBy {
    #[default]
    RequestNum,
    StatusCode,
    Length,
    Time,
    Interesting,
}

impl FuzzerSortBy {
    pub fn all() -> &'static [FuzzerSortBy] {
        &[
            FuzzerSortBy::RequestNum,
            FuzzerSortBy::StatusCode,
            FuzzerSortBy::Length,
            FuzzerSortBy::Time,
            FuzzerSortBy::Interesting,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            FuzzerSortBy::RequestNum => "Request #",
            FuzzerSortBy::StatusCode => "Status",
            FuzzerSortBy::Length => "Length",
            FuzzerSortBy::Time => "Time",
            FuzzerSortBy::Interesting => "Interesting",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            FuzzerSortBy::RequestNum => FuzzerSortBy::StatusCode,
            FuzzerSortBy::StatusCode => FuzzerSortBy::Length,
            FuzzerSortBy::Length => FuzzerSortBy::Time,
            FuzzerSortBy::Time => FuzzerSortBy::Interesting,
            FuzzerSortBy::Interesting => FuzzerSortBy::RequestNum,
        }
    }
}

/// Focus area within the Fuzzer tab
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FuzzerFocus {
    #[default]
    RequestTemplate,
    PayloadConfig,
    Results,
    ResultDetails,
}

impl FuzzerFocus {
    pub fn next(&self) -> Self {
        match self {
            FuzzerFocus::RequestTemplate => FuzzerFocus::PayloadConfig,
            FuzzerFocus::PayloadConfig => FuzzerFocus::Results,
            FuzzerFocus::Results => FuzzerFocus::ResultDetails,
            FuzzerFocus::ResultDetails => FuzzerFocus::RequestTemplate,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            FuzzerFocus::RequestTemplate => FuzzerFocus::ResultDetails,
            FuzzerFocus::PayloadConfig => FuzzerFocus::RequestTemplate,
            FuzzerFocus::Results => FuzzerFocus::PayloadConfig,
            FuzzerFocus::ResultDetails => FuzzerFocus::Results,
        }
    }
}

/// History entry for request history
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub timestamp: std::time::SystemTime,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub duration_ms: u64,
}

/// Request editor sub-tabs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequestEditorTab {
    #[default]
    Params,
    Headers,
    Body,
    Auth,
}

impl RequestEditorTab {
    pub fn all() -> &'static [RequestEditorTab] {
        &[
            RequestEditorTab::Params,
            RequestEditorTab::Headers,
            RequestEditorTab::Body,
            RequestEditorTab::Auth,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            RequestEditorTab::Params => "Params",
            RequestEditorTab::Headers => "Headers",
            RequestEditorTab::Body => "Body",
            RequestEditorTab::Auth => "Auth",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            RequestEditorTab::Params => RequestEditorTab::Headers,
            RequestEditorTab::Headers => RequestEditorTab::Body,
            RequestEditorTab::Body => RequestEditorTab::Auth,
            RequestEditorTab::Auth => RequestEditorTab::Params,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            RequestEditorTab::Params => RequestEditorTab::Auth,
            RequestEditorTab::Headers => RequestEditorTab::Params,
            RequestEditorTab::Body => RequestEditorTab::Headers,
            RequestEditorTab::Auth => RequestEditorTab::Body,
        }
    }
}

/// Body content type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyContentType {
    #[default]
    None,
    Json,
    FormUrlEncoded,
    FormData,
    Raw,
}

/// Simplified response for display
#[derive(Debug, Clone)]
pub struct CurrentResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
    pub size: usize,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            mode: AppMode::Normal,
            current_tab: MainTab::default(),
            focus: Focus::Workspace,
            should_quit: false,
            status_message: None,
            status_timestamp: None,
            proxy_running: false,
            scan_progress: None,
            current_request: None,
            current_response: None,
            selected_collection_item: 0,
            collection_scroll: 0,
            request_scroll: 0,
            response_scroll: 0,
            proxy_history_scroll: 0,
            url_input: String::new(),
            url_cursor: 0,
            command_input: String::new(),
            request_method: "GET".to_string(),
            is_loading: false,
            request_editor_tab: RequestEditorTab::default(),
            query_params: crate::tui::widgets::KeyValueEditorState::new(),
            headers: crate::tui::widgets::KeyValueEditorState::new(),
            body_content: String::new(),
            body_content_type: BodyContentType::default(),
            selected_environment: 0,
            env_selector_open: false,
            auth_type: AuthType::default(),
            auth_username: String::new(),
            auth_password: String::new(),
            auth_token: String::new(),
            auth_api_key_name: String::new(),
            auth_api_key_value: String::new(),
            auth_api_key_location: ApiKeyLocation::default(),
            auth_field_index: 0,
            request_history: Vec::new(),
            selected_history_item: 0,
            response_search: String::new(),
            response_search_matches: Vec::new(),
            current_search_match: 0,
            response_tab: ResponseTab::default(),
            response_raw_mode: false,
            history_focused: false,
            rename_buffer: String::new(),
            rename_target: None,
            delete_target: None,
            proxy_history: Vec::new(),
            selected_proxy_item: 0,
            proxy_filter: String::new(),
            show_proxy_details: false,
            proxy_details_tab: ProxyDetailsTab::default(),
            proxy_details_scroll: 0,
            findings: Vec::new(),
            selected_finding: 0,
            findings_scroll: 0,
            findings_filter: String::new(),
            findings_filter_cursor: 0,
            findings_expanded_hosts: std::collections::HashSet::new(),
            findings_selected_host: 0,
            findings_selected_within_host: None,
            intercept_enabled: false,
            intercepted_request: None,
            intercept_queue_count: 0,
            // Intercept editing state
            intercept_edit_section: InterceptEditSection::default(),
            intercept_url_input: String::new(),
            intercept_url_cursor: 0,
            intercept_method_input: String::new(),
            intercept_method_cursor: 0,
            intercept_headers_editor: crate::tui::widgets::KeyValueEditorState::default(),
            intercept_body_input: String::new(),
            intercept_body_cursor: 0,
            // Fuzzer UI state
            fuzzer_request_template: String::new(),
            fuzzer_attack_mode: crate::fuzzer::AttackMode::Sniper,
            fuzzer_payload_set: FuzzerPayloadSet::default(),
            fuzzer_custom_payloads: String::new(),
            fuzzer_results: Vec::new(),
            fuzzer_selected_result: 0,
            fuzzer_results_scroll: 0,
            fuzzer_state: crate::fuzzer::FuzzerState::Idle,
            fuzzer_stats: crate::fuzzer::FuzzerStats::default(),
            fuzzer_sort_by: FuzzerSortBy::default(),
            fuzzer_focus: FuzzerFocus::default(),
            fuzzer_concurrency: 10,
            fuzzer_delay_ms: 0,
            // Settings UI state
            settings_section: SettingsSection::default(),
            settings_proxy_port: 8080,
            settings_scanner_concurrency: 5,
            settings_auto_save: true,
            settings_auto_save_interval: 60,
            settings_dark_theme: true,
            settings_show_timing: true,
            settings_max_history: 100,
            // Scope state
            scope_manager: ScopeManager::default(),
            scope_enforce_proxy: true,
            scope_enforce_scanner: true,
            // Browser UI state
            browser_captures: Vec::new(),
            browser_selected_capture: 0,
            browser_url_input: String::new(),
            browser_mode: BrowserMode::default(),
            browser_scan_targets: String::new(),
            browser_scanning: false,
            browser_scan_progress: (0, 0),
            browser_resolution_idx: 0,
            browser_focus: BrowserFocus::default(),
            browser_last_url: None,
            browser_pending_navigation: None,
            // Spider UI state
            spider_url_input: String::new(),
            spider_discovered: Vec::new(),
            spider_state: crate::spider::SpiderState::Idle,
            spider_stats: crate::spider::SpiderStats {
                visited: 0,
                queued: 0,
                discovered: 0,
            },
            spider_selected_url: 0,
            spider_focus: SpiderFocus::default(),
            spider_max_depth: 5,
            spider_max_pages: 1000,
            spider_delay_ms: 100,
        }
    }
}

/// Main application struct
pub struct App {
    /// Application configuration
    pub config: Config,

    /// Shared application state
    pub state: Arc<RwLock<AppState>>,

    /// HTTP client
    pub http_client: HttpClient,

    /// Proxy server
    pub proxy: Option<ProxyServer>,

    /// Scan engine
    pub scanner: ScanEngine,

    /// Current workspace
    pub workspace: Workspace,

    /// Spider instance
    pub spider: Option<crate::spider::Spider>,

    /// Event channel sender
    event_tx: mpsc::Sender<AppEvent>,

    /// Event channel receiver
    event_rx: mpsc::Receiver<AppEvent>,

    /// Proxy port
    proxy_port: u16,
}

impl App {
    /// Create a new application instance
    pub async fn new(config: Config, proxy_port: u16) -> Result<Self> {
        let (event_tx, event_rx) = mpsc::channel(256);

        let http_client = HttpClient::new(&config)?;
        let scanner = ScanEngine::new(&config);
        let workspace = Workspace::new(&config)?;

        // Load session data
        let session = crate::session::SessionData::load_or_default();

        // Create state with session data applied
        let mut state = AppState::default();
        Self::apply_session_to_state(&mut state, &session);

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(state)),
            http_client,
            proxy: None,
            scanner,
            workspace,
            spider: None,
            event_tx,
            event_rx,
            proxy_port,
        })
    }

    /// Apply loaded session data to app state
    fn apply_session_to_state(state: &mut AppState, session: &crate::session::SessionData) {
        // Restore last URL and method
        if let Some(url) = &session.last_url {
            state.url_input = url.clone();
        }
        if let Some(method) = &session.last_method {
            state.request_method = method.clone();
        }

        // Restore fuzzer template
        if let Some(template) = &session.fuzzer_template {
            state.fuzzer_request_template = template.clone();
        }

        // Restore request history
        for entry in &session.request_history {
            state.request_history.push(HistoryEntry {
                method: entry.method.clone(),
                url: entry.url.clone(),
                status: entry.status,
                duration_ms: entry.duration_ms.unwrap_or(0),
                timestamp: entry.timestamp,
            });
        }

        // Restore active environment index
        if let Some(idx) = session.active_environment {
            state.selected_environment = idx;
        }

        tracing::debug!("Session applied: {} history entries",
            state.request_history.len());
    }

    /// Save current session state
    pub fn save_session(&self) -> Result<()> {
        let state = self.state.read();

        let mut session = crate::session::SessionData::new();

        // Save last URL and method
        if !state.url_input.is_empty() {
            session.last_url = Some(state.url_input.clone());
        }
        session.last_method = Some(state.request_method.clone());

        // Save fuzzer template
        if !state.fuzzer_request_template.is_empty() {
            session.fuzzer_template = Some(state.fuzzer_request_template.clone());
        }

        // Save request history
        for entry in &state.request_history {
            session.request_history.push(crate::session::HistoryEntry {
                timestamp: entry.timestamp,
                method: entry.method.clone(),
                url: entry.url.clone(),
                status: entry.status,
                duration_ms: Some(entry.duration_ms),
                response_size: None,
                headers: Vec::new(),
                body: None,
            });
        }

        // Save active environment index
        session.active_environment = Some(state.selected_environment);

        drop(state); // Release lock before saving

        session.save_default()?;
        tracing::info!("Session saved");
        Ok(())
    }

    /// Run the application in TUI mode
    pub async fn run_tui(&mut self) -> Result<()> {
        // Initialize terminal
        let mut tui = Tui::new()?;
        tui.enter()?;

        // Start proxy server
        self.start_proxy().await?;

        // Create event handler
        let event_handler = EventHandler::new(self.event_tx.clone());

        // Main event loop
        let result = self.main_loop(&mut tui, event_handler).await;

        // Save session before exiting
        if let Err(e) = self.save_session() {
            tracing::error!("Failed to save session: {}", e);
        }

        // Cleanup
        self.stop_proxy().await?;
        tui.exit()?;

        result
    }

    /// Run the application in headless mode
    pub async fn run_headless(
        &mut self,
        target: Option<&str>,
        script: Option<&str>,
    ) -> Result<()> {
        // Start proxy if needed
        self.start_proxy().await?;

        if let Some(script_path) = script {
            // Execute script
            tracing::info!("Executing script: {}", script_path);
            self.execute_script(script_path).await?;
        } else if let Some(target_url) = target {
            // Quick scan mode
            tracing::info!("Starting scan of: {}", target_url);
            self.quick_scan(target_url).await?;
        } else {
            tracing::warn!("Headless mode requires --target or --script");
        }

        self.stop_proxy().await?;
        Ok(())
    }

    /// Main TUI event loop
    async fn main_loop(
        &mut self,
        tui: &mut Tui,
        mut event_handler: EventHandler,
    ) -> Result<()> {
        let mut last_sync = std::time::Instant::now();

        loop {
            // Check if we should quit
            if self.state.read().should_quit {
                break;
            }

            // Clear old status messages (after 5 seconds)
            {
                let mut state = self.state.write();
                if let Some(timestamp) = state.status_timestamp {
                    if timestamp.elapsed() > std::time::Duration::from_secs(5) {
                        state.status_message = None;
                        state.status_timestamp = None;
                    }
                }
            }

            // Sync proxy history periodically (every 500ms)
            if last_sync.elapsed() > std::time::Duration::from_millis(500) {
                self.sync_proxy_history();
                last_sync = std::time::Instant::now();
            }

            // Process pending browser navigation with carbonyl
            // Using exact lazywitness approach - direct crossterm calls
            let pending_nav = self.state.read().browser_pending_navigation.clone();
            if let Some(url) = pending_nav {
                {
                    let mut state = self.state.write();
                    state.browser_pending_navigation = None;
                }

                tracing::info!("Launching carbonyl for: {} (proxy_port={})", url, self.proxy_port);

                // Launch carbonyl in a separate tmux window
                let result = crate::browser::launch_carbonyl(&url, self.proxy_port);

                match result {
                    Ok(()) => {
                        let mut state = self.state.write();
                        state.status_message = Some("Browser opened in tmux window. Press Ctrl-b n to switch.".to_string());
                        state.status_timestamp = Some(std::time::Instant::now());
                    }
                    Err(e) => {
                        let mut state = self.state.write();
                        state.status_message = Some(format!("Browser error: {}", e));
                        state.status_timestamp = Some(std::time::Instant::now());
                    }
                }
            }

            // Draw UI
            tui.draw(self)?;

            // Handle events
            if let Some(event) = event_handler.next().await {
                self.handle_event(event).await?;
            }
        }

        Ok(())
    }

    /// Handle an application event
    async fn handle_event(&mut self, event: AppEvent) -> Result<()> {
        match event {
            AppEvent::Quit => {
                self.state.write().should_quit = true;
            }
            AppEvent::Key(key) => {
                self.handle_key(key).await?;
            }
            AppEvent::Resize(width, height) => {
                tracing::debug!("Terminal resized to {}x{}", width, height);
            }
            AppEvent::ProxyRequest(req) => {
                self.handle_proxy_request(req).await?;
            }
            AppEvent::ScanProgress(progress) => {
                self.state.write().scan_progress = Some(progress);
            }
            AppEvent::ScanComplete(findings) => {
                self.state.write().scan_progress = None;
                tracing::info!("Scan complete with {} findings", findings.len());
            }
            AppEvent::Error(msg) => {
                let mut state = self.state.write();
                state.status_message = Some(format!("Error: {}", msg));
                state.status_timestamp = Some(std::time::Instant::now());
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keyboard input
    async fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        use crossterm::event::{KeyCode, KeyModifiers};

        // Check for Enter key actions (needs to be outside lock for async/mutable operations)
        if key.code == KeyCode::Enter && key.modifiers.is_empty() {
            let (focus, mode, url_empty, is_loading, selected_idx, current_tab, browser_mode) = {
                let state = self.state.read();
                (
                    state.focus,
                    state.mode,
                    state.url_input.is_empty(),
                    state.is_loading,
                    state.selected_collection_item,
                    state.current_tab,
                    state.browser_mode,
                )
            };

            // Skip early Enter handling if in Browser input mode - let it fall through to handle_normal_mode_key
            if current_tab == MainTab::Browser && browser_mode != BrowserMode::Browse {
                // Fall through to normal mode handling which handles Browser input
            }
            // Spider tab: start crawling
            else if current_tab == MainTab::Spider && mode == AppMode::Normal {
                self.start_spider().await?;
                return Ok(());
            }
            // Fuzzer tab: start fuzzing
            else if current_tab == MainTab::Fuzzer && mode == AppMode::Normal {
                self.start_fuzzer().await?;
                return Ok(());
            }
            // Scanner tab: expand/collapse host in findings tree
            else if current_tab == MainTab::Scanner && mode == AppMode::Normal && focus == Focus::Findings {
                let mut state = self.state.write();
                let (hosts, _) = crate::tui::group_findings_by_host(&state.findings, &state.findings_filter);
                if let Some(host) = hosts.get(state.findings_selected_host).cloned() {
                    if state.findings_expanded_hosts.contains(&host) {
                        state.findings_expanded_hosts.remove(&host);
                        // If we were inside this host, move to host level
                        state.findings_selected_within_host = None;
                    } else {
                        state.findings_expanded_hosts.insert(host);
                    }
                }
                return Ok(());
            }
            // In Workspace focus: load selected request or history item
            else if mode == AppMode::Normal && focus == Focus::Workspace {
                let history_focused = {
                    self.state.read().history_focused
                };
                if history_focused {
                    let history_idx = {
                        self.state.read().selected_history_item
                    };
                    self.load_history_entry(history_idx);
                } else {
                    self.load_request_at_index(selected_idx);
                }
                return Ok(());
            }

            // In RequestEditor focus with URL: send request
            else if mode == AppMode::Normal && focus == Focus::RequestEditor && !url_empty && !is_loading {
                self.send_current_request().await?;
                return Ok(());
            }
        }

        let mut state = self.state.write();

        match (key.modifiers, key.code) {
            // Global shortcuts
            (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
                state.should_quit = true;
            }
            (KeyModifiers::CONTROL, KeyCode::Char('q')) => {
                state.should_quit = true;
            }

            // Mode-specific handling
            _ => {
                match state.mode {
                    AppMode::Normal => {
                        drop(state); // Release lock before calling handler
                        let mut state = self.state.write();
                        self.handle_normal_mode_key(key, &mut state)?;
                    }
                    AppMode::EditUrl => {
                        self.handle_edit_url_key(key, &mut state)?;
                    }
                    AppMode::EditKeyValue => {
                        self.handle_edit_keyvalue_key(key, &mut state)?;
                    }
                    AppMode::EditBody => {
                        self.handle_edit_body_key(key, &mut state)?;
                    }
                    AppMode::EditAuth => {
                        self.handle_edit_auth_key(key, &mut state)?;
                    }
                    AppMode::SelectEnvironment => {
                        self.handle_env_selector_key(key, &mut state)?;
                    }
                    AppMode::SearchResponse => {
                        self.handle_search_key(key, &mut state)?;
                    }
                    AppMode::Help => {
                        // Esc or ? to close help
                        if key.code == KeyCode::Esc || key.code == KeyCode::Char('?') {
                            state.mode = AppMode::Normal;
                        }
                    }
                    AppMode::Command => {
                        match key.code {
                            KeyCode::Esc => {
                                state.command_input.clear();
                                state.mode = AppMode::Normal;
                            }
                            KeyCode::Enter => {
                                let cmd = state.command_input.clone();
                                state.command_input.clear();
                                state.mode = AppMode::Normal;
                                drop(state);
                                self.execute_command(&cmd)?;
                                return Ok(());
                            }
                            KeyCode::Backspace => {
                                state.command_input.pop();
                            }
                            KeyCode::Char(c) => {
                                state.command_input.push(c);
                            }
                            _ => {}
                        }
                    }
                    AppMode::ConfirmDelete => {
                        drop(state); // Release lock before calling handler
                        self.handle_confirm_delete(key)?;
                    }
                    AppMode::Rename => {
                        drop(state); // Release lock before calling handler
                        self.handle_rename(key)?;
                    }
                    AppMode::FilterProxy => {
                        self.handle_filter_proxy_key(key, &mut state)?;
                    }
                    AppMode::BrowserUrl => {
                        self.handle_browser_url_key(key, &mut state)?;
                    }
                    AppMode::ProxyDetails => {
                        self.handle_proxy_details_key(key, &mut state)?;
                    }
                    AppMode::EditInterceptUrl => {
                        self.handle_edit_intercept_url_key(key, &mut state)?;
                    }
                    AppMode::EditInterceptMethod => {
                        self.handle_edit_intercept_method_key(key, &mut state)?;
                    }
                    AppMode::EditInterceptHeaders => {
                        self.handle_edit_intercept_headers_key(key, &mut state)?;
                    }
                    AppMode::EditInterceptBody => {
                        self.handle_edit_intercept_body_key(key, &mut state)?;
                    }
                    AppMode::FindingDetails => {
                        self.handle_finding_details_key(key, &mut state)?;
                    }
                    AppMode::FilterFindings => {
                        self.handle_filter_findings_key(key, &mut state)?;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Handle keys in proxy details dialog mode
    fn handle_proxy_details_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::{KeyCode, KeyModifiers};

        match key.code {
            // Close dialog
            KeyCode::Esc | KeyCode::Char('q') => {
                state.mode = AppMode::Normal;
            }
            // Switch tabs with Tab or h/l
            KeyCode::Tab | KeyCode::Char('l') | KeyCode::Right => {
                state.proxy_details_tab = match state.proxy_details_tab {
                    ProxyDetailsTab::Request => ProxyDetailsTab::Response,
                    ProxyDetailsTab::Response => ProxyDetailsTab::Request,
                };
                state.proxy_details_scroll = 0;
            }
            KeyCode::BackTab | KeyCode::Char('h') | KeyCode::Left => {
                state.proxy_details_tab = match state.proxy_details_tab {
                    ProxyDetailsTab::Request => ProxyDetailsTab::Response,
                    ProxyDetailsTab::Response => ProxyDetailsTab::Request,
                };
                state.proxy_details_scroll = 0;
            }
            // Scroll down
            KeyCode::Char('j') | KeyCode::Down => {
                state.proxy_details_scroll = state.proxy_details_scroll.saturating_add(1);
            }
            // Scroll up
            KeyCode::Char('k') | KeyCode::Up => {
                state.proxy_details_scroll = state.proxy_details_scroll.saturating_sub(1);
            }
            // Page down
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.proxy_details_scroll = state.proxy_details_scroll.saturating_add(20);
            }
            KeyCode::PageDown => {
                state.proxy_details_scroll = state.proxy_details_scroll.saturating_add(20);
            }
            // Page up
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.proxy_details_scroll = state.proxy_details_scroll.saturating_sub(20);
            }
            KeyCode::PageUp => {
                state.proxy_details_scroll = state.proxy_details_scroll.saturating_sub(20);
            }
            // Go to top
            KeyCode::Char('g') => {
                state.proxy_details_scroll = 0;
            }
            // Go to bottom
            KeyCode::Char('G') => {
                state.proxy_details_scroll = usize::MAX / 2;
            }
            // Send to workspace (r = repeat/send to repeater)
            KeyCode::Char('r') => {
                if let Some(entry) = state.proxy_history.get(state.selected_proxy_item) {
                    // Populate workspace with this request
                    state.url_input = entry.url.clone();
                    state.request_method = entry.method.clone();

                    // Copy headers
                    state.headers.rows.clear();
                    for (key, value) in &entry.request_headers {
                        state.headers.rows.push(
                            crate::tui::widgets::KeyValueRow::with_key_value(key, value)
                        );
                    }

                    // Copy body if present
                    if let Some(body) = &entry.request_body {
                        state.body_content = body.clone();
                    }

                    // Switch to workspace tab
                    state.current_tab = MainTab::Workspace;
                    state.mode = AppMode::Normal;
                    state.status_message = Some("Request sent to Workspace".to_string());
                }
            }
            // Copy as cURL
            KeyCode::Char('c') => {
                if let Some(entry) = state.proxy_history.get(state.selected_proxy_item) {
                    let curl = self.entry_to_curl(entry);
                    if let Err(e) = self.copy_to_clipboard(&curl) {
                        state.status_message = Some(format!("Copy failed: {}", e));
                    } else {
                        state.status_message = Some("Copied as cURL".to_string());
                    }
                }
            }
            // Copy raw request/response
            KeyCode::Char('y') => {
                if let Some(entry) = state.proxy_history.get(state.selected_proxy_item) {
                    let raw = match state.proxy_details_tab {
                        ProxyDetailsTab::Request => self.entry_to_raw_request(entry),
                        ProxyDetailsTab::Response => self.entry_to_raw_response(entry),
                    };
                    if let Err(e) = self.copy_to_clipboard(&raw) {
                        state.status_message = Some(format!("Copy failed: {}", e));
                    } else {
                        let what = match state.proxy_details_tab {
                            ProxyDetailsTab::Request => "request",
                            ProxyDetailsTab::Response => "response",
                        };
                        state.status_message = Some(format!("Copied raw {}", what));
                    }
                }
            }
            // Edit URL (e) - only for intercepted requests
            KeyCode::Char('e') if state.intercepted_request.is_some() && state.proxy_details_tab == ProxyDetailsTab::Request => {
                if let Some(ref req) = state.intercepted_request {
                    state.intercept_url_input = req.url.clone();
                    state.intercept_url_cursor = state.intercept_url_input.len();
                    state.intercept_edit_section = InterceptEditSection::Url;
                    state.mode = AppMode::EditInterceptUrl;
                }
            }
            // Edit method (m) - only for intercepted requests
            KeyCode::Char('m') if state.intercepted_request.is_some() && state.proxy_details_tab == ProxyDetailsTab::Request => {
                if let Some(ref req) = state.intercepted_request {
                    state.intercept_method_input = req.method.clone();
                    state.intercept_method_cursor = state.intercept_method_input.len();
                    state.intercept_edit_section = InterceptEditSection::Method;
                    state.mode = AppMode::EditInterceptMethod;
                }
            }
            // Edit headers (i when on headers section) - only for intercepted requests
            KeyCode::Char('i') if state.intercepted_request.is_some() && state.proxy_details_tab == ProxyDetailsTab::Request => {
                if let Some(ref req) = state.intercepted_request {
                    // Initialize headers editor from intercepted request
                    state.intercept_headers_editor.rows.clear();
                    for (key, value) in &req.headers {
                        state.intercept_headers_editor.rows.push(
                            crate::tui::widgets::KeyValueRow::with_key_value(key, value)
                        );
                    }
                    state.intercept_headers_editor.selected_row = 0;
                    state.intercept_edit_section = InterceptEditSection::Headers;
                    state.mode = AppMode::EditInterceptHeaders;
                }
            }
            // Edit body (b) - only for intercepted requests
            KeyCode::Char('b') if state.intercepted_request.is_some() && state.proxy_details_tab == ProxyDetailsTab::Request => {
                if let Some(ref req) = state.intercepted_request {
                    state.intercept_body_input = req.body_text().unwrap_or_default();
                    state.intercept_body_cursor = state.intercept_body_input.len();
                    state.intercept_edit_section = InterceptEditSection::Body;
                    state.mode = AppMode::EditInterceptBody;
                }
            }
            // Forward intercepted request (f)
            KeyCode::Char('f') if state.intercepted_request.is_some() => {
                // Sync any edits back to the intercepted request before forwarding
                self.sync_intercept_edits(state);
                if let Some(req) = state.intercepted_request.take() {
                    // Resolve the intercept to allow proxy to continue
                    self.resolve_intercept(req.id, crate::proxy::InterceptDecision {
                        forward: true,
                        request: req,
                    });
                }
                state.mode = AppMode::Normal;
                state.status_message = Some("Request forwarded".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }
            // Drop intercepted request (x)
            KeyCode::Char('x') if state.intercepted_request.is_some() => {
                if let Some(mut req) = state.intercepted_request.take() {
                    req.drop = true;
                    // Resolve the intercept with drop decision
                    self.resolve_intercept(req.id, crate::proxy::InterceptDecision {
                        forward: false,
                        request: req,
                    });
                }
                state.mode = AppMode::Normal;
                state.status_message = Some("Request dropped".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle keys in finding details dialog mode
    fn handle_finding_details_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            // Close dialog
            KeyCode::Esc | KeyCode::Char('q') => {
                state.mode = AppMode::Normal;
            }
            // Navigate to previous finding
            KeyCode::Char('k') | KeyCode::Up => {
                if state.selected_finding > 0 {
                    state.selected_finding -= 1;
                }
            }
            // Navigate to next finding
            KeyCode::Char('j') | KeyCode::Down => {
                if state.selected_finding < state.findings.len().saturating_sub(1) {
                    state.selected_finding += 1;
                }
            }
            // Scroll down
            KeyCode::Char('d') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                state.findings_scroll = state.findings_scroll.saturating_add(10);
            }
            // Scroll up
            KeyCode::Char('u') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                state.findings_scroll = state.findings_scroll.saturating_sub(10);
            }
            _ => {}
        }
        Ok(())
    }

    /// Sync edit buffers back to the intercepted request
    fn sync_intercept_edits(&self, state: &mut AppState) {
        if let Some(ref mut req) = state.intercepted_request {
            // Only sync if we've been editing
            if !state.intercept_url_input.is_empty() && state.intercept_url_input != req.url {
                req.url = state.intercept_url_input.clone();
                req.modified = true;
            }
            if !state.intercept_method_input.is_empty() && state.intercept_method_input != req.method {
                req.method = state.intercept_method_input.clone();
                req.modified = true;
            }
            // Sync headers from editor
            if !state.intercept_headers_editor.rows.is_empty() {
                let mut new_headers = std::collections::HashMap::new();
                for row in &state.intercept_headers_editor.rows {
                    if row.enabled && !row.key.value.is_empty() {
                        new_headers.insert(row.key.value.clone(), row.value.value.clone());
                    }
                }
                if new_headers != req.headers {
                    req.headers = new_headers;
                    req.modified = true;
                }
            }
            // Sync body
            if !state.intercept_body_input.is_empty() {
                let current_body = req.body_text().unwrap_or_default();
                if state.intercept_body_input != current_body {
                    req.set_body_text(&state.intercept_body_input);
                }
            }
        }
    }

    /// Handle keys when editing intercepted request URL
    fn handle_edit_intercept_url_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                // Sync URL back to intercepted request
                if let Some(ref mut req) = state.intercepted_request {
                    if state.intercept_url_input != req.url {
                        req.url = state.intercept_url_input.clone();
                        req.modified = true;
                    }
                }
                state.mode = AppMode::ProxyDetails;
            }
            KeyCode::Backspace => {
                if state.intercept_url_cursor > 0 {
                    let mut prev = state.intercept_url_cursor - 1;
                    while prev > 0 && !state.intercept_url_input.is_char_boundary(prev) {
                        prev -= 1;
                    }
                    state.intercept_url_input.remove(prev);
                    state.intercept_url_cursor = prev;
                }
            }
            KeyCode::Delete => {
                if state.intercept_url_cursor < state.intercept_url_input.len() {
                    state.intercept_url_input.remove(state.intercept_url_cursor);
                }
            }
            KeyCode::Char(c) => {
                state.intercept_url_input.insert(state.intercept_url_cursor, c);
                state.intercept_url_cursor += c.len_utf8();
            }
            KeyCode::Left => {
                if state.intercept_url_cursor > 0 {
                    state.intercept_url_cursor -= 1;
                    while state.intercept_url_cursor > 0 && !state.intercept_url_input.is_char_boundary(state.intercept_url_cursor) {
                        state.intercept_url_cursor -= 1;
                    }
                }
            }
            KeyCode::Right => {
                if state.intercept_url_cursor < state.intercept_url_input.len() {
                    state.intercept_url_cursor += 1;
                    while state.intercept_url_cursor < state.intercept_url_input.len() && !state.intercept_url_input.is_char_boundary(state.intercept_url_cursor) {
                        state.intercept_url_cursor += 1;
                    }
                }
            }
            KeyCode::Home => {
                state.intercept_url_cursor = 0;
            }
            KeyCode::End => {
                state.intercept_url_cursor = state.intercept_url_input.len();
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle keys when editing intercepted request method
    fn handle_edit_intercept_method_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                // Sync method back to intercepted request
                if let Some(ref mut req) = state.intercepted_request {
                    let method = state.intercept_method_input.to_uppercase();
                    if method != req.method {
                        req.method = method;
                        req.modified = true;
                    }
                }
                state.mode = AppMode::ProxyDetails;
            }
            KeyCode::Backspace => {
                if state.intercept_method_cursor > 0 {
                    let mut prev = state.intercept_method_cursor - 1;
                    while prev > 0 && !state.intercept_method_input.is_char_boundary(prev) {
                        prev -= 1;
                    }
                    state.intercept_method_input.remove(prev);
                    state.intercept_method_cursor = prev;
                }
            }
            KeyCode::Delete => {
                if state.intercept_method_cursor < state.intercept_method_input.len() {
                    state.intercept_method_input.remove(state.intercept_method_cursor);
                }
            }
            KeyCode::Char(c) => {
                // Auto-uppercase for HTTP methods
                state.intercept_method_input.insert(state.intercept_method_cursor, c.to_ascii_uppercase());
                state.intercept_method_cursor += 1;
            }
            KeyCode::Left => {
                if state.intercept_method_cursor > 0 {
                    state.intercept_method_cursor -= 1;
                }
            }
            KeyCode::Right => {
                if state.intercept_method_cursor < state.intercept_method_input.len() {
                    state.intercept_method_cursor += 1;
                }
            }
            KeyCode::Home => {
                state.intercept_method_cursor = 0;
            }
            KeyCode::End => {
                state.intercept_method_cursor = state.intercept_method_input.len();
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle keys when editing intercepted request headers
    fn handle_edit_intercept_headers_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        // If we're actively editing a cell, handle text input
        if state.intercept_headers_editor.edit_column.is_some() {
            if state.intercept_headers_editor.handle_edit_key(key) {
                return Ok(());
            }
        }

        match key.code {
            KeyCode::Esc => {
                if state.intercept_headers_editor.edit_column.is_some() {
                    // Exit cell editing
                    state.intercept_headers_editor.edit_column = None;
                } else {
                    // Sync headers and return to details view
                    self.sync_intercept_headers(state);
                    state.mode = AppMode::ProxyDetails;
                }
            }
            KeyCode::Enter => {
                if state.intercept_headers_editor.edit_column.is_some() {
                    // Finish editing current cell
                    state.intercept_headers_editor.edit_column = None;
                } else {
                    // Start editing key column
                    state.intercept_headers_editor.edit_key();
                }
            }
            KeyCode::Char('i') if state.intercept_headers_editor.edit_column.is_none() => {
                state.intercept_headers_editor.edit_key();
            }
            KeyCode::Tab => {
                if state.intercept_headers_editor.edit_column.is_some() {
                    state.intercept_headers_editor.toggle_column();
                } else {
                    // Move to value column
                    state.intercept_headers_editor.edit_value();
                }
            }
            KeyCode::Char('j') | KeyCode::Down if state.intercept_headers_editor.edit_column.is_none() => {
                let len = state.intercept_headers_editor.rows.len();
                if len > 0 {
                    state.intercept_headers_editor.selected_row =
                        (state.intercept_headers_editor.selected_row + 1).min(len - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up if state.intercept_headers_editor.edit_column.is_none() => {
                state.intercept_headers_editor.selected_row =
                    state.intercept_headers_editor.selected_row.saturating_sub(1);
            }
            KeyCode::Char('o') if state.intercept_headers_editor.edit_column.is_none() => {
                // Add new header row
                state.intercept_headers_editor.rows.push(
                    crate::tui::widgets::KeyValueRow::default()
                );
                state.intercept_headers_editor.selected_row = state.intercept_headers_editor.rows.len() - 1;
                state.intercept_headers_editor.edit_key();
            }
            KeyCode::Char('d') if state.intercept_headers_editor.edit_column.is_none() => {
                // Delete current row
                if !state.intercept_headers_editor.rows.is_empty() {
                    state.intercept_headers_editor.rows.remove(state.intercept_headers_editor.selected_row);
                    if state.intercept_headers_editor.selected_row >= state.intercept_headers_editor.rows.len() && state.intercept_headers_editor.selected_row > 0 {
                        state.intercept_headers_editor.selected_row -= 1;
                    }
                }
            }
            KeyCode::Char(' ') if state.intercept_headers_editor.edit_column.is_none() => {
                // Toggle row enabled
                if let Some(row) = state.intercept_headers_editor.rows.get_mut(state.intercept_headers_editor.selected_row) {
                    row.enabled = !row.enabled;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Sync headers editor back to intercepted request
    fn sync_intercept_headers(&self, state: &mut AppState) {
        if let Some(ref mut req) = state.intercepted_request {
            let mut new_headers = std::collections::HashMap::new();
            for row in &state.intercept_headers_editor.rows {
                if row.enabled && !row.key.value.is_empty() {
                    new_headers.insert(row.key.value.clone(), row.value.value.clone());
                }
            }
            if new_headers != req.headers {
                req.headers = new_headers;
                req.modified = true;
            }
        }
    }

    /// Handle keys when editing intercepted request body
    fn handle_edit_intercept_body_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                // Sync body and return to details view
                if let Some(ref mut req) = state.intercepted_request {
                    let current = req.body_text().unwrap_or_default();
                    if state.intercept_body_input != current {
                        req.set_body_text(&state.intercept_body_input);
                    }
                }
                state.mode = AppMode::ProxyDetails;
            }
            KeyCode::Backspace => {
                if state.intercept_body_cursor > 0 {
                    let mut prev = state.intercept_body_cursor - 1;
                    while prev > 0 && !state.intercept_body_input.is_char_boundary(prev) {
                        prev -= 1;
                    }
                    state.intercept_body_input.remove(prev);
                    state.intercept_body_cursor = prev;
                }
            }
            KeyCode::Delete => {
                if state.intercept_body_cursor < state.intercept_body_input.len() {
                    state.intercept_body_input.remove(state.intercept_body_cursor);
                }
            }
            KeyCode::Enter => {
                state.intercept_body_input.insert(state.intercept_body_cursor, '\n');
                state.intercept_body_cursor += 1;
            }
            KeyCode::Tab => {
                state.intercept_body_input.insert_str(state.intercept_body_cursor, "  ");
                state.intercept_body_cursor += 2;
            }
            KeyCode::Char(c) => {
                state.intercept_body_input.insert(state.intercept_body_cursor, c);
                state.intercept_body_cursor += c.len_utf8();
            }
            KeyCode::Left => {
                if state.intercept_body_cursor > 0 {
                    state.intercept_body_cursor -= 1;
                    while state.intercept_body_cursor > 0 && !state.intercept_body_input.is_char_boundary(state.intercept_body_cursor) {
                        state.intercept_body_cursor -= 1;
                    }
                }
            }
            KeyCode::Right => {
                if state.intercept_body_cursor < state.intercept_body_input.len() {
                    state.intercept_body_cursor += 1;
                    while state.intercept_body_cursor < state.intercept_body_input.len() && !state.intercept_body_input.is_char_boundary(state.intercept_body_cursor) {
                        state.intercept_body_cursor += 1;
                    }
                }
            }
            KeyCode::Up => {
                // Move cursor up one line
                let before_cursor = &state.intercept_body_input[..state.intercept_body_cursor];
                if let Some(current_line_start) = before_cursor.rfind('\n') {
                    let col = state.intercept_body_cursor - current_line_start - 1;
                    let prev_content = &before_cursor[..current_line_start];
                    if let Some(prev_line_start) = prev_content.rfind('\n') {
                        let prev_line_len = current_line_start - prev_line_start - 1;
                        state.intercept_body_cursor = prev_line_start + 1 + col.min(prev_line_len);
                    } else {
                        state.intercept_body_cursor = col.min(current_line_start);
                    }
                }
            }
            KeyCode::Down => {
                // Move cursor down one line
                let after_cursor = &state.intercept_body_input[state.intercept_body_cursor..];
                if let Some(next_newline) = after_cursor.find('\n') {
                    let before_cursor = &state.intercept_body_input[..state.intercept_body_cursor];
                    let current_line_start = before_cursor.rfind('\n').map(|i| i + 1).unwrap_or(0);
                    let col = state.intercept_body_cursor - current_line_start;

                    let next_line_start = state.intercept_body_cursor + next_newline + 1;
                    let next_content = &state.intercept_body_input[next_line_start..];
                    let next_line_len = next_content.find('\n').unwrap_or(next_content.len());
                    state.intercept_body_cursor = next_line_start + col.min(next_line_len);
                }
            }
            KeyCode::Home => {
                // Move to start of current line
                let before_cursor = &state.intercept_body_input[..state.intercept_body_cursor];
                state.intercept_body_cursor = before_cursor.rfind('\n').map(|i| i + 1).unwrap_or(0);
            }
            KeyCode::End => {
                // Move to end of current line
                let after_cursor = &state.intercept_body_input[state.intercept_body_cursor..];
                let line_end = after_cursor.find('\n').unwrap_or(after_cursor.len());
                state.intercept_body_cursor += line_end;
            }
            _ => {}
        }
        Ok(())
    }

    /// Handle keys in URL edit mode
    fn handle_edit_url_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                // Sync URL back to spider if on Spider tab
                if state.current_tab == MainTab::Spider {
                    state.spider_url_input = state.url_input.clone();
                }
                state.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                // Sync URL back to spider if on Spider tab
                if state.current_tab == MainTab::Spider {
                    state.spider_url_input = state.url_input.clone();
                }
                // Exit edit mode, will trigger send on next key event
                state.mode = AppMode::Normal;
            }
            KeyCode::Backspace => {
                if state.url_cursor > 0 {
                    // Find the previous char boundary
                    let mut prev = state.url_cursor - 1;
                    while prev > 0 && !state.url_input.is_char_boundary(prev) {
                        prev -= 1;
                    }
                    state.url_input.remove(prev);
                    state.url_cursor = prev;
                }
                // Live sync to spider
                if state.current_tab == MainTab::Spider {
                    state.spider_url_input = state.url_input.clone();
                }
            }
            KeyCode::Delete => {
                if state.url_cursor < state.url_input.len() {
                    state.url_input.remove(state.url_cursor);
                }
                // Live sync to spider
                if state.current_tab == MainTab::Spider {
                    state.spider_url_input = state.url_input.clone();
                }
            }
            KeyCode::Char(c) => {
                state.url_input.insert(state.url_cursor, c);
                state.url_cursor += c.len_utf8();
                // Live sync to spider
                if state.current_tab == MainTab::Spider {
                    state.spider_url_input = state.url_input.clone();
                }
            }
            KeyCode::Left => {
                if state.url_cursor > 0 {
                    // Move to previous char boundary
                    state.url_cursor -= 1;
                    while state.url_cursor > 0 && !state.url_input.is_char_boundary(state.url_cursor) {
                        state.url_cursor -= 1;
                    }
                }
            }
            KeyCode::Right => {
                if state.url_cursor < state.url_input.len() {
                    // Move to next char boundary
                    state.url_cursor += 1;
                    while state.url_cursor < state.url_input.len() && !state.url_input.is_char_boundary(state.url_cursor) {
                        state.url_cursor += 1;
                    }
                }
            }
            KeyCode::Home => {
                state.url_cursor = 0;
            }
            KeyCode::End => {
                state.url_cursor = state.url_input.len();
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in key-value editor mode (params/headers)
    fn handle_edit_keyvalue_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        // Get the active editor based on current tab
        let editor = match state.request_editor_tab {
            RequestEditorTab::Params => &mut state.query_params,
            RequestEditorTab::Headers => &mut state.headers,
            _ => return Ok(()), // Not in a key-value tab
        };

        // Check if we're in edit mode within the editor
        if editor.edit_column.is_some() {
            // Forward to the text input handler
            if editor.handle_edit_key(key) {
                return Ok(());
            }
        }

        // Navigation mode within key-value editor
        match key.code {
            KeyCode::Esc => {
                if editor.edit_column.is_some() {
                    editor.exit_edit();
                } else {
                    state.mode = AppMode::Normal;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                editor.move_down();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                editor.move_up();
            }
            KeyCode::Char('i') | KeyCode::Enter => {
                editor.edit_key();
            }
            KeyCode::Tab => {
                if editor.edit_column.is_some() {
                    editor.toggle_column();
                } else {
                    editor.edit_value();
                }
            }
            KeyCode::Char('o') => {
                editor.add_row();
                editor.edit_key();
            }
            KeyCode::Char('d') => {
                editor.delete_row();
            }
            KeyCode::Char(' ') => {
                editor.toggle_enabled();
            }
            KeyCode::Char('[') => {
                // Switch to previous tab
                state.request_editor_tab = state.request_editor_tab.prev();
                if state.request_editor_tab == RequestEditorTab::Body
                    || state.request_editor_tab == RequestEditorTab::Auth
                {
                    state.mode = AppMode::Normal;
                }
            }
            KeyCode::Char(']') => {
                // Switch to next tab
                state.request_editor_tab = state.request_editor_tab.next();
                if state.request_editor_tab == RequestEditorTab::Body
                    || state.request_editor_tab == RequestEditorTab::Auth
                {
                    state.mode = AppMode::Normal;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in body edit mode
    fn handle_edit_body_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::{KeyCode, KeyModifiers};

        match key.code {
            KeyCode::Esc => {
                state.mode = AppMode::Normal;
            }
            KeyCode::Backspace => {
                state.body_content.pop();
            }
            KeyCode::Enter => {
                state.body_content.push('\n');
            }
            // Shift+Tab cycles body content type
            KeyCode::BackTab => {
                state.body_content_type = match state.body_content_type {
                    BodyContentType::None => BodyContentType::Json,
                    BodyContentType::Json => BodyContentType::FormUrlEncoded,
                    BodyContentType::FormUrlEncoded => BodyContentType::FormData,
                    BodyContentType::FormData => BodyContentType::Raw,
                    BodyContentType::Raw => BodyContentType::None,
                };
            }
            KeyCode::Tab => {
                // Regular Tab inserts spaces
                state.body_content.push_str("  "); // 2 spaces for tab
            }
            KeyCode::Char(c) => {
                state.body_content.push(c);
            }
            // Ctrl+Backspace deletes word
            KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Delete last word
                let trimmed = state.body_content.trim_end();
                if let Some(last_space) = trimmed.rfind(|c: char| c.is_whitespace()) {
                    state.body_content = trimmed[..last_space].to_string();
                } else {
                    state.body_content.clear();
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in auth edit mode
    fn handle_edit_auth_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;
        use crossterm::event::KeyModifiers;

        // Get max field count for current auth type
        let max_fields = match state.auth_type {
            AuthType::None => 0,
            AuthType::Basic => 2,   // username, password
            AuthType::Bearer => 1,  // token
            AuthType::ApiKey => 3,  // key name, value, location
        };

        match key.code {
            KeyCode::Esc => {
                state.mode = AppMode::Normal;
            }
            // Switch auth type with number keys
            KeyCode::Char('1') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.auth_type = AuthType::None;
                state.auth_field_index = 0;
            }
            KeyCode::Char('2') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.auth_type = AuthType::Basic;
                state.auth_field_index = 0;
            }
            KeyCode::Char('3') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.auth_type = AuthType::Bearer;
                state.auth_field_index = 0;
            }
            KeyCode::Char('4') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.auth_type = AuthType::ApiKey;
                state.auth_field_index = 0;
            }
            // Navigate between fields
            KeyCode::Tab | KeyCode::Down => {
                if max_fields > 0 {
                    state.auth_field_index = (state.auth_field_index + 1) % max_fields;
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if max_fields > 0 {
                    if state.auth_field_index == 0 {
                        state.auth_field_index = max_fields - 1;
                    } else {
                        state.auth_field_index -= 1;
                    }
                }
            }
            // For API Key location, use left/right to cycle
            KeyCode::Left | KeyCode::Right if state.auth_type == AuthType::ApiKey && state.auth_field_index == 2 => {
                state.auth_api_key_location = match state.auth_api_key_location {
                    ApiKeyLocation::Header => ApiKeyLocation::Query,
                    ApiKeyLocation::Query => ApiKeyLocation::Header,
                };
            }
            // Text input
            KeyCode::Char(c) => {
                let field = self.get_auth_field_mut(state);
                if let Some(f) = field {
                    f.push(c);
                }
            }
            KeyCode::Backspace => {
                let field = self.get_auth_field_mut(state);
                if let Some(f) = field {
                    f.pop();
                }
            }
            KeyCode::Enter => {
                // Move to next field or exit if at last field
                if max_fields > 0 && state.auth_field_index < max_fields - 1 {
                    state.auth_field_index += 1;
                } else {
                    state.mode = AppMode::Normal;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Get mutable reference to the currently focused auth field
    fn get_auth_field_mut<'a>(&self, state: &'a mut AppState) -> Option<&'a mut String> {
        match state.auth_type {
            AuthType::None => None,
            AuthType::Basic => match state.auth_field_index {
                0 => Some(&mut state.auth_username),
                1 => Some(&mut state.auth_password),
                _ => None,
            },
            AuthType::Bearer => match state.auth_field_index {
                0 => Some(&mut state.auth_token),
                _ => None,
            },
            AuthType::ApiKey => match state.auth_field_index {
                0 => Some(&mut state.auth_api_key_name),
                1 => Some(&mut state.auth_api_key_value),
                _ => None, // field 2 is location, handled separately
            },
        }
    }

    /// Handle keys in environment selector
    fn handle_env_selector_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        let env_count = self.workspace.environments().len() + 1; // +1 for "No Environment"

        match key.code {
            KeyCode::Esc => {
                state.env_selector_open = false;
                state.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                state.env_selector_open = false;
                state.mode = AppMode::Normal;
                // Environment is already selected
                let env_name = if state.selected_environment == 0 {
                    "No Environment".to_string()
                } else {
                    self.workspace
                        .environments()
                        .get(state.selected_environment - 1)
                        .map(|e| e.name.clone())
                        .unwrap_or_else(|| "Unknown".to_string())
                };
                state.status_message = Some(format!("Environment: {}", env_name));
                state.status_timestamp = Some(std::time::Instant::now());
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if state.selected_environment < env_count - 1 {
                    state.selected_environment += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if state.selected_environment > 0 {
                    state.selected_environment -= 1;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in response search mode
    fn handle_search_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                state.response_search.clear();
                state.response_search_matches.clear();
                state.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                // Perform search
                if !state.response_search.is_empty() {
                    if let Some(response) = &state.current_response {
                        let matches: Vec<(usize, usize)> = response
                            .body
                            .lines()
                            .enumerate()
                            .flat_map(|(line_num, line)| {
                                line.match_indices(&state.response_search)
                                    .map(move |(col, _)| (line_num, col))
                            })
                            .collect();
                        state.response_search_matches = matches;
                        state.current_search_match = 0;
                        if state.response_search_matches.is_empty() {
                            state.status_message = Some("No matches found".to_string());
                        } else {
                            state.status_message = Some(format!(
                                "Found {} matches",
                                state.response_search_matches.len()
                            ));
                        }
                        state.status_timestamp = Some(std::time::Instant::now());
                    }
                }
                state.mode = AppMode::Normal;
            }
            KeyCode::Backspace => {
                state.response_search.pop();
            }
            KeyCode::Char(c) => {
                state.response_search.push(c);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in proxy filter mode
    fn handle_filter_proxy_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                // Cancel filter and return to normal mode (but keep filter text)
                state.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                // Apply filter and return to normal mode
                state.mode = AppMode::Normal;
                state.selected_proxy_item = 0; // Reset selection
                state.status_message = Some(if state.proxy_filter.is_empty() {
                    "Filter cleared".to_string()
                } else {
                    format!("Filtering: {} (use !pattern to exclude)", state.proxy_filter)
                });
                state.status_timestamp = Some(std::time::Instant::now());
            }
            KeyCode::Backspace => {
                if !state.proxy_filter.is_empty() {
                    state.proxy_filter.pop();
                }
            }
            KeyCode::Char(c) => {
                state.proxy_filter.push(c);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in findings filter mode
    fn handle_filter_findings_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                // Cancel filter and return to normal mode
                state.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                // Apply filter and return to normal mode
                state.mode = AppMode::Normal;
                // Reset selection to first visible host
                state.findings_selected_host = 0;
                state.findings_selected_within_host = None;
                state.status_message = Some(if state.findings_filter.is_empty() {
                    "Filter cleared".to_string()
                } else {
                    format!("Filtering: {} (use !pattern to exclude)", state.findings_filter)
                });
                state.status_timestamp = Some(std::time::Instant::now());
            }
            KeyCode::Backspace => {
                if state.findings_filter_cursor > 0 {
                    let mut prev = state.findings_filter_cursor - 1;
                    while prev > 0 && !state.findings_filter.is_char_boundary(prev) {
                        prev -= 1;
                    }
                    state.findings_filter.remove(prev);
                    state.findings_filter_cursor = prev;
                }
            }
            KeyCode::Delete => {
                if state.findings_filter_cursor < state.findings_filter.len() {
                    state.findings_filter.remove(state.findings_filter_cursor);
                }
            }
            KeyCode::Left => {
                if state.findings_filter_cursor > 0 {
                    let mut prev = state.findings_filter_cursor - 1;
                    while prev > 0 && !state.findings_filter.is_char_boundary(prev) {
                        prev -= 1;
                    }
                    state.findings_filter_cursor = prev;
                }
            }
            KeyCode::Right => {
                if state.findings_filter_cursor < state.findings_filter.len() {
                    let mut next = state.findings_filter_cursor + 1;
                    while next < state.findings_filter.len() && !state.findings_filter.is_char_boundary(next) {
                        next += 1;
                    }
                    state.findings_filter_cursor = next;
                }
            }
            KeyCode::Home => {
                state.findings_filter_cursor = 0;
            }
            KeyCode::End => {
                state.findings_filter_cursor = state.findings_filter.len();
            }
            KeyCode::Char(c) => {
                state.findings_filter.insert(state.findings_filter_cursor, c);
                state.findings_filter_cursor += c.len_utf8();
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in browser URL dialog mode
    fn handle_browser_url_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                state.mode = AppMode::Normal;
                state.browser_url_input.clear();
                state.status_message = Some("Cancelled".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }
            KeyCode::Enter => {
                let url = state.browser_url_input.trim().to_string();
                tracing::info!("Browser dialog: launching URL '{}'", url);

                if !url.is_empty() {
                    // Add https:// if no scheme
                    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
                        url
                    } else {
                        format!("https://{}", url)
                    };

                    state.browser_pending_navigation = Some(full_url.clone());
                    state.status_message = Some(format!("Launching browser for {}...", full_url));
                } else {
                    // Empty URL - launch with blank page
                    state.browser_pending_navigation = Some("about:blank".to_string());
                    state.status_message = Some("Launching browser...".to_string());
                }

                state.browser_url_input.clear();
                state.mode = AppMode::Normal;
                state.status_timestamp = Some(std::time::Instant::now());
            }
            KeyCode::Backspace => {
                state.browser_url_input.pop();
            }
            KeyCode::Char(c) => {
                state.browser_url_input.push(c);
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in confirm delete mode
    fn handle_confirm_delete(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                let mut state = self.state.write();
                state.delete_target = None;
                state.mode = AppMode::Normal;
                state.status_message = Some("Delete cancelled".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                // Get the delete target index
                let (idx, selected_item) = {
                    let state = self.state.read();
                    (state.delete_target, state.selected_collection_item)
                };

                if let Some(idx) = idx {
                    // Delete the item at the given index
                    let deleted = self.delete_collection_item(idx);
                    let mut state = self.state.write();
                    if deleted {
                        state.status_message = Some("Item deleted".to_string());
                        // Adjust selection if needed
                        if selected_item >= idx && selected_item > 0 {
                            state.selected_collection_item -= 1;
                        }
                    } else {
                        state.status_message = Some("Failed to delete item".to_string());
                    }
                    state.status_timestamp = Some(std::time::Instant::now());
                    state.delete_target = None;
                    state.mode = AppMode::Normal;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Handle keys in rename mode
    fn handle_rename(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Esc => {
                let mut state = self.state.write();
                state.rename_buffer.clear();
                state.rename_target = None;
                state.mode = AppMode::Normal;
            }
            KeyCode::Enter => {
                // Get the rename info
                let (idx, new_name) = {
                    let state = self.state.read();
                    (state.rename_target, state.rename_buffer.clone())
                };

                if let Some(idx) = idx {
                    if !new_name.is_empty() {
                        let renamed = self.rename_collection_item(idx, &new_name);
                        let mut state = self.state.write();
                        if renamed {
                            state.status_message = Some(format!("Renamed to '{}'", new_name));
                        } else {
                            state.status_message = Some("Failed to rename item".to_string());
                        }
                        state.status_timestamp = Some(std::time::Instant::now());
                        state.rename_buffer.clear();
                        state.rename_target = None;
                        state.mode = AppMode::Normal;
                    }
                }
            }
            KeyCode::Backspace => {
                let mut state = self.state.write();
                state.rename_buffer.pop();
            }
            KeyCode::Char(c) => {
                let mut state = self.state.write();
                state.rename_buffer.push(c);
            }
            _ => {}
        }

        Ok(())
    }

    /// Delete a collection item at the given navigation index
    fn delete_collection_item(&mut self, nav_index: usize) -> bool {
        let items = self.get_collection_items();
        let item_info = items.get(nav_index).map(|item| (item.name.clone(), item.item_type));

        if let Some((name, item_type)) = item_info {
            // Find and delete the item from the workspace
            if item_type == CollectionItemType::Request || item_type == CollectionItemType::Folder {
                if let Some(project) = self.workspace.project_mut() {
                    for collection in &mut project.collections {
                        if Self::delete_item_recursive(&mut collection.items, &name) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn delete_item_recursive(items: &mut Vec<crate::workspace::CollectionItem>, name: &str) -> bool {
        use crate::workspace::CollectionItem;

        // Find and remove the item
        if let Some(pos) = items.iter().position(|item| {
            match item {
                CollectionItem::Request(r) => r.name == name,
                CollectionItem::Folder(f) => f.name == name,
            }
        }) {
            items.remove(pos);
            return true;
        }

        // Recursively search in folders
        for item in items.iter_mut() {
            if let CollectionItem::Folder(f) = item {
                if Self::delete_item_recursive(&mut f.items, name) {
                    return true;
                }
            }
        }

        false
    }

    /// Rename a collection item at the given navigation index
    fn rename_collection_item(&mut self, nav_index: usize, new_name: &str) -> bool {
        let items = self.get_collection_items();
        let old_name = items.get(nav_index).map(|item| item.name.clone());

        if let Some(old_name) = old_name {
            if let Some(project) = self.workspace.project_mut() {
                for collection in &mut project.collections {
                    if Self::rename_item_recursive(&mut collection.items, &old_name, new_name) {
                        return true;
                    }
                    // Also check collection name
                    if collection.name == old_name {
                        collection.name = new_name.to_string();
                        return true;
                    }
                }
            }
        }
        false
    }

    fn rename_item_recursive(items: &mut Vec<crate::workspace::CollectionItem>, old_name: &str, new_name: &str) -> bool {
        use crate::workspace::CollectionItem;

        for item in items.iter_mut() {
            match item {
                CollectionItem::Request(r) => {
                    if r.name == old_name {
                        r.name = new_name.to_string();
                        return true;
                    }
                }
                CollectionItem::Folder(f) => {
                    if f.name == old_name {
                        f.name = new_name.to_string();
                        return true;
                    }
                    if Self::rename_item_recursive(&mut f.items, old_name, new_name) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Export current request state to cURL command
    pub fn export_to_curl(&self) -> String {
        let state = self.state.read();
        let mut parts = vec!["curl".to_string()];

        // Add method if not GET
        if state.request_method != "GET" {
            parts.push(format!("-X {}", state.request_method));
        }

        // Add headers
        for row in &state.headers.rows {
            if row.enabled && !row.key.value.is_empty() {
                parts.push(format!("-H '{}: {}'", row.key.value, row.value.value));
            }
        }

        // Add body
        if !state.body_content.is_empty() {
            // Escape single quotes in the body
            let escaped_body = state.body_content.replace('\'', "'\\''");
            parts.push(format!("-d '{}'", escaped_body));
        }

        // Build URL with query params
        let mut url = state.url_input.clone();
        let query_pairs: Vec<String> = state.query_params.rows
            .iter()
            .filter(|r| r.enabled && !r.key.value.is_empty())
            .map(|r| format!("{}={}",
                urlencoding::encode(&r.key.value),
                urlencoding::encode(&r.value.value)))
            .collect();

        if !query_pairs.is_empty() {
            if url.contains('?') {
                url = format!("{}&{}", url, query_pairs.join("&"));
            } else {
                url = format!("{}?{}", url, query_pairs.join("&"));
            }
        }

        parts.push(format!("'{}'", url));

        parts.join(" \\\n  ")
    }

    /// Convert proxy history entry to cURL command
    fn entry_to_curl(&self, entry: &ProxyHistoryItem) -> String {
        let mut parts = vec!["curl".to_string()];

        // Add method if not GET
        if entry.method != "GET" {
            parts.push(format!("-X {}", entry.method));
        }

        // Add headers
        for (key, value) in &entry.request_headers {
            // Skip host header as it's implied by URL
            if key.to_lowercase() != "host" {
                parts.push(format!("-H '{}: {}'", key, value.replace('\'', "'\\''")));
            }
        }

        // Add body
        if let Some(body) = &entry.request_body {
            if !body.is_empty() {
                let escaped_body = body.replace('\'', "'\\''");
                parts.push(format!("-d '{}'", escaped_body));
            }
        }

        // Add URL
        parts.push(format!("'{}'", entry.url));

        parts.join(" \\\n  ")
    }

    /// Convert proxy history entry to raw HTTP request
    fn entry_to_raw_request(&self, entry: &ProxyHistoryItem) -> String {
        let mut lines = Vec::new();

        // Request line
        lines.push(format!("{} {} HTTP/1.1", entry.method, entry.path));

        // Headers
        for (key, value) in &entry.request_headers {
            lines.push(format!("{}: {}", key, value));
        }

        // Empty line before body
        lines.push(String::new());

        // Body
        if let Some(body) = &entry.request_body {
            lines.push(body.clone());
        }

        lines.join("\r\n")
    }

    /// Convert proxy history entry to raw HTTP response
    fn entry_to_raw_response(&self, entry: &ProxyHistoryItem) -> String {
        let mut lines = Vec::new();

        // Status line
        let status = entry.status.unwrap_or(0);
        let status_text = match status {
            200 => "OK",
            201 => "Created",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };
        lines.push(format!("HTTP/1.1 {} {}", status, status_text));

        // Headers
        if let Some(headers) = &entry.response_headers {
            for (key, value) in headers {
                lines.push(format!("{}: {}", key, value));
            }
        }

        // Empty line before body
        lines.push(String::new());

        // Body
        if let Some(body) = &entry.response_body {
            lines.push(body.clone());
        }

        lines.join("\r\n")
    }

    /// Copy text to clipboard
    fn copy_to_clipboard(&self, text: &str) -> Result<()> {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|e| anyhow::anyhow!("Failed to access clipboard: {}", e))?;
        clipboard.set_text(text)
            .map_err(|e| anyhow::anyhow!("Failed to copy to clipboard: {}", e))?;
        Ok(())
    }

    /// Export CA certificate to clipboard and file
    pub fn export_ca_cert(&self) -> Result<()> {
        let ca_pem = if let Some(proxy) = &self.proxy {
            proxy.ca_cert_pem().to_string()
        } else {
            let mut state = self.state.write();
            state.status_message = Some("Proxy not running - cannot export CA".to_string());
            state.status_timestamp = Some(std::time::Instant::now());
            return Ok(());
        };

        // Copy to clipboard
        let clipboard_result = match arboard::Clipboard::new() {
            Ok(mut clipboard) => clipboard.set_text(&ca_pem),
            Err(e) => Err(e),
        };

        // Save to file
        let ca_path = self.config.general.workspace_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("ancarna-ca.crt");

        let file_result = std::fs::write(&ca_path, &ca_pem);

        // Update status
        let mut state = self.state.write();
        match (clipboard_result, file_result) {
            (Ok(_), Ok(_)) => {
                state.status_message = Some(format!(
                    "CA certificate copied to clipboard and saved to {}",
                    ca_path.display()
                ));
            }
            (Ok(_), Err(_)) => {
                state.status_message = Some("CA certificate copied to clipboard".to_string());
            }
            (Err(_), Ok(_)) => {
                state.status_message = Some(format!(
                    "CA certificate saved to {}",
                    ca_path.display()
                ));
            }
            (Err(_), Err(_)) => {
                state.status_message = Some("Failed to export CA certificate".to_string());
            }
        }
        state.status_timestamp = Some(std::time::Instant::now());

        Ok(())
    }

    /// Load a history entry into the editor
    pub fn load_history_entry(&mut self, index: usize) {
        let entry = {
            let state = self.state.read();
            state.request_history.get(state.request_history.len().saturating_sub(1).saturating_sub(index)).cloned()
        };

        if let Some(entry) = entry {
            let mut state = self.state.write();

            // Set URL and method
            state.url_input = entry.url.clone();
            state.request_method = entry.method.clone();
            state.current_response = None;

            // Parse query params from URL
            let mut query_rows = Vec::new();
            if let Ok(parsed) = url::Url::parse(&entry.url) {
                for (key, value) in parsed.query_pairs() {
                    query_rows.push(crate::tui::widgets::KeyValueRow::with_key_value(&key, &value));
                }
                // Update URL to remove query string (params are now in editor)
                let mut clean_url = parsed.clone();
                clean_url.set_query(None);
                state.url_input = clean_url.to_string();
            }
            if query_rows.is_empty() {
                query_rows.push(crate::tui::widgets::KeyValueRow::new());
            }
            state.query_params = crate::tui::widgets::KeyValueEditorState::with_rows(query_rows);

            // Reset headers (history doesn't store them)
            state.headers = crate::tui::widgets::KeyValueEditorState::new();
            state.body_content.clear();

            // Update focus
            state.focus = Focus::RequestEditor;
            state.history_focused = false;
            state.status_message = Some(format!("Loaded from history: {} {}", entry.method, entry.url));
            state.status_timestamp = Some(std::time::Instant::now());
        }
    }

    /// Send the current request
    async fn send_current_request(&mut self) -> Result<()> {
        // Get active environment for variable substitution
        let active_env = self.workspace.active_environment().cloned();

        let request = {
            let mut state = self.state.write();
            state.is_loading = true;
            state.status_message = Some("Sending request...".to_string());
            state.status_timestamp = Some(std::time::Instant::now());

            // Build URL with query parameters from editor
            let base_url = state.url_input.clone();

            // Apply variable substitution to URL if environment is active
            let base_url = if let Some(ref env) = active_env {
                env.substitute(&base_url)
            } else {
                base_url
            };

            let mut url = base_url.clone();

            // Parse and rebuild URL with query params from editor
            let query_pairs = state.query_params.to_pairs();
            if !query_pairs.is_empty() {
                if let Ok(mut parsed) = url::Url::parse(&base_url) {
                    // Clear existing query and add from editor
                    parsed.set_query(None);
                    {
                        let mut pairs = parsed.query_pairs_mut();
                        for (key, value) in &query_pairs {
                            // Apply variable substitution to query params
                            let key = if let Some(ref env) = active_env {
                                env.substitute(key)
                            } else {
                                key.clone()
                            };
                            let value = if let Some(ref env) = active_env {
                                env.substitute(value)
                            } else {
                                value.clone()
                            };
                            pairs.append_pair(&key, &value);
                        }
                    }
                    url = parsed.to_string();
                } else if !base_url.contains('?') {
                    // Simple URL without query string - just append
                    let query_string: Vec<String> = query_pairs
                        .iter()
                        .map(|(k, v)| {
                            let k = if let Some(ref env) = active_env {
                                env.substitute(k)
                            } else {
                                k.clone()
                            };
                            let v = if let Some(ref env) = active_env {
                                env.substitute(v)
                            } else {
                                v.clone()
                            };
                            format!("{}={}", urlencoding::encode(&k), urlencoding::encode(&v))
                        })
                        .collect();
                    if !query_string.is_empty() {
                        url = format!("{}?{}", base_url, query_string.join("&"));
                    }
                }
            }

            // Build request with headers from editor
            let mut request = crate::http::Request::new(&state.request_method, &url);

            // Add headers from editor
            let header_pairs = state.headers.to_pairs();
            for (key, value) in header_pairs {
                // Apply variable substitution to headers
                let value = if let Some(ref env) = active_env {
                    env.substitute(&value)
                } else {
                    value
                };
                request.headers.insert(key, value);
            }

            // Add authentication headers
            match state.auth_type {
                AuthType::None => {}
                AuthType::Basic => {
                    if !state.auth_username.is_empty() {
                        let credentials = format!("{}:{}", state.auth_username, state.auth_password);
                        let encoded = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            credentials,
                        );
                        request.headers.insert(
                            "Authorization".to_string(),
                            format!("Basic {}", encoded),
                        );
                    }
                }
                AuthType::Bearer => {
                    if !state.auth_token.is_empty() {
                        let token = if let Some(ref env) = active_env {
                            env.substitute(&state.auth_token)
                        } else {
                            state.auth_token.clone()
                        };
                        request.headers.insert(
                            "Authorization".to_string(),
                            format!("Bearer {}", token),
                        );
                    }
                }
                AuthType::ApiKey => {
                    if !state.auth_api_key_name.is_empty() && !state.auth_api_key_value.is_empty() {
                        let key_value = if let Some(ref env) = active_env {
                            env.substitute(&state.auth_api_key_value)
                        } else {
                            state.auth_api_key_value.clone()
                        };
                        match state.auth_api_key_location {
                            ApiKeyLocation::Header => {
                                request.headers.insert(
                                    state.auth_api_key_name.clone(),
                                    key_value,
                                );
                            }
                            ApiKeyLocation::Query => {
                                // Will be added as query parameter
                                if let Ok(mut parsed) = url::Url::parse(&request.url) {
                                    parsed.query_pairs_mut().append_pair(
                                        &state.auth_api_key_name,
                                        &key_value,
                                    );
                                    request.url = parsed.to_string();
                                }
                            }
                        }
                    }
                }
            }

            // Add body if present
            if !state.body_content.is_empty() {
                // Apply variable substitution to body
                let body = if let Some(ref env) = active_env {
                    env.substitute(&state.body_content)
                } else {
                    state.body_content.clone()
                };
                request.body = Some(body);

                // Set Content-Type based on body type if not already set
                if !request.headers.contains_key("Content-Type")
                    && !request.headers.contains_key("content-type")
                {
                    let content_type = match state.body_content_type {
                        BodyContentType::Json => "application/json",
                        BodyContentType::FormUrlEncoded => "application/x-www-form-urlencoded",
                        BodyContentType::FormData => "multipart/form-data",
                        BodyContentType::Raw => "text/plain",
                        BodyContentType::None => "text/plain",
                    };
                    request.headers.insert("Content-Type".to_string(), content_type.to_string());
                }
            }

            request
        };

        let start = std::time::Instant::now();
        let result = self.http_client.execute(&request).await;
        let duration_ms = start.elapsed().as_millis() as u64;

        let mut state = self.state.write();
        state.is_loading = false;

        match result {
            Ok(response) => {
                let body = String::from_utf8_lossy(&response.body).to_string();
                let size = response.body.len();

                state.current_response = Some(CurrentResponse {
                    status: response.status,
                    status_text: response.status_text.clone(),
                    headers: response.headers.clone(),
                    body,
                    duration_ms,
                    size,
                });

                state.status_message = Some(format!(
                    "{} {} - {}ms",
                    response.status, response.status_text, duration_ms
                ));
                state.status_timestamp = Some(std::time::Instant::now());
                state.response_scroll = 0; // Reset scroll to top

                // Add to history
                state.request_history.push(HistoryEntry {
                    timestamp: std::time::SystemTime::now(),
                    method: request.method.clone(),
                    url: request.url.clone(),
                    status: Some(response.status),
                    duration_ms,
                });

                // Keep history limited to 100 items
                if state.request_history.len() > 100 {
                    state.request_history.remove(0);
                }
            }
            Err(e) => {
                state.current_response = None;
                state.status_message = Some(format!("Error: {}", e));
                state.status_timestamp = Some(std::time::Instant::now());

                // Add failed request to history
                state.request_history.push(HistoryEntry {
                    timestamp: std::time::SystemTime::now(),
                    method: request.method.clone(),
                    url: request.url.clone(),
                    status: None,
                    duration_ms,
                });
            }
        }

        Ok(())
    }

    /// Handle paste from clipboard, auto-detecting cURL commands
    fn handle_clipboard_paste(&self, state: &mut AppState) {
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => {
                match clipboard.get_text() {
                    Ok(text) => {
                        let text = text.trim();

                        // Check if it looks like a cURL command
                        if text.starts_with("curl ") || text.starts_with("curl\t") {
                            // Try to parse as cURL
                            match crate::workspace::import::curl::parse_curl(text) {
                                Ok(request) => {
                                    // Load the request into the editor
                                    state.url_input = request.url.clone();
                                    state.request_method = request.method.clone();

                                    // Load headers
                                    let headers: Vec<(String, String)> = request
                                        .headers
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.clone()))
                                        .collect();
                                    state.headers = crate::tui::widgets::KeyValueEditorState::from_pairs(headers);

                                    // Load body
                                    if let Some(body) = request.body {
                                        state.body_content = body;
                                        // Try to detect content type
                                        if state.body_content.starts_with('{') || state.body_content.starts_with('[') {
                                            state.body_content_type = BodyContentType::Json;
                                        } else if state.body_content.contains('=') && !state.body_content.contains('\n') {
                                            state.body_content_type = BodyContentType::FormUrlEncoded;
                                        } else {
                                            state.body_content_type = BodyContentType::Raw;
                                        }
                                    }

                                    // Parse query params from URL
                                    if let Ok(parsed_url) = url::Url::parse(&request.url) {
                                        let params: Vec<(String, String)> = parsed_url
                                            .query_pairs()
                                            .map(|(k, v)| (k.to_string(), v.to_string()))
                                            .collect();
                                        if !params.is_empty() {
                                            state.query_params = crate::tui::widgets::KeyValueEditorState::from_pairs(params);
                                            // Update URL to remove query string (params are now in editor)
                                            let mut clean_url = parsed_url.clone();
                                            clean_url.set_query(None);
                                            state.url_input = clean_url.to_string();
                                        }
                                    }

                                    state.focus = Focus::RequestEditor;
                                    state.status_message = Some("Imported cURL command".to_string());
                                    state.status_timestamp = Some(std::time::Instant::now());
                                }
                                Err(e) => {
                                    state.status_message = Some(format!("Failed to parse cURL: {}", e));
                                    state.status_timestamp = Some(std::time::Instant::now());
                                }
                            }
                        } else if text.starts_with("http://") || text.starts_with("https://") {
                            // Plain URL - just load it
                            state.url_input = text.to_string();

                            // Parse query params
                            if let Ok(parsed_url) = url::Url::parse(text) {
                                let params: Vec<(String, String)> = parsed_url
                                    .query_pairs()
                                    .map(|(k, v)| (k.to_string(), v.to_string()))
                                    .collect();
                                if !params.is_empty() {
                                    state.query_params = crate::tui::widgets::KeyValueEditorState::from_pairs(params);
                                    let mut clean_url = parsed_url.clone();
                                    clean_url.set_query(None);
                                    state.url_input = clean_url.to_string();
                                }
                            }

                            state.focus = Focus::RequestEditor;
                            state.status_message = Some("Pasted URL".to_string());
                            state.status_timestamp = Some(std::time::Instant::now());
                        } else {
                            // Unknown format - paste as URL anyway
                            state.url_input = text.to_string();
                            state.status_message = Some("Pasted text to URL".to_string());
                            state.status_timestamp = Some(std::time::Instant::now());
                        }
                    }
                    Err(e) => {
                        state.status_message = Some(format!("Clipboard read error: {}", e));
                        state.status_timestamp = Some(std::time::Instant::now());
                    }
                }
            }
            Err(e) => {
                state.status_message = Some(format!("Clipboard unavailable: {}", e));
                state.status_timestamp = Some(std::time::Instant::now());
            }
        }
    }

    /// Handle keys in normal mode
    fn handle_normal_mode_key(
        &self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> Result<()> {
        use crossterm::event::{KeyCode, KeyModifiers};

        match key.code {
            // Tab switching with number keys 1-7
            KeyCode::Char('1') => {
                state.current_tab = MainTab::Browser;
            }
            KeyCode::Char('2') => {
                state.current_tab = MainTab::Workspace;
            }
            KeyCode::Char('3') => {
                state.current_tab = MainTab::Proxy;
                state.focus = Focus::ProxyHistory;
            }
            KeyCode::Char('4') => {
                state.current_tab = MainTab::Scanner;
                state.focus = Focus::Findings;
            }
            KeyCode::Char('5') => {
                state.current_tab = MainTab::Spider;
            }
            KeyCode::Char('6') => {
                state.current_tab = MainTab::Fuzzer;
            }
            KeyCode::Char('7') => {
                state.current_tab = MainTab::Settings;
            }

            // Tab navigation with H/L (shift+h/l)
            KeyCode::Char('H') => {
                state.current_tab = state.current_tab.prev();
            }
            KeyCode::Char('L') => {
                state.current_tab = state.current_tab.next();
            }

            // Request editor tab switching with [ and ]
            KeyCode::Char('[') => {
                if state.focus == Focus::RequestEditor {
                    state.request_editor_tab = state.request_editor_tab.prev();
                }
            }
            KeyCode::Char(']') => {
                if state.focus == Focus::RequestEditor {
                    state.request_editor_tab = state.request_editor_tab.next();
                }
            }

            // Navigation within panels
            KeyCode::Char('h') | KeyCode::Left => {
                // Move focus left between panels
                state.focus = match state.focus {
                    Focus::ResponseViewer => Focus::RequestEditor,
                    Focus::RequestEditor => Focus::Workspace,
                    _ => state.focus,
                };
            }
            KeyCode::Char('j') | KeyCode::Down => {
                // Navigate down in current panel
                match state.focus {
                    Focus::Workspace => {
                        if state.history_focused {
                            let max_idx = state.request_history.len().saturating_sub(1);
                            if state.selected_history_item < max_idx {
                                state.selected_history_item += 1;
                            }
                        } else {
                            state.selected_collection_item = state.selected_collection_item.saturating_add(1);
                        }
                    }
                    Focus::RequestEditor => {
                        // Navigate within key-value editors
                        match state.request_editor_tab {
                            RequestEditorTab::Params => {
                                state.query_params.move_down();
                            }
                            RequestEditorTab::Headers => {
                                state.headers.move_down();
                            }
                            _ => {
                                state.request_scroll = state.request_scroll.saturating_add(1);
                            }
                        }
                    }
                    Focus::ResponseViewer => {
                        state.response_scroll = state.response_scroll.saturating_add(1);
                    }
                    Focus::ProxyHistory => {
                        let max_idx = state.proxy_history.len().saturating_sub(1);
                        if state.selected_proxy_item < max_idx {
                            state.selected_proxy_item += 1;
                            // Keep selection visible - assume ~20 visible lines
                            let visible_height = 20;
                            if state.selected_proxy_item >= state.proxy_history_scroll + visible_height {
                                state.proxy_history_scroll = state.selected_proxy_item.saturating_sub(visible_height - 1);
                            }
                        }
                    }
                    Focus::Findings => {
                        // Tree navigation: move down
                        let (hosts, findings_by_host) = crate::tui::group_findings_by_host(&state.findings, &state.findings_filter);
                        if hosts.is_empty() {
                            return Ok(());
                        }

                        match state.findings_selected_within_host {
                            None => {
                                // On a host - check if expanded
                                let current_host = hosts.get(state.findings_selected_host);
                                if let Some(host) = current_host {
                                    if state.findings_expanded_hosts.contains(host) {
                                        // Move into findings
                                        let count = findings_by_host.get(host).map(|v| v.len()).unwrap_or(0);
                                        if count > 0 {
                                            state.findings_selected_within_host = Some(0);
                                        } else if state.findings_selected_host < hosts.len() - 1 {
                                            state.findings_selected_host += 1;
                                        }
                                    } else {
                                        // Move to next host
                                        if state.findings_selected_host < hosts.len() - 1 {
                                            state.findings_selected_host += 1;
                                        }
                                    }
                                }
                            }
                            Some(finding_idx) => {
                                // Within findings of a host
                                let current_host = hosts.get(state.findings_selected_host);
                                if let Some(host) = current_host {
                                    let count = findings_by_host.get(host).map(|v| v.len()).unwrap_or(0);
                                    if finding_idx < count - 1 {
                                        state.findings_selected_within_host = Some(finding_idx + 1);
                                    } else {
                                        // Move to next host
                                        if state.findings_selected_host < hosts.len() - 1 {
                                            state.findings_selected_host += 1;
                                            state.findings_selected_within_host = None;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                // Navigate up in current panel
                match state.focus {
                    Focus::Workspace => {
                        if state.history_focused {
                            state.selected_history_item = state.selected_history_item.saturating_sub(1);
                        } else {
                            state.selected_collection_item = state.selected_collection_item.saturating_sub(1);
                        }
                    }
                    Focus::RequestEditor => {
                        // Navigate within key-value editors
                        match state.request_editor_tab {
                            RequestEditorTab::Params => {
                                state.query_params.move_up();
                            }
                            RequestEditorTab::Headers => {
                                state.headers.move_up();
                            }
                            _ => {
                                state.request_scroll = state.request_scroll.saturating_sub(1);
                            }
                        }
                    }
                    Focus::ResponseViewer => {
                        state.response_scroll = state.response_scroll.saturating_sub(1);
                    }
                    Focus::ProxyHistory => {
                        state.selected_proxy_item = state.selected_proxy_item.saturating_sub(1);
                        // Keep selection visible
                        if state.selected_proxy_item < state.proxy_history_scroll {
                            state.proxy_history_scroll = state.selected_proxy_item;
                        }
                    }
                    Focus::Findings => {
                        // Tree navigation: move up
                        let (hosts, findings_by_host) = crate::tui::group_findings_by_host(&state.findings, &state.findings_filter);
                        if hosts.is_empty() {
                            return Ok(());
                        }

                        match state.findings_selected_within_host {
                            None => {
                                // On a host - move to previous host's last finding or host itself
                                if state.findings_selected_host > 0 {
                                    state.findings_selected_host -= 1;
                                    let prev_host = &hosts[state.findings_selected_host];
                                    if state.findings_expanded_hosts.contains(prev_host) {
                                        let count = findings_by_host.get(prev_host).map(|v| v.len()).unwrap_or(0);
                                        if count > 0 {
                                            state.findings_selected_within_host = Some(count - 1);
                                        }
                                    }
                                }
                            }
                            Some(finding_idx) => {
                                if finding_idx > 0 {
                                    state.findings_selected_within_host = Some(finding_idx - 1);
                                } else {
                                    // Move to host
                                    state.findings_selected_within_host = None;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            KeyCode::Char('l') | KeyCode::Right => {
                // Move focus right between panels
                state.focus = match state.focus {
                    Focus::Workspace => Focus::RequestEditor,
                    Focus::RequestEditor => Focus::ResponseViewer,
                    _ => state.focus,
                };
            }

            // Page up/down for faster scrolling
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Half page down
                match state.focus {
                    Focus::Workspace => {
                        state.selected_collection_item = state.selected_collection_item.saturating_add(10);
                    }
                    Focus::RequestEditor => {
                        state.request_scroll = state.request_scroll.saturating_add(10);
                    }
                    Focus::ResponseViewer => {
                        state.response_scroll = state.response_scroll.saturating_add(10);
                    }
                    _ => {}
                }
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Half page up
                match state.focus {
                    Focus::Workspace => {
                        state.selected_collection_item = state.selected_collection_item.saturating_sub(10);
                    }
                    Focus::RequestEditor => {
                        state.request_scroll = state.request_scroll.saturating_sub(10);
                    }
                    Focus::ResponseViewer => {
                        state.response_scroll = state.response_scroll.saturating_sub(10);
                    }
                    _ => {}
                }
            }

            // Go to top/bottom
            KeyCode::Char('g') => {
                // Go to top
                match state.focus {
                    Focus::Workspace => state.selected_collection_item = 0,
                    Focus::RequestEditor => state.request_scroll = 0,
                    Focus::ResponseViewer => state.response_scroll = 0,
                    _ => {}
                }
            }
            KeyCode::Char('G') => {
                // Go to bottom (set to large number, will be clamped by render)
                match state.focus {
                    Focus::Workspace => state.selected_collection_item = usize::MAX / 2,
                    Focus::RequestEditor => state.request_scroll = usize::MAX / 2,
                    Focus::ResponseViewer => state.response_scroll = usize::MAX / 2,
                    _ => {}
                }
            }

            // Tab to cycle focus within view
            KeyCode::Tab => {
                state.focus = match state.current_tab {
                    MainTab::Workspace => match state.focus {
                        Focus::Workspace => Focus::RequestEditor,
                        Focus::RequestEditor => Focus::ResponseViewer,
                        Focus::ResponseViewer => Focus::Workspace,
                        _ => Focus::Workspace,
                    },
                    MainTab::Proxy => match state.focus {
                        Focus::ProxyHistory => Focus::RequestEditor,
                        Focus::RequestEditor => Focus::ResponseViewer,
                        Focus::ResponseViewer => Focus::ProxyHistory,
                        _ => Focus::ProxyHistory,
                    },
                    _ => Focus::Workspace,
                };
            }

            // Backtab (Shift+Tab) to cycle focus backwards
            KeyCode::BackTab => {
                state.focus = match state.current_tab {
                    MainTab::Workspace => match state.focus {
                        Focus::Workspace => Focus::ResponseViewer,
                        Focus::RequestEditor => Focus::Workspace,
                        Focus::ResponseViewer => Focus::RequestEditor,
                        _ => Focus::Workspace,
                    },
                    MainTab::Proxy => match state.focus {
                        Focus::ProxyHistory => Focus::ResponseViewer,
                        Focus::RequestEditor => Focus::ProxyHistory,
                        Focus::ResponseViewer => Focus::RequestEditor,
                        _ => Focus::ProxyHistory,
                    },
                    _ => Focus::Workspace,
                };
            }

            // Cycle HTTP method with 'm'
            KeyCode::Char('m') => {
                if state.focus == Focus::RequestEditor {
                    state.request_method = match state.request_method.as_str() {
                        "GET" => "POST".to_string(),
                        "POST" => "PUT".to_string(),
                        "PUT" => "PATCH".to_string(),
                        "PATCH" => "DELETE".to_string(),
                        "DELETE" => "HEAD".to_string(),
                        "HEAD" => "OPTIONS".to_string(),
                        "OPTIONS" => "GET".to_string(),
                        _ => "GET".to_string(),
                    };
                }
            }

            // Enter edit mode based on context
            KeyCode::Char('i') => {
                if state.focus == Focus::RequestEditor {
                    match state.request_editor_tab {
                        RequestEditorTab::Params => {
                            state.mode = AppMode::EditKeyValue;
                            state.query_params.focused = true;
                        }
                        RequestEditorTab::Headers => {
                            state.mode = AppMode::EditKeyValue;
                            state.headers.focused = true;
                        }
                        RequestEditorTab::Body => {
                            state.mode = AppMode::EditBody;
                        }
                        RequestEditorTab::Auth => {
                            state.auth_field_index = 0;
                            state.mode = AppMode::EditAuth;
                        }
                    }
                } else if state.focus == Focus::Workspace {
                    // In workspace, 'i' could edit URL directly
                    state.url_cursor = state.url_input.len();
                    state.mode = AppMode::EditUrl;
                }
            }

            // Quick URL edit with 'e' (always edits URL)
            KeyCode::Char('e') => {
                if state.focus == Focus::RequestEditor {
                    state.url_cursor = state.url_input.len();
                    state.mode = AppMode::EditUrl;
                }
            }

            // Add new row with 'o' (like vim)
            KeyCode::Char('o') => {
                if state.focus == Focus::RequestEditor {
                    match state.request_editor_tab {
                        RequestEditorTab::Params => {
                            state.query_params.add_row();
                            state.query_params.edit_key();
                            state.query_params.focused = true;
                            state.mode = AppMode::EditKeyValue;
                        }
                        RequestEditorTab::Headers => {
                            state.headers.add_row();
                            state.headers.edit_key();
                            state.headers.focused = true;
                            state.mode = AppMode::EditKeyValue;
                        }
                        _ => {}
                    }
                }
            }

            // Delete row with 'd' (in params/headers) or open details dialog in proxy/scanner
            KeyCode::Char('d') => {
                if (state.focus == Focus::ProxyHistory || state.current_tab == MainTab::Proxy)
                    && !state.proxy_history.is_empty()
                {
                    // Open proxy details dialog
                    state.mode = AppMode::ProxyDetails;
                    state.proxy_details_tab = ProxyDetailsTab::Request;
                    state.proxy_details_scroll = 0;
                } else if (state.focus == Focus::Findings || state.current_tab == MainTab::Scanner)
                    && !state.findings.is_empty()
                {
                    // Find the selected finding from tree selection
                    if let Some(finding_idx) = state.findings_selected_within_host {
                        // We have a finding selected within a host
                        let (hosts, findings_by_host) = crate::tui::group_findings_by_host(&state.findings, &state.findings_filter);
                        if let Some(host) = hosts.get(state.findings_selected_host) {
                            if let Some(host_findings) = findings_by_host.get(host) {
                                if let Some(finding) = host_findings.get(finding_idx) {
                                    // Find the index of this finding in the flat list
                                    if let Some(idx) = state.findings.iter().position(|f| f.id == finding.id) {
                                        state.selected_finding = idx;
                                        state.mode = AppMode::FindingDetails;
                                    }
                                }
                            }
                        }
                    }
                    // If no finding selected (just a host), don't open details
                } else if state.focus == Focus::RequestEditor {
                    match state.request_editor_tab {
                        RequestEditorTab::Params => {
                            state.query_params.delete_row();
                        }
                        RequestEditorTab::Headers => {
                            state.headers.delete_row();
                        }
                        _ => {}
                    }
                }
            }

            // Toggle enabled with space
            KeyCode::Char(' ') => {
                if state.focus == Focus::RequestEditor {
                    match state.request_editor_tab {
                        RequestEditorTab::Params => {
                            state.query_params.toggle_enabled();
                        }
                        RequestEditorTab::Headers => {
                            state.headers.toggle_enabled();
                        }
                        _ => {}
                    }
                }
            }

            // Escape to normal mode
            KeyCode::Esc => {
                state.mode = AppMode::Normal;
            }

            // Command palette
            KeyCode::Char(':') => {
                state.mode = AppMode::Command;
            }

            // Help
            KeyCode::Char('?') => {
                state.mode = AppMode::Help;
            }

            // Environment selector (E or Ctrl+E)
            KeyCode::Char('E') => {
                state.env_selector_open = true;
                state.mode = AppMode::SelectEnvironment;
            }
            KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                state.env_selector_open = true;
                state.mode = AppMode::SelectEnvironment;
            }

            // Search response or filter proxy/findings (/)
            KeyCode::Char('/') => {
                if state.focus == Focus::ResponseViewer {
                    state.response_search.clear();
                    state.mode = AppMode::SearchResponse;
                } else if state.focus == Focus::ProxyHistory {
                    state.proxy_filter.clear();
                    state.mode = AppMode::FilterProxy;
                } else if state.focus == Focus::Findings || state.current_tab == MainTab::Scanner {
                    state.findings_filter_cursor = state.findings_filter.len();
                    state.mode = AppMode::FilterFindings;
                }
            }

            // Response tab switching with [ and ]
            KeyCode::Char('[') if state.focus == Focus::ResponseViewer => {
                state.response_tab = state.response_tab.prev();
            }
            KeyCode::Char(']') if state.focus == Focus::ResponseViewer => {
                state.response_tab = state.response_tab.next();
            }

            // Toggle raw/pretty mode (r)
            KeyCode::Char('r') => {
                if state.focus == Focus::ResponseViewer {
                    state.response_raw_mode = !state.response_raw_mode;
                    state.status_message = Some(if state.response_raw_mode {
                        "Raw mode enabled".to_string()
                    } else {
                        "Pretty mode enabled".to_string()
                    });
                    state.status_timestamp = Some(std::time::Instant::now());
                }
            }

            // Next search match (n)
            KeyCode::Char('n') if !state.response_search_matches.is_empty() => {
                if state.focus == Focus::ResponseViewer {
                    state.current_search_match =
                        (state.current_search_match + 1) % state.response_search_matches.len();
                    // Scroll to match
                    if let Some((line, _)) = state.response_search_matches.get(state.current_search_match) {
                        state.response_scroll = *line;
                    }
                }
            }

            // Previous search match (N)
            KeyCode::Char('N') if !state.response_search_matches.is_empty() => {
                if state.focus == Focus::ResponseViewer {
                    state.current_search_match = if state.current_search_match == 0 {
                        state.response_search_matches.len() - 1
                    } else {
                        state.current_search_match - 1
                    };
                    // Scroll to match
                    if let Some((line, _)) = state.response_search_matches.get(state.current_search_match) {
                        state.response_scroll = *line;
                    }
                }
            }

            // Create new request (n) - when not searching
            KeyCode::Char('n') if state.response_search_matches.is_empty() => {
                // Clear current request and start fresh
                state.url_input.clear();
                state.url_cursor = 0;
                state.request_method = "GET".to_string();
                state.query_params = crate::tui::widgets::KeyValueEditorState::new();
                state.headers = crate::tui::widgets::KeyValueEditorState::new();
                state.body_content.clear();
                state.body_content_type = BodyContentType::None;
                state.auth_type = AuthType::None;
                state.auth_username.clear();
                state.auth_password.clear();
                state.auth_token.clear();
                state.auth_api_key_name.clear();
                state.auth_api_key_value.clear();
                state.current_request = None;
                state.current_response = None;
                state.focus = Focus::RequestEditor;
                state.mode = AppMode::EditUrl;
                state.status_message = Some("New request".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Copy response to clipboard (y)
            KeyCode::Char('y') => {
                if state.focus == Focus::ResponseViewer {
                    if let Some(response) = &state.current_response {
                        match arboard::Clipboard::new() {
                            Ok(mut clipboard) => {
                                match clipboard.set_text(&response.body) {
                                    Ok(_) => {
                                        state.status_message = Some(format!(
                                            "Copied {} bytes to clipboard",
                                            response.body.len()
                                        ));
                                    }
                                    Err(e) => {
                                        state.status_message = Some(format!("Clipboard error: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                state.status_message = Some(format!("Clipboard unavailable: {}", e));
                            }
                        }
                        state.status_timestamp = Some(std::time::Instant::now());
                    }
                } else if state.focus == Focus::RequestEditor {
                    // Copy current URL to clipboard
                    match arboard::Clipboard::new() {
                        Ok(mut clipboard) => {
                            match clipboard.set_text(&state.url_input) {
                                Ok(_) => {
                                    state.status_message = Some("URL copied to clipboard".to_string());
                                }
                                Err(e) => {
                                    state.status_message = Some(format!("Clipboard error: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            state.status_message = Some(format!("Clipboard unavailable: {}", e));
                        }
                    }
                    state.status_timestamp = Some(std::time::Instant::now());
                }
            }

            // Paste/Import from clipboard (Ctrl+V)
            KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.handle_clipboard_paste(state);
            }

            // Delete with confirmation (D)
            KeyCode::Char('D') => {
                if state.focus == Focus::Workspace && !state.history_focused {
                    let items = self.get_collection_items();
                    if let Some(item) = items.get(state.selected_collection_item) {
                        if item.item_type == CollectionItemType::Request {
                            state.delete_target = Some(state.selected_collection_item);
                            state.mode = AppMode::ConfirmDelete;
                        }
                    }
                }
            }

            // Rename (R)
            KeyCode::Char('R') => {
                if state.focus == Focus::Workspace && !state.history_focused {
                    let items = self.get_collection_items();
                    if let Some(item) = items.get(state.selected_collection_item) {
                        state.rename_buffer = item.name.clone();
                        state.rename_target = Some(state.selected_collection_item);
                        state.mode = AppMode::Rename;
                    }
                }
            }

            // Export to cURL (C) - but not in proxy tab where C installs cert
            KeyCode::Char('C') if state.current_tab != MainTab::Proxy => {
                if state.focus == Focus::RequestEditor && !state.url_input.is_empty() {
                    drop(state); // Release lock before calling export
                    let curl_cmd = self.export_to_curl();
                    let mut state = self.state.write();
                    match arboard::Clipboard::new() {
                        Ok(mut clipboard) => {
                            match clipboard.set_text(&curl_cmd) {
                                Ok(_) => {
                                    state.status_message = Some("Copied cURL command to clipboard".to_string());
                                }
                                Err(e) => {
                                    state.status_message = Some(format!("Clipboard error: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            state.status_message = Some(format!("Clipboard unavailable: {}", e));
                        }
                    }
                    state.status_timestamp = Some(std::time::Instant::now());
                    return Ok(());
                }
            }

            // Toggle history focus (Shift+H when in workspace)
            KeyCode::Char('h') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                // Already handled by H for tab navigation
            }

            // Select from history (Enter on history item)
            // This is handled via 'H' to toggle history focus and j/k to navigate
            KeyCode::Char('H') if state.focus == Focus::Workspace => {
                // Toggle between collections and history
                state.history_focused = !state.history_focused;
                if state.history_focused {
                    state.selected_history_item = 0;
                    state.status_message = Some("History mode - j/k:nav  Enter:load".to_string());
                } else {
                    state.status_message = Some("Collections mode".to_string());
                }
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Toggle intercept mode (I)
            KeyCode::Char('I') if state.current_tab == MainTab::Proxy => {
                state.intercept_enabled = !state.intercept_enabled;
                let enabled = state.intercept_enabled;

                // If disabling intercept, auto-forward any pending request
                let pending_request = if !enabled {
                    state.intercepted_request.take()
                } else {
                    None
                };

                state.status_message = Some(if enabled {
                    "Intercept enabled - requests will be paused".to_string()
                } else {
                    "Intercept disabled - pending requests forwarded".to_string()
                });
                state.status_timestamp = Some(std::time::Instant::now());

                // Sync to proxy's InterceptManager
                drop(state);
                if let Some(ref proxy) = self.proxy {
                    proxy.intercept().write().set_enabled(enabled);
                }

                // Forward the pending request if we had one
                if let Some(req) = pending_request {
                    self.resolve_intercept(req.id, crate::proxy::InterceptDecision {
                        forward: true,
                        request: req,
                    });
                }
            }

            // Install CA certificate (C in proxy tab)
            KeyCode::Char('C') if state.current_tab == MainTab::Proxy => {
                tracing::info!("Installing CA certificate...");
                drop(state); // Release lock before calling proxy methods
                if let Some(proxy) = &self.proxy {
                    let (successes, errors) = proxy.install_ca_cert();
                    let mut state = self.state.write();
                    let mut msgs = Vec::new();
                    msgs.extend(successes);
                    msgs.extend(errors);
                    if msgs.is_empty() {
                        state.status_message = Some("CA cert install: no action taken".to_string());
                    } else {
                        state.status_message = Some(msgs.join(" | "));
                    }
                    state.status_timestamp = Some(std::time::Instant::now());
                } else {
                    let mut state = self.state.write();
                    state.status_message = Some("Proxy not running - cannot install cert".to_string());
                    state.status_timestamp = Some(std::time::Instant::now());
                }
                return Ok(());
            }

            // Forward intercepted request (f when viewing intercepted)
            KeyCode::Char('f') if state.intercepted_request.is_some() && state.current_tab == MainTab::Proxy => {
                if let Some(req) = state.intercepted_request.take() {
                    drop(state); // Release lock before resolving
                    self.resolve_intercept(req.id, crate::proxy::InterceptDecision {
                        forward: true,
                        request: req,
                    });
                    let mut state = self.state.write();
                    state.status_message = Some("Request forwarded".to_string());
                    state.status_timestamp = Some(std::time::Instant::now());
                }
            }

            // Drop intercepted request (x when viewing intercepted)
            KeyCode::Char('x') if state.intercepted_request.is_some() && state.current_tab == MainTab::Proxy => {
                if let Some(mut req) = state.intercepted_request.take() {
                    req.drop = true;
                    drop(state); // Release lock before resolving
                    self.resolve_intercept(req.id, crate::proxy::InterceptDecision {
                        forward: false,
                        request: req,
                    });
                    let mut state = self.state.write();
                    state.status_message = Some("Request dropped".to_string());
                    state.status_timestamp = Some(std::time::Instant::now());
                }
            }

            // Export CA certificate (X in proxy tab)
            KeyCode::Char('X') if state.current_tab == MainTab::Proxy => {
                drop(state); // Release lock before accessing self
                self.export_ca_cert()?;
                return Ok(());
            }

            // ============ Fuzzer Tab Keyboard Handlers ============
            // Cycle focus within fuzzer panels (Tab)
            KeyCode::Tab if state.current_tab == MainTab::Fuzzer => {
                state.fuzzer_focus = state.fuzzer_focus.next();
            }
            KeyCode::BackTab if state.current_tab == MainTab::Fuzzer => {
                state.fuzzer_focus = state.fuzzer_focus.prev();
            }

            // Navigate fuzzer results (j/k when in results focus)
            KeyCode::Char('j') if state.current_tab == MainTab::Fuzzer && state.fuzzer_focus == FuzzerFocus::Results => {
                let max_idx = state.fuzzer_results.len().saturating_sub(1);
                if state.fuzzer_selected_result < max_idx {
                    state.fuzzer_selected_result += 1;
                    // Keep selection visible
                    let visible_height = 15;
                    if state.fuzzer_selected_result >= state.fuzzer_results_scroll + visible_height {
                        state.fuzzer_results_scroll = state.fuzzer_selected_result.saturating_sub(visible_height - 1);
                    }
                }
            }
            KeyCode::Char('k') if state.current_tab == MainTab::Fuzzer && state.fuzzer_focus == FuzzerFocus::Results => {
                state.fuzzer_selected_result = state.fuzzer_selected_result.saturating_sub(1);
                // Keep selection visible
                if state.fuzzer_selected_result < state.fuzzer_results_scroll {
                    state.fuzzer_results_scroll = state.fuzzer_selected_result;
                }
            }

            // Cycle attack mode (m)
            KeyCode::Char('m') if state.current_tab == MainTab::Fuzzer => {
                state.fuzzer_attack_mode = match state.fuzzer_attack_mode {
                    crate::fuzzer::AttackMode::Sniper => crate::fuzzer::AttackMode::Battering,
                    crate::fuzzer::AttackMode::Battering => crate::fuzzer::AttackMode::Pitchfork,
                    crate::fuzzer::AttackMode::Pitchfork => crate::fuzzer::AttackMode::ClusterBomb,
                    crate::fuzzer::AttackMode::ClusterBomb => crate::fuzzer::AttackMode::Sniper,
                };
                state.status_message = Some(format!("Attack mode: {}", state.fuzzer_attack_mode.name()));
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Cycle payload set (w)
            KeyCode::Char('w') if state.current_tab == MainTab::Fuzzer => {
                state.fuzzer_payload_set = state.fuzzer_payload_set.next();
                state.status_message = Some(format!("Payload set: {}", state.fuzzer_payload_set.name()));
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Cycle sort order (s)
            KeyCode::Char('s') if state.current_tab == MainTab::Fuzzer && !state.fuzzer_results.is_empty() => {
                state.fuzzer_sort_by = state.fuzzer_sort_by.next();
                state.status_message = Some(format!("Sort by: {}", state.fuzzer_sort_by.name()));
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Increase concurrency (+)
            KeyCode::Char('+') | KeyCode::Char('=') if state.current_tab == MainTab::Fuzzer => {
                state.fuzzer_concurrency = (state.fuzzer_concurrency + 5).min(100);
                state.status_message = Some(format!("Concurrency: {}", state.fuzzer_concurrency));
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Decrease concurrency (-)
            KeyCode::Char('-') if state.current_tab == MainTab::Fuzzer => {
                state.fuzzer_concurrency = state.fuzzer_concurrency.saturating_sub(5).max(1);
                state.status_message = Some(format!("Concurrency: {}", state.fuzzer_concurrency));
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Clear filter in scanner (c)
            KeyCode::Char('c') if state.current_tab == MainTab::Scanner && !state.findings_filter.is_empty() => {
                state.findings_filter.clear();
                state.findings_filter_cursor = 0;
                state.findings_selected_host = 0;
                state.findings_selected_within_host = None;
                state.status_message = Some("Filter cleared".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Clear fuzzer results (c)
            KeyCode::Char('c') if state.current_tab == MainTab::Fuzzer && !state.fuzzer_results.is_empty() => {
                state.fuzzer_results.clear();
                state.fuzzer_selected_result = 0;
                state.fuzzer_stats = crate::fuzzer::FuzzerStats::default();
                state.status_message = Some("Results cleared".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Jump to next interesting result (n)
            KeyCode::Char('n') if state.current_tab == MainTab::Fuzzer && !state.fuzzer_results.is_empty() => {
                let start = state.fuzzer_selected_result + 1;
                for i in start..state.fuzzer_results.len() {
                    if state.fuzzer_results[i].interesting {
                        state.fuzzer_selected_result = i;
                        break;
                    }
                }
            }

            // Jump to previous interesting result (N)
            KeyCode::Char('N') if state.current_tab == MainTab::Fuzzer && !state.fuzzer_results.is_empty() => {
                if state.fuzzer_selected_result > 0 {
                    for i in (0..state.fuzzer_selected_result).rev() {
                        if state.fuzzer_results[i].interesting {
                            state.fuzzer_selected_result = i;
                            break;
                        }
                    }
                }
            }

            // ============ Spider Tab Keyboard Handlers ============
            // Tab to cycle focus in Spider view
            KeyCode::Tab if state.current_tab == MainTab::Spider => {
                state.spider_focus = state.spider_focus.next();
            }
            KeyCode::BackTab if state.current_tab == MainTab::Spider => {
                state.spider_focus = state.spider_focus.prev();
            }
            // Navigate discovered URLs list (j/k)
            KeyCode::Char('j') if state.current_tab == MainTab::Spider && state.spider_focus == SpiderFocus::Results => {
                if !state.spider_discovered.is_empty() {
                    state.spider_selected_url = (state.spider_selected_url + 1).min(state.spider_discovered.len() - 1);
                }
            }
            KeyCode::Char('k') if state.current_tab == MainTab::Spider && state.spider_focus == SpiderFocus::Results => {
                state.spider_selected_url = state.spider_selected_url.saturating_sub(1);
            }
            // Edit URL input
            KeyCode::Char('i') if state.current_tab == MainTab::Spider && state.spider_focus == SpiderFocus::UrlInput => {
                // Use spider URL input for editing
                state.url_input = state.spider_url_input.clone();
                state.url_cursor = state.url_input.len();
                state.mode = AppMode::EditUrl;
            }
            // Adjust spider config
            KeyCode::Char('+') | KeyCode::Char('=') if state.current_tab == MainTab::Spider && state.spider_focus == SpiderFocus::Config => {
                state.spider_max_depth = (state.spider_max_depth + 1).min(20);
            }
            KeyCode::Char('-') if state.current_tab == MainTab::Spider && state.spider_focus == SpiderFocus::Config => {
                state.spider_max_depth = state.spider_max_depth.saturating_sub(1).max(1);
            }

            // ============ Browser Tab Keyboard Handlers ============
            // Navigate captures list (j/k)
            KeyCode::Char('j') if state.current_tab == MainTab::Browser => {
                if !state.browser_captures.is_empty() {
                    state.browser_selected_capture = (state.browser_selected_capture + 1).min(state.browser_captures.len() - 1);
                }
            }
            KeyCode::Char('k') if state.current_tab == MainTab::Browser => {
                state.browser_selected_capture = state.browser_selected_capture.saturating_sub(1);
            }
            // Open browser URL dialog (Enter on Browser tab)
            KeyCode::Enter if state.current_tab == MainTab::Browser => {
                state.mode = AppMode::BrowserUrl;
                state.browser_url_input.clear();
            }
            // Toggle theme (t on Settings)
            KeyCode::Char('t') if state.current_tab == MainTab::Settings => {
                state.settings_dark_theme = !state.settings_dark_theme;
                state.status_message = Some(format!("Theme: {}", if state.settings_dark_theme { "dark" } else { "light" }));
                state.status_timestamp = Some(std::time::Instant::now());
            }

            // Quit
            KeyCode::Char('q') => {
                state.should_quit = true;
            }

            _ => {}
        }

        Ok(())
    }

    /// Handle an intercepted proxy request
    async fn handle_proxy_request(&mut self, request: crate::proxy::InterceptedRequest) -> Result<()> {
        let mut state = self.state.write();

        // Only intercept if intercept mode is enabled
        if !state.intercept_enabled {
            tracing::debug!("Intercept disabled, ignoring request: {} {}", request.method, request.url);
            return Ok(());
        }

        // Queue the request for user review
        state.intercepted_request = Some(request.clone());
        state.intercept_queue_count += 1;

        // Switch to proxy tab to show the intercepted request
        if state.current_tab != MainTab::Proxy {
            state.current_tab = MainTab::Proxy;
        }

        // Show status message
        let msg = if request.is_response {
            format!("Intercepted response: {} {}", request.status.unwrap_or(0), request.url)
        } else {
            format!("Intercepted request: {} {}", request.method, request.url)
        };
        state.status_message = Some(msg);
        state.status_timestamp = Some(std::time::Instant::now());

        tracing::info!("Intercepted {} to {}",
            if request.is_response { "response" } else { "request" },
            request.url);

        Ok(())
    }

    /// Execute a command from the command palette
    fn execute_command(&self, cmd: &str) -> Result<()> {
        let cmd = cmd.trim();
        let mut state = self.state.write();

        match cmd {
            "q" | "quit" | "exit" => {
                state.should_quit = true;
            }
            "w" | "write" | "save" => {
                drop(state);
                if let Err(e) = self.save_session() {
                    let mut state = self.state.write();
                    state.status_message = Some(format!("Save failed: {}", e));
                    state.status_timestamp = Some(std::time::Instant::now());
                } else {
                    let mut state = self.state.write();
                    state.status_message = Some("Session saved".to_string());
                    state.status_timestamp = Some(std::time::Instant::now());
                }
                return Ok(());
            }
            "wq" => {
                drop(state);
                let _ = self.save_session();
                self.state.write().should_quit = true;
                return Ok(());
            }
            "clear" | "cls" => {
                state.request_history.clear();
                state.status_message = Some("History cleared".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }
            "proxy start" => {
                if state.proxy_running {
                    state.status_message = Some("Proxy already running".to_string());
                } else {
                    state.status_message = Some("Use the app to start proxy automatically".to_string());
                }
                state.status_timestamp = Some(std::time::Instant::now());
            }
            "proxy stop" => {
                state.status_message = Some("Proxy control via command not yet implemented".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
            }
            "intercept on" => {
                state.intercept_enabled = true;
                state.status_message = Some("Intercept mode enabled".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
                drop(state);
                if let Some(ref proxy) = self.proxy {
                    proxy.intercept().write().set_enabled(true);
                }
                return Ok(());
            }
            "intercept off" => {
                state.intercept_enabled = false;
                state.status_message = Some("Intercept mode disabled".to_string());
                state.status_timestamp = Some(std::time::Instant::now());
                drop(state);
                if let Some(ref proxy) = self.proxy {
                    proxy.intercept().write().set_enabled(false);
                }
                return Ok(());
            }
            "help" | "?" => {
                state.mode = AppMode::Help;
            }
            _ => {
                // Check for tab commands
                if let Some(tab_num) = cmd.strip_prefix("tab ") {
                    if let Ok(n) = tab_num.parse::<usize>() {
                        if n >= 1 && n <= 8 {
                            state.current_tab = match n {
                                1 => MainTab::Workspace,
                                2 => MainTab::Proxy,
                                3 => MainTab::Scanner,
                                4 => MainTab::Browser,
                                5 => MainTab::Spider,
                                6 => MainTab::Fuzzer,
                                7 => MainTab::Settings,
                                _ => state.current_tab,
                            };
                            state.status_message = Some(format!("Switched to {} tab", state.current_tab.name()));
                            state.status_timestamp = Some(std::time::Instant::now());
                        }
                    }
                } else if cmd.starts_with("report ") {
                    // Parse report command: report <format> <path>
                    // e.g., "report html /tmp/report.html"
                    let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                    if parts.len() >= 3 {
                        let format = parts[1];
                        let path = parts[2];
                        let findings = state.findings.clone();
                        let target_url = state.url_input.clone();
                        drop(state); // Release lock before file I/O

                        let metadata = ReportMetadata {
                            target: target_url,
                            ..Default::default()
                        };
                        let report = ScanReport::new(findings, metadata);

                        let result = match format {
                            "html" => report.to_html().and_then(|c| std::fs::write(path, c).map_err(Into::into)),
                            "json" => report.to_json().and_then(|c| std::fs::write(path, c).map_err(Into::into)),
                            "csv" => report.to_csv().and_then(|c| std::fs::write(path, c).map_err(Into::into)),
                            "md" | "markdown" => report.to_markdown().and_then(|c| std::fs::write(path, c).map_err(Into::into)),
                            _ => {
                                let mut state = self.state.write();
                                state.status_message = Some(format!("Unknown format: {}. Use html, json, csv, or md", format));
                                state.status_timestamp = Some(std::time::Instant::now());
                                return Ok(());
                            }
                        };

                        let mut state = self.state.write();
                        match result {
                            Ok(()) => {
                                state.status_message = Some(format!("Report saved to {}", path));
                            }
                            Err(e) => {
                                state.status_message = Some(format!("Report failed: {}", e));
                            }
                        }
                        state.status_timestamp = Some(std::time::Instant::now());
                        return Ok(());
                    } else {
                        state.status_message = Some("Usage: report <format> <path>".to_string());
                        state.status_timestamp = Some(std::time::Instant::now());
                    }
                } else if cmd.starts_with("set ") {
                    state.status_message = Some("Settings commands not yet implemented".to_string());
                    state.status_timestamp = Some(std::time::Instant::now());
                } else {
                    state.status_message = Some(format!("Unknown command: {}", cmd));
                    state.status_timestamp = Some(std::time::Instant::now());
                }
            }
        }

        Ok(())
    }

    /// Start the proxy server
    async fn start_proxy(&mut self) -> Result<()> {
        tracing::info!("Starting proxy on port {}", self.proxy_port);
        let proxy = ProxyServer::new(&self.config.proxy, self.proxy_port, self.event_tx.clone())?;
        proxy.start().await?;

        // Auto-install CA certificate for HTTPS interception
        let (successes, errors) = proxy.install_ca_cert();
        let mut status_parts = Vec::new();
        for s in &successes {
            tracing::info!("CA cert: {}", s);
        }
        for e in &errors {
            tracing::warn!("CA cert: {}", e);
        }

        // Show brief status
        if successes.iter().any(|s| s.contains("Installed to NSS")) {
            status_parts.push("CA cert installed to browser".to_string());
        } else if successes.iter().any(|s| s.contains("Already in NSS")) {
            status_parts.push("CA cert already installed".to_string());
        } else {
            status_parts.push("CA cert saved - install manually for HTTPS".to_string());
        }

        self.proxy = Some(proxy);
        let mut state = self.state.write();
        state.proxy_running = true;
        state.status_message = Some(format!("Proxy started on port {} | {}", self.proxy_port, status_parts.join(" | ")));
        state.status_timestamp = Some(std::time::Instant::now());

        Ok(())
    }

    /// Stop the proxy server
    async fn stop_proxy(&mut self) -> Result<()> {
        if let Some(proxy) = self.proxy.take() {
            proxy.stop().await?;
        }
        self.state.write().proxy_running = false;
        Ok(())
    }

    /// Resolve an intercept decision - sends the decision back to the proxy
    fn resolve_intercept(&self, id: u64, decision: crate::proxy::InterceptDecision) {
        if let Some(ref proxy) = self.proxy {
            let intercept_manager = proxy.intercept();
            let mut manager = intercept_manager.write();
            manager.resolve_intercept(id, decision);
        }
    }

    /// Start the spider crawl
    async fn start_spider(&mut self) -> Result<()> {
        let spider_url = {
            let state = self.state.read();
            state.spider_url_input.clone()
        };

        if spider_url.is_empty() {
            let mut state = self.state.write();
            state.status_message = Some("Enter a URL to start crawling".to_string());
            state.status_timestamp = Some(std::time::Instant::now());
            return Ok(());
        }

        // Validate URL
        if url::Url::parse(&spider_url).is_err() {
            let mut state = self.state.write();
            state.status_message = Some("Invalid URL format".to_string());
            state.status_timestamp = Some(std::time::Instant::now());
            return Ok(());
        }

        // Get config from state
        let (max_depth, max_pages, delay_ms) = {
            let state = self.state.read();
            (state.spider_max_depth, state.spider_max_pages, state.spider_delay_ms)
        };

        // Create spider with current config
        let config = crate::spider::SpiderConfig {
            max_depth,
            max_pages,
            delay_ms,
            ..Default::default()
        };

        let mut spider = crate::spider::Spider::new(config);

        // Update state to show running
        {
            let mut state = self.state.write();
            state.spider_state = crate::spider::SpiderState::Running;
            state.spider_discovered.clear();
            state.spider_selected_url = 0;
            state.status_message = Some(format!("Crawling: {}", spider_url));
            state.status_timestamp = Some(std::time::Instant::now());
        }

        tracing::info!("Starting spider crawl of: {}", spider_url);

        // Run crawl - this is blocking but we do it in-line for simplicity
        // In a production app, this would be spawned as a background task
        match spider.crawl(&spider_url, &self.http_client).await {
            Ok(discovered) => {
                let mut state = self.state.write();
                state.spider_discovered = discovered.clone();
                state.spider_state = crate::spider::SpiderState::Idle;
                state.spider_stats = spider.stats();
                state.status_message = Some(format!("Crawl complete: {} URLs discovered", discovered.len()));
                state.status_timestamp = Some(std::time::Instant::now());
                tracing::info!("Spider crawl complete: {} URLs discovered", discovered.len());
            }
            Err(e) => {
                let mut state = self.state.write();
                state.spider_state = crate::spider::SpiderState::Stopped;
                state.status_message = Some(format!("Crawl error: {}", e));
                state.status_timestamp = Some(std::time::Instant::now());
                tracing::error!("Spider crawl error: {}", e);
            }
        }

        self.spider = Some(spider);
        Ok(())
    }

    /// Start the fuzzer attack
    async fn start_fuzzer(&mut self) -> Result<()> {
        let (template, payload_set, attack_mode, concurrency, delay_ms, custom_payloads) = {
            let state = self.state.read();
            (
                state.fuzzer_request_template.clone(),
                state.fuzzer_payload_set.clone(),
                state.fuzzer_attack_mode,
                state.fuzzer_concurrency,
                state.fuzzer_delay_ms,
                state.fuzzer_custom_payloads.clone(),
            )
        };

        if template.is_empty() {
            let mut state = self.state.write();
            state.status_message = Some("Enter a request template with §markers§ for payload positions".to_string());
            state.status_timestamp = Some(std::time::Instant::now());
            return Ok(());
        }

        // Parse template to find §marker§ positions (Burp-style)
        let positions = Self::parse_fuzzer_positions(&template);
        if positions.is_empty() {
            let mut state = self.state.write();
            state.status_message = Some("No payload positions found. Use §marker§ syntax.".to_string());
            state.status_timestamp = Some(std::time::Instant::now());
            return Ok(());
        }

        // Get payloads based on selected payload set
        let payloads = match payload_set {
            FuzzerPayloadSet::Custom => {
                let custom: Vec<String> = custom_payloads
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect();
                if custom.is_empty() {
                    let mut state = self.state.write();
                    state.status_message = Some("Custom payloads are empty".to_string());
                    state.status_timestamp = Some(std::time::Instant::now());
                    return Ok(());
                }
                crate::fuzzer::PayloadSet::new("custom", custom)
            }
            FuzzerPayloadSet::CommonPasswords => crate::fuzzer::PayloadSet::common_passwords(),
            FuzzerPayloadSet::CommonUsernames => crate::fuzzer::PayloadSet::common_usernames(),
            FuzzerPayloadSet::SqlInjection => crate::fuzzer::PayloadSet::sqli_payloads(),
            FuzzerPayloadSet::Xss => crate::fuzzer::PayloadSet::xss_payloads(),
            FuzzerPayloadSet::PathTraversal => crate::fuzzer::PayloadSet::path_traversal_payloads(),
            FuzzerPayloadSet::CommandInjection => crate::fuzzer::PayloadSet::command_injection_payloads(),
            FuzzerPayloadSet::DirectoryBruteforce => crate::fuzzer::PayloadSet::directory_bruteforce(),
        };

        // Build base request from template (remove markers)
        let base_request = Self::parse_fuzzer_template(&template)?;

        // Create fuzzer config
        let config = crate::fuzzer::FuzzerConfig {
            max_concurrent: concurrency,
            delay_ms,
            timeout_secs: 30,
            follow_redirects: true,
            max_response_size: 10 * 1024 * 1024,
            length_variance_threshold: 10.0,
        };

        // Update state to show running
        {
            let mut state = self.state.write();
            state.fuzzer_state = crate::fuzzer::FuzzerState::Running;
            state.fuzzer_results.clear();
            state.fuzzer_selected_result = 0;
            state.fuzzer_stats = crate::fuzzer::FuzzerStats::default();
            state.status_message = Some(format!("Fuzzing: {} positions, {} payloads", positions.len(), payloads.len()));
            state.status_timestamp = Some(std::time::Instant::now());
        }

        tracing::info!("Starting fuzzer: {} positions, {} payloads, mode: {}",
            positions.len(), payloads.len(), attack_mode.name());

        // Create payload sets for each position (use same set for all in simple mode)
        let payload_sets: Vec<crate::fuzzer::PayloadSet> = positions.iter()
            .map(|_| payloads.clone())
            .collect();

        // Create and run fuzzer
        let fuzzer = match crate::fuzzer::Fuzzer::new(config) {
            Ok(f) => f,
            Err(e) => {
                let mut state = self.state.write();
                state.fuzzer_state = crate::fuzzer::FuzzerState::Stopped;
                state.status_message = Some(format!("Fuzzer error: {}", e));
                state.status_timestamp = Some(std::time::Instant::now());
                return Ok(());
            }
        };

        match fuzzer.fuzz(&base_request, positions, payload_sets, attack_mode).await {
            Ok(result_set) => {
                let mut state = self.state.write();
                state.fuzzer_results = result_set.results.clone();
                state.fuzzer_state = crate::fuzzer::FuzzerState::Completed;
                state.fuzzer_stats.requests_sent = state.fuzzer_results.len();
                state.fuzzer_stats.requests_remaining = 0;
                state.fuzzer_stats.interesting_count = state.fuzzer_results.iter()
                    .filter(|r| r.interesting)
                    .count();
                state.status_message = Some(format!(
                    "Fuzzing complete: {} requests, {} interesting",
                    state.fuzzer_results.len(),
                    state.fuzzer_stats.interesting_count
                ));
                state.status_timestamp = Some(std::time::Instant::now());
                tracing::info!("Fuzzer complete: {} results", state.fuzzer_results.len());
            }
            Err(e) => {
                let mut state = self.state.write();
                state.fuzzer_state = crate::fuzzer::FuzzerState::Stopped;
                state.status_message = Some(format!("Fuzzer error: {}", e));
                state.status_timestamp = Some(std::time::Instant::now());
                tracing::error!("Fuzzer error: {}", e);
            }
        }

        Ok(())
    }

    /// Parse fuzzer template to find §marker§ positions
    fn parse_fuzzer_positions(template: &str) -> Vec<crate::fuzzer::PayloadPosition> {
        let mut positions = Vec::new();
        let mut idx = 0;
        let mut pos_count = 0;

        while let Some(start) = template[idx..].find('§') {
            let abs_start = idx + start;
            if let Some(end) = template[abs_start + 1..].find('§') {
                let abs_end = abs_start + 1 + end;
                let marker = &template[abs_start + 1..abs_end];

                positions.push(crate::fuzzer::PayloadPosition {
                    name: if marker.is_empty() {
                        format!("pos{}", pos_count)
                    } else {
                        marker.to_string()
                    },
                    start: abs_start,
                    end: abs_end + 1,
                    original_value: marker.to_string(),
                });
                pos_count += 1;
                idx = abs_end + 1;
            } else {
                break;
            }
        }

        positions
    }

    /// Parse fuzzer template into a base request (removing markers)
    fn parse_fuzzer_template(template: &str) -> Result<crate::http::Request> {
        // Remove §markers§ and replace with empty strings for base request
        let clean_template = {
            let mut result = template.to_string();
            while let Some(start) = result.find('§') {
                if let Some(end) = result[start + 1..].find('§') {
                    result = format!("{}{}", &result[..start], &result[start + 1 + end + 1..]);
                } else {
                    break;
                }
            }
            result
        };

        // Parse HTTP request format
        // Expected: METHOD URL\nHeader: Value\n\nBody
        let lines: Vec<&str> = clean_template.lines().collect();
        if lines.is_empty() {
            anyhow::bail!("Empty request template");
        }

        // Parse first line: METHOD URL
        let first_line_parts: Vec<&str> = lines[0].splitn(2, ' ').collect();
        if first_line_parts.len() < 2 {
            anyhow::bail!("Invalid request line. Expected: METHOD URL");
        }

        let method = first_line_parts[0];
        let url = first_line_parts[1];

        let mut request = crate::http::Request::new(method, url);

        // Parse headers (lines until empty line)
        let mut body_start = lines.len();
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                request.headers.insert(
                    key.trim().to_string(),
                    value.trim().to_string(),
                );
            }
        }

        // Parse body (everything after empty line)
        if body_start < lines.len() {
            let body = lines[body_start..].join("\n");
            if !body.is_empty() {
                request.body = Some(body);
            }
        }

        Ok(request)
    }

    /// Execute a script file
    async fn execute_script(&self, path: &str) -> Result<()> {
        tracing::warn!("Script execution not yet fully implemented");

        // Read and execute the script file
        let script = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read script file: {}", path))?;

        let mut context = crate::scripting::ScriptContext::new(
            self.config.scripting.timeout_ms as u64,
        );

        let result = context.execute(&script)?;
        if result.success {
            tracing::info!("Script completed successfully");
            if let Some(value) = result.value {
                tracing::info!("Script result: {}", value);
            }
        } else if let Some(error) = result.error {
            tracing::error!("Script error: {}", error);
            anyhow::bail!("Script execution failed: {}", error);
        }

        Ok(())
    }

    /// Run a quick scan on a target URL
    async fn quick_scan(&self, url: &str) -> Result<()> {
        tracing::info!("Starting quick scan of: {}", url);

        // Check scope enforcement
        {
            let state = self.state.read();
            if state.scope_enforce_scanner && !state.scope_manager.is_in_scope(url) {
                tracing::warn!("Target URL is out of scope: {}", url);
                anyhow::bail!("Target URL is out of scope. Add it to scope or disable scope enforcement.");
            }
        }

        // Validate URL
        let parsed_url = url::Url::parse(url)
            .with_context(|| format!("Invalid target URL: {}", url))?;

        tracing::info!("Target host: {}", parsed_url.host_str().unwrap_or("unknown"));

        // Create a basic request to the target
        let request = crate::http::Request::new("GET", url);

        // Execute the request
        let response = self.http_client.execute(&request).await?;
        tracing::info!("Received response: {} {}", response.status, response.status_text);

        // Run passive scanner on the response
        let findings = self.scanner.passive_scan(&request, &response);
        if !findings.is_empty() {
            tracing::warn!("Found {} potential issues:", findings.len());
            for finding in &findings {
                tracing::warn!("  [{}] {}", finding.severity, finding.name);
            }
        } else {
            tracing::info!("No issues found by passive scanner");
        }

        // Note: Active scanning would go here but requires more setup
        Ok(())
    }

    /// Get event sender for external use
    pub fn event_sender(&self) -> mpsc::Sender<AppEvent> {
        self.event_tx.clone()
    }

    /// Get a flat list of all collection items for navigation
    /// Returns tuples of (depth, is_folder, name, Option<Request>)
    pub fn get_collection_items(&self) -> Vec<CollectionNavigationItem> {
        let mut items = Vec::new();

        if let Some(project) = self.workspace.project() {
            for collection in &project.collections {
                // Add collection as a "folder"
                items.push(CollectionNavigationItem {
                    depth: 0,
                    name: collection.name.clone(),
                    item_type: CollectionItemType::Collection,
                    request: None,
                });

                // Add items
                self.flatten_collection_items(&collection.items, 1, &mut items);
            }
        }

        items
    }

    fn flatten_collection_items(
        &self,
        items: &[crate::workspace::CollectionItem],
        depth: usize,
        result: &mut Vec<CollectionNavigationItem>,
    ) {
        use crate::workspace::CollectionItem;

        for item in items {
            match item {
                CollectionItem::Request(req) => {
                    result.push(CollectionNavigationItem {
                        depth,
                        name: req.name.clone(),
                        item_type: CollectionItemType::Request,
                        request: Some(req.request.clone()),
                    });
                }
                CollectionItem::Folder(folder) => {
                    result.push(CollectionNavigationItem {
                        depth,
                        name: folder.name.clone(),
                        item_type: CollectionItemType::Folder,
                        request: None,
                    });
                    self.flatten_collection_items(&folder.items, depth + 1, result);
                }
            }
        }
    }

    /// Sync proxy history from the proxy server to app state
    pub fn sync_proxy_history(&self) {
        if let Some(proxy) = &self.proxy {
            let history = proxy.history();
            let entries = history.get_all();

            if !entries.is_empty() {
                tracing::debug!("sync_proxy_history: found {} entries", entries.len());
            }

            // Get scope settings
            let (scope_enforce, scope_manager) = {
                let state = self.state.read();
                (state.scope_enforce_proxy, state.scope_manager.clone())
            };

            // Filter entries by scope if enforcement is enabled
            let entries: Vec<_> = if scope_enforce {
                entries.into_iter().filter(|e| scope_manager.is_in_scope(&e.url)).collect()
            } else {
                entries
            };

            // Track new entries for passive scanning
            let current_count = self.state.read().proxy_history.len();
            let new_entries: Vec<_> = entries.iter().skip(current_count).cloned().collect();

            let mut state = self.state.write();
            state.proxy_history = entries
                .into_iter()
                .map(|e| ProxyHistoryItem {
                    id: e.id,
                    method: e.method,
                    url: e.url,
                    host: e.host,
                    path: e.path,
                    status: e.status,
                    duration_ms: e.duration_ms,
                    response_size: e.response_size,
                    is_https: e.is_https,
                    content_type: e.content_type,
                    request_headers: e.request_headers,
                    request_body: e.request_body.map(|b| String::from_utf8_lossy(&b).to_string()),
                    response_headers: e.response_headers,
                    response_body: e.response_body.map(|b| String::from_utf8_lossy(&b).to_string()),
                })
                .collect();

            // Run passive scanning on new entries
            for entry in new_entries {
                if entry.status.is_some() && entry.response_body.is_some() {
                    // Create request/response for scanning
                    let request = crate::http::Request::new(&entry.method, &entry.url);
                    let body_bytes = entry.response_body.clone().unwrap_or_default();
                    let response = crate::http::Response {
                        status: entry.status.unwrap_or(0),
                        status_text: "OK".to_string(),
                        headers: entry.response_headers.unwrap_or_default(),
                        body: body_bytes.clone(),
                        duration_ms: entry.duration_ms.unwrap_or(0),
                        size: body_bytes.len(),
                        http_version: "HTTP/1.1".to_string(),
                        remote_addr: None,
                        tls_info: None,
                        timing: None,
                        cookies: Vec::new(),
                    };

                    // Run passive scanner
                    let new_findings = self.scanner.passive_scan(&request, &response);
                    if !new_findings.is_empty() {
                        state.findings.extend(new_findings);
                    }
                }
            }
        }
    }

    /// Get filtered proxy history items (supports !pattern for exclusion)
    pub fn get_filtered_proxy_history(&self) -> Vec<ProxyHistoryItem> {
        let state = self.state.read();
        if state.proxy_filter.is_empty() {
            return state.proxy_history.clone();
        }

        // Parse filter into include and exclude patterns
        let mut include_patterns: Vec<regex::Regex> = Vec::new();
        let mut exclude_patterns: Vec<regex::Regex> = Vec::new();

        for part in state.proxy_filter.split_whitespace() {
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

        state.proxy_history
            .iter()
            .filter(|item| {
                let searchable = format!("{} {} {}", item.host, item.url, item.method);

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
            .cloned()
            .collect()
    }

    /// Load a request from the collection at the given index
    pub fn load_request_at_index(&mut self, index: usize) {
        use crate::tui::widgets::{KeyValueEditorState, KeyValueRow};

        let items = self.get_collection_items();

        if let Some(item) = items.get(index) {
            if let Some(request) = &item.request {
                let mut state = self.state.write();

                // Set URL and method
                state.url_input = request.url.clone();
                state.request_method = request.method.clone();
                state.current_request = Some(request.clone());
                state.current_response = None;

                // Parse query params from URL
                let mut query_rows = Vec::new();
                if let Ok(parsed) = url::Url::parse(&request.url) {
                    for (key, value) in parsed.query_pairs() {
                        query_rows.push(KeyValueRow::with_key_value(&key, &value));
                    }
                }
                if query_rows.is_empty() {
                    query_rows.push(KeyValueRow::new());
                }
                state.query_params = KeyValueEditorState::with_rows(query_rows);

                // Load headers
                let header_rows: Vec<KeyValueRow> = request
                    .headers
                    .iter()
                    .map(|(k, v)| KeyValueRow::with_key_value(k, v))
                    .collect();
                state.headers = if header_rows.is_empty() {
                    KeyValueEditorState::new()
                } else {
                    KeyValueEditorState::with_rows(header_rows)
                };

                // Load body
                state.body_content = request.body.clone().unwrap_or_default();
                state.body_content_type = if state.body_content.is_empty() {
                    BodyContentType::None
                } else if state.body_content.trim_start().starts_with('{')
                    || state.body_content.trim_start().starts_with('[')
                {
                    BodyContentType::Json
                } else {
                    BodyContentType::Raw
                };

                // Reset UI state
                state.request_scroll = 0;
                state.response_scroll = 0;
                state.request_editor_tab = RequestEditorTab::Params;
                state.focus = Focus::RequestEditor;
                state.status_message = Some(format!("Loaded: {}", item.name));
                state.status_timestamp = Some(std::time::Instant::now());
            }
        }
    }
}

/// Type of collection item for navigation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionItemType {
    Collection,
    Folder,
    Request,
}

/// Flattened collection item for navigation
#[derive(Debug, Clone)]
pub struct CollectionNavigationItem {
    pub depth: usize,
    pub name: String,
    pub item_type: CollectionItemType,
    pub request: Option<crate::http::Request>,
}
