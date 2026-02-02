//! Custom error types for Ancarna
//!
//! Provides structured error handling with context propagation
//! and user-friendly error messages.


use thiserror::Error;

/// Main error type for Ancarna operations
#[derive(Error, Debug)]
pub enum AncarnaError {
    /// Configuration related errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// HTTP client errors
    #[error("HTTP error: {0}")]
    Http(#[from] HttpError),

    /// Proxy server errors
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),

    /// Scanner errors
    #[error("Scanner error: {0}")]
    Scanner(#[from] ScannerError),

    /// Workspace errors
    #[error("Workspace error: {0}")]
    Workspace(#[from] WorkspaceError),

    /// TUI errors
    #[error("TUI error: {0}")]
    Tui(#[from] TuiError),

    /// Scripting engine errors
    #[error("Script error: {0}")]
    Script(#[from] ScriptError),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic errors with context
    #[error("{context}: {source}")]
    WithContext {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {path}")]
    ReadError { path: String, source: std::io::Error },

    #[error("Failed to parse configuration: {0}")]
    ParseError(String),

    #[error("Invalid configuration value: {field} - {reason}")]
    ValidationError { field: String, reason: String },

    #[error("Missing required configuration: {0}")]
    MissingField(String),

    #[error("Configuration file not found: {0}")]
    NotFound(String),
}

/// HTTP client errors
#[derive(Error, Debug)]
pub enum HttpError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Response error: {status} {reason}")]
    ResponseError { status: u16, reason: String },

    #[error("Body too large: {size} bytes (max: {max})")]
    BodyTooLarge { size: usize, max: usize },
}

/// Proxy server errors
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Failed to start proxy on port {port}: {reason}")]
    StartError { port: u16, reason: String },

    #[error("Failed to generate certificate for {domain}: {reason}")]
    CertificateError { domain: String, reason: String },

    #[error("Connection to target failed: {target}")]
    TargetConnectionError { target: String },

    #[error("Invalid proxy request: {0}")]
    InvalidRequest(String),

    #[error("Proxy already running")]
    AlreadyRunning,

    #[error("Proxy not running")]
    NotRunning,
}

/// Scanner errors
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Scan failed: {0}")]
    ScanFailed(String),

    #[error("Invalid target URL: {0}")]
    InvalidTarget(String),

    #[error("Scan policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Scan timeout after {0}ms")]
    Timeout(u64),

    #[error("Maximum scan depth exceeded: {0}")]
    MaxDepthExceeded(usize),

    #[error("Scanner configuration error: {0}")]
    ConfigError(String),
}

/// Workspace/project errors
#[derive(Error, Debug)]
pub enum WorkspaceError {
    #[error("Workspace not found: {0}")]
    NotFound(String),

    #[error("Failed to create workspace: {0}")]
    CreateError(String),

    #[error("Failed to save workspace: {0}")]
    SaveError(String),

    #[error("Collection not found: {0}")]
    CollectionNotFound(String),

    #[error("Request not found: {0}")]
    RequestNotFound(String),

    #[error("Import failed: {format} - {reason}")]
    ImportError { format: String, reason: String },

    #[error("Export failed: {format} - {reason}")]
    ExportError { format: String, reason: String },
}

/// TUI errors
#[derive(Error, Debug)]
pub enum TuiError {
    #[error("Terminal initialization failed: {0}")]
    InitError(String),

    #[error("Render error: {0}")]
    RenderError(String),

    #[error("Terminal size too small: {width}x{height} (minimum: {min_width}x{min_height})")]
    TerminalTooSmall {
        width: u16,
        height: u16,
        min_width: u16,
        min_height: u16,
    },

    #[error("Input error: {0}")]
    InputError(String),
}

/// Scripting engine errors
#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Script execution failed: {0}")]
    ExecutionError(String),

    #[error("Script syntax error at line {line}: {message}")]
    SyntaxError { line: usize, message: String },

    #[error("Script timeout after {0}ms")]
    Timeout(u64),

    #[error("Script memory limit exceeded")]
    MemoryLimitExceeded,

    #[error("Script file not found: {0}")]
    FileNotFound(String),
}

impl AncarnaError {
    /// Create an error with additional context
    pub fn with_context<E>(context: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        AncarnaError::WithContext {
            context: context.into(),
            source: Box::new(source),
        }
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            AncarnaError::Config(e) => format!("Configuration problem: {}", e.user_hint()),
            AncarnaError::Http(e) => format!("Network issue: {}", e.user_hint()),
            AncarnaError::Proxy(e) => format!("Proxy issue: {}", e.user_hint()),
            AncarnaError::Scanner(e) => format!("Scanner issue: {}", e.user_hint()),
            AncarnaError::Workspace(e) => format!("Workspace issue: {}", e.user_hint()),
            AncarnaError::Tui(e) => format!("Display issue: {}", e.user_hint()),
            AncarnaError::Script(e) => format!("Script issue: {}", e.user_hint()),
            AncarnaError::Io(e) => format!("File system issue: {}", e),
            AncarnaError::WithContext { context, source } => {
                format!("{}: {}", context, source)
            }
        }
    }
}

/// Trait for providing user-friendly hints
pub trait UserHint {
    fn user_hint(&self) -> String;
}

impl UserHint for ConfigError {
    fn user_hint(&self) -> String {
        match self {
            ConfigError::ReadError { path, .. } => {
                format!("Could not read '{}'. Check if the file exists and you have read permissions.", path)
            }
            ConfigError::ParseError(_) => {
                "The configuration file has invalid syntax. Check for TOML formatting errors.".into()
            }
            ConfigError::ValidationError { field, reason } => {
                format!("Invalid value for '{}': {}", field, reason)
            }
            ConfigError::MissingField(field) => {
                format!("Required setting '{}' is missing from configuration.", field)
            }
            ConfigError::NotFound(path) => {
                format!("Configuration file '{}' not found. Run with --generate-config to create one.", path)
            }
        }
    }
}

impl UserHint for HttpError {
    fn user_hint(&self) -> String {
        match self {
            HttpError::ConnectionError(_) => {
                "Could not connect to the server. Check if it's running and accessible.".into()
            }
            HttpError::Timeout(ms) => {
                format!("Request timed out after {}ms. The server may be slow or unresponsive.", ms)
            }
            HttpError::InvalidUrl(url) => {
                format!("'{}' is not a valid URL. Check the format.", url)
            }
            HttpError::TlsError(_) => {
                "TLS/SSL connection failed. The certificate may be invalid or expired.".into()
            }
            HttpError::AuthError(_) => {
                "Authentication failed. Check your credentials.".into()
            }
            _ => self.to_string(),
        }
    }
}

impl UserHint for ProxyError {
    fn user_hint(&self) -> String {
        match self {
            ProxyError::StartError { port, .. } => {
                format!("Could not start proxy on port {}. It may already be in use.", port)
            }
            ProxyError::CertificateError { domain, .. } => {
                format!("Could not create certificate for '{}'. Check CA configuration.", domain)
            }
            _ => self.to_string(),
        }
    }
}

impl UserHint for ScannerError {
    fn user_hint(&self) -> String {
        match self {
            ScannerError::InvalidTarget(url) => {
                format!("'{}' is not a valid scan target. Use a full URL.", url)
            }
            ScannerError::PolicyNotFound(name) => {
                format!("Scan policy '{}' not found. Check available policies.", name)
            }
            ScannerError::Timeout(ms) => {
                format!("Scan timed out after {}ms. Try increasing the timeout.", ms)
            }
            _ => self.to_string(),
        }
    }
}

impl UserHint for WorkspaceError {
    fn user_hint(&self) -> String {
        match self {
            WorkspaceError::NotFound(path) => {
                format!("Workspace '{}' not found. Create a new workspace first.", path)
            }
            WorkspaceError::ImportError { format, reason } => {
                format!("Could not import {} file: {}", format, reason)
            }
            _ => self.to_string(),
        }
    }
}

impl UserHint for TuiError {
    fn user_hint(&self) -> String {
        match self {
            TuiError::TerminalTooSmall { min_width, min_height, .. } => {
                format!("Terminal too small. Minimum size is {}x{} characters.", min_width, min_height)
            }
            _ => self.to_string(),
        }
    }
}

impl UserHint for ScriptError {
    fn user_hint(&self) -> String {
        match self {
            ScriptError::SyntaxError { line, message } => {
                format!("Syntax error on line {}: {}", line, message)
            }
            ScriptError::Timeout(ms) => {
                format!("Script exceeded {}ms time limit. Check for infinite loops.", ms)
            }
            ScriptError::FileNotFound(path) => {
                format!("Script file '{}' not found.", path)
            }
            _ => self.to_string(),
        }
    }
}

/// Extension trait for adding context to Result types
pub trait ResultExt<T, E> {
    fn with_context<C>(self, context: C) -> Result<T, AncarnaError>
    where
        C: Into<String>;
}

impl<T, E> ResultExt<T, E> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn with_context<C>(self, context: C) -> Result<T, AncarnaError>
    where
        C: Into<String>,
    {
        self.map_err(|e| AncarnaError::with_context(context, e))
    }
}
