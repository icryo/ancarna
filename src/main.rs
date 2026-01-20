//! Ancarna - Terminal Security Testing Platform
//!
//! A TUI-based web application security testing tool with OWASP ZAP feature parity.

mod app;
mod error;
mod fuzzer;
mod http;
mod proxy;
mod browser;
mod reporting;
mod scanner;
mod scope;
mod scripting;
mod session;
mod spider;
mod tui;
mod workspace;

pub use error::*;

use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{execute, terminal};
use tokio::signal;
use tokio::sync::broadcast;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer,
};

use crate::app::{App, Config};

/// Terminal Security Testing Platform
#[derive(Parser, Debug)]
#[command(name = "ancarna")]
#[command(author, version, about = "Terminal Security Testing Platform", long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, env = "ANCARNA_CONFIG")]
    config: Option<String>,

    /// Workspace directory
    #[arg(short, long, env = "ANCARNA_WORKSPACE")]
    workspace: Option<String>,

    /// Start proxy server on specified port
    #[arg(short, long, default_value = "8080", env = "ANCARNA_PROXY_PORT")]
    proxy_port: u16,

    /// API server port (0 to disable)
    #[arg(long, default_value = "0", env = "ANCARNA_API_PORT")]
    api_port: u16,

    /// Run in headless mode (no TUI)
    #[arg(long, env = "ANCARNA_HEADLESS")]
    headless: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "ANCARNA_LOG_LEVEL")]
    log_level: String,

    /// Log file path (enables file logging)
    #[arg(long, env = "ANCARNA_LOG_FILE")]
    log_file: Option<String>,

    /// Enable JSON structured logging
    #[arg(long, env = "ANCARNA_LOG_JSON")]
    log_json: bool,

    /// Execute a script file and exit
    #[arg(long)]
    script: Option<String>,

    /// Target URL for quick scan
    #[arg(long)]
    target: Option<String>,

    /// Generate default configuration and exit
    #[arg(long)]
    generate_config: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate_config: bool,
}

/// Global flag for graceful shutdown
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls ring crypto provider (required for rustls 0.23+)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Handle special commands first
    if cli.generate_config {
        return generate_default_config();
    }

    // Set up panic hook for terminal restoration
    setup_panic_hook();

    // Initialize logging
    init_logging(&cli)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Ancarna"
    );

    // Load and validate configuration
    let config = load_config(&cli)?;

    if cli.validate_config {
        tracing::info!("Configuration is valid");
        return Ok(());
    }

    // Create shutdown signal channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Spawn signal handler
    let shutdown_tx_clone = shutdown_tx.clone();
    let shutdown_flag_clone = shutdown_flag.clone();
    tokio::spawn(async move {
        handle_signals(shutdown_tx_clone, shutdown_flag_clone).await;
    });

    // Run the application
    let result = run_app(cli, config, shutdown_tx.subscribe(), shutdown_flag).await;

    // Cleanup
    tracing::info!("Ancarna shutting down gracefully");

    result
}

/// Set up panic hook to restore terminal state
fn setup_panic_hook() {
    let original_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info| {
        // Try to restore terminal state
        let _ = terminal::disable_raw_mode();
        let _ = execute!(std::io::stdout(), terminal::LeaveAlternateScreen);

        // Call original panic hook
        original_hook(panic_info);
    }));
}

/// Initialize the logging system
fn init_logging(cli: &Cli) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    if let Some(log_path) = &cli.log_file {
        // File-based logging with rotation
        let file_appender = if log_path.contains('/') || log_path.contains('\\') {
            // Use specified directory
            let path = std::path::Path::new(log_path);
            let dir = path.parent().unwrap_or(std::path::Path::new("."));
            let filename = path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("ancarna.log");
            RollingFileAppender::new(Rotation::DAILY, dir, filename)
        } else {
            // Use default log directory
            let log_dir = Config::data_dir()
                .map(|d| d.join("logs"))
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            std::fs::create_dir_all(&log_dir).ok();
            RollingFileAppender::new(Rotation::DAILY, log_dir, log_path)
        };

        if cli.log_json {
            // JSON structured logging to file
            let file_layer = fmt::layer()
                .json()
                .with_writer(file_appender)
                .with_ansi(false);

            subscriber.with(file_layer).init();
        } else {
            // Plain text logging to file
            let file_layer = fmt::layer()
                .with_writer(file_appender)
                .with_ansi(false);

            subscriber.with(file_layer).init();
        }
    } else if cli.headless {
        // Console logging for headless mode
        if cli.log_json {
            subscriber.with(fmt::layer().json()).init();
        } else {
            subscriber.with(fmt::layer()).init();
        }
    } else {
        // TUI mode: log to file in data directory, don't pollute stdout
        let log_dir = Config::data_dir()
            .map(|d| d.join("logs"))
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        std::fs::create_dir_all(&log_dir).ok();

        let file_appender = RollingFileAppender::new(Rotation::DAILY, log_dir, "ancarna.log");
        let file_layer = fmt::layer()
            .with_writer(file_appender)
            .with_ansi(false);

        subscriber.with(file_layer).init();
    }

    Ok(())
}

/// Load configuration with CLI overrides
fn load_config(cli: &Cli) -> Result<Config> {
    let mut config = Config::load(cli.config.as_deref())?;

    // Apply CLI overrides
    if let Some(workspace) = &cli.workspace {
        config.general.workspace_dir = Some(std::path::PathBuf::from(workspace));
    }

    config.proxy.default_port = cli.proxy_port;

    // Validate configuration
    validate_config(&config)?;

    Ok(config)
}

/// Validate configuration
fn validate_config(config: &Config) -> Result<()> {
    // Validate proxy port
    if config.proxy.default_port == 0 {
        anyhow::bail!("Proxy port cannot be 0");
    }

    // Validate scanner settings
    if config.scanner.max_threads == 0 {
        anyhow::bail!("Scanner max_threads must be greater than 0");
    }

    if config.scanner.request_timeout == 0 {
        anyhow::bail!("Scanner request_timeout must be greater than 0");
    }

    // Validate scripting settings
    if config.scripting.enabled && config.scripting.timeout_ms == 0 {
        anyhow::bail!("Scripting timeout_ms must be greater than 0 when enabled");
    }

    Ok(())
}

/// Generate default configuration file
fn generate_default_config() -> Result<()> {
    let config = Config::default();
    let toml = toml::to_string_pretty(&config)
        .context("Failed to serialize configuration")?;

    println!("{}", toml);
    Ok(())
}

/// Handle shutdown signals
async fn handle_signals(shutdown_tx: broadcast::Sender<()>, shutdown_flag: Arc<AtomicBool>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT, initiating shutdown");
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, initiating shutdown");
            }
        }
    }

    #[cfg(windows)]
    {
        signal::ctrl_c().await.expect("Failed to register Ctrl+C handler");
        tracing::info!("Received Ctrl+C, initiating shutdown");
    }

    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    shutdown_flag.store(true, Ordering::SeqCst);
    let _ = shutdown_tx.send(());
}

/// Run the main application
async fn run_app(
    cli: Cli,
    config: Config,
    mut shutdown_rx: broadcast::Receiver<()>,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<()> {
    // Create application
    let mut app = App::new(config, cli.proxy_port).await?;

    // Handle different run modes
    if cli.headless {
        tracing::info!("Running in headless mode");

        tokio::select! {
            result = app.run_headless(cli.target.as_deref(), cli.script.as_deref()) => {
                result?;
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Shutdown signal received");
            }
        }
    } else {
        // Run TUI with shutdown handling
        tokio::select! {
            result = app.run_tui() => {
                result?;
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Shutdown signal received, closing TUI");
                // Terminal cleanup is handled by the panic hook and TUI module
            }
        }
    }

    Ok(())
}

/// Check if shutdown has been requested
#[allow(dead_code)]
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}
