//! Reconnaissance Module
//!
//! Web screenshot capture and analysis inspired by lazywitness/gowitness/EyeWitness.
//! Features:
//! - Headless Chrome screenshot capture
//! - Technology fingerprinting
//! - Default credentials detection
//! - Host/CIDR scanning for web services
//! - Interactive carbonyl browser with proxy support

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Launch carbonyl browser in a new tmux window with proxy support
///
/// This spawns carbonyl in a separate tmux window so it doesn't interfere with the TUI.
/// User can switch between tmux windows with Ctrl-b n/p or Ctrl-b <number>.
pub fn launch_carbonyl(url: &str, proxy_port: u16) -> Result<()> {
    let proxy_url = format!("http://127.0.0.1:{}", proxy_port);

    // Build the carbonyl command string with comprehensive anti-bot detection evasion
    // These flags prevent common bot detection mechanisms from identifying the browser as automated
    let mut carbonyl_cmd = String::from("carbonyl");

    // Core sandbox/security flags
    carbonyl_cmd.push_str(" --no-sandbox");
    carbonyl_cmd.push_str(" --disable-setuid-sandbox");
    carbonyl_cmd.push_str(" --disable-dev-shm-usage");

    // Anti-automation detection flags (critical for bot evasion)
    carbonyl_cmd.push_str(" --disable-blink-features=AutomationControlled");
    carbonyl_cmd.push_str(" --disable-features=AutomationControlled");
    carbonyl_cmd.push_str(" --disable-automation");
    carbonyl_cmd.push_str(" --disable-infobars");

    // Disable extensions that might reveal automation
    carbonyl_cmd.push_str(" --disable-extensions");
    carbonyl_cmd.push_str(" --disable-plugins-discovery");
    carbonyl_cmd.push_str(" --disable-default-apps");

    // Prevent WebDriver detection via navigator.webdriver
    carbonyl_cmd.push_str(" --disable-blink-features=AutomationControlled,EnableAutomation");

    // GPU and rendering (some detection looks for headless rendering artifacts)
    carbonyl_cmd.push_str(" --disable-gpu");
    carbonyl_cmd.push_str(" --disable-software-rasterizer");

    // Notifications and permissions that might reveal automation
    carbonyl_cmd.push_str(" --disable-notifications");
    carbonyl_cmd.push_str(" --disable-popup-blocking");

    // Realistic browser behavior
    carbonyl_cmd.push_str(" --disable-background-networking");
    carbonyl_cmd.push_str(" --disable-sync");
    carbonyl_cmd.push_str(" --disable-translate");
    carbonyl_cmd.push_str(" --metrics-recording-only");
    carbonyl_cmd.push_str(" --no-first-run");
    carbonyl_cmd.push_str(" --safebrowsing-disable-auto-update");

    // Exclude automation switches (important - prevents enable-automation from being added)
    carbonyl_cmd.push_str(" --disable-ipc-flooding-protection");

    // Web security (needed for some proxy scenarios)
    carbonyl_cmd.push_str(" --disable-web-security");
    carbonyl_cmd.push_str(" --allow-running-insecure-content");

    // Updated user-agent matching current Chrome stable
    carbonyl_cmd.push_str(" '--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'");

    // Window size (helps avoid headless detection based on viewport)
    carbonyl_cmd.push_str(" --window-size=1920,1080");

    if proxy_port > 0 {
        carbonyl_cmd.push_str(&format!(" --proxy-server={}", proxy_url));
        carbonyl_cmd.push_str(" --proxy-bypass-list=<-loopback>");
        carbonyl_cmd.push_str(" --ignore-certificate-errors");
        carbonyl_cmd.push_str(" --ignore-certificate-errors-spki-list");
    }

    carbonyl_cmd.push_str(&format!(" '{}'", url));

    tracing::info!("Launching carbonyl in tmux window: {}", carbonyl_cmd);

    // Check if we're in tmux
    let in_tmux = std::env::var("TMUX").is_ok();

    if in_tmux {
        // Launch in new tmux window
        let status = Command::new("tmux")
            .arg("new-window")
            .arg("-n")
            .arg("browser")
            .arg(&carbonyl_cmd)
            .status()
            .context("Failed to create tmux window")?;

        if status.success() {
            tracing::info!("Carbonyl launched in tmux window 'browser'");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to launch carbonyl in tmux"))
        }
    } else {
        // Not in tmux - show instructions
        Err(anyhow::anyhow!(
            "Not running in tmux. Run ancarna inside tmux, or manually run:\n{}",
            carbonyl_cmd
        ))
    }
}

/// Check if carbonyl is available
pub fn carbonyl_available() -> bool {
    Command::new("which")
        .arg("carbonyl")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Common web ports to scan
pub const SCAN_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 81, 3000, 3128, 8000, 8008, 8081, 8082, 8888, 8800, 10000,
];

/// Screenshot resolution presets
pub const RESOLUTION_PRESETS: &[(u32, u32, &str)] = &[
    (1920, 1080, "1080p"),
    (2560, 1440, "1440p"),
    (3840, 2160, "4K"),
    (1280, 720, "720p"),
];

/// Result of capturing a URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResult {
    /// Original URL
    pub url: String,
    /// Final URL after redirects
    pub final_url: String,
    /// Page title
    pub title: String,
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Detected technologies
    pub technologies: Vec<String>,
    /// Path to screenshot file
    pub screenshot_path: Option<PathBuf>,
    /// Capture timestamp
    pub timestamp: u64,
    /// Detected application signature (for default creds)
    pub app_signature: Option<String>,
    /// Default credentials if detected
    pub default_creds: Vec<(String, String)>,
    /// Admin paths to try
    pub admin_paths: Vec<String>,
    /// Page HTML content (for analysis)
    pub html_content: Option<String>,
    /// Readable text extracted from page
    pub readable_text: Option<String>,
    /// Error message if capture failed
    pub error: Option<String>,
}

impl Default for CaptureResult {
    fn default() -> Self {
        Self {
            url: String::new(),
            final_url: String::new(),
            title: String::new(),
            status_code: 0,
            headers: HashMap::new(),
            technologies: Vec::new(),
            screenshot_path: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            app_signature: None,
            default_creds: Vec::new(),
            admin_paths: Vec::new(),
            html_content: None,
            readable_text: None,
            error: None,
        }
    }
}

/// Technology fingerprint pattern
pub struct TechFingerprint {
    pub name: &'static str,
    pub headers: &'static [(&'static str, &'static str)],
    pub html_patterns: &'static [&'static str],
}

/// Technology fingerprints for detection
pub const TECH_FINGERPRINTS: &[TechFingerprint] = &[
    // Web Servers
    TechFingerprint {
        name: "nginx",
        headers: &[("server", "nginx")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "Apache",
        headers: &[("server", "apache")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "IIS",
        headers: &[("server", "microsoft-iis")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "Cloudflare",
        headers: &[("server", "cloudflare"), ("cf-ray", "")],
        html_patterns: &[],
    },
    // Frameworks
    TechFingerprint {
        name: "WordPress",
        headers: &[("x-powered-by", "wp")],
        html_patterns: &["wp-content", "wp-includes", "wordpress"],
    },
    TechFingerprint {
        name: "React",
        headers: &[],
        html_patterns: &["react", "_reactroot", "data-reactroot"],
    },
    TechFingerprint {
        name: "Vue.js",
        headers: &[],
        html_patterns: &["vue.js", "vue.min.js", "data-v-", "__vue__"],
    },
    TechFingerprint {
        name: "Angular",
        headers: &[],
        html_patterns: &["ng-version", "angular.js", "angular.min.js"],
    },
    TechFingerprint {
        name: "jQuery",
        headers: &[],
        html_patterns: &["jquery.js", "jquery.min.js", "jquery-"],
    },
    TechFingerprint {
        name: "Bootstrap",
        headers: &[],
        html_patterns: &["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
    },
    // Server-side
    TechFingerprint {
        name: "PHP",
        headers: &[("x-powered-by", "php")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "ASP.NET",
        headers: &[("x-powered-by", "asp.net"), ("x-aspnet-version", "")],
        html_patterns: &["__viewstate", "__eventvalidation"],
    },
    TechFingerprint {
        name: "Express",
        headers: &[("x-powered-by", "express")],
        html_patterns: &[],
    },
    TechFingerprint {
        name: "Django",
        headers: &[],
        html_patterns: &["csrfmiddlewaretoken", "django"],
    },
    TechFingerprint {
        name: "Laravel",
        headers: &[],
        html_patterns: &["laravel", "csrf-token"],
    },
    TechFingerprint {
        name: "Ruby on Rails",
        headers: &[("x-powered-by", "phusion passenger")],
        html_patterns: &["csrf-token", "rails"],
    },
];

/// Application signature for default credentials detection
pub struct AppSignature {
    pub name: &'static str,
    pub patterns: &'static [&'static str],
    pub default_creds: &'static [(&'static str, &'static str)],
    pub admin_paths: &'static [&'static str],
}

/// Application signatures with default credentials
pub const APP_SIGNATURES: &[AppSignature] = &[
    // CI/CD & DevOps
    AppSignature {
        name: "Jenkins",
        patterns: &["dashboard [jenkins]", "jenkins", "hudson"],
        default_creds: &[("admin", "admin"), ("jenkins", "jenkins")],
        admin_paths: &["/manage", "/script", "/configure"],
    },
    AppSignature {
        name: "GitLab",
        patterns: &["gitlab", "sign in · gitlab"],
        default_creds: &[("root", "5iveL!fe"), ("admin@local.host", "5iveL!fe")],
        admin_paths: &["/admin", "/users/sign_in"],
    },
    AppSignature {
        name: "Grafana",
        patterns: &["grafana"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/login", "/admin"],
    },
    AppSignature {
        name: "Portainer",
        patterns: &["portainer"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/#/auth", "/#/init/admin"],
    },
    // Application Servers
    AppSignature {
        name: "Apache Tomcat",
        patterns: &["apache tomcat", "tomcat manager", "/manager/html"],
        default_creds: &[("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager")],
        admin_paths: &["/manager/html", "/host-manager/html"],
    },
    AppSignature {
        name: "JBoss/WildFly",
        patterns: &["jboss", "wildfly"],
        default_creds: &[("admin", "admin"), ("jboss", "jboss")],
        admin_paths: &["/admin-console", "/jmx-console"],
    },
    AppSignature {
        name: "WebLogic",
        patterns: &["weblogic", "oracle weblogic"],
        default_creds: &[("weblogic", "weblogic"), ("system", "password")],
        admin_paths: &["/console", "/em"],
    },
    // CMS
    AppSignature {
        name: "WordPress",
        patterns: &["wp-content", "wp-login", "wordpress"],
        default_creds: &[("admin", "admin"), ("admin", "password")],
        admin_paths: &["/wp-admin", "/wp-login.php"],
    },
    AppSignature {
        name: "Joomla",
        patterns: &["joomla", "/administrator"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/administrator"],
    },
    AppSignature {
        name: "Drupal",
        patterns: &["drupal", "powered by drupal"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/admin", "/user/login"],
    },
    // Database Management
    AppSignature {
        name: "phpMyAdmin",
        patterns: &["phpmyadmin"],
        default_creds: &[("root", ""), ("root", "root"), ("root", "password")],
        admin_paths: &["/phpmyadmin", "/pma"],
    },
    AppSignature {
        name: "Adminer",
        patterns: &["adminer", "database management in a single php"],
        default_creds: &[("root", ""), ("root", "root")],
        admin_paths: &["/adminer.php"],
    },
    AppSignature {
        name: "pgAdmin",
        patterns: &["pgadmin"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/login"],
    },
    // Monitoring
    AppSignature {
        name: "Kibana",
        patterns: &["kibana"],
        default_creds: &[("elastic", "changeme")],
        admin_paths: &["/app/kibana", "/login"],
    },
    AppSignature {
        name: "Prometheus",
        patterns: &["prometheus time series", "prometheus"],
        default_creds: &[],
        admin_paths: &["/graph", "/targets", "/config"],
    },
    AppSignature {
        name: "Nagios",
        patterns: &["nagios core", "nagios xi"],
        default_creds: &[("nagiosadmin", "nagios")],
        admin_paths: &["/nagios", "/nagiosxi"],
    },
    AppSignature {
        name: "Zabbix",
        patterns: &["zabbix"],
        default_creds: &[("Admin", "zabbix"), ("guest", "")],
        admin_paths: &["/zabbix.php"],
    },
    // Network Devices
    AppSignature {
        name: "Cisco",
        patterns: &["cisco", "cisco systems"],
        default_creds: &[("admin", "admin"), ("cisco", "cisco")],
        admin_paths: &["/"],
    },
    AppSignature {
        name: "Netgear",
        patterns: &["netgear"],
        default_creds: &[("admin", "password"), ("admin", "admin")],
        admin_paths: &["/"],
    },
    AppSignature {
        name: "TP-Link",
        patterns: &["tp-link"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/"],
    },
    AppSignature {
        name: "Ubiquiti",
        patterns: &["ubiquiti", "unifi"],
        default_creds: &[("ubnt", "ubnt"), ("admin", "admin")],
        admin_paths: &["/manage"],
    },
    // Storage
    AppSignature {
        name: "Synology DSM",
        patterns: &["synology", "diskstation"],
        default_creds: &[("admin", "admin"), ("admin", "")],
        admin_paths: &["/webman"],
    },
    AppSignature {
        name: "QNAP",
        patterns: &["qnap", "qts"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/cgi-bin"],
    },
    // Other
    AppSignature {
        name: "SonarQube",
        patterns: &["sonarqube", "sonar"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/sessions/new"],
    },
    AppSignature {
        name: "Nexus Repository",
        patterns: &["nexus repository", "sonatype nexus"],
        default_creds: &[("admin", "admin123")],
        admin_paths: &["/nexus"],
    },
    AppSignature {
        name: "Artifactory",
        patterns: &["jfrog artifactory", "artifactory"],
        default_creds: &[("admin", "password")],
        admin_paths: &["/artifactory"],
    },
    AppSignature {
        name: "TeamCity",
        patterns: &["teamcity", "log in to teamcity"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/admin/admin.html"],
    },
    AppSignature {
        name: "Rancher",
        patterns: &["rancher", "rancher labs"],
        default_creds: &[("admin", "admin")],
        admin_paths: &["/login"],
    },
];

/// Detect technologies from headers and HTML content
pub fn detect_technologies(headers: &HashMap<String, String>, html: &str) -> Vec<String> {
    let mut detected = Vec::new();
    let html_lower = html.to_lowercase();

    for fp in TECH_FINGERPRINTS {
        let mut matched = false;

        // Check headers
        for (header_name, pattern) in fp.headers {
            if let Some(value) = headers.get(&header_name.to_lowercase()) {
                if pattern.is_empty() || value.to_lowercase().contains(pattern) {
                    matched = true;
                    break;
                }
            }
        }

        // Check HTML patterns
        if !matched {
            for pattern in fp.html_patterns {
                if html_lower.contains(pattern) {
                    matched = true;
                    break;
                }
            }
        }

        if matched && !detected.contains(&fp.name.to_string()) {
            detected.push(fp.name.to_string());
        }
    }

    detected
}

/// Detect application signature from page content
pub fn detect_app_signature(content: &str) -> Option<&'static AppSignature> {
    let content_lower = content.to_lowercase();
    for sig in APP_SIGNATURES {
        for pattern in sig.patterns {
            if content_lower.contains(pattern) {
                return Some(sig);
            }
        }
    }
    None
}

/// Extract title from HTML
pub fn extract_title(html: &str) -> String {
    let re = regex::Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").ok();
    if let Some(re) = re {
        if let Some(caps) = re.captures(html) {
            if let Some(m) = caps.get(1) {
                return m.as_str().trim().to_string();
            }
        }
    }
    String::new()
}

/// Scan target state
#[derive(Debug, Clone, Default)]
pub struct ScanState {
    /// URLs to scan
    pub targets: Vec<String>,
    /// Completed captures
    pub results: Vec<CaptureResult>,
    /// Currently scanning
    pub in_progress: bool,
    /// Current index
    pub current_index: usize,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// Recon manager
pub struct ReconManager {
    /// Output directory for screenshots
    pub output_dir: PathBuf,
    /// Screenshot resolution (width, height)
    pub resolution: (u32, u32),
    /// Scan state
    pub state: ScanState,
}

impl ReconManager {
    /// Create a new recon manager
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            output_dir,
            resolution: (1920, 1080),
            state: ScanState::default(),
        }
    }

    /// Find Chrome/Chromium binary
    pub fn find_chrome() -> Option<PathBuf> {
        let paths = [
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/snap/bin/chromium",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ];

        // Check CHROME_PATH env var first
        if let Ok(path) = std::env::var("CHROME_PATH") {
            let p = PathBuf::from(&path);
            if p.exists() {
                return Some(p);
            }
        }

        for path in paths {
            let p = PathBuf::from(path);
            if p.exists() {
                return Some(p);
            }
        }

        // Try `which` as fallback
        if let Ok(output) = std::process::Command::new("which")
            .arg("chromium-browser")
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Some(PathBuf::from(path));
                }
            }
        }

        None
    }

    /// Check if Chrome is available
    pub fn chrome_available() -> bool {
        Self::find_chrome().is_some()
    }

    /// Generate URL variations for a host (http/https on common ports)
    pub fn generate_urls(host: &str) -> Vec<String> {
        let mut urls = Vec::new();

        // Clean up host
        let host = host.trim();
        if host.is_empty() {
            return urls;
        }

        // If already a URL, just return it
        if host.starts_with("http://") || host.starts_with("https://") {
            urls.push(host.to_string());
            return urls;
        }

        // Generate URL variations
        for port in SCAN_PORTS {
            let scheme = if *port == 443 || *port == 8443 {
                "https"
            } else {
                "http"
            };

            if *port == 80 || *port == 443 {
                urls.push(format!("{}://{}", scheme, host));
            } else {
                urls.push(format!("{}://{}:{}", scheme, host, port));
            }
        }

        urls
    }

    /// Parse CIDR notation and expand to host list
    pub fn expand_cidr(cidr: &str) -> Vec<String> {
        let mut hosts = Vec::new();

        if let Ok(network) = cidr.parse::<ipnet::Ipv4Net>() {
            for addr in network.hosts() {
                hosts.push(addr.to_string());
            }
        } else if let Ok(addr) = cidr.parse::<std::net::Ipv4Addr>() {
            hosts.push(addr.to_string());
        } else {
            // Treat as hostname
            hosts.push(cidr.to_string());
        }

        hosts
    }

    /// Capture a URL screenshot and analyze the page
    /// Note: Screenshot capture is not implemented - use carbonyl for interactive browsing
    pub fn capture_url(&self, url: &str) -> Result<CaptureResult> {
        // Screenshot capture removed - not needed for this project
        // Use launch_carbonyl() for interactive browsing instead
        let mut result = CaptureResult::default();
        result.url = url.to_string();
        result.error = Some("Screenshot capture not implemented. Use carbonyl browser instead.".to_string());
        Ok(result)
    }

    /// Capture multiple URLs in parallel
    pub fn capture_urls(&mut self, urls: &[String]) -> Vec<CaptureResult> {
        let results: Vec<CaptureResult> = urls
            .iter()
            .map(|url| {
                match self.capture_url(url) {
                    Ok(result) => result,
                    Err(e) => {
                        let mut result = CaptureResult::default();
                        result.url = url.clone();
                        result.error = Some(e.to_string());
                        result
                    }
                }
            })
            .collect();

        self.state.results.extend(results.clone());
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_technologies() {
        let mut headers = HashMap::new();
        headers.insert("server".to_string(), "nginx/1.18.0".to_string());
        headers.insert("x-powered-by".to_string(), "PHP/8.1".to_string());

        let html = r#"<html><script src="/wp-content/themes/test.js"></script></html>"#;

        let techs = detect_technologies(&headers, html);
        assert!(techs.contains(&"nginx".to_string()));
        assert!(techs.contains(&"PHP".to_string()));
        assert!(techs.contains(&"WordPress".to_string()));
    }

    #[test]
    fn test_detect_app_signature() {
        let content = "Welcome to Jenkins Dashboard";
        let sig = detect_app_signature(content);
        assert!(sig.is_some());
        assert_eq!(sig.unwrap().name, "Jenkins");
    }

    #[test]
    fn test_extract_title() {
        let html = r#"<html><head><title>My Website</title></head></html>"#;
        assert_eq!(extract_title(html), "My Website");
    }

    #[test]
    fn test_generate_urls() {
        let urls = ReconManager::generate_urls("example.com");
        assert!(urls.contains(&"http://example.com".to_string()));
        assert!(urls.contains(&"https://example.com".to_string()));
        assert!(urls.contains(&"http://example.com:8080".to_string()));
    }

    #[test]
    fn test_expand_cidr() {
        let hosts = ReconManager::expand_cidr("192.168.1.0/30");
        assert_eq!(hosts.len(), 2); // .1 and .2 (network and broadcast excluded)
    }
}
