//! Scan engine orchestration

use anyhow::Result;
use parking_lot::RwLock;
use std::sync::Arc;

use super::findings::{Finding, Severity};
use super::passive::PassiveScanner;
use super::active::ActiveScanner;
use super::policies::ScanPolicy;
use crate::app::Config;
use crate::http::{Request, Response};

/// Scan engine state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    Idle,
    Running,
    Paused,
    Stopping,
}

/// Scan progress information
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub state: ScanState,
    pub total_requests: usize,
    pub completed_requests: usize,
    pub findings_count: usize,
    pub current_url: Option<String>,
}

/// Main scan engine
pub struct ScanEngine {
    /// Passive scanner
    passive: PassiveScanner,

    /// Active scanner
    active: ActiveScanner,

    /// Current scan policy
    policy: Arc<RwLock<ScanPolicy>>,

    /// Collected findings
    findings: Arc<RwLock<Vec<Finding>>>,

    /// Scan state
    state: Arc<RwLock<ScanState>>,

    /// Progress
    progress: Arc<RwLock<ScanProgress>>,

    /// Configuration
    config: Config,
}

impl ScanEngine {
    /// Create a new scan engine
    pub fn new(config: &Config) -> Self {
        Self {
            passive: PassiveScanner::new(),
            active: ActiveScanner::new(config),
            policy: Arc::new(RwLock::new(ScanPolicy::default())),
            findings: Arc::new(RwLock::new(Vec::new())),
            state: Arc::new(RwLock::new(ScanState::Idle)),
            progress: Arc::new(RwLock::new(ScanProgress {
                state: ScanState::Idle,
                total_requests: 0,
                completed_requests: 0,
                findings_count: 0,
                current_url: None,
            })),
            config: config.clone(),
        }
    }

    /// Passive scan a request/response pair
    pub fn passive_scan(&self, request: &Request, response: &Response) -> Vec<Finding> {
        if *self.state.read() == ScanState::Stopping {
            return Vec::new();
        }

        let findings = self.passive.scan(request, response);

        // Add findings to collection
        let mut all_findings = self.findings.write();
        all_findings.extend(findings.clone());

        // Update progress
        let mut progress = self.progress.write();
        progress.findings_count = all_findings.len();

        findings
    }

    /// Start active scan on a target
    pub async fn active_scan(&self, target_url: &str) -> Result<Vec<Finding>> {
        {
            let mut state = self.state.write();
            if *state != ScanState::Idle {
                return Err(anyhow::anyhow!("Scan already in progress"));
            }
            *state = ScanState::Running;
        }

        {
            let mut progress = self.progress.write();
            progress.state = ScanState::Running;
            progress.current_url = Some(target_url.to_string());
        }

        let policy = self.policy.read().clone();
        let findings = self.active.scan(target_url, &policy).await?;

        // Add findings to collection
        {
            let mut all_findings = self.findings.write();
            all_findings.extend(findings.clone());
        }

        {
            let mut state = self.state.write();
            *state = ScanState::Idle;
        }

        {
            let mut progress = self.progress.write();
            progress.state = ScanState::Idle;
            progress.findings_count = self.findings.read().len();
        }

        Ok(findings)
    }

    /// Stop the current scan
    pub fn stop_scan(&self) {
        let mut state = self.state.write();
        *state = ScanState::Stopping;

        let mut progress = self.progress.write();
        progress.state = ScanState::Stopping;
    }

    /// Pause the current scan
    pub fn pause_scan(&self) {
        let mut state = self.state.write();
        if *state == ScanState::Running {
            *state = ScanState::Paused;
        }

        let mut progress = self.progress.write();
        if progress.state == ScanState::Running {
            progress.state = ScanState::Paused;
        }
    }

    /// Resume a paused scan
    pub fn resume_scan(&self) {
        let mut state = self.state.write();
        if *state == ScanState::Paused {
            *state = ScanState::Running;
        }

        let mut progress = self.progress.write();
        if progress.state == ScanState::Paused {
            progress.state = ScanState::Running;
        }
    }

    /// Get current scan state
    pub fn state(&self) -> ScanState {
        *self.state.read()
    }

    /// Get scan progress
    pub fn progress(&self) -> ScanProgress {
        self.progress.read().clone()
    }

    /// Get all findings
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.read().clone()
    }

    /// Get findings by severity
    pub fn findings_by_severity(&self, severity: Severity) -> Vec<Finding> {
        self.findings
            .read()
            .iter()
            .filter(|f| f.severity_level() == severity)
            .cloned()
            .collect()
    }

    /// Clear all findings
    pub fn clear_findings(&self) {
        self.findings.write().clear();
        self.progress.write().findings_count = 0;
    }

    /// Set scan policy
    pub fn set_policy(&self, policy: ScanPolicy) {
        *self.policy.write() = policy;
    }

    /// Get current policy
    pub fn policy(&self) -> ScanPolicy {
        self.policy.read().clone()
    }

    /// Mark finding as false positive
    pub fn mark_false_positive(&self, finding_id: &str) {
        let mut findings = self.findings.write();
        if let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) {
            finding.false_positive = true;
        }
    }

    /// Confirm a finding
    pub fn confirm_finding(&self, finding_id: &str) {
        let mut findings = self.findings.write();
        if let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) {
            finding.confirmed = true;
        }
    }

    /// Add note to finding
    pub fn add_finding_note(&self, finding_id: &str, note: &str) {
        let mut findings = self.findings.write();
        if let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) {
            finding.notes = Some(note.to_string());
        }
    }
}
