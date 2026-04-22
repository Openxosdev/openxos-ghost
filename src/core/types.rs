use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single probe finding
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    /// What technique was used to surface this finding
    pub evasion_technique: String,
    /// Why standard tools would have missed this
    pub detection_gap: String,
    pub evidence: Evidence,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Raw evidence captured for a finding
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Evidence {
    pub request: String,
    pub response_code: Option<u16>,
    pub response_snippet: Option<String>,
    pub curl_repro: Option<String>,
}

/// Full scan result returned by web or net probe
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub mode: ScanMode,
    pub target: String,
    pub profile: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
    pub evasion_summary: EvasionSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ScanMode {
    Web,
    Net,
}

/// Summary of what evasion worked and what the detection gaps were
#[derive(Debug, Serialize, Deserialize)]
pub struct EvasionSummary {
    pub waf_detected: Option<String>,
    pub techniques_attempted: Vec<String>,
    pub techniques_succeeded: Vec<String>,
    pub detection_gaps: Vec<String>,
}
