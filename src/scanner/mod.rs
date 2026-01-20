//! Security scanner module
//!
//! Provides passive and active security scanning capabilities.

mod engine;
mod findings;
pub mod active;
pub mod js_analysis;
pub mod jwt;
pub mod param_discovery;
pub mod passive;
pub mod policies;

pub use engine::ScanEngine;
pub use findings::{Finding, Severity};
pub use js_analysis::{
    JsAnalyzer, JsEndpoint, JsSecret, JsAnalysisReport,
    EndpointType, SecretType, VulnerableLibrary, LibraryVulnerability,
};
pub use jwt::{JwtAnalyzer, JwtToken, JwtAttackType, JwtAttackResult, JwtAnalysisReport};
pub use param_discovery::{
    ParamMiner, ParamMinerConfig, DiscoveredParam, ParamLocation,
    CachePoisonTester, CachePoisonResult,
    COMMON_PARAMS, COMMON_HEADERS,
};
