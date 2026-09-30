//! Reputation and CVE enrichment.
//!
//! Everything here is opt-in and offline by default. Nothing in this module transmits
//! file content: reputation is looked up by the SHA-256 the scan already computed, and
//! CVE enrichment sends only a detected component name and version.

pub mod components;
pub mod creds;
pub mod cve;
pub mod http;
pub mod reputation;

use serde::{Deserialize, Serialize};

pub use components::Component;
pub use creds::Credentials;
pub use cve::CveReport;
pub use reputation::Reputation;

/// The enrichment attached to a report.
#[derive(Clone, Debug, Serialize, Default, Deserialize)]
pub struct Intel {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<Reputation>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cves: Option<CveReport>,
    /// Components detected from strings, present whenever detection ran.
    pub components: Vec<Component>,
}

impl Intel {
    pub fn is_empty(&self) -> bool {
        self.reputation.is_none() && self.cves.is_none() && self.components.is_empty()
    }
}
