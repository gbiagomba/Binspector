//! Reputation and CVE enrichment.
//!
//! Everything here is opt-in and offline by default. Nothing in this module transmits
//! file content: reputation is looked up by the SHA-256 the scan already computed, and
//! CVE enrichment sends only a detected component name and version.

pub mod budget;
pub mod cache;
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
    /// One entry per scanned target, each against that target's own file digest.
    ///
    /// A `Vec` rather than an `Option<Reputation>` since 6.0.0, because one answer per report was
    /// the wrong shape: in a multi-target run the single answer was about a synthesized manifest
    /// digest rather than about any file. This is the breaking change the major version is for.
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reputation: Vec<Reputation>,
    /// What a `--reputation-members` sweep asked, answered and skipped.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sweep: Option<reputation::Sweep>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cves: Option<CveReport>,
    /// Components detected from strings, present whenever detection ran.
    pub components: Vec<Component>,
}

impl Intel {
    pub fn is_empty(&self) -> bool {
        self.reputation.is_empty()
            && self.sweep.is_none()
            && self.cves.is_none()
            && self.components.is_empty()
    }
}
