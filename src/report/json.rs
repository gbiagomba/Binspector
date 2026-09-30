//! JSON report. Emits the whole model, or just the summary with --matches-only.

use anyhow::Result;
use std::io::Write;

use super::RenderOpts;
use crate::model::Report;

pub fn write(w: &mut dyn Write, r: &Report, opts: &RenderOpts) -> Result<()> {
    let json = if opts.matches_only {
        serde_json::to_string_pretty(&r.summary)?
    } else {
        serde_json::to_string_pretty(r)?
    };
    w.write_all(json.as_bytes())?;
    w.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests_support::{opts, sample_report};

    #[test]
    fn emits_valid_json_with_the_full_model() {
        let mut buf = Vec::new();
        write(&mut buf, &sample_report(), &opts()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["tool"], "binspector");
        assert_eq!(v["summary"][0]["function"], "strcpy");
        assert_eq!(v["summary"][0]["severity"], "critical");
        assert!(v["coverage"]["members_scanned"].is_number());
    }

    #[test]
    fn matches_only_emits_just_the_summary_array() {
        let o = RenderOpts {
            matches_only: true,
            ..opts()
        };
        let mut buf = Vec::new();
        write(&mut buf, &sample_report(), &o).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["function"], "strcpy");
    }
}
