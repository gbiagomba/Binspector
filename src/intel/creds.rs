//! Credential loading for the reputation and CVE services.
//!
//! Keys are never accepted as command line arguments, because arguments are visible
//! to other processes through `ps` and are recorded in shell history. They come from
//! the environment, or from a config file that must not be world or group readable.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct Credentials {
    pub virustotal: Option<String>,
    pub metadefender: Option<String>,
    pub nvd: Option<String>,
}

impl Credentials {
    /// Environment first, then the config file for anything still missing.
    pub fn load() -> Result<Self> {
        Self::load_from(None)
    }

    /// As [`load`], with an explicit credentials file taking the place of the default path.
    ///
    /// The precedence is deliberate and documented in `--help`: environment first, then the file.
    /// An operator who exports a key for one command should not have a stale file override it.
    pub fn load_from(explicit: Option<&Path>) -> Result<Self> {
        let mut c = Self {
            virustotal: env_key("VT_API_KEY").or_else(|| env_key("VIRUSTOTAL_API_KEY")),
            metadefender: env_key("MD_API_KEY").or_else(|| env_key("METADEFENDER_API_KEY")),
            nvd: env_key("NVD_API_KEY"),
        };
        if let Some(path) = explicit.map(PathBuf::from).or_else(config_path) {
            if !path.exists() && explicit.is_some() {
                anyhow::bail!(
                    "credentials file {} does not exist. Nothing was read from it, so a key you \
                     expected to be present is absent",
                    path.display()
                );
            }
            if path.exists() {
                let file = load_file(&path)?;
                if c.virustotal.is_none() {
                    c.virustotal = file.get("virustotal").cloned();
                }
                if c.metadefender.is_none() {
                    c.metadefender = file.get("metadefender").cloned();
                }
                if c.nvd.is_none() {
                    c.nvd = file.get("nvd").cloned();
                }
            }
        }
        Ok(c)
    }

    pub fn missing_message(service: &str, env_var: &str) -> String {
        format!(
            "no {} API key found. Set {} in the environment, or add it to \
             ~/.config/binspector/credentials (mode 0600). Keys are never accepted as command \
             line arguments, because arguments are visible in the process list.",
            service, env_var
        )
    }
}

fn env_key(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

pub fn config_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BINSPECTOR_CREDENTIALS") {
        if !p.trim().is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config/binspector/credentials"))
}

/// Parse `key = value` lines. Refuses a file that others can read.
pub fn load_file(path: &Path) -> Result<BTreeMap<String, String>> {
    check_permissions(path)?;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse(&text))
}

pub fn parse(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if !v.is_empty() {
                out.insert(k.trim().to_ascii_lowercase(), v.to_string());
            }
        }
    }
    out
}

/// A credentials file readable by group or others is a finding, not a warning.
/// Shared with `cache`, which stores the same class of user-level secret-adjacent state and must
/// refuse a world-readable file by the same rule rather than a looser one of its own.
#[cfg(unix)]
pub(super) fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {:o}, which lets other users read your API keys. Run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn check_permissions(_path: &Path) -> Result<()> {
    // Windows ACLs are not comparable to a POSIX mode; the file is trusted there.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_key_value_lines() {
        let m = parse("virustotal = abc123\n# comment\n\nnvd=\"xyz\"\nmetadefender='q'\n");
        assert_eq!(m.get("virustotal").unwrap(), "abc123");
        assert_eq!(m.get("nvd").unwrap(), "xyz");
        assert_eq!(m.get("metadefender").unwrap(), "q");
    }

    #[test]
    fn ignores_comments_blanks_and_empty_values() {
        let m = parse("# all comment\n\nkey =\nother = v\n");
        assert!(!m.contains_key("key"));
        assert_eq!(m.get("other").unwrap(), "v");
    }

    #[test]
    fn keys_are_lowercased_for_lookup() {
        let m = parse("VirusTotal = K\n");
        assert_eq!(m.get("virustotal").unwrap(), "K");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_world_readable_credentials_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("creds");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "virustotal = secret").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_file(&p).unwrap_err().to_string();
        assert!(err.contains("other users"), "{}", err);
        assert!(err.contains("chmod 600"));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_an_owner_only_credentials_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("creds");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "virustotal = secret").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_file(&p).unwrap().get("virustotal").unwrap(), "secret");
    }

    #[test]
    fn missing_message_names_the_env_var_and_forbids_cli_args() {
        let m = Credentials::missing_message("VirusTotal", "VT_API_KEY");
        assert!(m.contains("VT_API_KEY"));
        assert!(m.contains("never accepted as command line arguments"));
    }

    #[test]
    fn an_explicit_credentials_file_is_read_and_the_environment_still_wins() {
        // Written to tolerate a developer machine that really has NVD_API_KEY exported, which is
        // not incidental: the precedence is the contract, so the test asserts whichever half of
        // it applies rather than mutating the process environment under other tests.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        std::fs::write(&path, "nvd = from-the-file\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let c = Credentials::load_from(Some(&path)).expect("read");
        match env_key("NVD_API_KEY") {
            Some(from_env) => assert_eq!(
                c.nvd.as_deref(),
                Some(from_env.as_str()),
                "the environment takes precedence over the file"
            ),
            None => assert_eq!(c.nvd.as_deref(), Some("from-the-file")),
        }
    }

    #[test]
    fn the_file_parser_reads_every_service() {
        // The file half of the contract, independent of the environment entirely.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds");
        std::fs::write(
            &path,
            "# a comment\nvirustotal = vt-key\nmetadefender = md-key\nnvd = nvd-key\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let m = load_file(&path).expect("read");
        assert_eq!(m.get("virustotal").map(String::as_str), Some("vt-key"));
        assert_eq!(m.get("metadefender").map(String::as_str), Some("md-key"));
        assert_eq!(m.get("nvd").map(String::as_str), Some("nvd-key"));
    }

    #[test]
    fn a_named_credentials_file_that_is_absent_is_an_error_not_a_silent_miss() {
        // The default path is allowed to be absent, because most runs have no keys. A path the
        // operator typed is different: silently finding nothing there means a scan runs without
        // the enrichment they asked for and the report looks like the service had no answer.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        let err = Credentials::load_from(Some(&missing))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "{}", err);
    }

    #[test]
    fn no_flag_accepts_a_key_directly() {
        // A guard against a future convenience flag. An argument is visible to every process on
        // the machine through `ps` and is written to shell history, so a `--vt-key` would turn a
        // secret into a disclosure. The only inputs are the environment and a file.
        let help = <crate::cli::Cli as clap::CommandFactory>::command()
            .render_help()
            .to_string();
        for forbidden in ["--vt-key", "--api-key", "--nvd-key", "--token"] {
            assert!(!help.contains(forbidden), "{} must not exist", forbidden);
        }
    }
}
