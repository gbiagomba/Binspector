//! Minimal HTTP GET, implemented over `curl`.
//!
//! Two deliberate choices:
//!
//! **No Rust TLS stack.** A pure-Rust client pulls rustls, ring, and webpki, which is
//! a large dependency tree and a large amount of build output for a feature that is
//! off by default and used for a handful of requests. `curl` ships on macOS, modern
//! Windows, and effectively every Linux.
//!
//! **Secrets never reach the argument list.** An API key passed as `-H "key: SECRET"`
//! is visible to any other process via `ps`. Headers are therefore written to curl's
//! config on stdin instead, which never appears in the process table.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_str(&self.body).context("parsing response body as JSON")
    }
}

/// Check that a usable curl is present, with a clear message when it is not.
pub fn ensure_available() -> Result<()> {
    let out = Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match out {
        Ok(s) if s.success() => Ok(()),
        _ => bail!(
            "network lookups need `curl` on PATH, which was not found. Install curl, or omit \
             the lookup flags to run offline."
        ),
    }
}

/// GET `url` with optional secret headers.
///
/// `headers` values may contain credentials; they are passed through curl's config on
/// stdin so they stay out of the process argument list.
pub fn get(url: &str, headers: &[(&str, &str)], timeout: Duration) -> Result<Response> {
    if !url.starts_with("https://") {
        bail!("refusing a non-HTTPS request to {}", url);
    }

    let mut child = Command::new("curl")
        .args([
            "--config",
            "-",
            // Print the status code on its own trailing line so it can be split off.
            "--write-out",
            "\n%{http_code}",
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "3",
            "--max-time",
            &timeout.as_secs().to_string(),
            "--proto",
            "=https",
            "--tlsv1.2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning curl")?;

    {
        let stdin = child.stdin.as_mut().context("curl stdin unavailable")?;
        // The URL goes in the config too, so a credential-bearing URL would also stay
        // out of argv, and the quoting rules are curl's own.
        writeln!(stdin, "url = {}", quote(url))?;
        for (k, v) in headers {
            writeln!(stdin, "header = {}", quote(&format!("{}: {}", k, v)))?;
        }
    }

    let out = child.wait_with_output().context("running curl")?;
    if !out.status.success() && out.stdout.is_empty() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!(
            "curl failed: {}",
            if err.is_empty() {
                "no output".to_string()
            } else {
                redact(&err)
            }
        );
    }

    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, status) = match text.rsplit_once('\n') {
        Some((b, s)) => (b.to_string(), s.trim().parse::<u16>().unwrap_or(0)),
        None => (text, 0),
    };
    Ok(Response { status, body })
}

/// curl config quoting.
///
/// Wrapping in double quotes is not enough on its own: curl parses its config line by
/// line, so a literal newline inside a value would end the line and the remainder
/// would be read as a fresh directive. Curl's quoted form accepts the escapes `\\`,
/// `\"`, `\t`, `\n`, `\r`, and `\v`, so control characters are encoded rather than
/// passed through, and anything else unprintable is dropped.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0b}' => out.push_str("\\v"),
            // Any other control character has no escape and no legitimate use here.
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Strip anything that looks like a key from text that may be shown or logged.
pub fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for token in s.split_whitespace() {
        // A long hex or base64-ish run is very likely a credential.
        let looks_secret = token.len() >= 24
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if looks_secret {
            out.push_str("[redacted]");
        } else {
            out.push_str(token);
        }
        out.push(' ');
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https() {
        let r = get("http://example.com", &[], Duration::from_secs(5));
        assert!(r.unwrap_err().to_string().contains("non-HTTPS"));
        let r = get("ftp://example.com", &[], Duration::from_secs(5));
        assert!(r.is_err());
    }

    #[test]
    fn quoting_escapes_backslashes_and_quotes() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn a_newline_cannot_inject_a_second_config_directive() {
        // curl parses its config line by line, so a raw newline would end the value
        // and the rest would become a new directive. The escaped form must stay on
        // one physical line.
        let q = quote("x\nheader = X-Evil: 1");
        assert!(!q.contains('\n'), "raw newline survived: {:?}", q);
        assert_eq!(q.lines().count(), 1);
        assert!(q.contains("\\n"), "newline was not escaped: {:?}", q);
    }

    #[test]
    fn carriage_returns_and_tabs_are_escaped_too() {
        let q = quote("a\r\nb\tc");
        assert!(!q.contains('\r') && !q.contains('\n') && !q.contains('\t'));
        assert_eq!(q.lines().count(), 1);
    }

    #[test]
    fn other_control_characters_are_dropped() {
        let q = quote("a\u{0}b\u{7}c");
        assert_eq!(q, "\"abc\"");
    }

    #[test]
    fn redaction_hides_long_credential_like_tokens() {
        let key = "a".repeat(64);
        let msg = format!("failed with key {} at endpoint", key);
        let red = redact(&msg);
        assert!(!red.contains(&key));
        assert!(red.contains("[redacted]"));
        assert!(red.contains("endpoint"));
    }

    #[test]
    fn redaction_keeps_ordinary_words() {
        assert_eq!(
            redact("connection refused by host"),
            "connection refused by host"
        );
    }

    #[test]
    fn response_helpers() {
        let ok = Response {
            status: 200,
            body: r#"{"a":1}"#.into(),
        };
        assert!(ok.is_success());
        assert_eq!(ok.json().unwrap()["a"], 1);

        let nf = Response {
            status: 404,
            body: String::new(),
        };
        assert!(!nf.is_success());
        assert!(nf.json().is_err());
    }
}
