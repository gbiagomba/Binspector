use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use md5::Md5;
use regex::Regex;
use serde::Serialize;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};
use std::borrow::Cow;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
// no extra imports
use time::format_description::well_known::Rfc3339;

static BANNED_LIST: &str = include_str!("../sdl_banned_funct.list");

#[derive(Parser, Debug)]
#[command(
    name = "binspector",
    version,
    about = "Scan binaries for banned C functions"
)]
struct Cli {
    /// Path to the target binary file
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// Optional project name for output labeling
    #[arg(short, long)]
    project: Option<String>,

    /// Minimum string length to consider (ASCII/UTF-16)
    #[arg(short = 'l', long, default_value_t = 4)]
    min_len: usize,

    /// Emit JSON summary
    #[arg(long)]
    json: bool,

    /// Write output to a file instead of stdout
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Path to a custom banned list file (one function name per line)
    #[arg(long, value_name = "FILE")]
    banned_list: Option<PathBuf>,

    /// Emit only the matches (no metadata)
    #[arg(long)]
    matches_only: bool,

    /// Output format: text, json, or csv. Note: CSV is only supported with --matches-only.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Do not extract ASCII strings
    #[arg(long = "no-ascii")]
    no_ascii: bool,

    /// Do not extract UTF-16LE strings
    #[arg(long = "no-utf16")]
    no_utf16: bool,

    /// Case-insensitive matching when searching for banned function names
    #[arg(long = "ignore-case")]
    ignore_case: bool,

    /// Filter banned function names by a regex (applied to the function name)
    #[arg(long = "banned-filter", value_name = "REGEX")]
    banned_filter: Option<String>,

    /// Subcommands (reserved for future use)
    #[command(subcommand)]
    _cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Placeholder for future fuzzing capability
    Fuzz,
}

#[derive(Serialize)]
struct MatchRecord<'a> {
    function: &'a str,
    occurrences: usize,
}

#[derive(Serialize)]
struct Report<'a> {
    binary: String,
    project: Option<String>,
    timestamp: String,
    file_size: u64,
    md5: String,
    sha1: String,
    sha256: String,
    min_len: usize,
    banned_hit_count: usize,
    matches: Vec<MatchRecord<'a>>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Csv,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let bin = &cli.binary;
    if cli.no_ascii && cli.no_utf16 {
        bail!("Invalid options: both --no-ascii and --no-utf16 are set. Enable at least one extraction source.");
    }
    if !bin.exists() {
        bail!("Binary not found: {}", bin.display());
    }

    let content = read_all(bin).with_context(|| format!("reading {}", bin.display()))?;
    let ascii = if cli.no_ascii {
        Vec::new()
    } else {
        extract_ascii_strings(&content, cli.min_len)
    };
    let utf16 = if cli.no_utf16 {
        Vec::new()
    } else {
        extract_utf16le_strings(&content, cli.min_len)
    };

    // Combine unique strings for scanning while preserving multi-occurrence visibility by counting later
    let mut all_strings: Vec<Cow<str>> = Vec::with_capacity(ascii.len() + utf16.len());
    all_strings.extend(ascii.into_iter().map(Cow::Owned));
    all_strings.extend(utf16.into_iter().map(Cow::Owned));

    let banned_source: Cow<str> = if let Some(path) = cli.banned_list.as_ref() {
        Cow::Owned(
            fs::read_to_string(path)
                .with_context(|| format!("reading banned list {}", path.display()))?,
        )
    } else {
        Cow::Borrowed(BANNED_LIST)
    };
    let banned_filter = if let Some(pat) = &cli.banned_filter {
        Some(Regex::new(pat).with_context(|| format!("invalid regex: {}", pat))?)
    } else {
        None
    };
    let banned: Vec<String> = parse_and_sanitize_banned(&banned_source, banned_filter.as_ref());

    let mut matches: Vec<MatchRecord> = Vec::new();
    if cli.ignore_case {
        let lowered_strings: Vec<String> =
            all_strings.iter().map(|s| s.to_ascii_lowercase()).collect();
        for f in banned.iter() {
            let f_lower = f.to_ascii_lowercase();
            let mut count = 0usize;
            for s in lowered_strings.iter() {
                if s.contains(&f_lower) {
                    count += 1;
                }
            }
            if count > 0 {
                matches.push(MatchRecord {
                    function: f,
                    occurrences: count,
                });
            }
        }
    } else {
        for f in banned.iter() {
            let mut count = 0usize;
            for s in all_strings.iter() {
                if s.contains(f) {
                    count += 1;
                }
            }
            if count > 0 {
                matches.push(MatchRecord {
                    function: f,
                    occurrences: count,
                });
            }
        }
    }
    matches.sort_by_key(|m| std::cmp::Reverse(m.occurrences));

    let (md5, sha1, sha256) = hashes(&content);
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "".into());
    let file_size = content.len() as u64;
    let report = Report {
        binary: bin.display().to_string(),
        project: cli.project.clone(),
        timestamp,
        file_size,
        md5,
        sha1,
        sha256,
        min_len: cli.min_len,
        banned_hit_count: matches.iter().map(|m| m.occurrences).sum(),
        matches,
    };

    let format = cli.format.unwrap_or_else(|| {
        if cli.json {
            OutputFormat::Json
        } else {
            OutputFormat::Text
        }
    });

    if cli.matches_only {
        match format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&report.matches)?;
                write_or_print(cli.output.as_ref(), &json)?;
            }
            OutputFormat::Csv => {
                let csv = matches_to_csv(&report.matches);
                write_or_print(cli.output.as_ref(), &csv)?;
            }
            OutputFormat::Text => {
                let mut s = String::new();
                for m in &report.matches {
                    s.push_str(&format!("{}\t{}\n", m.function, m.occurrences));
                }
                write_or_print(cli.output.as_ref(), &s)?;
            }
        }
    } else {
        match format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&report)?;
                write_or_print(cli.output.as_ref(), &json)?;
            }
            OutputFormat::Csv => {
                bail!("CSV output is only supported with --matches-only");
            }
            OutputFormat::Text => {
                let mut s = String::new();
                s.push_str(&format!("Binspector report for {}\n", report.binary));
                if let Some(prj) = &report.project {
                    s.push_str(&format!("Project: {}\n", prj));
                }
                s.push_str(&format!("Size: {} bytes\n", report.file_size));
                s.push_str(&format!("MD5: {}\n", report.md5));
                s.push_str(&format!("SHA1: {}\n", report.sha1));
                s.push_str(&format!("SHA256: {}\n", report.sha256));
                s.push_str(&format!("Min string length: {}\n", report.min_len));
                s.push_str(&format!(
                    "Banned functions matched: {}\n",
                    report.matches.len()
                ));
                for m in &report.matches {
                    s.push_str(&format!(
                        "- {} ({} occurrences)\n",
                        m.function, m.occurrences
                    ));
                }
                write_or_print(cli.output.as_ref(), &s)?;
            }
        }
    }

    Ok(())
}

fn read_all(path: &Path) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if is_printable_ascii(b) {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    out.push(s);
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = String::from_utf8(cur) {
            out.push(s);
        }
    }
    out
}

fn extract_utf16le_strings(data: &[u8], min_len: usize) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);
        let ch = char::from_u32(word as u32).unwrap_or('\u{FFFD}');
        if ch.is_ascii_graphic() || ch == ' ' {
            cur.push(word);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf16(&cur) {
                    out.push(s);
                }
            }
            cur.clear();
        }
        i += 2;
    }
    if cur.len() >= min_len {
        if let Ok(s) = String::from_utf16(&cur) {
            out.push(s);
        }
    }
    out
}

fn is_printable_ascii(b: u8) -> bool {
    // 0x20..=0x7E are printable; also include tab
    b == b'\t' || (0x20..=0x7E).contains(&b)
}

fn hashes(data: &[u8]) -> (String, String, String) {
    // md5
    let mut md5 = Md5::new();
    md5.update(data);
    let md5 = hex::encode(md5.finalize());
    // sha1
    let mut sha1 = Sha1::new();
    sha1.update(data);
    let sha1 = hex::encode(sha1.finalize());
    // sha256
    let mut sha256 = Sha256::new();
    sha256.update(data);
    let sha256 = hex::encode(sha256.finalize());
    (md5, sha1, sha256)
}

fn matches_to_csv(matches: &[MatchRecord]) -> String {
    let mut s = String::from("function,occurrences\n");
    for m in matches {
        // very simple CSV; banned names are typically bare identifiers
        s.push_str(&format!("{},{}\n", m.function, m.occurrences));
    }
    s
}

fn write_or_print(path: Option<&PathBuf>, content: &str) -> Result<()> {
    if let Some(p) = path {
        fs::write(p, content).with_context(|| format!("writing {}", p.display()))?;
    } else {
        println!("{}", content);
    }
    Ok(())
}

fn parse_and_sanitize_banned(source: &str, re: Option<&Regex>) -> Vec<String> {
    use std::collections::HashSet;
    let mut set: HashSet<String> = HashSet::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cleaned = sanitize_token(line);
        // Some lines might contain multiple tokens separated by space (legacy list quirk)
        for tok in cleaned.split_whitespace() {
            let t = tok.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(regex) = re {
                if !regex.is_match(t) {
                    continue;
                }
            }
            set.insert(t.to_string());
        }
    }
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

fn sanitize_token(input: &str) -> String {
    // Remove zero-width and format characters commonly seen in corrupted lists
    input
        .chars()
        .filter(|&ch| !is_invisible_format_char(ch) && !ch.is_control())
        .collect()
}

fn is_invisible_format_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{FEFF}' // ZERO WIDTH NO-BREAK SPACE
        | '\u{2060}' // WORD JOINER
        | '\u{00AD}' // SOFT HYPHEN
        | '\u{034F}' // COMBINING GRAPHEME JOINER
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_extraction_basic() {
        let data = b"\x00hello\x20world\x00bad\xff";
        let got = extract_ascii_strings(data, 4);
        assert!(got.contains(&"hello world".to_string()));
        assert!(!got.contains(&"bad".to_string())); // filtered by min_len=4
    }
}
