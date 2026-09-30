//! Temporary spool for `--dump`.
//!
//! A full dump of a large sample is millions of strings, which is too much to hold
//! in memory and too much to regenerate per output format. Strings are written once
//! during the single unpack pass, then streamed back per format. The spool is a
//! temp file that is removed when the scan ends.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};

use crate::scan::strings::{Encoding, ExtractedString};

pub struct Spool {
    writer: BufWriter<File>,
    file: tempfile::NamedTempFile,
    count: usize,
}

pub struct SpoolRecord {
    pub member: String,
    pub offset: u64,
    pub encoding: Encoding,
    pub text: String,
    /// Byte ranges of banned-function matches inside `text`.
    pub hits: Vec<(usize, usize)>,
}

impl Spool {
    pub fn new() -> Result<Self> {
        let file = tempfile::NamedTempFile::new().context("creating dump spool")?;
        let handle = file.reopen().context("opening dump spool for write")?;
        Ok(Self {
            writer: BufWriter::new(handle),
            file,
            count: 0,
        })
    }

    pub fn push(
        &mut self,
        member: &str,
        s: &ExtractedString,
        hits: &[(usize, usize)],
    ) -> Result<()> {
        let hits_field = hits
            .iter()
            .map(|(a, b)| format!("{}:{}", a, b))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            self.writer,
            "{}\t{}\t{}\t{}\t{}",
            escape(member),
            s.offset,
            s.encoding.as_str(),
            hits_field,
            escape(&s.text)
        )
        .context("writing to dump spool")?;
        self.count += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Flush and return a reader positioned at the start.
    pub fn finish(mut self) -> Result<SpoolReader> {
        self.writer.flush().context("flushing dump spool")?;
        drop(self.writer);
        let mut handle = self.file.reopen().context("reopening dump spool")?;
        handle.seek(SeekFrom::Start(0))?;
        Ok(SpoolReader {
            reader: BufReader::new(handle),
            _file: self.file,
        })
    }
}

pub struct SpoolReader {
    reader: BufReader<File>,
    // Held so the temp file outlives the reader and is deleted on drop.
    _file: tempfile::NamedTempFile,
}

impl SpoolReader {
    /// Seek back to the first record, so several output formats can each stream the
    /// same spool.
    pub fn rewind(&mut self) -> Result<()> {
        self.reader
            .seek(SeekFrom::Start(0))
            .context("rewinding dump spool")?;
        Ok(())
    }

    /// Stream every record. Malformed lines are skipped rather than failing the run.
    pub fn for_each<F>(&mut self, mut f: F) -> Result<()>
    where
        F: FnMut(&SpoolRecord) -> Result<()>,
    {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            if let Some(rec) = parse_line(line.trim_end_matches('\n')) {
                f(&rec)?;
            }
        }
        Ok(())
    }
}

fn parse_line(line: &str) -> Option<SpoolRecord> {
    let mut parts = line.splitn(5, '\t');
    let member = unescape(parts.next()?);
    let offset = parts.next()?.parse().ok()?;
    let encoding = match parts.next()? {
        "utf16le" => Encoding::Utf16Le,
        _ => Encoding::Ascii,
    };
    let hits_field = parts.next()?;
    let text = unescape(parts.next()?);
    let mut hits = Vec::new();
    if !hits_field.is_empty() {
        for pair in hits_field.split(',') {
            let (a, b) = pair.split_once(':')?;
            hits.push((a.parse().ok()?, b.parse().ok()?));
        }
    }
    Some(SpoolRecord {
        member,
        offset,
        encoding,
        text,
        hits,
    })
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn es(text: &str, offset: u64) -> ExtractedString {
        ExtractedString {
            text: text.to_string(),
            encoding: Encoding::Ascii,
            offset,
        }
    }

    #[test]
    fn round_trips_records() {
        let mut spool = Spool::new().unwrap();
        spool
            .push("a :: b.exe", &es("hello gets world", 10), &[(6, 10)])
            .unwrap();
        spool.push("a :: c.exe", &es("clean", 20), &[]).unwrap();
        assert_eq!(spool.len(), 2);

        let mut reader = spool.finish().unwrap();
        let mut got = Vec::new();
        reader
            .for_each(|r| {
                got.push((r.member.clone(), r.offset, r.text.clone(), r.hits.clone()));
                Ok(())
            })
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "a :: b.exe");
        assert_eq!(got[0].1, 10);
        assert_eq!(got[0].2, "hello gets world");
        assert_eq!(got[0].3, vec![(6, 10)]);
        assert!(got[1].3.is_empty());
    }

    #[test]
    fn survives_tabs_and_newlines_in_text() {
        let mut spool = Spool::new().unwrap();
        spool
            .push("m", &es("has\ttab and\nnewline", 0), &[])
            .unwrap();
        let mut reader = spool.finish().unwrap();
        let mut texts = Vec::new();
        reader
            .for_each(|r| {
                texts.push(r.text.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(texts, vec!["has\ttab and\nnewline"]);
    }

    #[test]
    fn preserves_backslashes() {
        let mut spool = Spool::new().unwrap();
        spool
            .push("m", &es(r"C:\Windows\System32", 0), &[])
            .unwrap();
        let mut reader = spool.finish().unwrap();
        let mut texts = Vec::new();
        reader
            .for_each(|r| {
                texts.push(r.text.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(texts, vec![r"C:\Windows\System32"]);
    }

    #[test]
    fn utf16_encoding_round_trips() {
        let mut spool = Spool::new().unwrap();
        spool
            .push(
                "m",
                &ExtractedString {
                    text: "wide".into(),
                    encoding: Encoding::Utf16Le,
                    offset: 4,
                },
                &[],
            )
            .unwrap();
        let mut reader = spool.finish().unwrap();
        let mut encs = Vec::new();
        reader
            .for_each(|r| {
                encs.push(r.encoding);
                Ok(())
            })
            .unwrap();
        assert_eq!(encs, vec![Encoding::Utf16Le]);
    }
}
