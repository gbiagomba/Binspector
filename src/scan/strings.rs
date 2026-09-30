//! Printable string extraction, carrying the byte offset of every run.
//!
//! The offset matters: highlighting, SARIF regions, and manual verification all
//! need to point a reviewer at a real position inside a real file. The previous
//! implementation discarded position entirely.

use serde::Serialize;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    Ascii,
    Utf16Le,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Ascii => "ascii",
            Encoding::Utf16Le => "utf16le",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExtractedString {
    pub text: String,
    pub encoding: Encoding,
    /// Byte offset of the first byte of the run, within the member it came from.
    pub offset: u64,
}

/// Extract ASCII and/or UTF-16LE runs of at least `min_len` characters.
pub fn extract(data: &[u8], min_len: usize, ascii: bool, utf16: bool) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    if ascii {
        extract_ascii_into(data, min_len, &mut out);
    }
    if utf16 {
        extract_utf16le_into(data, min_len, &mut out);
    }
    out
}

pub fn extract_ascii_into(data: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    let mut start = 0usize;
    let mut cur: Vec<u8> = Vec::new();
    for (i, &b) in data.iter().enumerate() {
        if is_printable_ascii(b) {
            if cur.is_empty() {
                start = i;
            }
            cur.push(b);
        } else {
            flush_ascii(&mut cur, start, min_len, out);
        }
    }
    flush_ascii(&mut cur, start, min_len, out);
}

fn flush_ascii(cur: &mut Vec<u8>, start: usize, min_len: usize, out: &mut Vec<ExtractedString>) {
    if cur.len() >= min_len {
        if let Ok(text) = std::str::from_utf8(cur) {
            out.push(ExtractedString {
                text: text.to_string(),
                encoding: Encoding::Ascii,
                offset: start as u64,
            });
        }
    }
    cur.clear();
}

pub fn extract_utf16le_into(data: &[u8], min_len: usize, out: &mut Vec<ExtractedString>) {
    if data.len() < 2 {
        return;
    }
    let mut start = 0usize;
    let mut cur: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = u16::from_le_bytes([data[i], data[i + 1]]);
        let printable = match char::from_u32(word as u32) {
            Some(ch) => ch.is_ascii_graphic() || ch == ' ',
            None => false,
        };
        if printable {
            if cur.is_empty() {
                start = i;
            }
            cur.push(word);
        } else {
            flush_utf16(&mut cur, start, min_len, out);
        }
        i += 2;
    }
    flush_utf16(&mut cur, start, min_len, out);
}

fn flush_utf16(cur: &mut Vec<u16>, start: usize, min_len: usize, out: &mut Vec<ExtractedString>) {
    if cur.len() >= min_len {
        if let Ok(text) = String::from_utf16(cur) {
            out.push(ExtractedString {
                text,
                encoding: Encoding::Utf16Le,
                offset: start as u64,
            });
        }
    }
    cur.clear();
}

fn is_printable_ascii(b: u8) -> bool {
    // 0x20..=0x7E are printable; tab is kept because it appears in embedded text.
    b == b'\t' || (0x20..=0x7E).contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_extraction_basic() {
        let data = b"\x00hello world\x00bad\xff";
        let got = extract(data, 4, true, false);
        let texts: Vec<&str> = got.iter().map(|s| s.text.as_str()).collect();
        assert!(texts.contains(&"hello world"));
        // "bad" is shorter than min_len
        assert!(!texts.contains(&"bad"));
    }

    #[test]
    fn ascii_records_offset() {
        let data = b"\x00\x00hello";
        let got = extract(data, 4, true, false);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "hello");
        assert_eq!(got[0].offset, 2);
        assert_eq!(got[0].encoding, Encoding::Ascii);
    }

    #[test]
    fn utf16_extraction_and_offset() {
        // "test" in UTF-16LE, preceded by two null bytes.
        let mut data = vec![0u8, 0u8];
        for ch in "test".chars() {
            data.extend_from_slice(&(ch as u16).to_le_bytes());
        }
        let got = extract(&data, 4, false, true);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "test");
        assert_eq!(got[0].offset, 2);
        assert_eq!(got[0].encoding, Encoding::Utf16Le);
    }

    #[test]
    fn both_encodings_can_run_together() {
        let data = b"asciihere\x00";
        let got = extract(data, 4, true, true);
        assert!(got.iter().any(|s| s.encoding == Encoding::Ascii));
    }

    #[test]
    fn empty_input_is_safe() {
        assert!(extract(b"", 4, true, true).is_empty());
        assert!(extract(b"\x01", 4, true, true).is_empty());
    }
}
