//! Single-stream decompression: gzip, bzip2, xz, and zstd.
//!
//! These formats wrap exactly one payload rather than holding a member list, so they
//! decompress to a single child that the walk then treats like any other member. Until
//! now they were detected and reported as a coverage gap; a `.exe.gz` inside a bundle
//! was named in the report but its contents were never scanned.
//!
//! Every reader is bounded by the caller's budget. An unbounded decompressor is exactly
//! how a small file turns into a full disk.

use anyhow::{bail, Context, Result};
use std::io::Read;

use super::detect::Format;
use super::limits::Budget;

/// Decompress a single-stream container, bounded by `limit` bytes.
///
/// Returns the payload, or an error when the stream is corrupt. A stream that hits the
/// limit returns what was read so far, because a partial scan of a truncated payload is
/// still better than no scan.
pub fn decompress(
    data: &[u8],
    format: Format,
    limit: u64,
    at: &str,
    budget: &mut Budget,
) -> Result<Vec<u8>> {
    let cap = limit as usize;
    let mut out = Vec::new();

    let read_result = match format {
        Format::Gzip => {
            let mut r = flate2::read::MultiGzDecoder::new(data).take(limit);
            r.read_to_end(&mut out).map(|_| ())
        }
        Format::Bzip2 => {
            let mut r = bzip2::read::MultiBzDecoder::new(data).take(limit);
            r.read_to_end(&mut out).map(|_| ())
        }
        Format::Xz => {
            let mut r = lzma_rust2::XzReader::new(data, true).take(limit);
            r.read_to_end(&mut out).map(|_| ())
        }
        Format::Zstd => match zstd::stream::read::Decoder::new(data) {
            Ok(dec) => {
                let mut r = dec.take(limit);
                r.read_to_end(&mut out).map(|_| ())
            }
            Err(e) => Err(e),
        },
        other => bail!(
            "{} is not a single-stream compressed format",
            other.as_str()
        ),
    };

    match read_result {
        Ok(()) => {}
        Err(e) => {
            // Partial output is still worth scanning, so a mid-stream error degrades
            // rather than discarding what was already recovered.
            if out.is_empty() {
                return Err(e).with_context(|| {
                    format!("decompressing {} stream at {}", format.as_str(), at)
                });
            }
            budget.warn(format!(
                "{}: {} stream ended early ({}); scanning the {} bytes recovered",
                at,
                format.as_str(),
                e,
                out.len()
            ));
        }
    }

    if out.len() >= cap {
        budget.warn(format!(
            "{}: {} payload reached the {} byte cap and was truncated",
            at,
            format.as_str(),
            cap
        ));
    }
    Ok(out)
}

/// Strip a known single-stream suffix, so a decompressed child keeps a useful name.
pub fn inner_name(name: &str, format: Format) -> String {
    let suffixes: &[&str] = match format {
        Format::Gzip => &[".tgz", ".gz"],
        Format::Bzip2 => &[".tbz2", ".tbz", ".bz2"],
        Format::Xz => &[".txz", ".xz"],
        Format::Zstd => &[".tzst", ".zst"],
        _ => &[],
    };
    for s in suffixes {
        if name.len() > s.len() && name.to_ascii_lowercase().ends_with(s) {
            let base = &name[..name.len() - s.len()];
            // A tar shorthand expands to the tar it really is.
            if s.starts_with(".t") && s.len() > 3 {
                return format!("{}.tar", base);
            }
            return base.to_string();
        }
    }
    format!("{}.decompressed", name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::limits::Limits;
    use std::io::Write;

    fn budget() -> Budget {
        Budget::new(Limits::default(), 1000)
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn bz(data: &[u8]) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zst(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 3).unwrap()
    }

    #[test]
    fn round_trips_gzip() {
        let payload = b"\x00strcpy\x00embedded payload\x00";
        let mut b = budget();
        let out = decompress(&gz(payload), Format::Gzip, 1 << 20, "t", &mut b).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trips_bzip2() {
        let payload = b"\x00gets\x00another payload\x00";
        let mut b = budget();
        let out = decompress(&bz(payload), Format::Bzip2, 1 << 20, "t", &mut b).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn round_trips_zstd() {
        let payload = b"\x00sprintf\x00zstd payload\x00";
        let mut b = budget();
        let out = decompress(&zst(payload), Format::Zstd, 1 << 20, "t", &mut b).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn caps_a_large_payload_and_warns() {
        // 4 MiB of zeros compresses to almost nothing.
        let big = vec![0u8; 4 * 1024 * 1024];
        let mut b = budget();
        let out = decompress(&gz(&big), Format::Gzip, 4096, "t", &mut b).unwrap();
        assert_eq!(out.len(), 4096);
        assert!(
            b.warnings()
                .iter()
                .any(|w| w.contains("cap and was truncated")),
            "warnings: {:?}",
            b.warnings()
        );
    }

    #[test]
    fn corrupt_stream_with_no_output_is_an_error() {
        let mut b = budget();
        let r = decompress(
            &[0x1F, 0x8B, 0x08, 0x00, 0xFF, 0xFF],
            Format::Gzip,
            1 << 20,
            "t",
            &mut b,
        );
        assert!(r.is_err());
    }

    #[test]
    fn truncated_stream_keeps_what_was_recovered() {
        let payload = vec![b'A'; 200_000];
        let mut stream = gz(&payload);
        let keep = stream.len() - 8;
        stream.truncate(keep);
        let mut b = budget();
        let out = decompress(&stream, Format::Gzip, 1 << 20, "t", &mut b).unwrap();
        assert!(!out.is_empty(), "nothing recovered from a truncated stream");
        assert!(b.warnings().iter().any(|w| w.contains("ended early")));
    }

    #[test]
    fn rejects_a_format_that_is_not_single_stream() {
        let mut b = budget();
        assert!(decompress(b"x", Format::Zip, 1 << 20, "t", &mut b).is_err());
    }

    #[test]
    fn inner_name_strips_the_suffix() {
        assert_eq!(inner_name("App.exe.gz", Format::Gzip), "App.exe");
        assert_eq!(inner_name("data.bin.bz2", Format::Bzip2), "data.bin");
        assert_eq!(inner_name("blob.xz", Format::Xz), "blob");
        assert_eq!(inner_name("blob.zst", Format::Zstd), "blob");
    }

    #[test]
    fn inner_name_expands_tar_shorthands() {
        assert_eq!(inner_name("src.tgz", Format::Gzip), "src.tar");
        assert_eq!(inner_name("src.txz", Format::Xz), "src.tar");
        assert_eq!(inner_name("src.tbz2", Format::Bzip2), "src.tar");
    }

    #[test]
    fn inner_name_falls_back_when_there_is_no_suffix() {
        assert_eq!(inner_name("payload", Format::Gzip), "payload.decompressed");
        assert_eq!(inner_name(".gz", Format::Gzip), ".gz.decompressed");
    }
}
