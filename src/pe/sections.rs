//! Section table analysis, including per-section Shannon entropy.
//!
//! Entropy and section permissions are what packer detection rests on: packed or
//! encrypted payloads approach 8 bits per byte, and a section that is both writable
//! and executable is a red flag in a normally-built binary.

use serde::Serialize;

/// Section characteristic bits used here.
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Clone, Debug, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub contains_code: bool,
}

impl SectionInfo {
    /// Writable and executable at once. Legitimate builds almost never need this.
    pub fn is_write_execute(&self) -> bool {
        self.writable && self.executable
    }

    /// Entropy high enough to suggest compressed or encrypted content.
    pub fn is_high_entropy(&self) -> bool {
        self.entropy >= 7.2
    }

    /// Raw size zero but virtual size large: the classic unpacking stub layout.
    pub fn is_virtual_only(&self) -> bool {
        self.raw_size == 0 && self.virtual_size > 0
    }

    pub fn permissions(&self) -> String {
        format!(
            "{}{}{}",
            if self.readable { "r" } else { "-" },
            if self.writable { "w" } else { "-" },
            if self.executable { "x" } else { "-" }
        )
    }
}

pub fn analyze(pe: &goblin::pe::PE, data: &[u8]) -> Vec<SectionInfo> {
    pe.sections
        .iter()
        .map(|s| {
            let name = s.name().unwrap_or("<invalid>").to_string();
            let start = s.pointer_to_raw_data as usize;
            let len = s.size_of_raw_data as usize;
            // Clamp to the real buffer: a crafted header can claim more than exists.
            let body = data
                .get(start..start.saturating_add(len))
                .or_else(|| data.get(start..))
                .unwrap_or(&[]);
            let c = s.characteristics;
            SectionInfo {
                name,
                virtual_size: s.virtual_size,
                raw_size: s.size_of_raw_data,
                entropy: shannon_entropy(body),
                readable: c & IMAGE_SCN_MEM_READ != 0,
                writable: c & IMAGE_SCN_MEM_WRITE != 0,
                executable: c & IMAGE_SCN_MEM_EXECUTE != 0,
                contains_code: c & IMAGE_SCN_CNT_CODE != 0,
            }
        })
        .collect()
}

/// Shannon entropy in bits per byte, 0.0 to 8.0.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sect(name: &str, entropy: f64, w: bool, x: bool, raw: u32, virt: u32) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            virtual_size: virt,
            raw_size: raw,
            entropy,
            readable: true,
            writable: w,
            executable: x,
            contains_code: x,
        }
    }

    #[test]
    fn entropy_of_uniform_data_is_zero() {
        assert_eq!(shannon_entropy(&[0u8; 1000]), 0.0);
        assert_eq!(shannon_entropy(&[0xAA; 50]), 0.0);
    }

    #[test]
    fn entropy_of_every_byte_value_is_eight() {
        let all: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&all);
        assert!((h - 8.0).abs() < 1e-9, "entropy was {}", h);
    }

    #[test]
    fn entropy_of_two_equal_symbols_is_one_bit() {
        let data: Vec<u8> = (0..100)
            .map(|i| if i % 2 == 0 { 0u8 } else { 1u8 })
            .collect();
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 1e-9, "entropy was {}", h);
    }

    #[test]
    fn empty_input_is_safe() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn flags_write_execute_sections() {
        assert!(sect(".bad", 5.0, true, true, 100, 100).is_write_execute());
        assert!(!sect(".text", 5.0, false, true, 100, 100).is_write_execute());
        assert!(!sect(".data", 5.0, true, false, 100, 100).is_write_execute());
    }

    #[test]
    fn flags_high_entropy_and_virtual_only_sections() {
        assert!(sect("UPX1", 7.9, false, true, 100, 100).is_high_entropy());
        assert!(!sect(".text", 6.1, false, true, 100, 100).is_high_entropy());
        assert!(sect("UPX0", 0.0, true, true, 0, 4096).is_virtual_only());
        assert!(!sect(".text", 6.0, false, true, 4096, 4096).is_virtual_only());
    }

    #[test]
    fn permissions_render_as_rwx() {
        assert_eq!(sect(".text", 6.0, false, true, 1, 1).permissions(), "r-x");
        assert_eq!(sect(".data", 6.0, true, false, 1, 1).permissions(), "rw-");
        assert_eq!(sect(".bad", 6.0, true, true, 1, 1).permissions(), "rwx");
    }
}
