//! Column and list formatting shared by the report sections.
//!
//! These lived three times over: `preview` was byte-identical in `pe_section`, `exe_section` and
//! `targets_section`, the last two each carrying a comment explaining that copying seven lines was
//! cheaper than widening a private API. It was, until a fourth section wanted it. They are here now
//! so the next section reuses rather than copies, and so the `Sink` implementations can rely on one
//! definition of how a column is cut.
//!
//! The two truncation functions are deliberately separate and are not interchangeable. `truncate`
//! keeps the head, which is right for a signer Common Name or a function name. `fit_middle` keeps
//! both ends, which is the only correct choice for a provenance label: a dependency tree holds
//! `arm64/Microsoft.WindowsAppRuntime.2.msix` beside `x64/...`, sharing their tail and differing in
//! their head, while `bin/tool` and `lib/tool` are the reverse, so neither end alone is safe to drop.

/// Last component of a provenance chain, which is the part a reviewer recognises.
pub fn short_name(member: &str) -> &str {
    member.rsplit(" :: ").next().unwrap_or(member)
}

/// Name a few items and count the rest.
///
/// The trailing number is the count *not shown*, so `a, b, and 2 more` describes four items. That
/// is the existing behaviour of all three copies this replaced, and the goldens pin it.
pub fn preview(items: &[&str], max: usize) -> String {
    if items.len() <= max {
        return items.join(", ");
    }
    format!(
        "{}, and {} more",
        items[..max].join(", "),
        items.len() - max
    )
}

/// Fit a value into `max` columns, keeping the head and marking the cut with `~`.
///
/// Counts characters rather than bytes, so a non-ASCII value cannot shift the columns.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max.saturating_sub(1)).collect::<String>() + "~"
}

/// Fit a value into `max` columns, keeping both ends and eliding the middle.
///
/// Control characters are flattened to spaces, because a newline in a file name would otherwise
/// split one table row into two. See the module note for why the middle is the part that goes.
pub fn fit_middle(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let n = cleaned.chars().count();
    if n <= max {
        return cleaned;
    }
    if max <= 1 {
        return cleaned.chars().take(max).collect();
    }
    let keep = max - 1;
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let mut out = String::with_capacity(max);
    out.extend(cleaned.chars().take(head));
    out.push('~');
    out.extend(cleaned.chars().skip(n - tail));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_name_is_the_last_chain_component() {
        assert_eq!(short_name("bundle :: app.msix :: App.exe"), "App.exe");
        assert_eq!(short_name("App.exe"), "App.exe");
    }

    #[test]
    fn a_preview_counts_what_it_does_not_show() {
        assert_eq!(preview(&["a", "b"], 3), "a, b");
        assert_eq!(preview(&["a", "b", "c", "d"], 2), "a, b, and 2 more");
        // Exactly at the cap prints the whole list with no suffix.
        assert_eq!(preview(&["a", "b"], 2), "a, b");
    }

    #[test]
    fn truncate_keeps_the_head() {
        assert_eq!(truncate("abcdef", 10), "abcdef");
        assert_eq!(truncate("abcdef", 4), "abc~");
        // Characters, not bytes: six multi-byte chars must not be cut by byte count.
        assert_eq!(truncate("ααααα", 3), "αα~");
    }

    /// The defect this exists to prevent: tail-only truncation rendered
    /// `arm64/Microsoft.WindowsAppRuntime.2.msix` as `~64/Microsoft...`, which a reader cannot tell
    /// apart from the `x64/...` row beside it.
    #[test]
    fn fit_middle_keeps_both_ends() {
        let a = fit_middle("arm64/Microsoft.WindowsAppRuntime.2.msix", 20);
        let b = fit_middle("x64/Microsoft.WindowsAppRuntime.2.msix", 20);
        assert_ne!(a, b, "the two must stay distinguishable");
        assert!(a.starts_with("arm64"), "{}", a);
        assert!(a.ends_with(".msix"), "{}", a);
        assert_eq!(a.chars().count(), 20);
    }

    #[test]
    fn fit_middle_flattens_control_characters() {
        // A newline in a member name would otherwise split one row into two.
        assert_eq!(fit_middle("a\nb", 10), "a b");
        assert!(!fit_middle("x\ty", 10).contains('\t'));
    }

    #[test]
    fn fit_middle_degenerate_widths_do_not_panic() {
        for max in 0..4 {
            let out = fit_middle("abcdefgh", max);
            assert!(out.chars().count() <= max.max(1), "max {}: {:?}", max, out);
        }
    }
}
