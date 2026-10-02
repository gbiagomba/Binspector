//! Tests for the evidence rules.
//!
//! Split out of `evidence.rs` when that file reached the 1000-line soft limit `make loc-check`
//! enforces. Included with `#[path]` so it stays the same `tests` module and every `super::`
//! path keeps working.

use super::*;
/// An occurrence in a native PE where the matched token is the function name itself.
fn case<'a>(
    function: &'a str,
    base: Severity,
    confidence: Confidence,
    text: &'a str,
) -> Observation<'a> {
    let start = text
        .find(function)
        .expect("the function name appears in the text");
    Observation {
        function,
        base_severity: base,
        confidence,
        text,
        start,
        end: start + function.len(),
        member_format: Format::Pe,
        is_managed: false,
        // The default case is a PE, whose import table was read.
        imports_known: true,
        // A PE with code and no export of this name, so neither new exclusion fires and
        // every existing case keeps testing what it was written to test.
        has_code: Some(true),
        exported_here: false,
    }
}

#[test]
fn an_ordinary_word_survives_where_no_import_table_was_read() {
    // The coverage hole this guards: on an ELF or Mach-O member there is no path to
    // Confidence::Import, so requiring import backing would drop every `system` hit in a
    // Linux binary, which is exactly where a real system() call lives.
    let mut o = case("system", Severity::High, Confidence::Exact, "system");
    o.member_format = Format::Elf;
    o.imports_known = false;
    let r = adjudicate(&o);
    assert!(!r.is_excluded(), "an ELF system() must not be dropped");
    assert_eq!(r.severity(), Some(Severity::High));

    // On a PE, where the import table WAS read and does not contain it, the rule fires.
    let pe = case("system", Severity::High, Confidence::Exact, "system");
    assert_eq!(
        adjudicate(&pe).exclusion_rule(),
        Some(RULE_AMBIGUOUS_NAME),
        "on a PE the absence of the import is evidence"
    );
}

#[test]
fn an_ordinary_word_inside_a_larger_token_is_never_a_call() {
    // Observed on a real bundle: `h-system` and `x-system` inside an ICU locale table, in
    // a resource-only DLL with no import table at all. The token is embedded, so no
    // import table is needed to know it is not a call.
    for text in ["h-system", "x-system"] {
        let mut o = case("system", Severity::High, Confidence::Symbolic, text);
        o.imports_known = false;
        assert_eq!(
            adjudicate(&o).exclusion_rule(),
            Some(RULE_AMBIGUOUS_NAME),
            "text was {}",
            text
        );
    }
}

#[test]
fn pointer_validation_is_its_own_rule_not_read_only() {
    let o = case(
        "IsBadWritePtr",
        Severity::High,
        Confidence::Import,
        "IsBadWritePtr",
    );
    let r = adjudicate(&o);
    assert_eq!(r.severity(), Some(Severity::Medium), "not Low");
    assert_eq!(r.adjustments()[0].rule, RULE_POINTER_VALIDATION);
}

#[test]
fn allocators_are_demoted_like_other_non_destination_calls() {
    let o = case("malloc", Severity::High, Confidence::Import, "malloc");
    let r = adjudicate(&o);
    assert_eq!(r.severity(), Some(Severity::Medium));
    assert_eq!(r.adjustments()[0].rule, RULE_ALLOCATOR);
}

// Rule 1: a wrapper is the countermeasure, not the defect.

#[test]
fn msvc_wrapper_is_not_the_crt_function() {
    for text in [
        "?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ",
        "?strncat@WRStrSafe@@SAHPEAD_KPEBD_K@Z",
        "?wcscat@WRStrSafe@@SAHPEA_W_KPEB_W@Z",
        "?wcscpy@WRStrSafe@@SAHPEA_W_KPEB_W@Z",
    ] {
        let function = text[1..].split('@').next().unwrap();
        let o = case(function, Severity::Critical, Confidence::Symbolic, text);
        let ruling = adjudicate(&o);
        assert_eq!(
            ruling.exclusion_rule(),
            Some(RULE_SYMBOL_DEFINITION),
            "{} should be excluded as a symbol definition",
            text
        );
    }
}

#[test]
fn an_import_outranks_a_mangled_name() {
    // The critical counter-example. An import is recorded by the linker; a mangled
    // wrapper that happens to share the name does not retract it.
    let text = "?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ";
    let o = case("sprintf", Severity::Critical, Confidence::Import, text);
    let ruling = adjudicate(&o);
    assert!(!ruling.is_excluded());
    assert_eq!(ruling.severity(), Some(Severity::Critical));
    assert!(ruling.adjustments().is_empty());
}

#[test]
fn opencv_member_function_is_not_gets() {
    let o = case(
        "gets",
        Severity::Critical,
        Confidence::Symbolic,
        "cv::FileStorage::Impl::gets",
    );
    let ruling = adjudicate(&o);
    assert_eq!(ruling.exclusion_rule(), Some(RULE_SYMBOL_DEFINITION));
    assert!(ruling.adjustments().is_empty());
    // The evidence has to be enough for a reviewer to agree without rerunning the scan.
    match ruling {
        Ruling::Exclude { evidence, .. } => {
            assert!(
                evidence.contains("cv::FileStorage::Impl::gets"),
                "{}",
                evidence
            );
        }
        Ruling::Keep { .. } => unreachable!("already asserted excluded"),
    }
}

#[test]
fn a_qualified_import_is_still_kept() {
    let o = case(
        "gets",
        Severity::Critical,
        Confidence::Import,
        "cv::FileStorage::Impl::gets",
    );
    assert_eq!(adjudicate(&o).severity(), Some(Severity::Critical));
}

// The baseline the whole report rests on: a real import, untouched.

#[test]
fn a_plain_import_keeps_its_severity() {
    let o = case("strcpy", Severity::Critical, Confidence::Import, "strcpy");
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Critical));
    assert!(ruling.adjustments().is_empty());
}

// Rule 2: an English word needs an import behind it.

#[test]
fn ambiguous_word_needs_an_import() {
    let o = case("system", Severity::High, Confidence::Exact, "system");
    assert_eq!(adjudicate(&o).exclusion_rule(), Some(RULE_AMBIGUOUS_NAME));

    let o = case("system", Severity::High, Confidence::Import, "system");
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::High));
    assert!(ruling.adjustments().is_empty());
}

#[test]
fn the_ambiguous_list_stays_tiny() {
    // A name that is not also a common English word must keep carrying a finding on
    // text evidence, or boundary verification was for nothing.
    for function in ["strcpy", "sprintf", "memcpy", "alloca", "popen"] {
        let o = case(function, Severity::Critical, Confidence::Exact, function);
        assert!(
            !adjudicate(&o).is_excluded(),
            "{} must not be treated as an ordinary word",
            function
        );
    }
}

// Rule 3: managed assemblies have no native call sites.

#[test]
fn managed_assembly_has_no_native_call_site() {
    let mut o = case("strcpy", Severity::Critical, Confidence::Exact, "strcpy");
    o.is_managed = true;
    assert_eq!(adjudicate(&o).exclusion_rule(), Some(RULE_MANAGED));

    o.confidence = Confidence::Import;
    let ruling = adjudicate(&o);
    assert!(!ruling.is_excluded());
    assert_eq!(ruling.severity(), Some(Severity::Critical));
}

// Rule 4 and 5: what the primitive can actually do.

#[test]
fn read_only_primitive_is_demoted_to_low() {
    let o = case("strlen", Severity::High, Confidence::Import, "strlen");
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Low));
    assert_eq!(ruling.adjustments().len(), 1);
    assert_eq!(ruling.adjustments()[0].rule, RULE_READ_ONLY);
    assert_eq!(ruling.adjustments()[0].from, Severity::High);
    assert_eq!(ruling.adjustments()[0].to, Severity::Low);
}

#[test]
fn read_only_matching_ignores_case_and_a_leading_underscore() {
    for function in ["_tcslen", "tcslen", "WCSLEN", "memcmp"] {
        let o = case(function, Severity::High, Confidence::Import, function);
        assert_eq!(
            adjudicate(&o).severity(),
            Some(Severity::Low),
            "{} should be a read-only primitive",
            function
        );
    }
}

#[test]
fn bounded_memory_primitive_is_demoted_to_medium() {
    let o = case("memcpy", Severity::High, Confidence::Import, "memcpy");
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Medium));
    assert_eq!(ruling.adjustments().len(), 1);
    assert_eq!(ruling.adjustments()[0].rule, RULE_BOUNDED_MEMORY);
}

// Rule 6: capped, not excluded.

#[test]
fn non_executable_member_caps_at_low() {
    let mut o = case("atoi", Severity::Medium, Confidence::Exact, "atoi");
    o.member_format = Format::Unknown;
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Low));
    assert_eq!(ruling.adjustments().len(), 1);
    assert_eq!(ruling.adjustments()[0].rule, RULE_NON_EXECUTABLE);
}

#[test]
fn an_import_is_never_capped_for_its_member_format() {
    // A recorded import is evidence about the image, not about the string's
    // surroundings, so the member format cannot argue it away.
    let mut o = case("strcpy", Severity::Critical, Confidence::Import, "strcpy");
    o.member_format = Format::Zip;
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Critical));
    assert!(ruling.adjustments().is_empty());
}

#[test]
fn demotions_compose_to_the_lower_of_the_two() {
    // A read-only primitive in a non-executable member: rule 4 already reached the
    // floor, so rule 6 has nothing left to move and records nothing.
    let mut o = case("strlen", Severity::High, Confidence::Exact, "strlen");
    o.member_format = Format::Unknown;
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Low));
    assert_eq!(ruling.adjustments().len(), 1);
    assert_eq!(ruling.adjustments()[0].rule, RULE_READ_ONLY);

    // A bounded primitive in a non-executable member moves twice, High to Medium to
    // Low, and both steps are recorded.
    let mut o = case("memcpy", Severity::High, Confidence::Exact, "memcpy");
    o.member_format = Format::Unknown;
    let ruling = adjudicate(&o);
    assert_eq!(ruling.severity(), Some(Severity::Low));
    let rules: Vec<&str> = ruling.adjustments().iter().map(|a| a.rule).collect();
    assert_eq!(rules, vec![RULE_BOUNDED_MEMORY, RULE_NON_EXECUTABLE]);
    assert_eq!(ruling.adjustments()[1].from, Severity::Medium);
    assert_eq!(ruling.adjustments()[1].to, Severity::Low);
}

// Order is part of the contract.

#[test]
fn symbol_definition_is_attributed_before_managed() {
    let mut o = case(
        "sprintf",
        Severity::Critical,
        Confidence::Symbolic,
        "?sprintf@WRStrSafe@@SAHPEAD_KPEBDZZ",
    );
    o.is_managed = true;
    assert_eq!(
        adjudicate(&o).exclusion_rule(),
        Some(RULE_SYMBOL_DEFINITION),
        "rule 1 runs before rule 3"
    );
}

#[test]
fn ambiguous_name_is_attributed_before_managed() {
    let mut o = case("system", Severity::High, Confidence::Exact, "system");
    o.is_managed = true;
    assert_eq!(adjudicate(&o).exclusion_rule(), Some(RULE_AMBIGUOUS_NAME));
}

#[test]
fn an_exclusion_beats_every_demotion() {
    // `free` is both an ambiguous word and nothing else; the exclusion wins outright
    // rather than producing a demoted finding.
    let o = case("free", Severity::High, Confidence::Symbolic, "x/free");
    let ruling = adjudicate(&o);
    assert!(ruling.is_excluded());
    assert!(ruling.adjustments().is_empty());
    assert_eq!(ruling.severity(), None);
}

// A demotion may never raise a severity.

#[test]
fn a_demotion_never_raises() {
    let o = case("memcpy", Severity::Low, Confidence::Import, "memcpy");
    let ruling = adjudicate(&o);
    assert_eq!(
        ruling.severity(),
        Some(Severity::Low),
        "bounded-memory-primitive must not raise Low to Medium"
    );
    assert!(ruling.adjustments().is_empty());
}

#[test]
fn cap_severity_always_picks_the_milder_value() {
    use Severity::{Critical, High, Low, Medium};
    assert_eq!(cap_severity(Critical, Low), Low);
    assert_eq!(cap_severity(Critical, Medium), Medium);
    assert_eq!(cap_severity(Low, Medium), Low);
    assert_eq!(cap_severity(Low, Critical), Low);
    assert_eq!(cap_severity(Medium, Critical), Medium);
    assert_eq!(cap_severity(High, High), High);
}

#[test]
fn snippet_truncates_on_a_character_boundary() {
    let long = "é".repeat(200);
    let cut = snippet(&long);
    assert!(cut.ends_with("..."));
    assert!(cut.len() <= 124);
    assert_eq!(snippet("short"), "short");
}

#[test]
fn rule_names_are_stable() {
    // The exclusion accounting and the report both key off these strings.
    assert_eq!(RULE_SYMBOL_DEFINITION, "symbol-definition");
    assert_eq!(RULE_AMBIGUOUS_NAME, "ambiguous-name-no-import");
    assert_eq!(RULE_MANAGED, "managed-no-native-call");
    assert_eq!(RULE_READ_ONLY, "read-only-primitive");
    assert_eq!(RULE_BOUNDED_MEMORY, "bounded-memory-primitive");
    assert_eq!(RULE_NON_EXECUTABLE, "non-executable-member");
}

#[test]
fn a_counted_string_primitive_is_demoted_to_medium() {
    // 15 of one real report's 57 criticals were `strncpy`, rated identically to `strcpy`.
    // It takes a count, so the defect is a wrong count or a missing terminator.
    let o = case("strncpy", Severity::Critical, Confidence::Import, "strncpy");
    let r = adjudicate(&o);
    assert_eq!(r.severity(), Some(Severity::Medium));
    let a = r
        .adjustments()
        .iter()
        .find(|a| a.rule == RULE_BOUNDED_STRING)
        .expect("the counted-string rule fired");
    assert_eq!(a.from, Severity::Critical);
    assert_eq!(a.to, Severity::Medium);
    // The evidence names the real failure mode rather than saying only "bounded".
    assert!(a.evidence.contains("CWE-170"), "{}", a.evidence);
}

#[test]
fn the_counted_string_rule_covers_the_whole_family_including_underscored_spellings() {
    for f in [
        "strncat",
        "wcsncpy",
        "wcsncat",
        "lstrcpynA",
        "lstrcpynW",
        "_tcsncpy",
        "_mbsnbcpy",
        "stpncpy",
    ] {
        let o = case(f, Severity::Critical, Confidence::Import, f);
        assert_eq!(
            adjudicate(&o).severity(),
            Some(Severity::Medium),
            "{} takes a count and must not rate as an unbounded write",
            f
        );
    }
}

#[test]
fn snprintf_is_not_treated_as_a_counted_string_primitive() {
    // It terminates, so its weakness is the ignored return value rather than a missing
    // NUL. Crediting it under this rule would claim a property it does not have.
    let o = case("snprintf", Severity::High, Confidence::Import, "snprintf");
    assert!(adjudicate(&o)
        .adjustments()
        .iter()
        .all(|a| a.rule != RULE_BOUNDED_STRING));
}

#[test]
fn a_member_with_no_code_cannot_call_anything() {
    // `icudt74.dll` is one 34 MiB `.rdata` section of CLDR locale data with no import
    // directory, and it drew five HIGH `system` findings. The matched strings are
    // numbering-system and calendar-system keys.
    let mut o = case("system", Severity::High, Confidence::Exact, "system");
    o.has_code = Some(false);
    // No import directory, which is why these five survived every other rule: the
    // ambiguous-word rule needs a table the name can be absent *from*, and there is none.
    o.imports_known = false;
    let r = adjudicate(&o);
    assert_eq!(r.exclusion_rule(), Some(RULE_NO_CODE_SECTION));
}

#[test]
fn an_unparsed_member_is_not_assumed_to_have_no_code() {
    // `None` is the honest answer for anything that did not parse as a PE, and a packed
    // image is exactly where a hidden `system` matters most. Only `Some(false)` excludes.
    let mut o = case("strcpy", Severity::Critical, Confidence::Exact, "strcpy");
    o.has_code = None;
    assert_eq!(adjudicate(&o).exclusion_rule(), None);
}

#[test]
fn an_import_survives_a_member_with_no_code_section() {
    // Contradictory evidence, and the import table wins because it is a linker-recorded
    // fact while the section flags are a claim about the file.
    let mut o = case("strcpy", Severity::Critical, Confidence::Import, "strcpy");
    o.has_code = Some(false);
    assert_eq!(adjudicate(&o).exclusion_rule(), None);
}

#[test]
fn the_definition_site_is_not_charged_for_what_it_exports() {
    // `vcruntime140_cor3.dll` was reported for memcpy, memmove, memset and memcmp: the C
    // runtime flagged for supplying the primitives it exists to supply.
    let mut o = case("memcpy", Severity::High, Confidence::Exact, "memcpy");
    o.exported_here = true;
    let r = adjudicate(&o);
    assert_eq!(r.exclusion_rule(), Some(RULE_DEFINITION_SITE));
}

#[test]
fn a_member_that_both_exports_and_imports_a_name_keeps_the_import_finding() {
    let mut o = case("memcpy", Severity::High, Confidence::Import, "memcpy");
    o.exported_here = true;
    assert_eq!(adjudicate(&o).exclusion_rule(), None);
}
