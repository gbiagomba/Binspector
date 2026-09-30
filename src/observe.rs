//! Progress and decision reporting for verbose mode.
//!
//! The library does not print. Every `println!` and `eprintln!` lives in `main.rs`, and the
//! scan returns its warnings in `Report.warnings`. That separation is worth keeping, so
//! verbose output is delivered as events to an observer that the binary wires to stderr.
//!
//! The point of this is auditability rather than debugging. A scan of a large bundle reports
//! thousands of members and tens of thousands of suppressed occurrences, and a reviewer
//! otherwise has to take those numbers on trust. `Event::Suppressed` names the rule that
//! fired, so the suppression count can be checked rather than believed.

use std::cell::Cell;
use std::io::Write;

use crate::container::Format;
use crate::scan::confidence::Confidence;

/// Verbosity levels, mapped from the `-v` count.
pub mod level {
    /// Phases, archives opened, totals, timing.
    pub const SUMMARY: u8 = 1;
    /// Every member, every skip, every suppression decision.
    pub const DECISIONS: u8 = 2;
    /// Per-string trace.
    pub const TRACE: u8 = 3;
}

/// Something the scan decided or discovered.
#[derive(Debug)]
pub enum Event<'a> {
    /// A named stage of the run began.
    Phase { name: &'a str },
    /// An archive was opened and yielded members.
    Container {
        chain: &'a str,
        format: Format,
        size: u64,
        depth: usize,
        members: usize,
    },
    /// A leaf was scanned.
    Member {
        chain: &'a str,
        format: Format,
        size: u64,
        depth: usize,
        strings: usize,
    },
    /// Something was not scanned, with the reason.
    Skipped { chain: &'a str, reason: &'a str },
    /// A PE parse was attempted.
    Pe {
        member: &'a str,
        parsed: bool,
        managed: bool,
        mitigations_off: usize,
    },
    /// An occurrence was recorded.
    Hit {
        function: &'a str,
        member: &'a str,
        confidence: Confidence,
    },
    /// An occurrence was excluded, with the rule that excluded it.
    Suppressed {
        function: &'a str,
        member: &'a str,
        reason: &'a str,
    },
    /// One extracted string, for the trace level.
    String {
        member: &'a str,
        offset: u64,
        hits: usize,
        text: &'a str,
    },
    /// A phase completed.
    Timing { phase: &'a str, ms: u128 },
    /// A note about verbose output itself, such as a volume guard.
    Notice { message: &'a str },
}

impl Event<'_> {
    /// The lowest verbosity level at which this event should be shown.
    pub fn min_level(&self) -> u8 {
        match self {
            Event::Phase { .. }
            | Event::Container { .. }
            | Event::Timing { .. }
            | Event::Notice { .. } => level::SUMMARY,
            Event::Member { .. }
            | Event::Skipped { .. }
            | Event::Pe { .. }
            | Event::Hit { .. }
            | Event::Suppressed { .. } => level::DECISIONS,
            Event::String { .. } => level::TRACE,
        }
    }
}

pub trait Observer {
    fn on(&self, event: &Event);

    /// Whether anything at `level` would be emitted. Lets a caller skip building an event
    /// whose fields cost something to assemble.
    fn wants(&self, _level: u8) -> bool {
        true
    }
}

/// The default. Does nothing, so the non-verbose path is unchanged.
pub struct Null;

impl Observer for Null {
    fn on(&self, _event: &Event) {}
    fn wants(&self, _level: u8) -> bool {
        false
    }
}

/// Writes to stderr, so stdout stays clean for the report.
pub struct Stderr {
    level: u8,
    /// Counts trace events so the volume guard fires once rather than per string.
    traced: Cell<u64>,
    guard_at: u64,
    guard_fired: Cell<bool>,
}

impl Stderr {
    pub fn new(level: u8) -> Self {
        Self {
            level,
            traced: Cell::new(0),
            guard_at: 100_000,
            guard_fired: Cell::new(false),
        }
    }

    pub fn level(&self) -> u8 {
        self.level
    }

    fn emit(&self, s: &str) {
        // A failed write to stderr must not take the scan down with it.
        let _ = writeln!(std::io::stderr(), "{}", s);
    }
}

impl Observer for Stderr {
    fn wants(&self, level: u8) -> bool {
        self.level >= level
    }

    fn on(&self, event: &Event) {
        if self.level < event.min_level() {
            return;
        }
        match event {
            Event::Phase { name } => self.emit(&format!("== {}", name)),
            Event::Container {
                chain,
                format,
                size,
                depth,
                members,
            } => self.emit(&format!(
                "[{}] open  {:<7} {:>10} bytes  {} member(s)  {}",
                depth,
                format.as_str(),
                size,
                members,
                chain
            )),
            Event::Member {
                chain,
                format,
                size,
                depth,
                strings,
            } => self.emit(&format!(
                "[{}] scan  {:<7} {:>10} bytes  {:>8} string(s)  {}",
                depth,
                format.as_str(),
                size,
                strings,
                chain
            )),
            Event::Skipped { chain, reason } => {
                self.emit(&format!("     skip  {}: {}", chain, reason))
            }
            Event::Pe {
                member,
                parsed,
                managed,
                mitigations_off,
            } => {
                if *parsed {
                    self.emit(&format!(
                        "     pe    {}{}, {} mitigation(s) off",
                        member,
                        if *managed { " (managed)" } else { "" },
                        mitigations_off
                    ))
                } else {
                    self.emit(&format!("     pe    {}: not parseable", member))
                }
            }
            Event::Hit {
                function,
                member,
                confidence,
            } => self.emit(&format!(
                "     hit   {:<24} {:<9} {}",
                function,
                confidence.as_str(),
                member
            )),
            Event::Suppressed {
                function,
                member,
                reason,
            } => self.emit(&format!(
                "     drop  {:<24} {:<9} {}",
                function, reason, member
            )),
            Event::String {
                member,
                offset,
                hits,
                text,
            } => {
                let n = self.traced.get() + 1;
                self.traced.set(n);
                if n > self.guard_at {
                    if !self.guard_fired.get() {
                        self.guard_fired.set(true);
                        self.emit(&format!(
                            "== trace suppressed after {} strings. Narrow the scan with \
                             --banned-filter or a larger --min-len, or raise the volume you \
                             are willing to read.",
                            self.guard_at
                        ));
                    }
                    return;
                }
                self.emit(&format!(
                    "     str   0x{:<10x} {:>2} hit(s)  {}  {}",
                    offset, hits, member, text
                ))
            }
            Event::Timing { phase, ms } => self.emit(&format!("== {} took {} ms", phase, ms)),
            Event::Notice { message } => self.emit(&format!("== {}", message)),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::cell::RefCell;

    /// Records events as strings, for asserting on sequence and content.
    pub struct Recorder {
        pub level: u8,
        pub events: RefCell<Vec<String>>,
    }

    impl Recorder {
        pub fn new(level: u8) -> Self {
            Self {
                level,
                events: RefCell::new(Vec::new()),
            }
        }

        pub fn kinds(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    impl Observer for Recorder {
        fn wants(&self, level: u8) -> bool {
            self.level >= level
        }

        fn on(&self, event: &Event) {
            if self.level < event.min_level() {
                return;
            }
            let s = match event {
                Event::Phase { name } => format!("phase:{}", name),
                Event::Container { chain, members, .. } => {
                    format!("container:{}:{}", chain, members)
                }
                Event::Member { chain, strings, .. } => format!("member:{}:{}", chain, strings),
                Event::Skipped { chain, reason } => format!("skip:{}:{}", chain, reason),
                Event::Pe { member, parsed, .. } => format!("pe:{}:{}", member, parsed),
                Event::Hit {
                    function,
                    confidence,
                    ..
                } => format!("hit:{}:{}", function, confidence.as_str()),
                Event::Suppressed {
                    function, reason, ..
                } => format!("drop:{}:{}", function, reason),
                Event::String { offset, hits, .. } => format!("str:{}:{}", offset, hits),
                Event::Timing { phase, .. } => format!("timing:{}", phase),
                Event::Notice { .. } => "notice".to_string(),
            };
            self.events.borrow_mut().push(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Recorder;
    use super::*;

    #[test]
    fn null_observer_wants_nothing() {
        let n = Null;
        assert!(!n.wants(level::SUMMARY));
        assert!(!n.wants(level::TRACE));
        // And accepts events without panicking.
        n.on(&Event::Phase { name: "x" });
    }

    #[test]
    fn min_level_places_each_event() {
        assert_eq!(Event::Phase { name: "p" }.min_level(), level::SUMMARY);
        assert_eq!(
            Event::Skipped {
                chain: "c",
                reason: "r"
            }
            .min_level(),
            level::DECISIONS
        );
        assert_eq!(
            Event::String {
                member: "m",
                offset: 0,
                hits: 0,
                text: "t"
            }
            .min_level(),
            level::TRACE
        );
    }

    #[test]
    fn level_one_shows_phases_but_not_members() {
        let r = Recorder::new(level::SUMMARY);
        r.on(&Event::Phase { name: "unpack" });
        r.on(&Event::Member {
            chain: "a",
            format: Format::Pe,
            size: 1,
            depth: 0,
            strings: 2,
        });
        assert_eq!(r.kinds(), vec!["phase:unpack"]);
    }

    #[test]
    fn level_two_adds_members_and_suppressions() {
        let r = Recorder::new(level::DECISIONS);
        r.on(&Event::Member {
            chain: "a",
            format: Format::Pe,
            size: 1,
            depth: 0,
            strings: 2,
        });
        r.on(&Event::Suppressed {
            function: "system",
            member: "a",
            reason: "prose",
        });
        r.on(&Event::String {
            member: "a",
            offset: 0,
            hits: 0,
            text: "t",
        });
        // Members and drops appear; the per-string trace does not.
        assert_eq!(r.kinds(), vec!["member:a:2", "drop:system:prose"]);
    }

    #[test]
    fn level_three_adds_the_string_trace() {
        let r = Recorder::new(level::TRACE);
        r.on(&Event::String {
            member: "a",
            offset: 16,
            hits: 1,
            text: "gets",
        });
        assert_eq!(r.kinds(), vec!["str:16:1"]);
    }

    #[test]
    fn wants_reflects_the_level() {
        let r = Recorder::new(level::DECISIONS);
        assert!(r.wants(level::SUMMARY));
        assert!(r.wants(level::DECISIONS));
        assert!(!r.wants(level::TRACE));
    }

    #[test]
    fn stderr_observer_reports_its_level() {
        let s = Stderr::new(2);
        assert_eq!(s.level(), 2);
        assert!(s.wants(level::DECISIONS));
        assert!(!s.wants(level::TRACE));
    }

    #[test]
    fn trace_guard_fires_once_and_then_stays_quiet() {
        // A low guard makes the behaviour observable without emitting 100k lines.
        let s = Stderr {
            level: level::TRACE,
            traced: Cell::new(0),
            guard_at: 2,
            guard_fired: Cell::new(false),
        };
        for _ in 0..10 {
            s.on(&Event::String {
                member: "m",
                offset: 0,
                hits: 0,
                text: "x",
            });
        }
        assert!(s.guard_fired.get(), "guard never fired");
        assert_eq!(s.traced.get(), 10, "every string should still be counted");
    }
}
