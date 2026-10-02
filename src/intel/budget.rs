//! Pacing and a request ceiling for the network lookups.
//!
//! **Why this exists.** Until 6.0.0 there was no pacing, no ceiling and no backoff anywhere:
//! `http::get` issues a request the moment it is called, and `cve.rs` looped over every detected
//! component back to back. That was survivable while a scan made one reputation request and a
//! handful of CVE queries. A member sweep asks about thousands of hashes, and a service that
//! publishes 4 requests per minute will answer the first four and rate-limit the rest, so an
//! unpaced sweep produces a page of errors rather than answers.
//!
//! **A ceiling, not just a rate.** Pacing alone would still consume a daily quota, slowly. The
//! ceiling is what stops a single scan spending a day's allowance without being asked, and the
//! count of what it skipped is reported rather than dropped: an unchecked member is never rendered
//! as clean, which is the habit `excluded_by_rule` and the indicator drop counters already follow.
//!
//! **On `Retry-After`, which this deliberately does not read.** A 429 carries the header, and
//! honouring it would be better than guessing. Reading it through this transport needs curl's
//! `%header{}` write-out, added in curl 7.83, and an older system curl fails the whole request with
//! `unknown --write-out variable` rather than just omitting the field. Trading a working lookup on
//! an older system for a better backoff on a newer one is the wrong way round, so a 429 backs off
//! on a fixed schedule instead. Pacing makes a 429 the exception rather than the rule, which is
//! what makes that acceptable.

use std::time::Duration;

/// Requests per minute a free tier typically allows, and the threshold at which this warns.
///
/// VirusTotal publishes 4 per minute and 500 per day for its public API. A configured rate at or
/// below this is taken as a sign that the key is a public one, which matters for more than pacing:
/// see [`Budget::tier_note`].
pub const FREE_TIER_PER_MINUTE: u32 = 4;

/// What a sweep is allowed to spend, and what it spent.
///
/// Not `Clone`: a budget is a single authority over a quota, and two copies would each believe they
/// had the whole allowance.
pub struct Budget {
    per_minute: u32,
    ceiling: usize,
    spent: usize,
    skipped: usize,
    /// Injected so a test can assert pacing without waiting for it.
    sleeper: fn(Duration),
}

fn real_sleep(d: Duration) {
    std::thread::sleep(d);
}

/// A no-op sleeper, for tests and for a dry run.
pub fn no_sleep(_d: Duration) {}

impl Budget {
    /// `per_minute` of 0 means no pacing. `ceiling` of 0 means no requests are allowed at all,
    /// which is how a caller expresses "report what you would have asked" without asking.
    pub fn new(per_minute: u32, ceiling: usize) -> Self {
        Self {
            per_minute,
            ceiling,
            spent: 0,
            skipped: 0,
            sleeper: real_sleep,
        }
    }

    /// As [`new`], without ever sleeping. For tests, and for counting what a sweep would cost.
    pub fn dry(per_minute: u32, ceiling: usize) -> Self {
        let mut b = Self::new(per_minute, ceiling);
        b.sleeper = no_sleep;
        b
    }

    /// Claim one request, pacing first.
    ///
    /// `false` means the ceiling is reached and the caller must not issue the request. The refusal
    /// is counted, so the report can say how much went unchecked.
    pub fn claim(&mut self) -> bool {
        if self.spent >= self.ceiling {
            self.skipped += 1;
            return false;
        }
        // Paced before the request rather than after, so the first one is immediate and the gap
        // falls between requests where it belongs.
        if self.spent > 0 && self.per_minute > 0 {
            (self.sleeper)(Duration::from_millis(
                60_000 / u64::from(self.per_minute).max(1),
            ));
        }
        self.spent += 1;
        true
    }

    /// Back off after a rate-limit response, and say whether retrying is still within budget.
    ///
    /// A full minute, because every service this talks to publishes its limit per minute: a shorter
    /// wait would be another 429 and a longer one is pure delay. `attempt` is 1-based.
    pub fn rate_limited(&mut self, attempt: u32) -> bool {
        const MAX_ATTEMPTS: u32 = 3;
        if attempt >= MAX_ATTEMPTS {
            return false;
        }
        (self.sleeper)(Duration::from_secs(60 * u64::from(attempt)));
        true
    }

    /// Count a request the caller decided not to make, such as one answered from the cache.
    ///
    /// Deliberately separate from a ceiling refusal: a cache hit is an answer, and counting it as
    /// unchecked would understate coverage.
    pub fn note_skipped(&mut self) {
        self.skipped += 1;
    }

    pub fn spent(&self) -> usize {
        self.spent
    }

    pub fn skipped(&self) -> usize {
        self.skipped
    }

    pub fn exhausted(&self) -> bool {
        self.spent >= self.ceiling
    }

    /// The terms warning, when the configured rate suggests a public key.
    ///
    /// `None` when it does not. Stated once per run rather than per request, and it continues rather
    /// than refusing, because whether a given use is within a service's terms is the operator's
    /// judgement and not something a scanner can determine.
    pub fn tier_note(&self) -> Option<&'static str> {
        if self.per_minute > 0 && self.per_minute <= FREE_TIER_PER_MINUTE {
            Some(
                "the configured request rate matches a free API tier. VirusTotal's public API \
                 documentation states it must not be used in business workflows that do not \
                 contribute new files, and binspector never uploads file content by design, so a \
                 bulk lookup on a public key may fall outside those terms. A paid or enterprise \
                 key carries no such restriction.",
            )
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_stops_spending_and_counts_the_refusals() {
        let mut b = Budget::dry(0, 3);
        for _ in 0..3 {
            assert!(b.claim(), "within the ceiling");
        }
        assert!(b.exhausted());
        for _ in 0..5 {
            assert!(!b.claim(), "past the ceiling");
        }
        assert_eq!(b.spent(), 3);
        assert_eq!(b.skipped(), 5, "every refusal is counted, not dropped");
    }

    #[test]
    fn a_ceiling_of_zero_allows_nothing() {
        // How a caller asks what a sweep would cost without making a single request.
        let mut b = Budget::dry(0, 0);
        assert!(!b.claim());
        assert_eq!(b.spent(), 0);
        assert_eq!(b.skipped(), 1);
    }

    #[test]
    fn pacing_falls_between_requests_not_before_the_first() {
        // Recorded through a sleeper that counts instead of sleeping, so the property is asserted
        // rather than timed.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SLEEPS: AtomicUsize = AtomicUsize::new(0);
        fn counting(_d: Duration) {
            SLEEPS.fetch_add(1, Ordering::SeqCst);
        }
        SLEEPS.store(0, Ordering::SeqCst);
        let mut b = Budget::new(4, 10);
        b.sleeper = counting;
        assert!(b.claim());
        assert_eq!(SLEEPS.load(Ordering::SeqCst), 0, "the first is immediate");
        assert!(b.claim());
        assert!(b.claim());
        assert_eq!(
            SLEEPS.load(Ordering::SeqCst),
            2,
            "one gap between each pair"
        );
    }

    #[test]
    fn no_pacing_is_configurable_for_a_key_with_no_published_rate() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static SLEEPS: AtomicUsize = AtomicUsize::new(0);
        fn counting(_d: Duration) {
            SLEEPS.fetch_add(1, Ordering::SeqCst);
        }
        SLEEPS.store(0, Ordering::SeqCst);
        let mut b = Budget::new(0, 10);
        b.sleeper = counting;
        for _ in 0..4 {
            assert!(b.claim());
        }
        assert_eq!(SLEEPS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_rate_limit_retries_a_bounded_number_of_times() {
        let mut b = Budget::dry(4, 100);
        assert!(b.rate_limited(1), "first 429 is worth retrying");
        assert!(b.rate_limited(2));
        assert!(!b.rate_limited(3), "three attempts is enough");
        assert!(!b.rate_limited(9));
    }

    #[test]
    fn a_cache_hit_is_not_counted_as_unchecked() {
        // A cache hit is an answer. Counting it as a refusal would understate coverage and make a
        // second run of the same package look worse than the first.
        let mut b = Budget::dry(0, 10);
        b.note_skipped();
        assert_eq!(b.spent(), 0);
        assert_eq!(b.skipped(), 1);
        // And the ceiling is untouched by it.
        assert!(!b.exhausted());
    }

    #[test]
    fn a_free_tier_rate_carries_the_terms_note_and_a_paid_one_does_not() {
        assert!(Budget::dry(4, 500).tier_note().is_some());
        assert!(Budget::dry(1, 500).tier_note().is_some());
        assert!(Budget::dry(60, 100_000).tier_note().is_none());
        // Unpaced means the operator told us the rate does not apply, so there is nothing to infer.
        assert!(Budget::dry(0, 100).tier_note().is_none());
        let note = Budget::dry(4, 500).tier_note().unwrap();
        assert!(note.contains("must not be used in business workflows"));
        assert!(note.contains("never uploads"));
    }
}
