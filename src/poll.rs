//! Deadlines for waiting on asynchronous Kibana work, such as Fleet actions.
//!
//! The deadline bounds the whole wait, including each observation's requests
//! and body reads: an observation still running at the deadline is abandoned,
//! and no observation starts at or after it. A zero timeout therefore returns
//! [`WaitOutcome::TimedOut`] without sending a request. A state observed before
//! the deadline is reported even if the deadline passes while it is evaluated.
//!
//! Waiting never retries a failed request: the first error is returned. Dropping
//! the future cancels the wait.
use std::{future::Future, time::Duration};

use tokio::time::{Instant, sleep_until, timeout_at};

use crate::Result;

/// How long to wait and how often to check.
#[derive(Clone, Copy, Debug)]
pub struct PollOptions {
    timeout: Duration,
    interval: Duration,
}

impl PollOptions {
    /// Checks every two seconds until `timeout` has passed.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            interval: Duration::from_secs(2),
        }
    }

    /// The pause between the end of one observation and the start of the next.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }
}

impl Default for PollOptions {
    /// Three minutes, checking every two seconds.
    fn default() -> Self {
        Self::new(Duration::from_secs(180))
    }
}

/// The result of waiting. A finished state can still describe a failure, such
/// as an action where some agents failed; inspect it.
#[derive(Clone, Debug)]
#[must_use]
#[non_exhaustive]
pub enum WaitOutcome<T> {
    Finished(T),
    /// The deadline passed. `last` is the most recent state observed, if any.
    TimedOut {
        last: Option<T>,
    },
    /// The resource was observed and then could no longer be found, for
    /// example because it was deleted or fell outside the searched window.
    /// `last` is the final state observed.
    Vanished {
        last: T,
    },
}

impl<T> WaitOutcome<T> {
    /// Returns the state only for [`Self::Finished`]. This says that waiting ended,
    /// not that the operation succeeded. Use [`Self::last`] to inspect a state
    /// retained after a timeout or disappearance.
    pub fn finished(self) -> Option<T> {
        match self {
            Self::Finished(value) => Some(value),
            Self::TimedOut { .. } | Self::Vanished { .. } => None,
        }
    }

    /// The most recent state observed, whatever the outcome.
    pub fn last(&self) -> Option<&T> {
        match self {
            Self::Finished(value) | Self::Vanished { last: value } => Some(value),
            Self::TimedOut { last } => last.as_ref(),
        }
    }
}

/// Calls `observe` until it reports a state accepted by `finished` or the deadline passes.
/// `observe` returns `None` while the resource is not visible. A resource that
/// is not visible after having been observed ends the wait as vanished.
pub(crate) async fn wait<T, F, Fut>(
    options: PollOptions,
    mut observe: F,
    finished: impl Fn(&T) -> bool,
) -> Result<WaitOutcome<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let deadline = Instant::now() + options.timeout;
    let mut last = None;
    loop {
        if Instant::now() >= deadline {
            return Ok(WaitOutcome::TimedOut { last });
        }
        let Ok(observed) = timeout_at(deadline, observe()).await else {
            return Ok(WaitOutcome::TimedOut { last });
        };
        match (observed?, last) {
            (Some(state), _) if finished(&state) => return Ok(WaitOutcome::Finished(state)),
            (Some(state), _) => last = Some(state),
            (None, Some(previous)) => return Ok(WaitOutcome::Vanished { last: previous }),
            (None, None) => last = None,
        }
        sleep_until(deadline.min(Instant::now() + options.interval)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
    };

    use tokio::time::sleep;

    use super::*;

    fn options(timeout: u64, interval: u64) -> PollOptions {
        PollOptions::new(Duration::from_millis(timeout)).interval(Duration::from_millis(interval))
    }

    /// Replays scripted observations, each after a delay, counting how many started.
    struct Script {
        steps: RefCell<VecDeque<(u64, Option<&'static str>)>>,
        started: Cell<usize>,
    }

    impl Script {
        fn new(steps: &[(u64, Option<&'static str>)]) -> Self {
            Self {
                steps: RefCell::new(steps.iter().copied().collect()),
                started: Cell::new(0),
            }
        }

        async fn observe(&self) -> Result<Option<&'static str>> {
            self.started.set(self.started.get() + 1);
            let (delay, state) = self.steps.borrow_mut().pop_front().unwrap_or((0, None));
            sleep(Duration::from_millis(delay)).await;
            Ok(state)
        }
    }

    fn done(state: &&str) -> bool {
        *state == "done"
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_observation_is_bounded_by_the_deadline() {
        let script = Script::new(&[(0, Some("running")), (10_000, Some("done"))]);
        let started = Instant::now();
        let outcome = wait(options(100, 10), || script.observe(), done)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                WaitOutcome::TimedOut {
                    last: Some("running")
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(started.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_state_arriving_after_the_deadline_is_not_reported() {
        let script = Script::new(&[(150, Some("done"))]);
        let outcome = wait(options(10, 10), || script.observe(), done)
            .await
            .unwrap();
        assert!(
            matches!(outcome, WaitOutcome::TimedOut { last: None }),
            "{outcome:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_observation_starts_at_or_after_the_deadline() {
        let script = Script::new(&[(0, Some("running")); 10]);
        let outcome = wait(options(100, 100), || script.observe(), done)
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            WaitOutcome::TimedOut {
                last: Some("running")
            }
        ));
        assert_eq!(script.started.get(), 1, "the sleep ends at the deadline");

        let script = Script::new(&[(0, Some("done"))]);
        let outcome = wait(options(0, 10), || script.observe(), done)
            .await
            .unwrap();
        assert!(matches!(outcome, WaitOutcome::TimedOut { last: None }));
        assert_eq!(script.started.get(), 0, "a zero timeout sends nothing");
    }

    #[tokio::test(start_paused = true)]
    async fn a_state_that_disappears_after_being_seen_has_vanished() {
        let script = Script::new(&[(0, None), (0, Some("running")), (0, None)]);
        let outcome = wait(options(1_000, 10), || script.observe(), done)
            .await
            .unwrap();
        assert!(
            matches!(outcome, WaitOutcome::Vanished { last: "running" }),
            "{outcome:?}"
        );
        assert_eq!(outcome.last(), Some(&"running"));
        assert!(outcome.finished().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn finishing_within_the_deadline_wins_and_errors_end_the_wait() {
        let script = Script::new(&[(0, Some("running")), (90, Some("done"))]);
        let outcome = wait(options(100, 10), || script.observe(), done)
            .await
            .unwrap();
        assert_eq!(outcome.finished(), Some("done"));

        let error = wait(
            options(100, 10),
            || async { Err::<Option<()>, _>(crate::Error::InvalidRequest("boom".into())) },
            |()| false,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, crate::Error::InvalidRequest(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_the_wait_cancels_the_running_observation() {
        let script = Script::new(&[(10_000, Some("done"))]);
        let wait = wait(options(60_000, 10), || script.observe(), done);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wait)
                .await
                .is_err()
        );
        assert_eq!(script.started.get(), 1);
    }
}
