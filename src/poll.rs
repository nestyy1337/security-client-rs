//! Deadlines for waiting on asynchronous Kibana work, such as Fleet actions.
//!
//! Waiting never retries a failed request: the first error is returned. Dropping
//! the future cancels the wait.
use std::{future::Future, time::Duration};

use tokio::time::{Instant, sleep, timeout_at};

use crate::Result;

/// How long to wait and how often to check.
#[derive(Clone, Copy, Debug)]
pub struct PollOptions {
    timeout: Duration,
    interval: Duration,
}

impl PollOptions {
    /// Checks every two seconds until `timeout` has passed, including in-flight requests.
    /// A zero timeout returns immediately without sending a request.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            interval: Duration::from_secs(2),
        }
    }

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
pub enum WaitOutcome<T> {
    Finished(T),
    /// The deadline passed. `last` is the most recent state observed, if any.
    TimedOut {
        last: Option<T>,
    },
}

impl<T> WaitOutcome<T> {
    pub fn finished(self) -> Option<T> {
        match self {
            Self::Finished(value) => Some(value),
            Self::TimedOut { .. } => None,
        }
    }
}

/// Calls `observe` until it reports a state accepted by `finished` or the deadline passes.
/// `observe` returns `None` while the resource is not visible yet.
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
        let observed = match timeout_at(deadline, observe()).await {
            Ok(result) => result?,
            Err(_) => return Ok(WaitOutcome::TimedOut { last }),
        };
        if let Some(state) = observed {
            if Instant::now() < deadline && finished(&state) {
                return Ok(WaitOutcome::Finished(state));
            }
            last = Some(state);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(WaitOutcome::TimedOut { last });
        }
        sleep(options.interval.min(deadline - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn slow_observations_cannot_finish_after_the_deadline() {
        let start = Instant::now();
        let timeout = Duration::from_millis(20);
        let outcome = wait(
            PollOptions::new(timeout),
            || async {
                sleep(Duration::from_millis(150)).await;
                Ok(Some(1))
            },
            |_| true,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, WaitOutcome::TimedOut { last: None }));
        assert_eq!(start.elapsed(), timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_observations_keep_the_last_state_and_stop_at_the_deadline() {
        let calls = Cell::new(0);
        let outcome = wait(
            PollOptions::new(Duration::from_millis(25)).interval(Duration::from_millis(10)),
            || {
                let call = calls.get();
                calls.set(call + 1);
                std::future::ready(Ok((call == 0).then_some(7)))
            },
            |_| false,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, WaitOutcome::TimedOut { last: Some(7) }));
        assert_eq!(calls.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_deadline_does_not_start_an_observation() {
        let outcome = wait::<(), _, _>(
            PollOptions::new(Duration::ZERO),
            || async { panic!("an expired wait must not send a request") },
            |_| true,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, WaitOutcome::TimedOut { last: None }));
    }
}
