//! Deadlines for waiting on asynchronous Kibana work, such as Fleet actions.
//!
//! Waiting never retries a failed request: the first error is returned. Dropping
//! the future cancels the wait.
use std::{future::Future, time::Duration};

use tokio::time::{Instant, sleep};

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
    loop {
        let last = match observe().await? {
            Some(state) if finished(&state) => return Ok(WaitOutcome::Finished(state)),
            last => last,
        };
        let now = Instant::now();
        if now >= deadline {
            return Ok(WaitOutcome::TimedOut { last });
        }
        sleep(options.interval.min(deadline - now)).await;
    }
}
