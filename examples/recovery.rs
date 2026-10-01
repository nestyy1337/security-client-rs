//! Handling errors: retrying reads, resolving version conflicts and reconciling
//! a mutation whose outcome is unknown. The client never retries by itself.
use std::time::Duration;

use kibana_rs::{
    Error, Kibana, Result,
    cases::{CasePatch, CaseStatus},
    http::{Credentials, StatusCode, TransportBuilder, Url},
    security::{DetectionRule, QueryRule, RuleSelector},
};

#[derive(Debug, thiserror::Error)]
enum RetryError {
    #[error("read retry deadline expired")]
    Deadline,
    #[error(transparent)]
    Request(#[from] Error),
}

/// Retries a read on 429, 502, 503 and transport failures, honoring
/// `Retry-After` and giving up at an overall deadline. Only use this for
/// requests that are safe to repeat. Deadline exhaustion is returned separately
/// from the last request error.
async fn retry_read<T, F, Fut>(
    deadline: Duration,
    mut read: F,
) -> std::result::Result<T, RetryError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let give_up = tokio::time::Instant::now() + deadline;
    tokio::time::timeout_at(give_up, async {
        let mut backoff = Duration::from_millis(500);
        loop {
            if tokio::time::Instant::now() >= give_up {
                return Err(RetryError::Deadline);
            }
            let result = read().await;
            if tokio::time::Instant::now() >= give_up {
                return Err(RetryError::Deadline);
            }
            let error = match result {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            let transient = matches!(
                error.status(),
                Some(
                    StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                )
            ) || matches!(error, Error::Transport(_) | Error::Body { .. });
            let wait = error.retry_after().unwrap_or(backoff);
            if !transient {
                return Err(error.into());
            }
            tokio::time::sleep(wait).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    })
    .await
    .unwrap_or(Err(RetryError::Deadline))
}

/// A timeout while sending the request or reading the response leaves the
/// outcome unknown, and a retry after a lost response fails with 409 because
/// the rule exists. Either way the stable `rule_id` lets the caller read back
/// instead of creating a duplicate. The whole send-and-decode operation is
/// checked, since the body can fail after Kibana has answered, including when
/// it exceeds the configured size limit. Read-back uses the same limit and
/// can fail too; recovery does not automatically raise it.
async fn create_or_find(client: &Kibana, rule: &QueryRule, rule_id: &str) -> Result<DetectionRule> {
    let created = async {
        client
            .security()
            .create_rule(rule)
            .send()
            .await?
            .json()
            .await
    }
    .await;
    match created {
        Ok(rule) => Ok(rule),
        Err(error)
            if matches!(
                error,
                Error::Transport(_)
                    | Error::Body { .. }
                    | Error::Decode { .. }
                    | Error::ResponseTooLarge { .. }
            ) || error.status() == Some(StatusCode::CONFLICT) =>
        {
            // A successful status that arrived before the failure shows Kibana
            // accepted the request, not that the rule is as requested.
            if let Some(status) = error.status().filter(StatusCode::is_success) {
                eprintln!("Kibana answered {status} before the failure; reading the rule back");
            }
            client
                .security()
                .get_rule(RuleSelector::RuleId(rule_id))
                .send()
                .await?
                .json()
                .await
        }
        Err(error) => Err(error),
    }
}

/// On HTTP 409 the case changed since it was read: read it again and reapply.
async fn close_case(client: &Kibana, case_id: &str) -> Result<()> {
    for _ in 0..3 {
        let case = client.cases().get(case_id).send().await?.json().await?;
        let patch = CasePatch::new(&case.id, &case.version).status(CaseStatus::Closed);
        match client.cases().update([patch]).send().await {
            Err(error) if error.status() == Some(StatusCode::CONFLICT) => {}
            other => return other.map(|_| ()),
        }
    }
    Err(Error::InvalidRequest(
        "case kept changing; giving up".into(),
    ))
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let transport = TransportBuilder::new(Url::parse(&std::env::var("KIBANA_URL")?)?)
        .auth(Credentials::EncodedApiKey(std::env::var("KIBANA_API_KEY")?))
        .build()?;
    let client =
        Kibana::new(transport).space(std::env::var("KIBANA_SPACE").unwrap_or("default".into()))?;

    let status = retry_read(Duration::from_secs(60), || async {
        client.status().send().await?.json().await
    })
    .await?;
    println!("Kibana {}", status["version"]["number"]);

    let rule = QueryRule::new(
        "Recovery example",
        "Safe to delete",
        "event.outcome: failure",
    )
    .rule_id("recovery-example");
    let created = create_or_find(&client, &rule, "recovery-example").await?;
    println!("rule {} exists", created.rule_id);
    client
        .security()
        .delete_rule(RuleSelector::RuleId("recovery-example"))
        .send()
        .await?;

    if let Ok(case_id) = std::env::var("KIBANA_CASE_ID") {
        close_case(&client, &case_id).await?;
    }

    match client.cases().get("does-not-exist").send().await {
        Err(error) => println!("{error}: {}", error.message().unwrap_or_default()),
        Ok(_) => println!("unexpectedly found a case"),
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(test)]
mod tests {
    use super::*;
    use common::Mock;
    use serde_json::json;

    #[tokio::test]
    async fn oversized_creation_responses_are_reconciled_without_repeating_the_write() {
        let found = json!({
            "id": "saved-rule", "rule_id": "recovery-example", "name": "Recovery example",
            "description": "Safe to delete", "enabled": false, "severity": "low",
            "risk_score": 21, "type": "query",
        });
        let limit = found.to_string().len();
        let mut oversized = found.clone();
        oversized["extra_setting"] = json!("x".repeat(limit));
        let rule = QueryRule::new(
            "Recovery example",
            "Safe to delete",
            "event.outcome: failure",
        )
        .rule_id("recovery-example");

        for oversized_readback in [false, true] {
            let mock = Mock::start().await;
            let client = Kibana::new(
                TransportBuilder::new(Url::parse(&mock.url).unwrap())
                    .response_limit(limit)
                    .build()
                    .unwrap(),
            );
            mock.reply(201, oversized.to_string());
            mock.json(if oversized_readback {
                oversized.clone()
            } else {
                found.clone()
            });

            let result = create_or_find(&client, &rule, "recovery-example").await;
            if oversized_readback {
                assert!(matches!(
                    result,
                    Err(Error::ResponseTooLarge { status: StatusCode::OK, limit: actual, .. })
                        if actual == limit
                ));
            } else {
                let recovered = result.unwrap();
                assert_eq!(recovered.id, "saved-rule");
                assert_eq!(recovered.rule_id, "recovery-example");
            }
            assert_eq!(mock.request_count(), 2);
            mock.take()
                .route("POST", "/api/detection_engine/rules", &[]);
            mock.take().route(
                "GET",
                "/api/detection_engine/rules",
                &[("rule_id", "recovery-example")],
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retry_deadline_cancels_a_slow_success() {
        for delay in [Duration::from_millis(5), Duration::from_millis(100)] {
            let result = retry_read(Duration::from_millis(5), || async {
                tokio::time::sleep(delay).await;
                Ok(())
            })
            .await;
            assert!(
                matches!(result, Err(RetryError::Deadline)),
                "a read completed after its deadline"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn no_read_starts_at_or_after_the_retry_deadline() {
        for budget in [Duration::ZERO, Duration::from_millis(500)] {
            let attempts = std::cell::Cell::new(0);
            let result = retry_read(budget, || {
                attempts.set(attempts.get() + 1);
                let attempt = attempts.get();
                async move {
                    if attempt == 1 {
                        Err(reqwest::Client::new()
                            .get("invalid URL")
                            .build()
                            .unwrap_err()
                            .into())
                    } else {
                        Ok(())
                    }
                }
            })
            .await;
            assert!(
                matches!(result, Err(RetryError::Deadline)),
                "a retry succeeded after its deadline"
            );
            assert_eq!(attempts.get(), usize::from(!budget.is_zero()));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn successful_reads_and_permanent_errors_finish_before_the_deadline() {
        assert_eq!(
            retry_read(Duration::from_secs(1), || async { Ok(42) })
                .await
                .unwrap(),
            42
        );
        let error = retry_read::<(), _, _>(Duration::from_secs(1), || async {
            Err(Error::InvalidRequest("permanent".into()))
        })
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            RetryError::Request(Error::InvalidRequest(_))
        ));
    }
}
