//! Handling errors: retrying reads, resolving version conflicts and reconciling
//! a mutation whose outcome is unknown. The client never retries by itself.
use std::time::{Duration, Instant};

use kibana_rs::{
    Error, Kibana, Result,
    cases::{CasePatch, CaseStatus},
    http::{Credentials, StatusCode, TransportBuilder, Url},
    security::{DetectionRule, QueryRule, RuleSelector},
};

/// Retries a read on 429, 502, 503 and transport failures, honoring
/// `Retry-After` and giving up at an overall deadline. Only use this for
/// requests that are safe to repeat.
async fn retry_read<T, F, Fut>(deadline: Duration, mut read: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let give_up = Instant::now() + deadline;
    let mut backoff = Duration::from_millis(500);
    loop {
        let error = match read().await {
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
        ) || matches!(error, Error::Transport(_));
        let wait = error.retry_after().unwrap_or(backoff);
        if !transient || Instant::now() + wait > give_up {
            return Err(error);
        }
        tokio::time::sleep(wait).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// A timeout on create leaves the outcome unknown, and a retry after a lost
/// response fails with 409 because the rule exists. Either way the stable
/// `rule_id` lets the caller read back instead of creating a duplicate.
async fn create_or_find(client: &Kibana, rule: &QueryRule, rule_id: &str) -> Result<DetectionRule> {
    match client.security().create_rule(rule).send().await {
        Ok(response) => response.json().await,
        Err(error)
            if matches!(error, Error::Transport(_))
                || error.status() == Some(StatusCode::CONFLICT) =>
        {
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
            Err(error) if error.status() == Some(StatusCode::CONFLICT) => continue,
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
