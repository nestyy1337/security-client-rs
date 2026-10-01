use security_client_rs::{
    Kibana,
    http::{Credentials, TransportBuilder, Url},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let credentials = if let Ok(key) = std::env::var("KIBANA_API_KEY") {
        Credentials::EncodedApiKey(key)
    } else {
        Credentials::Basic(
            std::env::var("KIBANA_USERNAME")?,
            std::env::var("KIBANA_PASSWORD")?,
        )
    };
    let transport = TransportBuilder::new(Url::parse(&std::env::var("KIBANA_URL")?)?)
        .auth(credentials)
        .build()?;
    let client =
        Kibana::new(transport).space(std::env::var("KIBANA_SPACE").unwrap_or("default".into()))?;

    let rules = client
        .security()
        .find_rules()
        .per_page(50)
        .send()
        .await?
        .json()
        .await?;
    println!("{} detection rules, page {}", rules.total, rules.page);
    for rule in rules.data {
        println!(
            "{} | {} | enabled={}",
            rule.name, rule.severity, rule.enabled
        );
    }

    let policies = client
        .fleet()
        .find_agent_policies()
        .send()
        .await?
        .json()
        .await?;
    println!("{} agent policies", policies.total);
    for policy in policies.items {
        println!(
            "{} | revision {} | {}",
            policy.name, policy.revision, policy.namespace
        );
    }
    Ok(())
}
