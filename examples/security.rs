use kibana_rs::{Auth, Client, PageOptions, security::FindRules};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = if let Ok(key) = std::env::var("KIBANA_API_KEY") {
        Auth::ApiKey(key)
    } else {
        Auth::Basic {
            username: std::env::var("KIBANA_USERNAME")?,
            password: std::env::var("KIBANA_PASSWORD")?,
        }
    };
    let client = Client::builder(std::env::var("KIBANA_URL")?)
        .auth(auth)
        .build()?
        .space(std::env::var("KIBANA_SPACE").unwrap_or("default".into()))?;

    let rules = client.security().rules(&FindRules::default()).await?;
    println!("{} detection rules, page {}", rules.total, rules.page);
    for rule in rules.data {
        println!(
            "{} | {} | enabled={}",
            rule.name, rule.severity, rule.enabled
        );
    }

    let policies = client
        .fleet()
        .agent_policies(&PageOptions::default())
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
