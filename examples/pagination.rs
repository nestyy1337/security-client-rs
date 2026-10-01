//! Reads whole collections with `items()` and `pages()` instead of paging by hand.
use futures_util::TryStreamExt;
use security_client_rs::{
    Kibana,
    http::{Credentials, TransportBuilder, Url},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = TransportBuilder::new(Url::parse(&std::env::var("KIBANA_URL")?)?)
        .auth(Credentials::EncodedApiKey(std::env::var("KIBANA_API_KEY")?))
        .build()?;
    let client = Kibana::new(transport);

    // One request per page of 100, until every rule has been read.
    let mut disabled = Vec::new();
    let mut rules = client.security().find_rules().per_page(100).items();
    while let Some(rule) = rules.try_next().await? {
        if !rule.enabled {
            disabled.push(rule.name);
        }
    }
    println!("{} disabled rules: {disabled:?}", disabled.len());

    // Pages expose the collection total as reported by Kibana.
    let pages: Vec<_> = client
        .fleet()
        .find_agents()
        .kuery("status:offline")
        .per_page(500)
        .pages()
        .try_collect()
        .await?;
    let offline: usize = pages.iter().map(|page| page.items.len()).sum();
    println!("{offline} offline agents across {} pages", pages.len());
    Ok(())
}
