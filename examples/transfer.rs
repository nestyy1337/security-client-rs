//! Streams a rule export to a file and imports it, reporting per-rule failures
//! that Kibana returns inside a successful response.
use futures_util::TryStreamExt;
use kibana_rs::{
    Kibana,
    http::{Credentials, TransportBuilder, Url},
};
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = TransportBuilder::new(Url::parse(&std::env::var("KIBANA_URL")?)?)
        .auth(Credentials::EncodedApiKey(std::env::var("KIBANA_API_KEY")?))
        .build()?;
    let source = Kibana::new(transport.clone()).space(std::env::var("SOURCE_SPACE")?)?;
    let target = Kibana::new(transport).space(std::env::var("TARGET_SPACE")?)?;

    // Stream without the response size limit rather than buffering the export.
    let path = std::env::temp_dir().join("rules.ndjson");
    let mut file = tokio::fs::File::create(&path).await?;
    let mut export = source
        .security()
        .export_rules()
        .exclude_export_details(true)
        .send()
        .await?
        .bytes_stream();
    while let Some(chunk) = export.try_next().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    let result = target
        .security()
        .import_rules(tokio::fs::read(&path).await?)
        .overwrite(false)
        .send()
        .await?
        .json()
        .await?;
    println!(
        "imported {} rules, success={}",
        result.success_count, result.success
    );
    for error in &result.errors {
        println!("failed rule {:?}: {}", error.rule_id, error.error.message);
    }
    for error in &result.exceptions_errors {
        println!("failed exception {:?}: {}", error.id, error.error.message);
    }
    for error in &result.action_connectors_errors {
        println!("failed connector {:?}: {}", error.id, error.error.message);
    }
    Ok(())
}
