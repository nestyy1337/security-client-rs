use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use kibana_rs::{
    Error, Kibana,
    cases::{CaseComment, CasePatch, CaseStatus, NewCase, SECURITY_OWNER},
    fleet::{NewAgentPolicy, NewPackagePolicy, PackageRef},
    http::{Credentials, TransportBuilder, Url},
    security::{QueryRule, RuleSelector, Severity},
    spaces::Space,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct App {
    client: Kibana,
    space: String,
    activity: Arc<Mutex<VecDeque<Activity>>>,
}

#[derive(Clone, Serialize)]
struct Activity {
    time: u64,
    action: String,
    resource: String,
}

impl App {
    fn record(&self, action: &str, resource: &str) {
        let mut log = self.activity.lock().unwrap_or_else(|p| p.into_inner());
        log.push_front(Activity {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            action: action.into(),
            resource: resource.into(),
        });
        log.truncate(100);
    }
}

struct ApiError(Error);
impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        Self(e)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self
            .0
            .status()
            .filter(|s| s.is_client_error())
            .unwrap_or(StatusCode::BAD_GATEWAY);
        let message = self.0.message().unwrap_or_else(|| self.0.to_string());
        (
            status,
            Json(json!({"error":message,"status":status.as_u16()})),
        )
            .into_response()
    }
}
type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let credentials = if let Ok(key) = std::env::var("KIBANA_API_KEY") {
        Credentials::EncodedApiKey(key)
    } else {
        Credentials::Basic(
            std::env::var("KIBANA_USERNAME").unwrap_or("elastic".into()),
            std::env::var("KIBANA_PASSWORD")?,
        )
    };
    let root = Kibana::new(
        TransportBuilder::new(Url::parse(&std::env::var("KIBANA_URL")?)?)
            .auth(credentials)
            .timeout(Duration::from_secs(180))
            .build()?,
    );
    let space = std::env::var("KIBANA_SPACE").unwrap_or("kibana-rs".into());
    if std::env::args().any(|arg| arg == "--seed") {
        seed(&root, &space).await?;
        println!("Demo resources are ready in space {space}");
        return Ok(());
    }
    let app = App {
        client: root.space(&space)?,
        space,
        activity: Arc::new(Mutex::new(VecDeque::new())),
    };
    let router = Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route(
            "/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css")],
                    include_str!("app.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript")],
                    include_str!("app.js"),
                )
            }),
        )
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/screenshots/{name}", get(screenshot))
        .route("/api/status", get(status))
        .route("/api/summary", get(summary))
        .route("/api/activity", get(activity))
        .route("/api/rules", get(rules).post(create_rule))
        .route(
            "/api/rules/{id}",
            get(rule).patch(update_rule).delete(delete_rule),
        )
        .route("/api/policies", get(policies).post(create_policy))
        .route(
            "/api/policies/{id}",
            get(policy).put(update_policy).delete(delete_policy),
        )
        .route("/api/integrations", get(integrations))
        .route(
            "/api/integrations/{name}/{version}/install",
            post(install_integration),
        )
        .route(
            "/api/package-policies",
            get(package_policies).post(create_package_policy),
        )
        .route(
            "/api/package-policies/{id}",
            axum::routing::delete(delete_package_policy),
        )
        .route("/api/agents", get(agents))
        .route("/api/cases", get(cases).post(create_case))
        .route(
            "/api/cases/{id}",
            get(case).patch(update_case).delete(delete_case),
        )
        .route("/api/cases/{id}/comments", get(comments).post(comment))
        .layer(middleware::from_fn(browser_guard))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(app);
    let bind = std::env::var("KIBANA_RS_BIND").unwrap_or("127.0.0.1:8787".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("kibana-rs workbench listening on {bind}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn screenshot(Path(name): Path<String>) -> Response {
    if !matches!(
        name.as_str(),
        "rules-desktop.png"
            | "fleet-desktop.png"
            | "integrations-desktop.png"
            | "rules-mobile.png"
            | "rule-detail-mobile.png"
    ) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(directory) = std::env::var("KIBANA_RS_SCREENSHOTS") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match std::fs::read(std::path::Path::new(&directory).join(name)) {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/png")], bytes).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn browser_guard(req: Request, next: Next) -> Response {
    if !matches!(
        *req.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) && req
        .headers()
        .get("x-kibana-rs")
        .and_then(|v| v.to_str().ok())
        != Some("1")
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"Missing request protection header"})),
        )
            .into_response();
    }
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY,"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[derive(Deserialize)]
struct ListQuery {
    page: Option<u32>,
    search: Option<String>,
}
impl ListQuery {
    fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }
}

async fn status(State(a): State<App>) -> ApiResult<Value> {
    let s = a.client.status().send().await?.json().await?;
    Ok(Json(
        json!({"version":s["version"]["number"],"health":s["status"]["overall"]["level"],"space":a.space}),
    ))
}
async fn summary(State(a): State<App>) -> ApiResult<Value> {
    let (rules, cases, policies, agents) = tokio::join!(
        async {
            a.client
                .security()
                .find_rules()
                .per_page(1)
                .send()
                .await?
                .json()
                .await
        },
        async {
            a.client
                .cases()
                .find()
                .owner(SECURITY_OWNER)
                .per_page(1)
                .send()
                .await?
                .json()
                .await
        },
        async {
            a.client
                .fleet()
                .find_agent_policies()
                .per_page(1)
                .send()
                .await?
                .json()
                .await
        },
        async {
            a.client
                .fleet()
                .find_agents()
                .per_page(1)
                .send()
                .await?
                .json()
                .await
        }
    );
    Ok(Json(
        json!({"rules":rules?.total,"cases":cases?.total,"policies":policies?.total,"agents":agents?.total}),
    ))
}
async fn activity(State(a): State<App>) -> Json<Value> {
    Json(json!({"items":a.activity.lock().unwrap_or_else(|p|p.into_inner()).clone()}))
}
async fn rules(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let page = a
        .client
        .security()
        .find_rules()
        .page(q.page())
        .per_page(50)
        .send()
        .await?;
    Ok(Json(page.json_as().await?))
}
async fn rule(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let rule = a
        .client
        .security()
        .get_rule(RuleSelector::Id(&id))
        .send()
        .await?;
    Ok(Json(rule.json_as().await?))
}
#[derive(Deserialize)]
struct RuleForm {
    name: String,
    description: String,
    query: String,
    severity: Severity,
    index: Vec<String>,
}
async fn create_rule(State(a): State<App>, Json(form): Json<RuleForm>) -> ApiResult<Value> {
    let input = QueryRule::new(form.name, form.description, form.query)
        .severity(form.severity)
        .index(form.index)
        .tags(["kibana-rs"]);
    let rule = a
        .client
        .security()
        .create_rule(&input)
        .send()
        .await?
        .json()
        .await?;
    a.record("Created detection rule", &rule.name);
    Ok(Json(json!(rule)))
}
#[derive(Deserialize)]
struct RuleChange {
    enabled: Option<bool>,
    name: Option<String>,
    query: Option<String>,
    description: Option<String>,
}
async fn update_rule(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(form): Json<RuleChange>,
) -> ApiResult<Value> {
    let mut patch = a.client.security().patch_rule(RuleSelector::Id(&id));
    if let Some(enabled) = form.enabled {
        patch = patch.enabled(enabled);
    }
    if let Some(name) = &form.name {
        patch = patch.name(name);
    }
    if let Some(query) = &form.query {
        patch = patch.query(query);
    }
    if let Some(description) = &form.description {
        patch = patch.description(description);
    }
    let rule = patch.send().await?.json().await?;
    a.record("Updated detection rule", &rule.name);
    Ok(Json(json!(rule)))
}
async fn delete_rule(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let rule = a
        .client
        .security()
        .delete_rule(RuleSelector::Id(&id))
        .send()
        .await?
        .json()
        .await?;
    a.record("Deleted detection rule", &rule.name);
    Ok(Json(json!({"deleted":id})))
}
async fn policies(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let page = a
        .client
        .fleet()
        .find_agent_policies()
        .page(q.page())
        .per_page(50)
        .send()
        .await?;
    Ok(Json(page.json_as().await?))
}
async fn policy(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let policy = a
        .client
        .fleet()
        .get_agent_policy(&id)
        .send()
        .await?
        .json()
        .await?;
    Ok(Json(json!(policy.item)))
}
#[derive(Deserialize)]
struct PolicyForm {
    name: String,
    namespace: String,
    description: Option<String>,
}
async fn create_policy(State(a): State<App>, Json(form): Json<PolicyForm>) -> ApiResult<Value> {
    let mut request =
        NewAgentPolicy::new(form.name, form.namespace).monitoring_enabled(Vec::<String>::new());
    if let Some(description) = form.description {
        request = request.description(description);
    }
    let result = a
        .client
        .fleet()
        .create_agent_policy(&request)
        .send()
        .await?
        .json()
        .await?
        .item;
    a.record("Created agent policy", &result.name);
    Ok(Json(json!(result)))
}
async fn update_policy(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(form): Json<PolicyForm>,
) -> ApiResult<Value> {
    let mut request = NewAgentPolicy::new(form.name, form.namespace);
    if let Some(description) = form.description {
        request = request.description(description);
    }
    let result = a
        .client
        .fleet()
        .update_agent_policy(&id, &request)
        .send()
        .await?
        .json()
        .await?
        .item;
    a.record("Updated agent policy", &result.name);
    Ok(Json(json!(result)))
}
async fn delete_policy(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let result = a
        .client
        .fleet()
        .delete_agent_policy(&id)
        .send()
        .await?
        .json()
        .await?;
    a.record("Deleted agent policy", &id);
    Ok(Json(result))
}
async fn integrations(State(a): State<App>) -> ApiResult<Value> {
    let packages = a.client.fleet().list_packages().send().await?;
    Ok(Json(packages.json_as().await?))
}
async fn install_integration(
    State(a): State<App>,
    Path((name, version)): Path<(String, String)>,
) -> ApiResult<Value> {
    let result = a
        .client
        .fleet()
        .install_package(&name, &version)
        .send()
        .await?
        .json()
        .await?;
    a.record("Installed integration", &format!("{name} {version}"));
    Ok(Json(result))
}
async fn package_policies(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let page = a
        .client
        .fleet()
        .find_package_policies()
        .page(q.page())
        .per_page(50)
        .send()
        .await?;
    Ok(Json(page.json_as().await?))
}
#[derive(Deserialize)]
struct PackageForm {
    name: String,
    namespace: String,
    policy_id: String,
    package: String,
    version: String,
}
async fn create_package_policy(
    State(a): State<App>,
    Json(form): Json<PackageForm>,
) -> ApiResult<Value> {
    let request = NewPackagePolicy::new(
        form.name,
        form.namespace,
        PackageRef::new(form.package, form.version),
    )
    .policy_id(form.policy_id);
    let result = a
        .client
        .fleet()
        .create_package_policy(&request)
        .send()
        .await?
        .json()
        .await?
        .item;
    a.record("Assigned integration", &result.name);
    Ok(Json(json!(result)))
}
async fn delete_package_policy(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let result = a
        .client
        .fleet()
        .delete_package_policy(&id)
        .send()
        .await?
        .json()
        .await?;
    a.record("Removed integration policy", &id);
    Ok(Json(result))
}
async fn agents(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let page = a
        .client
        .fleet()
        .find_agents()
        .page(q.page())
        .per_page(50)
        .send()
        .await?;
    Ok(Json(page.json_as().await?))
}
async fn cases(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let mut find = a
        .client
        .cases()
        .find()
        .owner(SECURITY_OWNER)
        .page(q.page())
        .per_page(50);
    if let Some(search) = &q.search {
        find = find.search(search);
    }
    Ok(Json(find.send().await?.json_as().await?))
}
async fn case(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    Ok(Json(
        a.client.cases().get(&id).send().await?.json_as().await?,
    ))
}
#[derive(Deserialize)]
struct CaseForm {
    title: String,
    description: String,
    severity: Severity,
}
async fn create_case(State(a): State<App>, Json(form): Json<CaseForm>) -> ApiResult<Value> {
    let request = NewCase::security(form.title, form.description)
        .severity(form.severity)
        .tags(["kibana-rs"]);
    let result = a
        .client
        .cases()
        .create(&request)
        .send()
        .await?
        .json()
        .await?;
    a.record("Opened security case", &result.title);
    Ok(Json(json!(result)))
}
#[derive(Deserialize)]
struct CaseChange {
    version: String,
    status: String,
}
async fn update_case(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(form): Json<CaseChange>,
) -> ApiResult<Value> {
    let status = match form.status.as_str() {
        "open" => CaseStatus::Open,
        "in-progress" => CaseStatus::InProgress,
        "closed" => CaseStatus::Closed,
        _ => return Err(Error::InvalidRequest("invalid case status".into()).into()),
    };
    let patch = CasePatch::new(&id, &form.version).status(status);
    let result = a
        .client
        .cases()
        .update([patch])
        .send()
        .await?
        .json()
        .await?;
    a.record("Updated case status", &id);
    Ok(Json(json!(result)))
}
async fn delete_case(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    a.client.cases().delete([&id]).send().await?;
    a.record("Deleted security case", &id);
    Ok(Json(json!({"deleted":id})))
}
async fn comments(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let page = a
        .client
        .cases()
        .find_comments(&id)
        .per_page(100)
        .send()
        .await?;
    Ok(Json(page.json_as().await?))
}
#[derive(Deserialize)]
struct CommentForm {
    comment: String,
}
async fn comment(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(form): Json<CommentForm>,
) -> ApiResult<Value> {
    let comment = CaseComment::user(SECURITY_OWNER, form.comment);
    let result = a
        .client
        .cases()
        .add_comment(&id, &comment)
        .send()
        .await?
        .json()
        .await?;
    a.record("Added case comment", &id);
    Ok(Json(json!(result)))
}

async fn seed(root: &Kibana, space: &str) -> Result<(), Error> {
    match root.spaces().get(space).send().await {
        Ok(_) => {}
        Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {
            let mut definition = Space::new(space, "Security lab");
            definition.description = Some("Isolated kibana-rs demonstration".into());
            root.spaces().create(&definition).send().await?;
        }
        Err(e) => return Err(e),
    }
    let client = root.space(space)?;
    client.security().create_alerts_index().send().await?;
    client.fleet().setup().send().await?;
    let definitions = [
        (
            "krs-demo-auth",
            "Failed privileged authentication",
            "event.category: authentication and event.outcome: failure and user.name: root",
            Severity::High,
        ),
        (
            "krs-demo-shell",
            "Unusual command interpreter",
            "event.category: process and process.name: (nc or ncat)",
            Severity::Medium,
        ),
        (
            "krs-demo-admin",
            "Administrative account changes",
            "event.category: iam and event.type: change",
            Severity::High,
        ),
    ];
    for (id, name, query, severity) in definitions {
        match client
            .security()
            .get_rule(RuleSelector::RuleId(id))
            .send()
            .await
        {
            Ok(_) => continue,
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {}
            Err(e) => return Err(e),
        }
        let rule = QueryRule::new(
            name,
            "Demonstration detection rule. No production events are connected.",
            query,
        )
        .rule_id(id)
        .severity(severity)
        .tags(["kibana-rs", "demo"]);
        client.security().create_rule(&rule).send().await?;
    }
    let existing = client
        .cases()
        .find()
        .owner(SECURITY_OWNER)
        .send()
        .await?
        .json()
        .await?;
    for title in [
        "Privileged authentication review",
        "Linux endpoint coverage review",
    ] {
        if !existing.cases.iter().any(|c| c.title == title) {
            let case = NewCase::security(
                title,
                "Sample investigation created by kibana-rs. This is demonstration data, not a production incident.",
            )
            .tags(["demo", "security"])
            .severity(Severity::Medium);
            client.cases().create(&case).send().await?;
        }
    }
    let mut policies = client
        .fleet()
        .find_agent_policies()
        .send()
        .await?
        .json()
        .await?
        .items;
    for (name, description) in [
        (
            "SOC Linux endpoints",
            "Authentication and system telemetry for the security lab",
        ),
        (
            "SOC staging",
            "A separate policy for validating integration changes",
        ),
    ] {
        if !policies.iter().any(|p| p.name == name) {
            let policy = NewAgentPolicy::new(name, "default")
                .description(description)
                .monitoring_enabled(Vec::<String>::new());
            policies.push(
                client
                    .fleet()
                    .create_agent_policy(&policy)
                    .send()
                    .await?
                    .json()
                    .await?
                    .item,
            );
        }
    }
    let packages = client.fleet().list_packages().send().await?.json().await?;
    let package = packages
        .items
        .iter()
        .find(|p| p.name == "system")
        .ok_or_else(|| Error::Configuration("system integration missing from registry".into()))?;
    client
        .fleet()
        .install_package(&package.name, &package.version)
        .send()
        .await?;
    let installed = client
        .fleet()
        .find_package_policies()
        .send()
        .await?
        .json()
        .await?;
    if !installed
        .items
        .iter()
        .any(|p| p.name == "Linux system telemetry")
    {
        let policy = policies
            .iter()
            .find(|p| p.name == "SOC Linux endpoints")
            .unwrap();
        let telemetry = NewPackagePolicy::new(
            "Linux system telemetry",
            "default",
            PackageRef::new(&package.name, &package.version),
        )
        .policy_id(&policy.id)
        .description("System logs and metrics for the demo policy");
        client
            .fleet()
            .create_package_policy(&telemetry)
            .send()
            .await?;
    }
    Ok(())
}
