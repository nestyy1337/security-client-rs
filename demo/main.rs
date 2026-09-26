use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use kibana_rs::{
    Auth, Client, Error, PageOptions,
    cases::{CasePatch, CaseStatus, FindCases, NewCase},
    fleet::{AgentPolicyRequest, PackagePolicyRequest, PackageRef},
    security::{FindRules, QueryRule, RulePatch, RuleSelector, Severity},
    spaces::Space,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct App {
    client: Client,
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
        let message = match &self.0 {
            Error::Api { body, .. } => serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| self.0.to_string()),
            _ => self.0.to_string(),
        };
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
    let auth = if let Ok(key) = std::env::var("KIBANA_API_KEY") {
        Auth::ApiKey(key)
    } else {
        Auth::Basic {
            username: std::env::var("KIBANA_USERNAME").unwrap_or("elastic".into()),
            password: std::env::var("KIBANA_PASSWORD")?,
        }
    };
    let root = Client::builder(std::env::var("KIBANA_URL")?)
        .auth(auth)
        .timeout(Duration::from_secs(180))
        .build()?;
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
    fn fleet(&self) -> PageOptions {
        PageOptions {
            page: self.page(),
            per_page: 50,
            kuery: None,
        }
    }
}

async fn status(State(a): State<App>) -> ApiResult<Value> {
    let s = a.client.status().await?;
    Ok(Json(
        json!({"version":s["version"]["number"],"health":s["status"]["overall"]["level"],"space":a.space}),
    ))
}
async fn summary(State(a): State<App>) -> ApiResult<Value> {
    let (rules, cases, policies, agents) = tokio::join!(
        async {
            a.client
                .security()
                .rules(&FindRules {
                    per_page: 1,
                    ..Default::default()
                })
                .await
        },
        async {
            a.client
                .cases()
                .find(&FindCases {
                    per_page: 1,
                    ..Default::default()
                })
                .await
        },
        async {
            a.client
                .fleet()
                .agent_policies(&PageOptions {
                    per_page: 1,
                    ..Default::default()
                })
                .await
        },
        async {
            a.client
                .fleet()
                .agents(&PageOptions {
                    per_page: 1,
                    ..Default::default()
                })
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
    Ok(Json(
        serde_json::to_value(
            a.client
                .security()
                .rules(&FindRules {
                    page: q.page(),
                    per_page: 50,
                    filter: None,
                })
                .await?,
        )
        .map_err(Error::from)?,
    ))
}
async fn rule(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    Ok(Json(json!(
        a.client.security().rule(RuleSelector::Id(&id)).await?
    )))
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
    let mut input = QueryRule::new(form.name, form.description, form.query);
    input.severity = form.severity;
    input.index = form.index;
    input.tags = vec!["kibana-rs".into()];
    let rule = a.client.security().create_rule(&input).await?;
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
    let rule = a
        .client
        .security()
        .update_rule(
            RuleSelector::Id(&id),
            &RulePatch {
                enabled: form.enabled,
                name: form.name,
                query: form.query,
                description: form.description,
                ..Default::default()
            },
        )
        .await?;
    a.record("Updated detection rule", &rule.name);
    Ok(Json(json!(rule)))
}
async fn delete_rule(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let rule = a
        .client
        .security()
        .delete_rule(RuleSelector::Id(&id))
        .await?;
    a.record("Deleted detection rule", &rule.name);
    Ok(Json(json!({"deleted":id})))
}
async fn policies(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    Ok(Json(json!(
        a.client.fleet().agent_policies(&q.fleet()).await?
    )))
}
async fn policy(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    Ok(Json(json!(a.client.fleet().agent_policy(&id).await?)))
}
#[derive(Deserialize)]
struct PolicyForm {
    name: String,
    namespace: String,
    description: Option<String>,
}
async fn create_policy(State(a): State<App>, Json(form): Json<PolicyForm>) -> ApiResult<Value> {
    let mut request = AgentPolicyRequest::new(form.name, form.namespace);
    request.description = form.description;
    request.monitoring_enabled = Some(vec![]);
    let result = a.client.fleet().create_agent_policy(&request).await?;
    a.record("Created agent policy", &result.name);
    Ok(Json(json!(result)))
}
async fn update_policy(
    State(a): State<App>,
    Path(id): Path<String>,
    Json(form): Json<PolicyForm>,
) -> ApiResult<Value> {
    let mut request = AgentPolicyRequest::new(form.name, form.namespace);
    request.description = form.description;
    let result = a.client.fleet().update_agent_policy(&id, &request).await?;
    a.record("Updated agent policy", &result.name);
    Ok(Json(json!(result)))
}
async fn delete_policy(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let result = a.client.fleet().delete_agent_policy(&id).await?;
    a.record("Deleted agent policy", &id);
    Ok(Json(result))
}
async fn integrations(State(a): State<App>) -> ApiResult<Value> {
    Ok(Json(json!(a.client.fleet().integrations().await?)))
}
async fn install_integration(
    State(a): State<App>,
    Path((name, version)): Path<(String, String)>,
) -> ApiResult<Value> {
    let result = a
        .client
        .fleet()
        .install_integration(&name, &version)
        .await?;
    a.record("Installed integration", &format!("{name} {version}"));
    Ok(Json(result))
}
async fn package_policies(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    Ok(Json(json!(
        a.client.fleet().package_policies(&q.fleet()).await?
    )))
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
    let request = PackagePolicyRequest {
        name: form.name,
        namespace: form.namespace,
        policy_ids: vec![form.policy_id],
        package: PackageRef {
            name: form.package,
            version: form.version,
        },
        inputs: BTreeMap::new(),
        description: None,
    };
    let result = a.client.fleet().create_package_policy(&request).await?;
    a.record("Assigned integration", &result.name);
    Ok(Json(json!(result)))
}
async fn delete_package_policy(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    let result = a.client.fleet().delete_package_policy(&id).await?;
    a.record("Removed integration policy", &id);
    Ok(Json(result))
}
async fn agents(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    Ok(Json(json!(a.client.fleet().agents(&q.fleet()).await?)))
}
async fn cases(State(a): State<App>, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    Ok(Json(json!(
        a.client
            .cases()
            .find(&FindCases {
                page: q.page(),
                search: q.search,
                ..Default::default()
            })
            .await?
    )))
}
async fn case(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    Ok(Json(json!(a.client.cases().get(&id).await?)))
}
#[derive(Deserialize)]
struct CaseForm {
    title: String,
    description: String,
    severity: Severity,
}
async fn create_case(State(a): State<App>, Json(form): Json<CaseForm>) -> ApiResult<Value> {
    let mut request = NewCase::security(form.title, form.description);
    request.severity = form.severity;
    request.tags = vec!["kibana-rs".into()];
    let result = a.client.cases().create(&request).await?;
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
        _ => return Err(Error::Configuration("invalid case status".into()).into()),
    };
    let result = a
        .client
        .cases()
        .update(&[CasePatch {
            id: &id,
            version: &form.version,
            status: Some(status),
            title: None,
            severity: None,
        }])
        .await?;
    a.record("Updated case status", &id);
    Ok(Json(json!(result)))
}
async fn delete_case(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    a.client.cases().delete(&[&id]).await?;
    a.record("Deleted security case", &id);
    Ok(Json(json!({"deleted":id})))
}
async fn comments(State(a): State<App>, Path(id): Path<String>) -> ApiResult<Value> {
    Ok(Json(a.client.cases().comments(&id, 1, 100).await?))
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
    let result = a
        .client
        .cases()
        .comment(&id, "securitySolution", &form.comment)
        .await?;
    a.record("Added case comment", &id);
    Ok(Json(result))
}

async fn seed(root: &Client, space: &str) -> Result<(), Error> {
    match root.spaces().get(space).await {
        Ok(_) => {}
        Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {
            root.spaces()
                .create(&Space {
                    id: space.into(),
                    name: "Security lab".into(),
                    description: "Isolated kibana-rs demonstration".into(),
                    disabled_features: vec![],
                })
                .await?;
        }
        Err(e) => return Err(e),
    }
    let client = root.space(space)?;
    client.security().initialize().await?;
    client.fleet().setup().await?;
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
        match client.security().rule(RuleSelector::RuleId(id)).await {
            Ok(_) => continue,
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => {}
            Err(e) => return Err(e),
        }
        let mut rule = QueryRule::new(
            name,
            "Demonstration detection rule. No production events are connected.",
            query,
        );
        rule.rule_id = Some(id.into());
        rule.severity = severity;
        rule.tags = vec!["kibana-rs".into(), "demo".into()];
        client.security().create_rule(&rule).await?;
    }
    let existing = client.cases().find(&FindCases::default()).await?;
    for title in [
        "Privileged authentication review",
        "Linux endpoint coverage review",
    ] {
        if !existing.cases.iter().any(|c| c.title == title) {
            let mut case = NewCase::security(
                title,
                "Sample investigation created by kibana-rs. This is demonstration data, not a production incident.",
            );
            case.tags = vec!["demo".into(), "security".into()];
            case.severity = Severity::Medium;
            client.cases().create(&case).await?;
        }
    }
    let mut policies = client
        .fleet()
        .agent_policies(&PageOptions::default())
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
            let mut policy = AgentPolicyRequest::new(name, "default");
            policy.description = Some(description.into());
            policy.monitoring_enabled = Some(vec![]);
            policies.push(client.fleet().create_agent_policy(&policy).await?);
        }
    }
    let packages = client.fleet().integrations().await?;
    let package = packages
        .items
        .iter()
        .find(|p| p.name == "system")
        .ok_or_else(|| Error::Configuration("system integration missing from registry".into()))?;
    client
        .fleet()
        .install_integration(&package.name, &package.version)
        .await?;
    let installed = client
        .fleet()
        .package_policies(&PageOptions::default())
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
        client
            .fleet()
            .create_package_policy(&PackagePolicyRequest {
                name: "Linux system telemetry".into(),
                namespace: "default".into(),
                policy_ids: vec![policy.id.clone()],
                package: PackageRef {
                    name: package.name.clone(),
                    version: package.version.clone(),
                },
                inputs: BTreeMap::new(),
                description: Some("System logs and metrics for the demo policy".into()),
            })
            .await?;
    }
    Ok(())
}
