//! Progress of submitted agent actions and the files they upload.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{Fleet, Items};
use crate::{
    Scope,
    http::{Method, Raw},
    request::endpoint,
};

/// The state of an agent action. States added by newer Kibana versions are
/// kept as [`Unknown`](Self::Unknown).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum ActionStatus {
    InProgress,
    Complete,
    Failed,
    Cancelled,
    Expired,
    RolloutPassed,
    Unknown(String),
}

impl ActionStatus {
    /// Kibana's name for the state, such as `IN_PROGRESS`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InProgress => "IN_PROGRESS",
            Self::Complete => "COMPLETE",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Expired => "EXPIRED",
            Self::RolloutPassed => "ROLLOUT_PASSED",
            Self::Unknown(status) => status,
        }
    }

    /// Whether the action can no longer progress. An unknown state counts as
    /// finished, so waiting stops at a state this client cannot interpret
    /// instead of running until the deadline.
    /// This also returns true for known failures; inspect the status before
    /// treating the action as successful.
    ///
    /// ```
    /// use kibana_rs::fleet::ActionStatus;
    ///
    /// assert!(ActionStatus::Failed.is_finished());
    /// assert!(!ActionStatus::InProgress.is_finished());
    /// let added_by_kibana = ActionStatus::from("NEW_STATUS".to_owned());
    /// assert!(added_by_kibana.is_finished());
    /// assert!(matches!(added_by_kibana, ActionStatus::Unknown(_)));
    /// ```
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::InProgress)
    }
}

impl From<String> for ActionStatus {
    fn from(status: String) -> Self {
        match status.as_str() {
            "IN_PROGRESS" => Self::InProgress,
            "COMPLETE" => Self::Complete,
            "FAILED" => Self::Failed,
            "CANCELLED" => Self::Cancelled,
            "EXPIRED" => Self::Expired,
            "ROLLOUT_PASSED" => Self::RolloutPassed,
            _ => Self::Unknown(status),
        }
    }
}

impl From<ActionStatus> for String {
    fn from(status: ActionStatus) -> Self {
        match status {
            ActionStatus::Unknown(status) => status,
            known => known.as_str().to_owned(),
        }
    }
}

/// The state of a file uploaded by an agent. States added by newer Kibana
/// versions are kept as [`Unknown`](Self::Unknown).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum UploadStatus {
    AwaitingUpload,
    InProgress,
    /// The file can be downloaded.
    Ready,
    Failed,
    Expired,
    Deleted,
    Unknown(String),
}

impl UploadStatus {
    /// Kibana's name for the state, such as `READY`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::AwaitingUpload => "AWAITING_UPLOAD",
            Self::InProgress => "IN_PROGRESS",
            Self::Ready => "READY",
            Self::Failed => "FAILED",
            Self::Expired => "EXPIRED",
            Self::Deleted => "DELETED",
            Self::Unknown(status) => status,
        }
    }

    /// Whether the upload can no longer change. As with [`ActionStatus`], an
    /// unknown state counts as finished.
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::AwaitingUpload | Self::InProgress)
    }
}

impl From<String> for UploadStatus {
    fn from(status: String) -> Self {
        match status.as_str() {
            "AWAITING_UPLOAD" => Self::AwaitingUpload,
            "IN_PROGRESS" => Self::InProgress,
            "READY" => Self::Ready,
            "FAILED" => Self::Failed,
            "EXPIRED" => Self::Expired,
            "DELETED" => Self::Deleted,
            _ => Self::Unknown(status),
        }
    }
}

impl From<UploadStatus> for String {
    fn from(status: UploadStatus) -> Self {
        match status {
            UploadStatus::Unknown(status) => status,
            known => known.as_str().to_owned(),
        }
    }
}

/// Inspect failure counts and errors, including while the action is in progress.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentActionStatus {
    pub action_id: String,
    pub status: ActionStatus,
    #[serde(rename = "type")]
    pub action_type: String,
    pub nb_agents_action_created: u64,
    pub nb_agents_ack: u64,
    pub nb_agents_failed: u64,
    pub nb_agents_actioned: u64,
    #[serde(default)]
    pub latest_errors: Vec<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AgentActionStatus {
    /// See [`ActionStatus::is_finished`]. Check the failure counts too.
    pub fn is_finished(&self) -> bool {
        self.status.is_finished()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentUpload {
    pub id: String,
    pub name: String,
    pub action_id: String,
    pub status: UploadStatus,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AgentUpload {
    /// See [`UploadStatus::is_finished`].
    pub fn is_finished(&self) -> bool {
        self.status.is_finished()
    }
}

impl<'a> Fleet<'a> {
    /// Recent agent actions with completion and failure counts, newest first.
    /// Pages start at zero.
    pub fn agent_action_status(&self) -> AgentActionStatuses<'a> {
        AgentActionStatuses(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agents", "action_status"],
        ))
    }

    /// Kibana supports cancellation of upgrade and unenrollment actions only.
    pub fn cancel_agent_action(&self, action_id: &str) -> CancelAgentAction<'a> {
        CancelAgentAction(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "actions", action_id, "cancel"],
                )
                .json(&json!({})),
        )
    }

    pub fn list_agent_uploads(&self, agent_id: &str) -> ListAgentUploads<'a> {
        ListAgentUploads(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agents", agent_id, "uploads"],
        ))
    }

    /// Downloads an upload after it reports `READY`. Diagnostic archives can
    /// contain sensitive configuration.
    pub fn download_agent_file(&self, file_id: &str, file_name: &str) -> DownloadAgentFile<'a> {
        DownloadAgentFile(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agents", "files", file_id, file_name],
        ))
    }
}

endpoint! {
    /// `GET /api/fleet/agents/action_status`
    AgentActionStatuses => Items<AgentActionStatus>
}

impl AgentActionStatuses<'_> {
    /// Zero-based page number, unlike Fleet resource collections.
    pub fn page(self, page: u32) -> Self {
        Self(self.0.param("page", page))
    }

    pub fn per_page(self, per_page: u32) -> Self {
        Self(self.0.positive_param("perPage", per_page))
    }

    /// Only actions created after this ISO 8601 time.
    pub fn date(self, date: &str) -> Self {
        Self(self.0.param("date", date))
    }

    /// Only actions from the last `seconds`.
    pub fn latest(self, seconds: u32) -> Self {
        Self(self.0.param("latest", seconds))
    }

    /// How many recent errors to include per action.
    pub fn error_size(self, size: u32) -> Self {
        Self(self.0.param("errorSize", size))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/actions/{actionId}/cancel`
    CancelAgentAction => Value
}

endpoint! {
    /// `GET /api/fleet/agents/{agentId}/uploads`
    ListAgentUploads => Items<AgentUpload>
}

endpoint! {
    /// `GET /api/fleet/agents/files/{fileId}/{fileName}`
    DownloadAgentFile => Raw
}
