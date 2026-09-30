//! Waiting for asynchronous Fleet work. Each wait is bounded by
//! [`PollOptions`]; see [`crate::poll`] for the deadline rules.
use super::{AgentActionStatus, AgentUpload, Fleet, agents::Agent};
use crate::{
    Result,
    poll::{self, PollOptions, WaitOutcome},
};

impl<'a> Fleet<'a> {
    /// Waits until an agent action finishes.
    ///
    /// Kibana has no lookup by action ID, so each check searches progressively
    /// larger history windows, up to 10,000 action documents, within the
    /// deadline. Bulk actions can occupy multiple documents. An action that was
    /// seen and then can no longer be found, for example because newer actions
    /// pushed it out of that window, ends the
    /// wait as [`WaitOutcome::Vanished`] with its last state.
    pub async fn wait_for_action(
        &self,
        action_id: &str,
        options: PollOptions,
    ) -> Result<WaitOutcome<AgentActionStatus>> {
        poll::wait(
            options,
            || self.find_action(action_id),
            AgentActionStatus::is_finished,
        )
        .await
    }

    async fn find_action(&self, action_id: &str) -> Result<Option<AgentActionStatus>> {
        for size in [100, 1_000, 10_000] {
            let actions = self
                .agent_action_status()
                .page(0)
                .per_page(size)
                .send()
                .await?
                .json()
                .await?;
            if let Some(action) = actions.items.into_iter().find(|a| a.action_id == action_id) {
                return Ok(Some(action));
            }
        }
        Ok(None)
    }

    /// Waits until the upload created by a diagnostics action finishes.
    /// Download it with [`download_agent_file`](Self::download_agent_file) once
    /// it is [`Ready`](super::UploadStatus::Ready). An upload that was seen and
    /// then disappears ends the wait as [`WaitOutcome::Vanished`].
    pub async fn wait_for_upload(
        &self,
        agent_id: &str,
        action_id: &str,
        options: PollOptions,
    ) -> Result<WaitOutcome<AgentUpload>> {
        poll::wait(
            options,
            || async {
                let uploads = self
                    .list_agent_uploads(agent_id)
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(uploads.items.into_iter().find(|u| u.action_id == action_id))
            },
            AgentUpload::is_finished,
        )
        .await
    }

    /// Waits until the agent is online and reports `policy_id` at `revision` or
    /// later. An agent that has not reported a revision has not acknowledged it.
    pub async fn wait_for_agent_policy(
        &self,
        agent_id: &str,
        policy_id: &str,
        revision: u64,
        options: PollOptions,
    ) -> Result<WaitOutcome<Agent>> {
        poll::wait(
            options,
            || async {
                Ok(Some(
                    self.get_agent(agent_id).send().await?.json().await?.item,
                ))
            },
            |agent| {
                agent.policy_id.as_deref() == Some(policy_id)
                    && agent.status.as_deref() == Some("online")
                    && agent
                        .policy_revision
                        .is_some_and(|current| current >= revision)
            },
        )
        .await
    }
}
