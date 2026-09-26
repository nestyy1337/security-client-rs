const paths = {
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z M9 12l2 2 4-4",
  case: "M8 6V4h8v2 M3 7h18v14H3V7Z M3 12h18 M10 12v3h4v-3",
  policy: "M6 3h9l4 4v14H6V3Z M14 3v5h5 M9 12h7 M9 16h5",
  grid: "M3 3h7v7H3V3Z M14 3h7v7h-7V3Z M3 14h7v7H3v-7Z M14 14h7v7h-7v-7Z",
  monitor: "M3 4h18v13H3V4Z M8 21h8 M12 17v4",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  layers: "m12 3 10 5-10 5L2 8l10-5Z M2 12l10 5 10-5 M2 16l10 5 10-5",
  lock: "M6 10h12v11H6V10Z M8 10V7a4 4 0 0 1 8 0v3",
  plus: "M12 5v14 M5 12h14",
  close: "m6 6 12 12 M18 6 6 18",
  search: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14 M15 15l6 6",
  refresh: "M20 8a8 8 0 1 0 1 7 M20 3v5h-5",
  arrow: "M6 12h12 M13 7l5 5-5 5",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 11v6 M12 7v.1",
  check: "m5 12 4 4L19 6",
  more: "M5 12h.1 M12 12h.1 M19 12h.1",
};
const icon = (name) =>
  `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="${paths[name] || paths.policy}"></path></svg>`;
document
  .querySelectorAll("[data-icon]")
  .forEach((el) => (el.innerHTML = icon(el.dataset.icon)));
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const label = (value) => String(value || "Unknown").replace(/[_-]/g, " ");
const date = (value) =>
  value
    ? new Date(value).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
      })
    : "Not available";
const badge = (value, display) =>
  `<span class="badge ${esc(value)}">${esc(display || label(value))}</span>`;
const titles = {
  rules: "Detection rules",
  cases: "Cases",
  policies: "Agent policies",
  integrations: "Integrations",
  agents: "Agents",
  activity: "Recent operations",
};
const subtitles = {
  rules: "Manage detection logic across your security environment.",
  cases: "Track investigations and document the next step.",
  policies: "Define how your endpoints collect and send telemetry.",
  integrations: "Install packages and assign telemetry to agent policies.",
  agents: "Inspect the agents enrolled in this Kibana space.",
  activity: "Successful changes made through this workbench since startup.",
};
const notes = {
  rules:
    "Rules are created disabled. Enable them when you are ready to evaluate incoming events.",
  cases:
    "These are demonstration cases in an isolated space. No production incidents are connected.",
  policies:
    "Integration policies define the telemetry collected by agents assigned to each policy.",
  integrations:
    "Installing a package prepares its assets. Assign it to an agent policy to configure collection.",
  agents:
    "Enrolling agents requires a Fleet Server. This lab currently demonstrates policy and integration management.",
  activity:
    "This is a session activity list, not a durable security audit log.",
};
const createLabels = {
  rules: "Create rule",
  cases: "Open case",
  policies: "Create policy",
  integrations: "Assign integration",
};
let view = "rules",
  page = 1,
  tab = "all",
  search = "",
  rows = [],
  total = 0,
  loadId = 0,
  formMode = "",
  selected = null,
  toastTimer,
  focusedBeforeDrawer;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Kibana-Rs": "1",
      ...options.headers,
    },
  });
  const body = await response.text();
  let data;
  try {
    data = body ? JSON.parse(body) : {};
  } catch {
    throw new Error(
      `The server returned an unexpected response (${response.status}).`,
    );
  }
  if (!response.ok)
    throw new Error(
      data.error || data.message || `Request failed (${response.status})`,
    );
  return data;
}
function toast(message) {
  clearTimeout(toastTimer);
  $("toast").textContent = message;
  $("toast").classList.remove("hidden");
  toastTimer = setTimeout(() => $("toast").classList.add("hidden"), 5000);
}
function showError(message) {
  $("page-error").textContent = message;
  $("page-error").classList.remove("hidden");
}
async function refreshMeta() {
  try {
    const [status, summary] = await Promise.all([
      api("/api/status"),
      api("/api/summary"),
    ]);
    $("connection").innerHTML =
      `<span class="dot ${status.health === "available" ? "" : "pending"}"></span>Kibana ${esc(status.version || "unknown")} ${status.health === "available" ? "connected" : esc(status.health)}`;
    $("footer-connection").innerHTML =
      `<span class="dot ${status.health === "available" ? "" : "pending"}"></span>Security lab · ${esc(status.health || "Unknown status")}`;
    for (const key of ["rules", "cases", "policies", "agents"])
      $("count-" + key).textContent = summary[key].toLocaleString();
    $("nav-rules").textContent = summary.rules;
    $("nav-cases").textContent = summary.cases;
  } catch (e) {
    $("connection").innerHTML =
      `<span class="dot failed"></span>Connection error`;
    $("footer-connection").innerHTML =
      '<span class="dot failed"></span>Connection unavailable';
    showError(e.message);
  }
}
function configureView() {
  $("page-title").textContent = titles[view];
  $("breadcrumb").textContent = titles[view];
  $("page-subtitle").textContent = subtitles[view];
  $("context-note").textContent = notes[view];
  $("eyebrow").textContent = ["rules", "cases"].includes(view)
    ? "SECURITY OPERATIONS"
    : view === "activity"
      ? "WORKSPACE"
      : "FLEET MANAGEMENT";
  $("create").classList.toggle("hidden", !createLabels[view]);
  $("create-label").textContent = createLabels[view] || "";
  $("search").placeholder =
    `Search ${view === "policies" ? "policies" : view === "activity" ? "operations" : view}...`;
  document.querySelectorAll(".nav-item").forEach((el) => {
    el.classList.toggle("active", el.dataset.view === view);
    el.setAttribute(
      "aria-current",
      el.dataset.view === view ? "page" : "false",
    );
  });
  let tabs =
    view === "rules"
      ? [
          ["all", "All rules"],
          ["enabled", "Enabled"],
          ["disabled", "Disabled"],
        ]
      : view === "cases"
        ? [
            ["all", "All cases"],
            ["open", "Open"],
            ["closed", "Closed"],
          ]
        : view === "integrations"
          ? [
              ["installed", "Installed"],
              ["catalogue", "Catalogue"],
              ["assigned", "Assigned policies"],
            ]
          : [["all", titles[view]]];
  $("tabs").innerHTML = tabs
    .map(
      ([key, text]) =>
        `<button class="tab ${tab === key ? "active" : ""}" data-tab="${key}">${esc(text)}</button>`,
    )
    .join("");
}
async function navigate(next) {
  view = next;
  page = 1;
  tab = view === "integrations" ? "installed" : "all";
  search = "";
  $("search").value = "";
  closeDrawer();
  configureView();
  await load();
}
async function load() {
  const ticket = ++loadId;
  $("page-error").classList.add("hidden");
  $("content").innerHTML = '<div class="loading">Loading from Kibana...</div>';
  $("refresh").disabled = true;
  try {
    const endpoint =
      view === "integrations"
        ? tab === "assigned"
          ? "package-policies"
          : "integrations"
        : view;
    const result = await api(`/api/${endpoint}?page=${page}`);
    if (ticket !== loadId) return;
    rows = result.data || result.cases || result.items || [];
    total = result.total ?? rows.length;
    render();
    $("last-refresh").textContent =
      `Updated ${new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
  } catch (e) {
    if (ticket !== loadId) return;
    rows = [];
    total = 0;
    showError(e.message);
    $("content").innerHTML = empty(
      "Could not load this view",
      "The request failed. Refresh to try again.",
      "info",
    );
    $("result-count").textContent = "Request failed";
  } finally {
    if (ticket === loadId) $("refresh").disabled = false;
  }
}
function empty(title, description, name = "grid") {
  return `<div class="empty">${icon(name)}<h3>${esc(title)}</h3><div>${esc(description)}</div></div>`;
}
function render() {
  let filtered = rows.filter((row) =>
    JSON.stringify([
      row.name,
      row.title,
      row.description,
      row.id,
      row.action,
      row.resource,
    ])
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  if (view === "rules" && tab !== "all")
    filtered = filtered.filter((r) => r.enabled === (tab === "enabled"));
  if (view === "cases" && tab !== "all")
    filtered = filtered.filter((r) => r.status === tab);
  if (view === "integrations" && tab === "installed")
    filtered = filtered.filter(
      (r) =>
        r.status === "installed" ||
        r.installationInfo?.install_status === "installed",
    );
  if (view === "integrations" && tab !== "assigned")
    filtered.sort((a, b) =>
      a.name === "system"
        ? -1
        : b.name === "system"
          ? 1
          : (a.title || a.name).localeCompare(b.title || b.name),
    );
  const catalogue = view === "integrations" && tab !== "assigned";
  const visible = catalogue
    ? filtered.slice((page - 1) * 24, page * 24)
    : filtered;
  if (view === "activity") renderActivity(filtered);
  else if (catalogue) renderIntegrations(visible);
  else if (visible.length) renderTable(visible);
  else
    $("content").innerHTML = empty(
      view === "agents"
        ? "No agents enrolled"
        : search
          ? "No matching results"
          : "No resources here yet",
      view === "agents"
        ? "Your agent policies are ready. Enroll an agent through Fleet Server to see it here."
        : search
          ? "Try a different search or filter."
          : "Create a resource to get started.",
      view === "agents" ? "monitor" : "grid",
    );
  const count = catalogue ? filtered.length : total;
  $("result-count").textContent = catalogue
    ? `${visible.length} of ${count.toLocaleString()} integrations`
    : `${visible.length} shown · ${total.toLocaleString()} total${search || !["all", "assigned"].includes(tab) ? " · filtered view" : ""}`;
  $("page-number").textContent = `Page ${page}`;
  $("previous").disabled = page <= 1;
  $("next").disabled = page * (catalogue ? 24 : 50) >= count;
  document
    .querySelector(".pagination")
    .classList.toggle("hidden", view === "activity");
}
function nameCell(row, title, subtitle, name = "shield", type = view) {
  return `<div class="name-cell"><span class="row-icon">${icon(name)}</span><div><button class="row-title" data-inspect="${type}" data-id="${esc(row.id)}">${esc(title)}</button><span class="row-sub">${esc(subtitle)}</span></div></div>`;
}
function renderTable(items) {
  let headings, body;
  if (view === "rules") {
    headings = ["Rule name", "Severity", "Status", "Updated", ""];
    body = items
      .map(
        (r) =>
          `<tr><td>${nameCell(r, r.name, `${r.type === "query" ? "Custom query" : label(r.type)} · ${r.tags?.includes("demo") ? "Demo rule" : "Security rule"}`)}</td><td>${badge(r.severity)}</td><td><button class="badge status-button ${r.enabled ? "enabled" : "disabled"}" data-toggle-rule="${esc(r.id)}" data-enabled="${!r.enabled}" aria-label="${r.enabled ? "Disable" : "Enable"} ${esc(r.name)}">${r.enabled ? '<span class="dot"></span>' : ""}${r.enabled ? "Enabled" : "Disabled"}</button></td><td>${date(r.updated_at)}</td><td><button class="row-more" aria-label="View ${esc(r.name)}" data-inspect="rules" data-id="${esc(r.id)}">${icon("arrow")}</button></td></tr>`,
      )
      .join("");
  } else if (view === "cases") {
    headings = ["Case", "Severity", "Status", "Created", ""];
    body = items
      .map(
        (r) =>
          `<tr><td>${nameCell(r, r.title, `${r.totalComment || 0} comments · Security`, "case")}</td><td>${badge(r.severity)}</td><td>${badge(r.status)}</td><td>${date(r.created_at)}</td><td><button class="row-more" aria-label="View case" data-inspect="cases" data-id="${esc(r.id)}">${icon("arrow")}</button></td></tr>`,
      )
      .join("");
  } else if (view === "policies") {
    headings = [
      "Agent policy",
      "Namespace",
      "Revision",
      "Integrations",
      "Agents",
    ];
    body = items
      .map(
        (r) =>
          `<tr><td>${nameCell(r, r.name, r.description || "Agent configuration", "policy")}</td><td><span class="tag">${esc(r.namespace)}</span></td><td>Revision ${r.revision}</td><td>${r.package_policies?.length || 0} assigned</td><td>${r.agents ?? 0}</td></tr>`,
      )
      .join("");
  } else if (view === "integrations") {
    headings = ["Integration policy", "Package", "Version", "Namespace", ""];
    body = items
      .map(
        (r) =>
          `<tr><td>${nameCell(r, r.name, "Assigned to " + (r.policy_ids?.length || 1) + " agent policy", "grid", "package-policy")}</td><td>${esc(r.package?.name)}</td><td>${esc(r.package?.version)}</td><td><span class="tag">${esc(r.namespace)}</span></td><td>${badge("installed", "Assigned")}</td></tr>`,
      )
      .join("");
  } else {
    headings = ["Agent", "Status", "Policy", "Active"];
    body = items
      .map(
        (r) =>
          `<tr><td>${esc(r.local_metadata?.host?.hostname || r.id)}</td><td>${badge(r.status)}</td><td>${esc(r.policy_id)}</td><td>${r.active ? "Yes" : "No"}</td></tr>`,
      )
      .join("");
  }
  $("content").innerHTML =
    `<div class="table-scroll"><table data-view="${view}"><thead><tr>${headings.map((h) => `<th scope="col">${h}</th>`).join("")}</tr></thead><tbody>${body}</tbody></table></div>`;
}
function renderIntegrations(items) {
  if (!items.length) {
    $("content").innerHTML = empty(
      "No integrations found",
      "Choose Catalogue to browse available packages.",
    );
    return;
  }
  $("content").innerHTML = `<div class="integration-grid">${items
    .map((r) => {
      const installed =
        r.status === "installed" ||
        r.installationInfo?.install_status === "installed";
      const action =
        installed && !r.policy_templates?.length
          ? '<span class="tag">Assets only</span>'
          : `<button class="button small secondary" ${installed ? `data-assign="${esc(r.name)}" data-version="${esc(r.version)}"` : `data-install="${esc(r.name)}" data-version="${esc(r.version)}"`}>${installed ? "Assign to policy" : "Install package"}${icon("arrow")}</button>`;
      return `<article class="integration-card"><div class="integration-top"><span class="package-icon">${esc(r.name.slice(0, 2).toUpperCase())}</span>${badge(installed ? "installed" : "available")}</div><h3>${esc(r.title || r.name)}</h3><p>${esc(r.description || "Elastic integration package")}</p><div class="integration-bottom"><span>v${esc(r.version)}</span>${action}</div></article>`;
    })
    .join("")}</div>`;
}
function renderActivity(items) {
  $("content").innerHTML = items.length
    ? `<div class="activity-list">${items.map((r) => `<div class="activity-row"><span>${icon("check")}</span><div><p>${esc(r.action)}</p><small>${esc(r.resource)}</small></div><time>${new Date(r.time * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</time></div>`).join("")}</div>`
    : empty(
        "No operations this session",
        "Changes made here will appear after Kibana confirms them.",
        "activity",
      );
}
function closeDrawer() {
  $("drawer").classList.add("hidden");
  $("drawer-overlay").classList.add("hidden");
  selected = null;
  if (focusedBeforeDrawer?.isConnected) focusedBeforeDrawer.focus();
}
async function inspect(type, id) {
  focusedBeforeDrawer = document.activeElement;
  $("drawer").classList.remove("hidden");
  $("drawer-overlay").classList.remove("hidden");
  $("drawer").innerHTML = '<div class="loading">Loading details...</div>';
  $("drawer").focus();
  try {
    const item =
      type === "package-policy"
        ? rows.find((r) => r.id === id)
        : await api(`/api/${type}/${encodeURIComponent(id)}`);
    if ($("drawer").classList.contains("hidden")) return;
    selected = { type, item };
    let content = "";
    if (type === "rules")
      content = `<div class="detail-grid"><div><small>Severity</small>${badge(item.severity)}</div><div><small>Status</small>${badge(item.enabled ? "enabled" : "disabled")}</div><div><small>Rule type</small><strong>${esc(label(item.type))}</strong></div><div><small>Risk score</small><strong>${esc(item.risk_score)}</strong></div></div><h3>Description</h3><p>${esc(item.description)}</p><h3>Detection query</h3><pre>${esc(item.query || "No query field for this rule type")}</pre><h3>Index patterns</h3><p>${esc(item.index?.join(", "))}</p><h3>Tags</h3>${(item.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join("")}<div class="drawer-actions"><button class="button primary" data-toggle-rule="${esc(id)}" data-enabled="${!item.enabled}">${item.enabled ? "Disable rule" : "Enable rule"}</button><button class="button secondary" data-edit="rule">Edit rule</button><button class="button danger" data-delete="rules" data-id="${esc(id)}">Delete</button></div>`;
    if (type === "policies")
      content = `<div class="detail-grid"><div><small>Namespace</small><strong>${esc(item.namespace)}</strong></div><div><small>Revision</small><strong>${item.revision}</strong></div><div><small>Enrolled agents</small><strong>${item.agents ?? 0}</strong></div><div><small>Integrations</small><strong>${item.package_policies?.length || 0}</strong></div></div><h3>Description</h3><p>${esc(item.description || "No description")}</p><h3>Assigned integrations</h3>${item.package_policies?.length ? item.package_policies.map((p) => `<p>${esc(typeof p === "string" ? p : p.name)}</p>`).join("") : "<p>No integration policies assigned yet.</p>"}<div class="drawer-actions"><button class="button primary" data-assign-policy="${esc(id)}">Assign integration</button><button class="button secondary" data-edit="policy">Edit policy</button><button class="button danger" data-delete="policies" data-id="${esc(id)}">Delete</button></div>`;
    if (type === "cases")
      content = `<div class="detail-grid"><div><small>Severity</small>${badge(item.severity)}</div><div><small>Status</small>${badge(item.status)}</div></div><h3>Description</h3><p>${esc(item.description)}</p><div class="drawer-actions">${[
        "open",
        "in-progress",
        "closed",
      ]
        .filter((s) => s !== item.status)
        .map(
          (s) =>
            `<button class="button secondary" data-case-status="${s}">${s === "closed" ? "Close case" : s === "in-progress" ? "Start investigation" : "Reopen"}</button>`,
        )
        .join(
          "",
        )}<button class="button danger" data-delete="cases" data-id="${esc(id)}">Delete</button></div><h3>Investigation notes</h3><div id="case-comments" class="loading">Loading comments...</div><label class="field">Add a note<textarea id="comment-text" placeholder="What did you find?" maxlength="5000"></textarea></label><button class="button primary" id="add-comment">Add note</button>`;
    if (type === "package-policy")
      content = `<div class="detail-grid"><div><small>Package</small><strong>${esc(item.package.name)}</strong></div><div><small>Version</small><strong>${esc(item.package.version)}</strong></div><div><small>Namespace</small><strong>${esc(item.namespace)}</strong></div><div><small>Revision</small><strong>${item.revision}</strong></div></div><h3>Agent policies</h3><p>${esc(item.policy_ids?.join("\n"))}</p><h3>Configured inputs</h3><pre>${esc(JSON.stringify(item.inputs, null, 2))}</pre><div class="drawer-actions"><button class="button danger" data-delete="package-policies" data-id="${esc(id)}">Remove assignment</button></div>`;
    $("drawer").innerHTML =
      `<div class="drawer-heading"><div><div class="eyebrow">${type === "package-policy" ? "INTEGRATION POLICY" : esc(titles[type])}</div><h2 id="drawer-title">${esc(item.name || item.title)}</h2><span class="row-sub">${esc(item.id)}</span></div><button class="close-button" id="close-drawer" aria-label="Close details">${icon("close")}</button></div>${content}`;
    if (type === "cases") {
      const comments = await api(
        `/api/cases/${encodeURIComponent(id)}/comments`,
      );
      if (selected?.item.id !== id) return;
      $("case-comments").classList.remove("loading");
      $("case-comments").innerHTML = comments.comments?.length
        ? comments.comments
            .map(
              (c) =>
                `<div class="comment-card"><p>${esc(c.comment || "Alert attachment")}</p><small>${date(c.created_at)}</small></div>`,
            )
            .join("")
        : "<p>No notes yet.</p>";
    }
  } catch (e) {
    $("drawer").innerHTML =
      `<button class="close-button" id="close-drawer" aria-label="Close">${icon("close")}</button><p>${esc(e.message)}</p>`;
  }
}
function field(name, title, value = "", type = "text", help = "") {
  return `<label class="field">${esc(title)}${type === "textarea" ? `<textarea name="${name}" required maxlength="5000">${esc(value)}</textarea>` : `<input name="${name}" type="${type}" value="${esc(value)}" required maxlength="${name === "title" ? "160" : "255"}">`}${help ? `<small>${esc(help)}</small>` : ""}</label>`;
}
function severityField() {
  return '<label class="field">Severity<select name="severity" aria-label="Severity"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>';
}
async function openForm(mode, preset = {}) {
  formMode = mode;
  const item = selected?.item;
  $("form-error").classList.add("hidden");
  $("submit-form").disabled = false;
  $("submit-form").textContent = mode.startsWith("edit")
    ? "Save changes"
    : mode === "assign"
      ? "Assign integration"
      : "Create";
  let html;
  if (mode === "rules" || mode === "edit-rule") {
    $("form-title").textContent =
      mode === "rules" ? "Create detection rule" : "Edit detection rule";
    html =
      field("name", "Rule name", mode === "edit-rule" ? item.name : "") +
      field(
        "description",
        "Description",
        mode === "edit-rule" ? item.description : "",
        "textarea",
      ) +
      field(
        "query",
        "KQL query",
        mode === "edit-rule"
          ? item.query
          : "event.category: authentication and event.outcome: failure",
        "textarea",
      );
    if (mode === "rules")
      html += `<div class="form-row">${severityField()}${field("index", "Index pattern", "logs-*")}</div><p class="row-sub">This rule will be created disabled.</p>`;
  } else if (mode === "cases") {
    $("form-title").textContent = "Open a security case";
    html =
      field("title", "Case title") +
      field("description", "Description", "", "textarea") +
      severityField();
  } else if (mode === "policies" || mode === "edit-policy") {
    $("form-title").textContent =
      mode === "policies" ? "Create agent policy" : "Edit agent policy";
    html =
      field("name", "Policy name", mode === "edit-policy" ? item.name : "") +
      field(
        "namespace",
        "Namespace",
        mode === "edit-policy" ? item.namespace : "default",
      ) +
      field(
        "description",
        "Description",
        mode === "edit-policy" ? item.description || "" : "",
        "textarea",
      );
  } else if (mode === "assign") {
    $("form-title").textContent = "Assign an integration";
    $("form-fields").innerHTML =
      '<div class="loading">Loading packages and policies...</div>';
    $("form-dialog").showModal();
    try {
      const [packages, policies] = await Promise.all([
        api("/api/integrations"),
        api("/api/policies"),
      ]);
      const installed = packages.items.filter(
        (p) =>
          (p.status === "installed" ||
            p.installationInfo?.install_status === "installed") &&
          p.policy_templates?.length,
      );
      if (!installed.length || !policies.items.length)
        throw new Error(
          "Install an integration and create an agent policy first.",
        );
      html =
        field("name", "Integration policy name", "") +
        `<label class="field">Installed package<select name="package" aria-label="Installed package">${installed.map((p) => `<option value="${esc(p.name)}|${esc(p.version)}" ${preset.package === p.name ? "selected" : ""}>${esc(p.title || p.name)} · ${esc(p.version)}</option>`).join("")}</select></label><label class="field">Agent policy<select name="policy_id" aria-label="Agent policy">${policies.items.map((p) => `<option value="${esc(p.id)}" ${preset.policy === p.id ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>` +
        field("namespace", "Namespace", "default") +
        '<p class="row-sub">The integration will use its default input settings. Review them in Kibana before enrolling production agents.</p>';
    } catch (e) {
      $("form-fields").innerHTML =
        `<p class="form-error">${esc(e.message)}</p>`;
      $("submit-form").disabled = true;
      return;
    }
  }
  $("form-fields").innerHTML = html;
  if (!$("form-dialog").open) $("form-dialog").showModal();
  $("form-fields").querySelector("input,textarea,select")?.focus();
}
async function mutate(path, method, body, message) {
  const result = await api(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  toast(message);
  await Promise.all([load(), refreshMeta()]);
  return result;
}
$("resource-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = Object.fromEntries(new FormData(e.target));
  const button = $("submit-form");
  button.disabled = true;
  button.textContent = "Saving...";
  $("form-error").classList.add("hidden");
  try {
    if (formMode === "rules") {
      data.index = data.index
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      await mutate("/api/rules", "POST", data, "Detection rule created");
    } else if (formMode === "cases")
      await mutate("/api/cases", "POST", data, "Security case opened");
    else if (formMode === "policies")
      await mutate("/api/policies", "POST", data, "Agent policy created");
    else if (formMode === "edit-rule")
      await mutate(
        `/api/rules/${encodeURIComponent(selected.item.id)}`,
        "PATCH",
        data,
        "Detection rule updated",
      );
    else if (formMode === "edit-policy")
      await mutate(
        `/api/policies/${encodeURIComponent(selected.item.id)}`,
        "PUT",
        data,
        "Agent policy updated",
      );
    else {
      const [name, version] = data.package.split("|");
      data.package = name;
      data.version = version;
      await mutate(
        "/api/package-policies",
        "POST",
        data,
        "Integration assigned to policy",
      );
    }
    $("form-dialog").close();
    closeDrawer();
  } catch (e) {
    $("form-error").textContent = e.message;
    $("form-error").classList.remove("hidden");
  } finally {
    button.disabled = false;
    button.textContent = "Save";
  }
});
document.addEventListener("click", async (e) => {
  const el = e.target.closest("button");
  if (!el || el.disabled) return;
  try {
    if (el.dataset.view) {
      await navigate(el.dataset.view);
      return;
    }
    if (el.dataset.tab) {
      tab = el.dataset.tab;
      page = 1;
      configureView();
      if (view === "integrations") await load();
      else render();
      return;
    }
    if (el.dataset.inspect) {
      await inspect(el.dataset.inspect, el.dataset.id);
      return;
    }
    if (el.dataset.toggleRule) {
      el.disabled = true;
      await mutate(
        `/api/rules/${encodeURIComponent(el.dataset.toggleRule)}`,
        "PATCH",
        { enabled: el.dataset.enabled === "true" },
        "Rule status updated",
      );
      if (selected?.type === "rules")
        await inspect("rules", el.dataset.toggleRule);
      return;
    }
    if (el.dataset.install) {
      el.disabled = true;
      el.textContent = "Installing...";
      await mutate(
        `/api/integrations/${encodeURIComponent(el.dataset.install)}/${encodeURIComponent(el.dataset.version)}/install`,
        "POST",
        {},
        "Integration installed",
      );
      return;
    }
    if (el.dataset.assign) {
      await openForm("assign", { package: el.dataset.assign });
      return;
    }
    if (el.dataset.assignPolicy) {
      await openForm("assign", { policy: el.dataset.assignPolicy });
      return;
    }
    if (el.dataset.edit) {
      await openForm("edit-" + el.dataset.edit);
      return;
    }
    if (el.dataset.delete) {
      if (!confirm("Delete this resource from the isolated Security lab?"))
        return;
      el.disabled = true;
      await mutate(
        `/api/${el.dataset.delete}/${encodeURIComponent(el.dataset.id)}`,
        "DELETE",
        undefined,
        "Resource deleted",
      );
      closeDrawer();
      return;
    }
    if (el.dataset.caseStatus) {
      const id = selected.item.id;
      el.disabled = true;
      await mutate(
        `/api/cases/${encodeURIComponent(id)}`,
        "PATCH",
        { version: selected.item.version, status: el.dataset.caseStatus },
        "Case status updated",
      );
      await inspect("cases", id);
      return;
    }
    if (el.id === "add-comment") {
      const text = $("comment-text").value.trim();
      if (!text) return;
      el.disabled = true;
      const id = selected.item.id;
      await mutate(
        `/api/cases/${encodeURIComponent(id)}/comments`,
        "POST",
        { comment: text },
        "Investigation note added",
      );
      await inspect("cases", id);
      return;
    }
  } catch (err) {
    toast(err.message);
    el.disabled = false;
    if (el.dataset.install) el.textContent = "Install package";
  }
});
$("create").addEventListener("click", () =>
  openForm(view === "integrations" ? "assign" : view),
);
$("refresh").addEventListener("click", () =>
  Promise.all([load(), refreshMeta()]),
);
$("search").addEventListener("input", (e) => {
  search = e.target.value;
  if (view === "integrations" && tab !== "assigned") page = 1;
  render();
});
$("previous").addEventListener("click", () => {
  page--;
  if (view === "integrations" && tab !== "assigned") render();
  else load();
});
$("next").addEventListener("click", () => {
  page++;
  if (view === "integrations" && tab !== "assigned") render();
  else load();
});
for (const id of ["close-form", "cancel-form"])
  $(id).addEventListener("click", () => $("form-dialog").close());
$("drawer-overlay").addEventListener("click", closeDrawer);
document.addEventListener("click", (e) => {
  if (e.target.closest("#close-drawer")) closeDrawer();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("form-dialog").open) closeDrawer();
  if (
    e.key === "Tab" &&
    !$("drawer").classList.contains("hidden") &&
    !$("form-dialog").open
  ) {
    const items = [
      ...$("drawer").querySelectorAll(
        "button:not([disabled]),textarea,input,select,a[href]",
      ),
    ];
    const first = items[0],
      last = items.at(-1);
    if (
      e.shiftKey &&
      (document.activeElement === first ||
        document.activeElement === $("drawer"))
    ) {
      e.preventDefault();
      last?.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first?.focus();
    }
  }
});
configureView();
Promise.all([load(), refreshMeta()]);
