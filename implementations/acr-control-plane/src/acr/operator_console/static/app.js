const state = {
  operatorApiKey: "",
  killswitchSecret: "",
  currentPolicyDraftId: null,
  sessionPrincipal: null,
};

function setMessage(message, isError = false) {
  const el = document.getElementById("global-message");
  el.textContent = message;
  el.classList.remove("hidden", "error");
  if (isError) el.classList.add("error");
}

function clearMessage() {
  document.getElementById("global-message").classList.add("hidden");
}

function sessionHeaders(extra = {}) {
  const headers = { ...extra };
  if (state.operatorApiKey) headers["X-Operator-API-Key"] = state.operatorApiKey;
  if (state.killswitchSecret) headers["X-Killswitch-Secret"] = state.killswitchSecret;
  return headers;
}

async function apiFetch(path, options = {}) {
  const headers = sessionHeaders(options.headers || {});
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  let payload = text;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch (_) {}
  if (!response.ok) {
    throw new Error(typeof payload === "string" ? payload : JSON.stringify(payload));
  }
  return payload;
}

function renderTable(targetId, rows, columns) {
  const target = document.getElementById(targetId);
  if (!rows || rows.length === 0) {
    target.innerHTML = `<p class="hint">No data available.</p>`;
    return;
  }
  const head = columns.map((column) => `<th>${column.label}</th>`).join("");
  const body = rows
    .map((row) => {
      const cells = columns
        .map((column) => `<td>${column.render ? column.render(row) : escapeHtml(row[column.key])}</td>`)
        .join("");
      return `<tr>${cells}</tr>`;
    })
    .join("");
  target.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function renderStack(targetId, rows, template) {
  const target = document.getElementById(targetId);
  if (!rows || rows.length === 0) {
    target.innerHTML = `<p class="hint">No data available.</p>`;
    return;
  }
  target.innerHTML = `<div class="stack-list">${rows.map(template).join("")}</div>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function compactJson(value) {
  return escapeHtml(JSON.stringify(value, null, 2));
}

function policyTemplateDefaults(template) {
  const defaults = {
    customer_support: {
      allowedTools: ["query_customer_db", "send_email", "create_ticket", "issue_refund"],
      forbiddenTools: ["delete_customer", "modify_billing"],
      escalateTool: "issue_refund",
      approvalQueue: "finance-approvals",
      piiFields: ["body", "notes"],
    },
    finance_ops: {
      allowedTools: ["issue_refund", "close_invoice", "send_email"],
      forbiddenTools: ["delete_ledger", "wire_transfer"],
      escalateTool: "issue_refund",
      approvalQueue: "finance-approvals",
      piiFields: ["memo", "body"],
    },
    research_assistant: {
      allowedTools: ["web_search", "summarize_docs", "create_brief"],
      forbiddenTools: ["send_email", "delete_customer"],
      escalateTool: "publish_report",
      approvalQueue: "editorial-review",
      piiFields: ["summary", "notes"],
    },
    it_automation: {
      allowedTools: ["create_ticket", "restart_service", "read_logs"],
      forbiddenTools: ["drop_database", "delete_cluster"],
      escalateTool: "restart_service",
      approvalQueue: "sre-approvals",
      piiFields: ["ticket_body", "notes"],
    },
  };
  return defaults[template] || defaults.customer_support;
}

function generatePolicyStarter(formData) {
  const template = policyTemplateDefaults(formData.template);
  const allowedTools = (formData.allowed_tools ? formData.allowed_tools.split(",") : template.allowedTools)
    .map((item) => item.trim())
    .filter(Boolean);
  const forbiddenTools = (formData.forbidden_tools ? formData.forbidden_tools.split(",") : template.forbiddenTools)
    .map((item) => item.trim())
    .filter(Boolean);
  const piiFields = (formData.pii_fields ? formData.pii_fields.split(",") : template.piiFields)
    .map((item) => item.trim())
    .filter(Boolean);
  const escalateTool = (formData.escalate_tool || template.escalateTool || "").trim();
  const approvalQueue = (formData.approval_queue || template.approvalQueue || "default").trim();
  const spendLimit = Number(formData.max_cost_per_hour_usd || 5);
  const actionLimit = Number(formData.max_actions_per_minute || 30);
  const defaultActionCost = formData.default_action_cost_usd ? Number(formData.default_action_cost_usd) : null;
  const toolCosts = parseJsonField(formData.tool_costs_usd_json, {});
  const escalationThreshold = formData.escalate_over_amount ? Number(formData.escalate_over_amount) : null;

  const manifest = {
    agent_id: formData.agent_id,
    owner: formData.owner,
    purpose: formData.purpose,
    risk_tier: formData.risk_tier,
    allowed_tools: allowedTools,
    forbidden_tools: forbiddenTools,
    boundaries: {
      max_actions_per_minute: actionLimit,
      max_cost_per_hour_usd: spendLimit,
      default_action_cost_usd: defaultActionCost,
      tool_costs_usd: toolCosts,
      credential_rotation_days: 90,
      allowed_regions: [],
    },
  };

  const policyLines = [
    `package acr`,
    ``,
    `import future.keywords.contains`,
    `import future.keywords.if`,
    ``,
    `# Starter policy generated by the ACR operator console`,
    `# Template: ${formData.template}`,
    ``,
  ];

  piiFields.forEach((field) => {
    policyLines.push(
      `deny contains reason if {`,
      `    input.action.tool_name == "send_email"`,
      `    value := input.action.parameters.${field}`,
      `    regex.match(\`\\d{3}-\\d{2}-\\d{4}\`, value)`,
      `    reason := "PII detected in outbound ${field}: SSN pattern found"`,
      `}`,
      ``
    );
  });

  if (escalateTool) {
    if (escalationThreshold !== null && !Number.isNaN(escalationThreshold)) {
      policyLines.push(
        `escalate if {`,
        `    input.action.tool_name == "${escalateTool}"`,
        `    amount := input.action.parameters.amount`,
        `    amount > ${escalationThreshold}`,
        `}`,
        ``,
        `escalate_queue := "${approvalQueue}" if {`,
        `    input.action.tool_name == "${escalateTool}"`,
        `    input.action.parameters.amount > ${escalationThreshold}`,
        `}`,
        ``
      );
    } else {
      policyLines.push(
        `escalate if {`,
        `    input.action.tool_name == "${escalateTool}"`,
        `}`,
        ``,
        `escalate_queue := "${approvalQueue}" if {`,
        `    input.action.tool_name == "${escalateTool}"`,
        `}`,
        ``
      );
    }
  }

  forbiddenTools.forEach((tool) => {
    policyLines.push(
      `deny contains reason if {`,
      `    input.action.tool_name == "${tool}"`,
      `    reason := "Forbidden tool: ${tool}"`,
      `}`,
      ``
    );
  });

  policyLines.push(
    `# Notes for the operator team:`,
    `# - Review queue ownership for ${approvalQueue}`,
    `# - Tune max actions/minute and spend ceilings to match real risk`,
    `# - Add additional deny and escalation rules for sensitive data access`,
    ``
  );

  return {
    manifest,
    rego: policyLines.join("\n"),
  };
}

async function copyTextFrom(id) {
  const text = document.getElementById(id).textContent;
  await navigator.clipboard.writeText(text);
}

function readForm(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function parseJsonField(rawValue, fallback = {}) {
  if (!rawValue || !rawValue.trim()) return fallback;
  return JSON.parse(rawValue);
}

function updateSessionUI() {
  document.getElementById("operator-api-key").value = state.operatorApiKey;
  document.getElementById("killswitch-secret").value = state.killswitchSecret;
  const pill = document.getElementById("session-state");
  if (state.sessionPrincipal) {
    pill.textContent = `Signed in as ${state.sessionPrincipal.subject} via ${state.sessionPrincipal.source}`;
    pill.className = "status-pill good";
  } else if (state.operatorApiKey) {
    pill.textContent = "Operator API key configured";
    pill.className = "status-pill good";
  } else {
    pill.textContent = "Session not configured";
    pill.className = "status-pill neutral";
  }
}

async function loadSessionPrincipal() {
  try {
    state.sessionPrincipal = await apiFetch("/acr/auth/session");
  } catch (_) {
    state.sessionPrincipal = null;
  }
  updateSessionUI();
}

async function loadOverview() {
  const [healthResult, readyResult, approvalsResult, containmentResult] = await Promise.allSettled([
    apiFetch("/acr/health"),
    apiFetch("/acr/ready"),
    apiFetch("/acr/approvals"),
    apiFetch("/acr/containment/status"),
  ]);

  const health = healthResult.status === "fulfilled" ? healthResult.value : { status: "unavailable" };
  const ready = readyResult.status === "fulfilled" ? readyResult.value : { status: "unavailable" };
  const approvals = approvalsResult.status === "fulfilled" ? approvalsResult.value : [];
  const containment = containmentResult.status === "fulfilled" ? containmentResult.value : [];

  document.getElementById("health-gateway").textContent = health.status;
  document.getElementById("health-ready").textContent = ready.status;
  document.getElementById("metric-approvals").textContent = approvals.length;
  document.getElementById("metric-killed").textContent = containment.length;

  renderStack(
    "overview-approvals",
    approvals.slice(0, 4),
    (item) => `<div class="stack-item"><strong>${escapeHtml(item.request_id)}</strong><div>${escapeHtml(item.agent_id)} · ${escapeHtml(item.tool_name)}</div><small>${escapeHtml(item.approval_queue)}</small></div>`
  );
  renderStack(
    "overview-containment",
    containment.slice(0, 4),
    (item) => `<div class="stack-item"><strong>${escapeHtml(item.agent_id)}</strong><div>${escapeHtml(item.reason || "Contained")}</div><small>${escapeHtml(item.killed_by || "unknown")}</small></div>`
  );
}

async function loadAgents() {
  const agents = await apiFetch("/acr/agents");
  renderTable("agents-table", agents, [
    { label: "Agent", key: "agent_id" },
    { label: "Owner", key: "owner" },
    { label: "Purpose", key: "purpose" },
    { label: "Risk", key: "risk_tier" },
    { label: "Status", render: (row) => (row.is_active ? "active" : "inactive") },
  ]);
}

async function loadOperatorKeys() {
  const rows = await apiFetch("/acr/operator-keys");
  renderTable("operator-keys-table", rows, [
    { label: "Key ID", key: "key_id" },
    { label: "Name", key: "name" },
    { label: "Subject", key: "subject" },
    { label: "Roles", render: (row) => escapeHtml((row.roles || []).join(", ")) },
    { label: "Active", render: (row) => String(row.is_active) },
    { label: "Last Used", render: (row) => escapeHtml(row.last_used_at || "") },
  ]);
}

async function loadPolicyDrafts() {
  const rows = await apiFetch("/acr/policy-drafts");
  renderTable("policy-drafts-table", rows, [
    { label: "Draft ID", key: "draft_id" },
    { label: "Name", key: "name" },
    { label: "Agent", key: "agent_id" },
    { label: "Template", key: "template" },
    { label: "Updated By", key: "updated_by" },
  ]);
}

async function loadPolicyReleases() {
  const rows = await apiFetch("/acr/policy-drafts/releases/history");
  renderTable("policy-releases-table", rows, [
    { label: "Release ID", key: "release_id" },
    { label: "Agent", key: "agent_id" },
    { label: "Version", render: (row) => String(row.version) },
    { label: "Status", key: "status" },
    { label: "Activation", key: "activation_status" },
    { label: "Backend", key: "publish_backend" },
    { label: "Artifact", render: (row) => escapeHtml(row.artifact_uri || "") },
    { label: "Active Bundle", render: (row) => escapeHtml(row.active_bundle_uri || "") },
    { label: "Activated By", key: "activated_by" },
    { label: "Published By", key: "published_by" },
    { label: "Rollback From", key: "rollback_from_release_id" },
  ]);
}

async function loadApprovals() {
  const approvals = await apiFetch("/acr/approvals");
  renderTable("approvals-table", approvals, [
    { label: "Request", key: "request_id" },
    { label: "Agent", key: "agent_id" },
    { label: "Tool", key: "tool_name" },
    { label: "Queue", key: "approval_queue" },
    { label: "Status", key: "status" },
  ]);
}

async function loadEvents(params = {}) {
  const query = new URLSearchParams();
  if (params.agent_id) query.set("agent_id", params.agent_id);
  if (params.event_type) query.set("event_type", params.event_type);
  const suffix = query.toString() ? `?${query}` : "";
  const events = await apiFetch(`/acr/events${suffix}`);
  renderTable("events-table", events, [
    { label: "Event", render: (row) => escapeHtml(row.event_type) },
    { label: "Agent", render: (row) => escapeHtml(row.agent?.agent_id || "") },
    { label: "Decision", render: (row) => escapeHtml(row.output?.decision || "") },
    { label: "Tool", render: (row) => escapeHtml(row.request?.tool_name || "") },
    { label: "Request", render: (row) => escapeHtml(row.request?.request_id || "") },
  ]);
}

async function loadDecisions(params = {}) {
  const query = new URLSearchParams();
  ["agent_id", "tool_name", "decision", "enforcement_mode", "reason_contains", "correlation_id", "window_start", "window_end"].forEach((key) => {
    if (params[key]) query.set(key, params[key]);
  });
  query.set("limit", "50");
  const suffix = query.toString() ? `?${query}` : "";
  const payload = await apiFetch(`/acr/decisions${suffix}`);
  renderTable("decisions-table", payload.items, [
    { label: "Created", key: "created_at" },
    { label: "Agent", key: "agent_id" },
    { label: "Decision", key: "decision" },
    { label: "Mode", key: "enforcement_mode" },
    { label: "Tool", key: "tool_name" },
    { label: "Seq", render: (row) => String(row.sequence ?? "") },
    { label: "Correlation", key: "correlation_id" },
  ]);
}

async function loadMetrics() {
  const response = await fetch("/acr/metrics", { headers: sessionHeaders() });
  const text = await response.text();
  if (!response.ok) throw new Error(text);
  document.getElementById("metrics-output").textContent = text;
}

async function loadContainment() {
  const rows = await apiFetch("/acr/containment/status");
  renderTable("containment-table", rows, [
    { label: "Agent", key: "agent_id" },
    { label: "Killed", render: (row) => String(row.is_killed) },
    { label: "Reason", key: "reason" },
    { label: "By", key: "killed_by" },
  ]);
}

async function loadBaselineVersions(agentId = "") {
  if (!agentId) {
    document.getElementById("drift-versions-table").innerHTML = `<p class="hint">Enter an agent_id to inspect governed baseline versions.</p>`;
    return;
  }
  const rows = await apiFetch(`/acr/drift/${encodeURIComponent(agentId)}/baseline/versions`);
  renderTable("drift-versions-table", rows, [
    { label: "Version", key: "baseline_version_id" },
    { label: "Status", key: "status" },
    { label: "Samples", render: (row) => String(row.sample_count) },
    { label: "Window", render: (row) => `${row.window_days}d` },
    { label: "Created By", key: "created_by" },
    { label: "Activated By", key: "activated_by" },
    { label: "Notes", render: (row) => escapeHtml(row.notes || "") },
  ]);
}

async function refreshDashboard() {
  clearMessage();
  const results = await Promise.allSettled([
    loadOverview(),
    loadOperatorKeys(),
    loadPolicyDrafts(),
    loadPolicyReleases(),
    loadAgents(),
    loadApprovals(),
    loadEvents(),
    loadDecisions(),
    loadContainment(),
    loadBaselineVersions(),
    loadMetrics(),
  ]);
  const failures = results.filter((result) => result.status === "rejected");
  if (failures.length) {
    setMessage("Dashboard refreshed with limited access. Some panels are unavailable for this operator.", true);
  } else {
    setMessage("Dashboard refreshed.");
  }
}

function installNavigation() {
  document.querySelectorAll(".nav-link").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach((node) => node.classList.remove("active"));
      document.querySelectorAll(".page").forEach((node) => node.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(button.dataset.section).classList.add("active");
    });
  });
}

function installSessionControls() {
  document.getElementById("oidc-login").addEventListener("click", () => {
    window.location.href = "/acr/auth/oidc/login";
  });
  document.getElementById("oidc-logout").addEventListener("click", async () => {
    try {
      await apiFetch("/acr/auth/logout", { method: "POST" });
      state.sessionPrincipal = null;
      updateSessionUI();
      setMessage("SSO session cleared.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });
  document.getElementById("save-session").addEventListener("click", () => {
    state.operatorApiKey = document.getElementById("operator-api-key").value.trim();
    state.killswitchSecret = document.getElementById("killswitch-secret").value.trim();
    updateSessionUI();
    setMessage("Operator session loaded for this tab only.");
  });
  document.getElementById("clear-session").addEventListener("click", () => {
    state.operatorApiKey = "";
    state.killswitchSecret = "";
    document.getElementById("operator-api-key").value = "";
    document.getElementById("killswitch-secret").value = "";
    updateSessionUI();
    setMessage("Operator session cleared.");
  });
}

function installForms() {
  document.getElementById("agent-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = readForm(event.target);
      const payload = {
        agent_id: data.agent_id,
        owner: data.owner,
        purpose: data.purpose,
        allowed_tools: data.allowed_tools ? data.allowed_tools.split(",").map((item) => item.trim()).filter(Boolean) : [],
        forbidden_tools: data.forbidden_tools ? data.forbidden_tools.split(",").map((item) => item.trim()).filter(Boolean) : [],
        boundaries: {
          max_actions_per_minute: Number(data.max_actions_per_minute || 30),
          max_cost_per_hour_usd: Number(data.max_cost_per_hour_usd || 5),
          default_action_cost_usd: data.default_action_cost_usd ? Number(data.default_action_cost_usd) : null,
          tool_costs_usd: parseJsonField(data.tool_costs_usd_json, {}),
          credential_rotation_days: 90,
          allowed_regions: [],
        },
      };
      await apiFetch("/acr/agents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      await loadAgents();
      setMessage(`Agent ${data.agent_id} registered.`);
      event.target.reset();
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("policy-wizard-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const starter = generatePolicyStarter(readForm(event.target));
      document.getElementById("policy-manifest-output").textContent = JSON.stringify(starter.manifest, null, 2);
      document.getElementById("policy-rego-output").textContent = starter.rego;
      setMessage("Policy starter generated.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("save-policy-draft").addEventListener("click", async () => {
    try {
      const form = document.getElementById("policy-wizard-form");
      const formData = readForm(form);
      const starter = generatePolicyStarter(formData);
      const payload = {
        name: formData.draft_name || `${formData.agent_id} draft`,
        agent_id: formData.agent_id,
        template: formData.template,
        manifest: starter.manifest,
        rego_policy: starter.rego,
        wizard_inputs: formData,
      };
      const path = state.currentPolicyDraftId
        ? `/acr/policy-drafts/${encodeURIComponent(state.currentPolicyDraftId)}`
        : "/acr/policy-drafts";
      const method = state.currentPolicyDraftId ? "PUT" : "POST";
      const draft = await apiFetch(path, {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      state.currentPolicyDraftId = draft.draft_id;
      document.getElementById("policy-manifest-output").textContent = JSON.stringify(draft.manifest, null, 2);
      document.getElementById("policy-rego-output").textContent = draft.rego_policy;
      await loadPolicyDrafts();
      setMessage(`Policy draft ${draft.draft_id} saved.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("operator-key-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const data = readForm(event.target);
      const payload = await apiFetch("/acr/operator-keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: data.name,
          subject: data.subject,
          roles: data.roles.split(",").map((item) => item.trim()).filter(Boolean),
        }),
      });
      document.getElementById("operator-key-output").textContent = JSON.stringify(payload, null, 2);
      await loadOperatorKeys();
      setMessage(`Operator key ${payload.key_id} created. Copy the api_key now.`);
      event.target.reset();
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.querySelectorAll("[data-operator-key-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const { key_id } = readForm(document.getElementById("operator-key-manage-form"));
      try {
        const path = `/acr/operator-keys/${encodeURIComponent(key_id)}/${button.dataset.operatorKeyAction}`;
        const payload = await apiFetch(path, { method: "POST" });
        document.getElementById("operator-key-manage-output").textContent = JSON.stringify(payload, null, 2);
        await loadOperatorKeys();
        setMessage(`Operator key ${button.dataset.operatorKeyAction} completed.`);
      } catch (error) {
        setMessage(error.message, true);
      }
    });
  });

  document.getElementById("token-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const { agent_id } = readForm(event.target);
      const payload = await apiFetch(`/acr/agents/${encodeURIComponent(agent_id)}/token`, { method: "POST" });
      document.getElementById("token-output").textContent = JSON.stringify(payload, null, 2);
      setMessage(`Token issued for ${agent_id}.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.querySelectorAll("[data-decision]").forEach((button) => {
    button.addEventListener("click", async () => {
      const form = document.getElementById("approval-form");
      const data = readForm(form);
      try {
        const payload = await apiFetch(`/acr/approvals/${encodeURIComponent(data.request_id)}/${button.dataset.decision}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ decided_by: data.decided_by || undefined, reason: data.reason || undefined }),
        });
        document.getElementById("approval-output").textContent = JSON.stringify(payload, null, 2);
        await loadApprovals();
        setMessage(`Approval ${button.dataset.decision} completed.`);
      } catch (error) {
        setMessage(error.message, true);
      }
    });
  });

  document.getElementById("events-filter").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await loadEvents(readForm(event.target));
      setMessage("Event filters applied.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("decisions-filter").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await loadDecisions(readForm(event.target));
      setMessage("Decision filters applied.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("chain-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const { identifier } = readForm(event.target);
      const payload = await apiFetch(`/acr/decisions/chain/${encodeURIComponent(identifier)}`);
      document.getElementById("chain-output").textContent = JSON.stringify(payload, null, 2);
      setMessage("Decision chain loaded.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("trace-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const { correlation_id } = readForm(event.target);
      const payload = await apiFetch(`/acr/events/${encodeURIComponent(correlation_id)}`);
      document.getElementById("trace-output").textContent = JSON.stringify(payload, null, 2);
      setMessage("Trace loaded.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.querySelectorAll("[data-drift-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const data = readForm(document.getElementById("drift-form"));
      try {
        const action = button.dataset.driftAction;
        let payload;
        if (action === "score") {
          payload = await apiFetch(`/acr/drift/${encodeURIComponent(data.agent_id)}`);
        } else if (action === "baseline") {
          payload = await apiFetch(`/acr/drift/${encodeURIComponent(data.agent_id)}/baseline`);
        } else if (action === "versions") {
          await loadBaselineVersions(data.agent_id);
          payload = { status: "loaded_versions", agent_id: data.agent_id };
        } else if (action === "propose") {
          payload = await apiFetch(`/acr/drift/${encodeURIComponent(data.agent_id)}/baseline/propose`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              window_days: Number(data.window_days || 30),
              notes: data.notes || data.intent_step || undefined,
            }),
          });
          await loadBaselineVersions(data.agent_id);
        } else {
          payload = await apiFetch(`/acr/drift/${encodeURIComponent(data.agent_id)}/baseline/reset`, { method: "POST" });
          await loadBaselineVersions(data.agent_id);
        }
        document.getElementById("drift-output").textContent = JSON.stringify(payload, null, 2);
        setMessage(`Drift ${action} completed.`);
      } catch (error) {
        setMessage(error.message, true);
      }
    });
  });

  document.querySelectorAll("[data-baseline-review]").forEach((button) => {
    button.addEventListener("click", async () => {
      const data = readForm(document.getElementById("baseline-review-form"));
      try {
        const action = button.dataset.baselineReview;
        const payload = await apiFetch(
          `/acr/drift/${encodeURIComponent(data.agent_id)}/baseline/${encodeURIComponent(data.baseline_version_id)}/${action}`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ notes: data.notes || undefined }),
          }
        );
        document.getElementById("baseline-review-output").textContent = JSON.stringify(payload, null, 2);
        await loadBaselineVersions(data.agent_id);
        setMessage(`Baseline ${action} completed.`);
      } catch (error) {
        setMessage(error.message, true);
      }
    });
  });

  document.querySelectorAll("[data-containment-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const data = readForm(document.getElementById("containment-form"));
      try {
        let payload;
        if (button.dataset.containmentAction === "status") {
          payload = await apiFetch(`/acr/containment/status/${encodeURIComponent(data.agent_id)}`);
        } else {
          payload = await apiFetch(`/acr/containment/${button.dataset.containmentAction}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              agent_id: data.agent_id,
              operator_id: data.operator_id || undefined,
              reason: data.reason || undefined,
            }),
          });
        }
        document.getElementById("containment-output").textContent = JSON.stringify(payload, null, 2);
        await loadContainment();
        setMessage(`Containment ${button.dataset.containmentAction} completed.`);
      } catch (error) {
        setMessage(error.message, true);
      }
    });
  });

  document.getElementById("copy-manifest").addEventListener("click", async () => {
    try {
      await copyTextFrom("policy-manifest-output");
      setMessage("Manifest copied.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("copy-rego").addEventListener("click", async () => {
    try {
      await copyTextFrom("policy-rego-output");
      setMessage("Rego policy copied.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("refresh-policy-drafts").addEventListener("click", async () => {
    try {
      await loadPolicyDrafts();
      setMessage("Policy drafts refreshed.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("load-policy-draft-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const { draft_id } = readForm(event.target);
      const draft = await apiFetch(`/acr/policy-drafts/${encodeURIComponent(draft_id)}`);
      state.currentPolicyDraftId = draft.draft_id;
      const form = document.getElementById("policy-wizard-form");
      const wizard = draft.wizard_inputs || {};
      Object.entries(wizard).forEach(([key, value]) => {
        if (form.elements.namedItem(key)) {
          form.elements.namedItem(key).value = value;
        }
      });
      form.elements.namedItem("draft_name").value = draft.name;
      document.getElementById("policy-manifest-output").textContent = JSON.stringify(draft.manifest, null, 2);
      document.getElementById("policy-rego-output").textContent = draft.rego_policy;
      document.getElementById("policy-bundle-output").textContent = "Draft loaded. Click Export Bundle to view publishable files.";
      document.getElementById("policy-simulation-output").textContent = "Draft loaded. Configure a sample action and run the simulator.";
      setMessage(`Loaded policy draft ${draft.draft_id}.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("export-policy-bundle").addEventListener("click", async () => {
    try {
      if (!state.currentPolicyDraftId) throw new Error("Load or save a draft first.");
      const bundle = await apiFetch(`/acr/policy-drafts/${encodeURIComponent(state.currentPolicyDraftId)}/bundle`);
      document.getElementById("policy-bundle-output").textContent = JSON.stringify(bundle, null, 2);
      setMessage(`Bundle exported for ${bundle.draft_id}.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("policy-simulator-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      if (!state.currentPolicyDraftId) throw new Error("Load or save a draft first.");
      const data = readForm(event.target);
      const payload = {
        action: {
          tool_name: data.tool_name,
          parameters: parseJsonField(data.parameters_json, {}),
        },
        context: parseJsonField(data.context_json, {}),
      };
      const simulation = await apiFetch(
        `/acr/policy-drafts/${encodeURIComponent(state.currentPolicyDraftId)}/simulate`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );
      document.getElementById("policy-simulation-output").textContent = JSON.stringify(simulation, null, 2);
      setMessage(`Simulation completed with decision: ${simulation.final_decision}.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("validate-policy-draft").addEventListener("click", async () => {
    try {
      if (!state.currentPolicyDraftId) throw new Error("Load or save a draft first.");
      const validation = await apiFetch(`/acr/policy-drafts/${encodeURIComponent(state.currentPolicyDraftId)}/validate`);
      document.getElementById("policy-validation-output").textContent = JSON.stringify(validation, null, 2);
      setMessage(validation.valid ? "Draft validation passed." : "Draft validation found issues.", !validation.valid);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("publish-policy-draft").addEventListener("click", async () => {
    try {
      if (!state.currentPolicyDraftId) throw new Error("Load or save a draft first.");
      const { publish_notes } = readForm(document.getElementById("policy-publish-form"));
      const release = await apiFetch(`/acr/policy-drafts/${encodeURIComponent(state.currentPolicyDraftId)}/publish`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: publish_notes || undefined }),
      });
      document.getElementById("policy-validation-output").textContent = JSON.stringify(release, null, 2);
      document.getElementById("policy-release-output").textContent = JSON.stringify(release, null, 2);
      await loadPolicyReleases();
      setMessage(`Published release ${release.release_id} for ${release.agent_id}. Activate it to update the live OPA bundle alias.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("refresh-policy-releases").addEventListener("click", async () => {
    try {
      await loadPolicyReleases();
      setMessage("Policy releases refreshed.");
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("activate-policy-release").addEventListener("click", async () => {
    try {
      const { release_id } = readForm(document.getElementById("policy-release-actions-form"));
      const release = await apiFetch(`/acr/policy-drafts/releases/${encodeURIComponent(release_id)}/activate`, {
        method: "POST",
      });
      document.getElementById("policy-release-output").textContent = JSON.stringify(release, null, 2);
      await loadPolicyReleases();
      setMessage(`Activated release ${release.release_id}. OPA can pull the active bundle from ${release.active_bundle_uri}.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.getElementById("policy-release-actions-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const { release_id } = readForm(event.target);
      const { publish_notes } = readForm(document.getElementById("policy-publish-form"));
      const release = await apiFetch(`/acr/policy-drafts/releases/${encodeURIComponent(release_id)}/rollback`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: publish_notes || undefined }),
      });
      document.getElementById("policy-validation-output").textContent = JSON.stringify(release, null, 2);
      document.getElementById("policy-release-output").textContent = JSON.stringify(release, null, 2);
      await loadPolicyReleases();
      setMessage(`Rollback published as release ${release.release_id}.`);
    } catch (error) {
      setMessage(error.message, true);
    }
  });
}

function installRefreshers() {
  document.getElementById("refresh-all").addEventListener("click", async () => {
    try {
      await refreshDashboard();
    } catch (error) {
      setMessage(error.message, true);
    }
  });

  document.querySelectorAll("[data-action='load-agents']").forEach((button) => button.addEventListener("click", () => loadAgents().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-operator-keys']").forEach((button) => button.addEventListener("click", () => loadOperatorKeys().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-policy-drafts']").forEach((button) => button.addEventListener("click", () => loadPolicyDrafts().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-approvals']").forEach((button) => button.addEventListener("click", () => loadApprovals().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-events']").forEach((button) => button.addEventListener("click", () => loadEvents().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-decisions']").forEach((button) => button.addEventListener("click", () => loadDecisions().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-containment']").forEach((button) => button.addEventListener("click", () => loadContainment().catch((error) => setMessage(error.message, true))));
  document.querySelectorAll("[data-action='load-metrics']").forEach((button) => button.addEventListener("click", () => loadMetrics().catch((error) => setMessage(error.message, true))));
}

document.addEventListener("DOMContentLoaded", async () => {
  updateSessionUI();
  installNavigation();
  installSessionControls();
  installForms();
  installRefreshers();
  await loadSessionPrincipal();
  try {
    await refreshDashboard();
  } catch (error) {
    setMessage("Configure an operator API key to use the console.", true);
  }
});
