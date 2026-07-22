import {
  escapeHtml,
  formatTime,
  initNavigation,
  metricCard,
  request,
  setBusy,
  statusBadge,
  toast,
} from "/ui/common.js";
import { initI18n, onLocaleChange, t } from "/ui/i18n.js";

initI18n();

const state = {
  authConfig: null,
  overview: null,
  nodes: [],
  metrics: "",
  activeView: "overview",
  timer: null,
};
const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const loginError = document.querySelector("#login-error");

const switchView = initNavigation({
  overview: () => t("admin.nav.overview"),
  nodes: () => t("admin.nav.nodes"),
  metrics: () => t("admin.nav.metrics"),
}, (view) => {
  state.activeView = view;
  if (view === "metrics") loadMetrics().catch((error) => toast(t("admin.metrics.loadFailed"), error.message, "error"));
});

async function authenticatedRequest(path, options) {
  try {
    return await request(path, options);
  } catch (error) {
    if (error.status !== 401) throw error;
    await request("/auth/session?site=admin");
    return request(path, options);
  }
}

function showApp() {
  loginScreen.classList.add("is-hidden");
  appShell.classList.remove("is-hidden");
  startRefresh();
}

function showLogin(message = "") {
  stopRefresh();
  appShell.classList.add("is-hidden");
  loginScreen.classList.remove("is-hidden");
  loginError.textContent = message;
}

function startRefresh() {
  stopRefresh();
  state.timer = window.setInterval(() => loadAll({ quiet: true }).catch(() => {}), 10_000);
}

function stopRefresh() {
  if (state.timer) window.clearInterval(state.timer);
  state.timer = null;
}

async function loadMetrics() {
  state.metrics = await authenticatedRequest("/metrics");
  document.querySelector("#metrics-output").textContent = state.metrics || t("common.noMetrics");
}

async function loadAll({ quiet = false } = {}) {
  const button = document.querySelector("#refresh-button");
  if (!quiet) setBusy(button, true, t("common.refreshing"));
  try {
    const [overview, nodes] = await Promise.all([
      authenticatedRequest("/v1/admin/monitoring"),
      authenticatedRequest("/v1/admin/nodes"),
    ]);
    state.overview = overview;
    state.nodes = nodes.items || [];
    render();
    if (state.activeView === "metrics") await loadMetrics();
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      showLogin(error.message);
    } else if (!quiet) {
      toast(t("admin.refreshFailed"), error.message, "error");
    }
    throw error;
  } finally {
    if (!quiet) setBusy(button, false);
  }
}

function percentage(assigned, total) {
  return total ? Math.min(100, Math.round((assigned / total) * 100)) : 0;
}

function capacityItem(label, assigned, total, unit) {
  const used = percentage(assigned, total);
  return `<article class="capacity-item"><header><strong>${escapeHtml(label)}</strong><span>${escapeHtml(assigned)} / ${escapeHtml(total)} ${escapeHtml(unit)} · ${used}%</span></header><progress class="progress" max="100" value="${used}">${used}%</progress></article>`;
}

function lifecycleRow(label, value, total) {
  const width = percentage(value, total);
  return `<div class="lifecycle-row"><strong>${escapeHtml(label)}</strong><progress class="progress" max="100" value="${width}">${width}%</progress><span>${escapeHtml(value)}</span></div>`;
}

function render() {
  if (!state.overview) return;
  const overview = state.overview;
  document.querySelector("#admin-metrics").innerHTML = [
    metricCard(t("admin.metric.fleetNodes"), overview.nodes.total, t("admin.metric.nodeDetail", { ready: overview.nodes.ready, lost: overview.nodes.lost })),
    metricCard(t("admin.metric.totalCats"), overview.cats.total, t("admin.metric.running", { count: overview.cats.running })),
    metricCard(t("admin.metric.cpuAllocation"), `${percentage(overview.capacity.assigned_cpus, overview.capacity.total_cpus)}%`, `${overview.capacity.assigned_cpus} / ${overview.capacity.total_cpus} CPU`),
    metricCard(t("admin.metric.activeOperations"), overview.operations.pending + overview.operations.running, t("admin.metric.failed", { count: overview.operations.failed })),
  ].join("");
  document.querySelector("#generated-at").textContent = t("admin.generatedAt", { time: formatTime(overview.generated_at_unix) });
  document.querySelector("#capacity-grid").innerHTML = [
    capacityItem("CPU", overview.capacity.assigned_cpus, overview.capacity.total_cpus, t("admin.unit.cores")),
    capacityItem(t("common.memory"), overview.capacity.assigned_memory_mib, overview.capacity.total_memory_mib, "MiB"),
  ].join("");
  document.querySelector("#lifecycle-summary").innerHTML = `<div class="lifecycle-list">${[
    [t("status.running"), overview.cats.running],
    [t("status.suspended"), overview.cats.suspended],
    [t("status.warm"), overview.cats.warm],
    [t("status.cold"), overview.cats.cold],
    [t("admin.lifecycle.transitional"), overview.cats.transitional],
    [t("admin.lifecycle.failedUnknown"), overview.cats.failed_or_unknown],
  ].map(([label, value]) => lifecycleRow(label, value, overview.cats.total)).join("")}</div>`;
  document.querySelector("#node-health-strip").innerHTML = state.nodes.length
    ? `<div class="health-strip">${state.nodes.map((summary) => `<article class="health-node"><header><strong>${escapeHtml(summary.node.id)}</strong>${statusBadge(summary.node.state)}</header><p>${escapeHtml(summary.assigned_cats)} Cats · ${escapeHtml(t("admin.node.heartbeatAgo", { seconds: summary.heartbeat_age_seconds }))}</p></article>`).join("")}</div>`
    : `<div class="mini-empty">${escapeHtml(t("admin.empty.nodes"))}</div>`;
  renderNodes();
}

function nodeActions(summary) {
  const actions = [];
  if (summary.node.state === "ready") {
    actions.push(["cordon", t("admin.action.cordon")], ["drain", t("admin.action.drain")]);
  } else if (summary.node.state === "cordoned") {
    actions.push(["uncordon", t("admin.action.uncordon")], ["drain", t("admin.action.drain")], ["delete", t("admin.action.delete")]);
  } else if (summary.node.state === "draining") {
    actions.push(["uncordon", t("admin.action.cancelDrain")]);
  } else if (summary.node.state === "lost") {
    actions.push(["delete", t("admin.action.delete")]);
  }
  return actions.map(([action, label]) => `<button class="mini-button ${action === "delete" ? "danger" : ""}" data-node-action="${action}" data-node="${escapeHtml(summary.node.id)}">${label}</button>`).join("");
}

function telemetryText(telemetry) {
  if (!telemetry) return "—";
  const load = telemetry.load_average_1m == null ? "n/a" : Number(telemetry.load_average_1m).toFixed(2);
  return t("admin.node.load", { count: telemetry.observed_cats, load });
}

function renderNodes() {
  const body = document.querySelector("#nodes-table");
  const empty = document.querySelector("#nodes-empty");
  empty.classList.toggle("is-hidden", state.nodes.length !== 0);
  body.closest(".table-wrap").classList.toggle("is-hidden", state.nodes.length === 0);
  body.innerHTML = state.nodes.map((summary) => `<tr>
    <td><div class="resource-name"><span class="resource-avatar node-avatar">N</span><span><strong>${escapeHtml(summary.node.id)}</strong><small>${escapeHtml(summary.node.agent_url)}</small></span></div></td>
    <td>${statusBadge(summary.node.state)}</td>
    <td>${escapeHtml(summary.assigned_cats)} Cats<br><small>${escapeHtml(summary.assigned_cpus)} CPU · ${escapeHtml(summary.assigned_memory_mib)} MiB</small></td>
    <td>${escapeHtml(summary.node.capacity.cpus)} CPU · ${escapeHtml(summary.node.capacity.memory_mib)} MiB</td>
    <td>${escapeHtml(t("admin.node.secondsAgo", { seconds: summary.heartbeat_age_seconds }))}<br><small>${formatTime(summary.node.last_heartbeat_unix)}</small></td>
    <td>${escapeHtml(telemetryText(summary.node.telemetry))}</td>
    <td><div class="row-actions">${nodeActions(summary)}</div></td>
  </tr>`).join("");
}

async function mutateNode(id, action, button) {
  const warning = action === "drain"
    ? t("admin.node.drainConfirm", { id })
    : action === "delete"
      ? t("admin.node.deleteConfirm", { id })
      : t("admin.node.actionConfirm", { id, action: t(`admin.action.${action}`) });
  if (!window.confirm(warning)) return;
  setBusy(button, true);
  try {
    const path = action === "delete"
      ? `/v1/admin/nodes/${encodeURIComponent(id)}`
      : `/v1/admin/nodes/${encodeURIComponent(id)}/actions/${action}`;
    await authenticatedRequest(path, { method: action === "delete" ? "DELETE" : "POST" });
    await loadAll({ quiet: true });
    toast(t("admin.node.operationCompleted"), `${id} · ${t(`admin.action.${action}`)}`);
  } finally {
    setBusy(button, false);
  }
}

function startWorkOsLogin() {
  const query = new URLSearchParams({ site: "admin" });
  window.location.assign(`/auth/login?${query}`);
}

document.querySelector("#workos-login-button").addEventListener("click", startWorkOsLogin);

document.querySelector("#logout-button").addEventListener("click", () => {
  window.location.assign("/auth/logout?site=admin");
});
document.querySelector("#refresh-button").addEventListener("click", () => loadAll().catch(() => {}));
document.querySelector("#nodes-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-node-action]");
  if (!button) return;
  mutateNode(button.dataset.node, button.dataset.nodeAction, button).catch((error) => toast(t("admin.node.operationFailed"), error.message, "error"));
});
document.querySelector("#copy-metrics").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.metrics || document.querySelector("#metrics-output").textContent);
    toast(t("admin.metrics.copied"));
  } catch (error) {
    toast(t("common.copyFailed"), error.message, "error");
  }
});

function updateLoginDescription() {
  if (!state.authConfig) return;
  document.querySelector("#login-description").textContent = state.authConfig.workos_enabled
    ? t("admin.login.description")
    : t("admin.login.unconfigured");
}

onLocaleChange(() => {
  updateLoginDescription();
  switchView(state.activeView);
  render();
  if (state.activeView === "metrics" && !state.metrics) {
    document.querySelector("#metrics-output").textContent = t("common.loading");
  }
});

async function initializeAuth() {
  try {
    state.authConfig = await request("/auth/config");
    document.querySelector("#workos-login-button").classList.toggle("is-hidden", !state.authConfig.workos_enabled);
    updateLoginDescription();
    if (state.authConfig.workos_enabled) {
      try {
        await request("/auth/session?site=admin");
        showApp();
        await loadAll({ quiet: true });
        return;
      } catch (_) {
        // No WorkOS administrator session yet.
      }
    }
  } catch (error) {
    loginError.textContent = t("admin.authConfigFailed", { message: error.message });
  }
  showLogin(loginError.textContent);
}

initializeAuth();
