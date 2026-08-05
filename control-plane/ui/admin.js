import {
  escapeHtml,
  formatBytes,
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
  selectedNodeId: null,
  nodeCats: [],
  nodeDetailsLoading: false,
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

function consumeAuthError() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get("auth_error");
  if (!code) return "";
  url.searchParams.delete("auth_error");
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
  if (code === "admin_access_required") return t("auth.error.adminAccessRequired");
  return t("auth.error.authenticationFailed");
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
    if (state.selectedNodeId && document.querySelector("#node-detail-dialog").open) {
      await loadNodeCats(state.selectedNodeId, { quiet: true });
    }
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

function formatPercent(value) {
  if (value == null || !Number.isFinite(Number(value))) return "—";
  return `${Number(value).toFixed(1)}%`;
}

function formatMib(value) {
  return formatBytes(Number(value || 0) * 1024 * 1024);
}

function usageDetail(used, total, formatter) {
  if (used == null || total == null) return t("admin.metric.telemetryUnavailable");
  return `${formatter(used)} / ${formatter(total)}`;
}

function capacityItem(label, assigned, total, formatter) {
  const used = percentage(assigned, total);
  return `<article class="capacity-item"><header><strong>${escapeHtml(label)}</strong><span>${escapeHtml(formatter(assigned))} / ${escapeHtml(formatter(total))} · ${used}%</span></header><progress class="progress" max="100" value="${used}">${used}%</progress></article>`;
}

function lifecycleRow(label, value, total) {
  const width = percentage(value, total);
  return `<div class="lifecycle-row"><strong>${escapeHtml(label)}</strong><progress class="progress" max="100" value="${width}">${width}%</progress><span>${escapeHtml(value)}</span></div>`;
}

function render() {
  if (!state.overview) return;
  const overview = state.overview;
  const usage = overview.usage || {};
  document.querySelector("#admin-metrics").innerHTML = [
    metricCard(t("admin.metric.fleetNodes"), overview.nodes.total, t("admin.metric.nodeDetail", { ready: overview.nodes.ready, lost: overview.nodes.lost, fenced: overview.nodes.fenced })),
    metricCard(t("admin.metric.totalCats"), overview.cats.total, t("admin.metric.running", { count: overview.cats.running })),
    metricCard(t("admin.metric.cpuUsage"), formatPercent(usage.cpu_usage_percent), t("admin.metric.cpuDetail", { logical: usage.logical_cpus ?? overview.capacity.total_cpus, assigned: overview.capacity.assigned_cpus })),
    metricCard(t("admin.metric.memoryUsage"), formatPercent(usage.memory_total_mib == null ? null : (usage.memory_used_mib / usage.memory_total_mib) * 100), usageDetail(usage.memory_used_mib, usage.memory_total_mib, formatMib)),
    metricCard(t("admin.metric.diskUsage"), formatPercent(usage.disk_total_bytes == null ? null : (usage.disk_used_bytes / usage.disk_total_bytes) * 100), usageDetail(usage.disk_used_bytes, usage.disk_total_bytes, formatBytes)),
    metricCard(t("admin.metric.activeOperations"), overview.operations.pending + overview.operations.running, t("admin.metric.failed", { count: overview.operations.failed })),
  ].join("");
  document.querySelector("#generated-at").textContent = t("admin.generatedAt", { time: formatTime(overview.generated_at_unix) });
  document.querySelector("#capacity-grid").innerHTML = [
    capacityItem("CPU", overview.capacity.assigned_cpus, overview.capacity.total_cpus, (value) => `${value} ${t("admin.unit.vcpus")}`),
    capacityItem(t("common.memory"), overview.capacity.assigned_memory_mib, overview.capacity.total_memory_mib, formatMib),
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
    ? `<div class="health-strip">${state.nodes.map((summary) => `<button class="health-node node-select-card" type="button" data-node-detail="${escapeHtml(summary.node.id)}"><header><strong>${escapeHtml(summary.node.id)}</strong>${statusBadge(summary.node.state)}</header><p>${escapeHtml(summary.assigned_cats)} Cats · ${escapeHtml(t("admin.node.heartbeatAgo", { seconds: summary.heartbeat_age_seconds }))}</p></button>`).join("")}</div>`
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
    actions.push(["fence", t("admin.action.fence")]);
  } else if (summary.node.state === "fenced") {
    actions.push(["delete", t("admin.action.delete")]);
  }
  return actions.map(([action, label]) => `<button class="mini-button ${action === "delete" ? "danger" : ""}" data-node-action="${action}" data-node="${escapeHtml(summary.node.id)}">${label}</button>`).join("");
}

function telemetryMeter(label, value, detail = "") {
  const numeric = value == null || !Number.isFinite(Number(value))
    ? null
    : Math.max(0, Math.min(100, Number(value)));
  return `<div class="telemetry-meter ${numeric == null ? "is-unavailable" : ""}">
    <header><span>${escapeHtml(label)}</span><strong>${escapeHtml(formatPercent(numeric))}</strong></header>
    <progress max="100" value="${numeric ?? 0}">${escapeHtml(formatPercent(numeric))}</progress>
    <small>${escapeHtml(detail)}</small>
  </div>`;
}

function telemetrySummary(telemetry) {
  if (!telemetry) return "—";
  const memoryTotal = telemetry.host_memory_total_mib;
  const memoryUsed = memoryTotal == null || telemetry.host_memory_available_mib == null
    ? null
    : Math.max(0, memoryTotal - telemetry.host_memory_available_mib);
  const memoryPercent = memoryUsed == null || !memoryTotal
    ? null
    : (memoryUsed / memoryTotal) * 100;
  const diskTotal = telemetry.host_disk_total_bytes;
  const diskUsed = diskTotal == null || telemetry.host_disk_available_bytes == null
    ? null
    : Math.max(0, diskTotal - telemetry.host_disk_available_bytes);
  const diskPercent = diskUsed == null || !diskTotal ? null : (diskUsed / diskTotal) * 100;
  return `<div class="telemetry-summary">
    ${telemetryMeter(t("admin.node.cpuLabel"), telemetry.host_cpu_usage_percent)}
    ${telemetryMeter(t("admin.node.memoryLabel"), memoryPercent, memoryUsed == null ? "" : `${formatMib(memoryUsed)} / ${formatMib(memoryTotal)}`)}
    ${telemetryMeter(t("admin.node.diskLabel"), diskPercent, diskUsed == null ? "" : `${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`)}
  </div>`;
}

function renderNodes() {
  const body = document.querySelector("#nodes-table");
  const empty = document.querySelector("#nodes-empty");
  empty.classList.toggle("is-hidden", state.nodes.length !== 0);
  body.closest(".table-wrap").classList.toggle("is-hidden", state.nodes.length === 0);
  body.innerHTML = state.nodes.map((summary) => `<tr class="node-row" data-node-detail="${escapeHtml(summary.node.id)}" tabindex="0">
    <td><div class="resource-name"><span class="resource-avatar node-avatar">N</span><span><strong>${escapeHtml(summary.node.id)}</strong><small>${escapeHtml(summary.node.agent_url)}</small></span></div></td>
    <td>${statusBadge(summary.node.state)}</td>
    <td>${escapeHtml(summary.assigned_cats)} Cats<br><small>${escapeHtml(summary.assigned_cpus)} vCPU · ${escapeHtml(formatMib(summary.assigned_memory_mib))}</small>${summary.orphan_cats ? `<br><small class="node-orphan-warning">${escapeHtml(t("admin.node.orphanCats", { count: summary.orphan_cats }))}</small>` : ""}</td>
    <td>${escapeHtml(summary.node.capacity.cpus)} vCPU · ${escapeHtml(formatMib(summary.node.capacity.memory_mib))}</td>
    <td>${escapeHtml(t("admin.node.secondsAgo", { seconds: summary.heartbeat_age_seconds }))}<br><small>${formatTime(summary.node.last_heartbeat_unix)}</small></td>
    <td class="host-telemetry-cell">${telemetrySummary(summary.node.telemetry)}</td>
    <td><div class="row-actions">${nodeActions(summary)}</div></td>
  </tr>`).join("");
}

function requestedActual(requested, actual, actualLabel = t("admin.nodeDetail.actual")) {
  const actualClass = actual === t("admin.nodeDetail.unavailable") ? "node-detail-unavailable" : "";
  return `<div class="resource-comparison">
    <span><small>${escapeHtml(t("admin.nodeDetail.requested"))}</small><strong>${escapeHtml(requested)}</strong></span>
    <span class="actual"><small>${escapeHtml(actualLabel)}</small><strong class="${actualClass}">${escapeHtml(actual)}</strong></span>
  </div>`;
}

function actualValue(value, formatter) {
  return value == null || !Number.isFinite(Number(value))
    ? t("admin.nodeDetail.unavailable")
    : formatter(Number(value));
}

function renderNodeDetails() {
  const summary = state.nodes.find((item) => item.node.id === state.selectedNodeId);
  if (!summary) return;
  document.querySelector("#node-detail-title").textContent = summary.node.id;
  document.querySelector("#node-detail-summary").innerHTML = `<section class="node-detail-summary">
    <div class="node-detail-identity"><span class="resource-avatar node-avatar">N</span><span><strong>${escapeHtml(summary.node.id)}</strong><small>${escapeHtml(summary.node.agent_url)}</small><small>${escapeHtml(t("admin.node.heartbeatAgo", { seconds: summary.heartbeat_age_seconds }))}</small>${summary.orphan_cats ? `<small class="node-orphan-warning">${escapeHtml(t("admin.node.orphanCats", { count: summary.orphan_cats }))}</small>` : ""}</span>${statusBadge(summary.node.state)}</div>
    ${telemetrySummary(summary.node.telemetry)}
  </section>`;

  const body = document.querySelector("#node-cats-table");
  const table = body.closest(".table-wrap");
  const empty = document.querySelector("#node-cats-empty");
  const loading = document.querySelector("#node-cats-loading");
  loading.classList.toggle("is-hidden", !state.nodeDetailsLoading);
  table.classList.toggle("is-hidden", state.nodeDetailsLoading || state.nodeCats.length === 0);
  empty.classList.toggle("is-hidden", state.nodeDetailsLoading || state.nodeCats.length !== 0);
  body.innerHTML = state.nodeCats.map((item) => {
    const actual = item.actual || {};
    return `<tr>
      <td><div class="resource-name"><span class="resource-avatar">C</span><span><strong>${escapeHtml(item.cat.name)}</strong><small>${escapeHtml(item.cat.workspace_id)} · ${escapeHtml(item.cat.id)}</small></span></div></td>
      <td>${statusBadge(item.cat.observed_state)}<br><small>${escapeHtml(t("common.generation", { value: item.cat.generation }))}</small></td>
      <td>${requestedActual(
        `${item.cat.spec.cpus} ${t("admin.unit.vcpus")}`,
        actualValue(actual.cpu_usage_cores, (value) => `${value.toFixed(2)} ${t("admin.unit.vcpus")}`),
      )}</td>
      <td>${requestedActual(
        formatMib(item.cat.spec.memory_mib),
        actualValue(actual.memory_rss_bytes, formatBytes),
        t("admin.nodeDetail.processRss"),
      )}</td>
      <td>${requestedActual(
        formatBytes(item.requested_disk_bytes),
        actualValue(actual.host_disk_used_bytes, formatBytes),
        t("admin.nodeDetail.hostFootprint"),
      )}</td>
    </tr>`;
  }).join("");
}

async function loadNodeCats(id, { quiet = false } = {}) {
  if (!quiet) {
    state.nodeDetailsLoading = true;
    state.nodeCats = [];
    renderNodeDetails();
  }
  try {
    const response = await authenticatedRequest(`/v1/admin/nodes/${encodeURIComponent(id)}/cats`);
    if (state.selectedNodeId === id) state.nodeCats = response.items || [];
  } catch (error) {
    if (!quiet) toast(t("admin.nodeDetail.loadFailed"), error.message, "error");
    throw error;
  } finally {
    if (state.selectedNodeId === id) {
      state.nodeDetailsLoading = false;
      renderNodeDetails();
    }
  }
}

function openNodeDetails(id) {
  state.selectedNodeId = id;
  state.nodeCats = [];
  state.nodeDetailsLoading = true;
  renderNodeDetails();
  const dialog = document.querySelector("#node-detail-dialog");
  if (!dialog.open) dialog.showModal();
  loadNodeCats(id).catch(() => {});
}

async function mutateNode(id, action, button) {
  const warning = action === "drain"
    ? t("admin.node.drainConfirm", { id })
    : action === "fence"
      ? t("admin.node.fenceConfirm", { id })
    : action === "delete"
      ? t("admin.node.deleteConfirm", { id })
      : t("admin.node.actionConfirm", { id, action: t(`admin.action.${action}`) });
  if (!window.confirm(warning)) return;
  setBusy(button, true);
  try {
    const path = action === "delete"
      ? `/v1/admin/nodes/${encodeURIComponent(id)}`
      : `/v1/admin/nodes/${encodeURIComponent(id)}/actions/${action}`;
    await authenticatedRequest(path, {
      method: action === "delete" ? "DELETE" : "POST",
      body: action === "fence"
        ? JSON.stringify({ confirm_host_stopped_or_isolated: true })
        : undefined,
    });
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
  if (button) {
    mutateNode(button.dataset.node, button.dataset.nodeAction, button).catch((error) => toast(t("admin.node.operationFailed"), error.message, "error"));
    return;
  }
  const row = event.target.closest("[data-node-detail]");
  if (row) openNodeDetails(row.dataset.nodeDetail);
});
document.querySelector("#nodes-table").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("[data-node-detail]");
  if (!row) return;
  event.preventDefault();
  openNodeDetails(row.dataset.nodeDetail);
});
document.querySelector("#node-health-strip").addEventListener("click", (event) => {
  const node = event.target.closest("[data-node-detail]");
  if (node) openNodeDetails(node.dataset.nodeDetail);
});
document.querySelector("#node-detail-dialog").addEventListener("close", () => {
  state.selectedNodeId = null;
  state.nodeCats = [];
  state.nodeDetailsLoading = false;
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
  if (state.selectedNodeId) renderNodeDetails();
  if (state.activeView === "metrics" && !state.metrics) {
    document.querySelector("#metrics-output").textContent = t("common.loading");
  }
});

async function initializeAuth() {
  const callbackError = consumeAuthError();
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
  showLogin(loginError.textContent || callbackError);
}

initializeAuth();
