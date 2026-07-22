import {
  escapeHtml,
  formatTime,
  initNavigation,
  initTokenToggle,
  metricCard,
  request,
  setBusy,
  statusBadge,
  toast,
} from "/ui/common.js";

const TOKEN_KEY = "cats.admin.token";
const state = {
  token: "",
  authMode: "token",
  authConfig: null,
  overview: null,
  nodes: [],
  metrics: "",
  activeView: "overview",
  timer: null,
};
const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");

initTokenToggle();
initNavigation({ overview: "Fleet 概览", nodes: "工作节点", metrics: "Metrics" }, (view) => {
  state.activeView = view;
  if (view === "metrics") loadMetrics().catch((error) => toast("Metrics 加载失败", error.message, "error"));
});

async function authenticatedRequest(path, options) {
  try {
    return await request(path, state.token, options);
  } catch (error) {
    if (state.authMode !== "workos" || error.status !== 401) throw error;
    await request("/auth/session?site=admin", "");
    return request(path, "", options);
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
  document.querySelector("#metrics-output").textContent = state.metrics || "# no metrics";
}

async function loadAll({ quiet = false } = {}) {
  const button = document.querySelector("#refresh-button");
  if (!quiet) setBusy(button, true, "刷新中…");
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
      sessionStorage.removeItem(TOKEN_KEY);
      showLogin(error.message);
    } else if (!quiet) {
      toast("刷新失败", error.message, "error");
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
    metricCard("Fleet Nodes", overview.nodes.total, `${overview.nodes.ready} ready · ${overview.nodes.lost} lost`),
    metricCard("Total Cats", overview.cats.total, `${overview.cats.running} running`),
    metricCard("CPU Allocation", `${percentage(overview.capacity.assigned_cpus, overview.capacity.total_cpus)}%`, `${overview.capacity.assigned_cpus} / ${overview.capacity.total_cpus} CPU`),
    metricCard("Active Operations", overview.operations.pending + overview.operations.running, `${overview.operations.failed} failed`),
  ].join("");
  document.querySelector("#generated-at").textContent = `生成于 ${formatTime(overview.generated_at_unix)}`;
  document.querySelector("#capacity-grid").innerHTML = [
    capacityItem("CPU", overview.capacity.assigned_cpus, overview.capacity.total_cpus, "cores"),
    capacityItem("Memory", overview.capacity.assigned_memory_mib, overview.capacity.total_memory_mib, "MiB"),
  ].join("");
  document.querySelector("#lifecycle-summary").innerHTML = `<div class="lifecycle-list">${[
    ["Running", overview.cats.running],
    ["Suspended", overview.cats.suspended],
    ["Warm", overview.cats.warm],
    ["Cold", overview.cats.cold],
    ["Transitional", overview.cats.transitional],
    ["Failed / Unknown", overview.cats.failed_or_unknown],
  ].map(([label, value]) => lifecycleRow(label, value, overview.cats.total)).join("")}</div>`;
  document.querySelector("#node-health-strip").innerHTML = state.nodes.length
    ? `<div class="health-strip">${state.nodes.map((summary) => `<article class="health-node"><header><strong>${escapeHtml(summary.node.id)}</strong>${statusBadge(summary.node.state)}</header><p>${escapeHtml(summary.assigned_cats)} Cats · heartbeat ${escapeHtml(summary.heartbeat_age_seconds)}s ago</p></article>`).join("")}</div>`
    : '<div class="mini-empty">没有已注册节点。</div>';
  renderNodes();
}

function nodeActions(summary) {
  const actions = [];
  if (summary.node.state === "ready") {
    actions.push(["cordon", "Cordon"], ["drain", "Drain"]);
  } else if (summary.node.state === "cordoned") {
    actions.push(["uncordon", "Uncordon"], ["drain", "Drain"], ["delete", "Delete"]);
  } else if (summary.node.state === "draining") {
    actions.push(["uncordon", "Cancel drain"]);
  } else if (summary.node.state === "lost") {
    actions.push(["delete", "Delete"]);
  }
  return actions.map(([action, label]) => `<button class="mini-button ${action === "delete" ? "danger" : ""}" data-node-action="${action}" data-node="${escapeHtml(summary.node.id)}">${label}</button>`).join("");
}

function telemetryText(telemetry) {
  if (!telemetry) return "—";
  const load = telemetry.load_average_1m == null ? "n/a" : Number(telemetry.load_average_1m).toFixed(2);
  return `${telemetry.observed_cats} Cats · load ${load}`;
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
    <td>${escapeHtml(summary.heartbeat_age_seconds)}s ago<br><small>${formatTime(summary.node.last_heartbeat_unix)}</small></td>
    <td>${escapeHtml(telemetryText(summary.node.telemetry))}</td>
    <td><div class="row-actions">${nodeActions(summary)}</div></td>
  </tr>`).join("");
}

async function mutateNode(id, action, button) {
  const warning = action === "drain"
    ? `Drain 节点 “${id}”？现有 Cats 会被停止、fence 并重新调度。`
    : action === "delete"
      ? `从注册表删除节点 “${id}”？节点必须为空且处于 cordoned/lost。`
      : `${action} 节点 “${id}”？`;
  if (!window.confirm(warning)) return;
  setBusy(button, true);
  try {
    const path = action === "delete"
      ? `/v1/admin/nodes/${encodeURIComponent(id)}`
      : `/v1/admin/nodes/${encodeURIComponent(id)}/actions/${action}`;
    await authenticatedRequest(path, { method: action === "delete" ? "DELETE" : "POST" });
    await loadAll({ quiet: true });
    toast("节点操作完成", `${id} · ${action}`);
  } finally {
    setBusy(button, false);
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.authConfig?.workos_enabled && !state.authConfig.token_login_enabled) {
    startWorkOsLogin();
    return;
  }
  const button = loginForm.querySelector('button[type="submit"]');
  const token = String(new FormData(loginForm).get("token") || "").trim();
  loginError.textContent = "";
  setBusy(button, true, "正在验证…");
  try {
    await request("/v1/admin/monitoring", token);
    state.token = token;
    state.authMode = "token";
    sessionStorage.setItem(TOKEN_KEY, token);
    showApp();
    await loadAll({ quiet: true });
  } catch (error) {
    loginError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

function startWorkOsLogin() {
  const query = new URLSearchParams({ site: "admin", return_to: "/admin/" });
  window.location.assign(`/auth/login?${query}`);
}

document.querySelector("#workos-login-button").addEventListener("click", startWorkOsLogin);

document.querySelector("#logout-button").addEventListener("click", () => {
  if (state.authMode === "workos") {
    window.location.assign("/auth/logout?site=admin");
    return;
  }
  sessionStorage.removeItem(TOKEN_KEY);
  state.token = "";
  showLogin();
});
document.querySelector("#refresh-button").addEventListener("click", () => loadAll().catch(() => {}));
document.querySelector("#nodes-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-node-action]");
  if (!button) return;
  mutateNode(button.dataset.node, button.dataset.nodeAction, button).catch((error) => toast("节点操作失败", error.message, "error"));
});
document.querySelector("#copy-metrics").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.metrics || document.querySelector("#metrics-output").textContent);
    toast("Metrics 已复制");
  } catch (error) {
    toast("复制失败", error.message, "error");
  }
});

async function initializeAuth() {
  state.token = sessionStorage.getItem(TOKEN_KEY) || "";
  try {
    state.authConfig = await request("/auth/config", "");
    document.querySelector("#workos-login-button").classList.toggle("is-hidden", !state.authConfig.workos_enabled);
    document.querySelector("#token-login-section").classList.toggle("is-hidden", !state.authConfig.token_login_enabled);
    document.querySelector("#login-description").textContent = state.authConfig.workos_enabled
      ? "通过 WorkOS 登录，并验证 Fleet 管理员权限。"
      : "使用 Administrator Token 登录。该站点可排空和删除工作节点。";
    if (state.authConfig.workos_enabled) {
      try {
        await request("/auth/session?site=admin", "");
        state.authMode = "workos";
        state.token = "";
        sessionStorage.removeItem(TOKEN_KEY);
        showApp();
        await loadAll({ quiet: true });
        return;
      } catch (_) {
        // No WorkOS administrator session yet.
      }
    }
    if (state.token && state.authConfig.token_login_enabled) {
      state.authMode = "token";
      showApp();
      await loadAll({ quiet: true });
      return;
    }
  } catch (error) {
    loginError.textContent = `读取登录配置失败：${error.message}`;
  }
  showLogin(loginError.textContent);
}

initializeAuth();
