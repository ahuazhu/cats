import {
  escapeHtml,
  formatBytes,
  formatTime,
  initNavigation,
  metricCard,
  operationKind,
  request,
  resourceKind,
  setBusy,
  sleep,
  splitCommand,
  statusBadge,
  toast,
} from "/ui/common.js";
import { initI18n, localizedApiMessage, onLocaleChange, t } from "/ui/i18n.js";

initI18n();

const state = {
  project: "",
  authConfig: null,
  cats: [],
  disks: [],
  operations: [],
  activeView: "overview",
  execCat: "",
  loading: false,
};

const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const loginError = document.querySelector("#login-error");
const createCatDialog = document.querySelector("#create-cat-dialog");
const createDiskDialog = document.querySelector("#create-disk-dialog");
const execDialog = document.querySelector("#exec-dialog");

const switchView = initNavigation(
  {
    overview: () => t("user.nav.overview"),
    cats: () => t("user.nav.cats"),
    disks: () => t("user.disks.title"),
    operations: () => t("user.nav.operations"),
  },
  (view) => { state.activeView = view; },
);

function projectPath(path) {
  return `/v1/projects/${encodeURIComponent(state.project)}${path}`;
}

function workspaceLabel(project) {
  return project.startsWith("personal-user_") ? t("user.workspace.personal") : project;
}

async function authenticatedRequest(path, options) {
  try {
    return await request(path, options);
  } catch (error) {
    if (error.status !== 401) throw error;
    await request("/auth/session?site=user");
    return request(path, options);
  }
}

function idempotencyHeaders() {
  return { "Idempotency-Key": globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}` };
}

function showApp() {
  loginScreen.classList.add("is-hidden");
  appShell.classList.remove("is-hidden");
  const label = workspaceLabel(state.project);
  document.querySelector("#sidebar-project").textContent = label;
  document.querySelector("#header-project").textContent = label;
}

function showLogin(message = "") {
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
  if (code === "workspace_access_required") return t("auth.error.workspaceAccessRequired");
  return t("auth.error.authenticationFailed");
}

async function loadAll({ quiet = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  const button = document.querySelector("#refresh-button");
  if (!quiet) setBusy(button, true, t("common.refreshing"));
  try {
    const [cats, disks, operations] = await Promise.all([
      authenticatedRequest(projectPath("/cats")),
      authenticatedRequest(projectPath("/disks")),
      authenticatedRequest(projectPath("/operations")),
    ]);
    state.cats = cats.items || [];
    state.disks = disks.items || [];
    state.operations = operations.items || [];
    render();
  } catch (error) {
    if (error.status === 401 || error.status === 403) {
      showLogin(error.message);
    } else if (!quiet) {
      toast(t("user.refreshFailed"), error.message, "error");
    }
    throw error;
  } finally {
    state.loading = false;
    if (!quiet) setBusy(button, false);
  }
}

function render() {
  renderOverview();
  renderCats();
  renderDisks();
  renderOperations();
}

function renderOverview() {
  const counts = state.cats.reduce((result, cat) => {
    result[cat.observed_state] = (result[cat.observed_state] || 0) + 1;
    return result;
  }, {});
  const persistentDisks = state.disks.filter((disk) => disk.kind === "persistent");
  const activeOperations = state.operations.filter((operation) => ["pending", "running"].includes(operation.phase));
  document.querySelector("#user-metrics").innerHTML = [
    metricCard(t("user.metric.totalCats"), state.cats.length, t("user.metric.running", { count: counts.running || 0 })),
    metricCard(t("user.metric.sleeping"), (counts.suspended || 0) + (counts.warm || 0), t("user.metric.fastResume")),
    metricCard(t("user.metric.persistentDisks"), persistentDisks.length, formatBytes(persistentDisks.reduce((sum, disk) => sum + disk.size_bytes, 0))),
    metricCard(t("user.metric.activeOperations"), activeOperations.length, t("user.metric.controlTasks")),
  ].join("");

  const recentCats = [...state.cats].sort((a, b) => b.created_at_unix - a.created_at_unix).slice(0, 5);
  document.querySelector("#recent-cats").innerHTML = recentCats.length
    ? `<div class="compact-list">${recentCats.map((cat) => `<div class="compact-row"><div><strong>${escapeHtml(cat.name)}</strong><small>${escapeHtml(cat.spec.cpus)} CPU · ${escapeHtml(cat.spec.memory_mib)} MiB · ${escapeHtml(cat.node_id || t("common.notScheduled"))}</small></div>${statusBadge(cat.observed_state)}</div>`).join("")}</div>`
    : `<div class="mini-empty">${escapeHtml(t("user.empty.recentCats"))}</div>`;

  const recentOperations = [...state.operations].sort((a, b) => b.updated_at_unix - a.updated_at_unix).slice(0, 5);
  document.querySelector("#recent-operations").innerHTML = recentOperations.length
    ? `<div class="compact-list">${recentOperations.map((operation) => `<div class="compact-row"><div><strong>${escapeHtml(operationKind(operation.kind))}</strong><small>${formatTime(operation.updated_at_unix)}</small></div>${statusBadge(operation.phase)}</div>`).join("")}</div>`
    : `<div class="mini-empty">${escapeHtml(t("user.empty.recentOperations"))}</div>`;
}

function catActions(cat) {
  const stateActions = {
    running: ["exec", "suspend", "warm", "stop"],
    suspended: ["resume", "warm", "stop"],
    warm: ["resume", "stop"],
    cold: ["start"],
    failed: ["start"],
    unknown: ["start"],
  };
  const actions = stateActions[cat.observed_state] || [];
  const buttons = actions.map((action) => `<button class="mini-button" data-cat-action="${action}" data-cat="${escapeHtml(cat.name)}">${escapeHtml(t(`user.action.${action}`))}</button>`);
  if (cat.observed_state === "running") {
    buttons.push(`<button class="mini-button" data-cat-action="expose" data-cat="${escapeHtml(cat.name)}">${escapeHtml(t("user.action.expose"))}</button>`);
  }
  buttons.push(`<button class="mini-button danger" data-cat-action="destroy" data-cat="${escapeHtml(cat.name)}">${escapeHtml(t("user.action.destroy"))}</button>`);
  return buttons.join("");
}

function renderCats() {
  const body = document.querySelector("#cats-table");
  const empty = document.querySelector("#cats-empty");
  const table = body.closest(".table-wrap");
  empty.classList.toggle("is-hidden", state.cats.length !== 0);
  table.classList.toggle("is-hidden", state.cats.length === 0);
  body.innerHTML = state.cats.map((cat) => `<tr>
    <td><div class="resource-name"><span class="resource-avatar">C</span><span><strong>${escapeHtml(cat.name)}</strong><small>${escapeHtml(cat.id)}</small></span></div></td>
    <td>${statusBadge(cat.observed_state)}</td>
    <td>${escapeHtml(cat.spec.cpus)} CPU · ${escapeHtml(cat.spec.memory_mib)} MiB</td>
    <td>${escapeHtml(cat.node_id || "—")}</td>
    <td>${formatTime(cat.created_at_unix)}</td>
    <td><div class="row-actions">${catActions(cat)}</div></td>
  </tr>`).join("");
}

function diskActions(disk) {
  const buttons = [`<button class="mini-button" data-disk-action="snapshot" data-disk="${escapeHtml(disk.name)}">${escapeHtml(t("user.action.snapshot"))}</button>`];
  if (disk.kind === "persistent") {
    if (disk.state === "bound") {
      buttons.push(`<button class="mini-button" data-disk-action="unmount" data-disk="${escapeHtml(disk.name)}">${escapeHtml(t("user.action.unmount"))}</button>`);
    } else if (disk.state === "available") {
      buttons.push(`<button class="mini-button" data-disk-action="mount" data-disk="${escapeHtml(disk.name)}">${escapeHtml(t("user.action.mount"))}</button>`);
      buttons.push(`<button class="mini-button" data-disk-action="resize" data-disk="${escapeHtml(disk.name)}">${escapeHtml(t("user.action.resize"))}</button>`);
      buttons.push(`<button class="mini-button danger" data-disk-action="delete" data-disk="${escapeHtml(disk.name)}">${escapeHtml(t("user.action.delete"))}</button>`);
    }
  }
  return buttons.join("");
}

function renderDisks() {
  const body = document.querySelector("#disks-table");
  const empty = document.querySelector("#disks-empty");
  const persistentCount = state.disks.filter((disk) => disk.kind === "persistent").length;
  empty.classList.toggle("is-hidden", persistentCount !== 0 || state.disks.length !== 0);
  body.closest(".table-wrap").classList.toggle("is-hidden", state.disks.length === 0);
  const catNames = new Map(state.cats.map((cat) => [cat.id, cat.name]));
  body.innerHTML = state.disks.map((disk) => `<tr>
    <td><div class="resource-name"><span class="resource-avatar">D</span><span><strong>${escapeHtml(disk.name)}</strong><small>${escapeHtml(disk.id)}</small></span></div></td>
    <td>${escapeHtml(resourceKind(disk.kind))}</td><td>${formatBytes(disk.size_bytes)}</td><td>${statusBadge(disk.state)}</td>
    <td>${escapeHtml(catNames.get(disk.bound_cat_id) || disk.bound_cat_id || "—")}</td>
    <td><div class="row-actions">${diskActions(disk)}</div></td>
  </tr>`).join("");
}

function renderOperations() {
  const body = document.querySelector("#operations-table");
  const empty = document.querySelector("#operations-empty");
  const operations = [...state.operations].sort((a, b) => b.updated_at_unix - a.updated_at_unix);
  empty.classList.toggle("is-hidden", operations.length !== 0);
  body.closest(".table-wrap").classList.toggle("is-hidden", operations.length === 0);
  body.innerHTML = operations.map((operation) => `<tr>
    <td><div class="resource-name"><span><strong>${escapeHtml(operation.id)}</strong><small>${escapeHtml(t("common.generation", { value: operation.resource_generation }))}</small></span></div></td>
    <td>${escapeHtml(operationKind(operation.kind))}</td><td>${escapeHtml(operation.resource_id)}</td><td>${statusBadge(operation.phase)}</td>
    <td>${formatTime(operation.updated_at_unix)}</td><td>${escapeHtml(operation.error ? localizedApiMessage(operation.error.code, operation.error.message) : "—")}</td>
  </tr>`).join("");
}

async function waitForOperation(operation) {
  if (!operation?.id) return;
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const current = await authenticatedRequest(`/v1/operations/${encodeURIComponent(operation.id)}`);
    if (current.phase === "succeeded") return current;
    if (current.phase === "failed") throw new Error(current.error ? localizedApiMessage(current.error.code, current.error.message) : t("user.operationFailed", { id: current.id }));
    await sleep(300);
  }
  throw new Error(t("user.operationTimeout", { id: operation.id }));
}

async function mutateCat(name, action, button) {
  if (action === "exec") {
    state.execCat = name;
    document.querySelector("#exec-cat-name").textContent = name;
    const output = document.querySelector("#exec-output");
    output.classList.remove("is-error");
    output.textContent = t("user.execDialog.waiting");
    execDialog.showModal();
    return;
  }
  if (action === "expose") {
    const port = window.prompt(t("user.expose.portPrompt", { name }), "8080");
    if (port === null) return;
    const endpointName = window.prompt(t("user.expose.namePrompt"), "web");
    if (endpointName === null) return;
    setBusy(button, true);
    try {
      const response = await authenticatedRequest(projectPath(`/cats/${encodeURIComponent(name)}/endpoints`), {
        method: "POST",
        body: JSON.stringify({ name: endpointName, target_port: Number(port), protocol: "http", wake_policy: "wake_on_request" }),
      });
      toast(t("user.expose.created"), response.endpoint.hostname);
    } finally {
      setBusy(button, false);
    }
    return;
  }
  if (action === "destroy" && !window.confirm(t("user.destroy.confirm", { name }))) return;
  setBusy(button, true);
  try {
    const path = action === "destroy"
      ? projectPath(`/cats/${encodeURIComponent(name)}`)
      : projectPath(`/cats/${encodeURIComponent(name)}/actions/${action}`);
    const response = await authenticatedRequest(path, {
      method: action === "destroy" ? "DELETE" : "POST",
      headers: idempotencyHeaders(),
    });
    toast(t("user.operation.accepted"), `${name} · ${t(`user.action.${action}`)}`);
    await waitForOperation(response.operation);
    await loadAll({ quiet: true });
    toast(t("user.operation.completed"), `${name} · ${t(`user.action.${action}`)}`);
  } finally {
    setBusy(button, false);
  }
}

async function mutateDisk(name, action, button) {
  const disk = state.disks.find((item) => item.name === name);
  if (!disk) return;
  let method = "POST";
  let path = projectPath(`/disks/${encodeURIComponent(name)}/actions/${action}`);
  let body;
  if (action === "mount") {
    if (!state.cats.length) throw new Error(t("user.mount.noCats"));
    const cat = window.prompt(t("user.mount.catPrompt"), state.cats[0].name);
    if (cat === null) return;
    const mountAt = window.prompt(t("user.mount.pathPrompt"), "/data");
    if (mountAt === null) return;
    body = { cat_id: cat, mount_at: mountAt };
  } else if (action === "resize") {
    const currentGiB = disk.size_bytes / (1024 ** 3);
    const size = window.prompt(t("user.resize.prompt"), String(currentGiB));
    if (size === null) return;
    body = { size_bytes: Math.round(Number(size) * (1024 ** 3)) };
  } else if (action === "unmount") {
    body = {};
  } else if (action === "snapshot") {
    path = projectPath(`/disks/${encodeURIComponent(name)}/snapshots`);
  } else if (action === "delete") {
    if (!window.confirm(t("user.disk.deleteConfirm", { name }))) return;
    method = "DELETE";
    path = projectPath(`/disks/${encodeURIComponent(name)}`);
  }
  setBusy(button, true);
  try {
    const response = await authenticatedRequest(path, {
      method,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    await loadAll({ quiet: true });
    toast(action === "snapshot" ? t("user.disk.snapshotCreated") : t("user.disk.operationCompleted"), response?.id || `${name} · ${t(`user.action.${action}`)}`);
  } finally {
    setBusy(button, false);
  }
}

function startWorkOsLogin() {
  const query = new URLSearchParams({ site: "user" });
  window.location.assign(`/auth/login?${query}`);
}

document.querySelector("#workos-login-button").addEventListener("click", startWorkOsLogin);

document.querySelector("#logout-button").addEventListener("click", () => {
  window.location.assign("/auth/logout?site=user");
});
document.querySelector("#refresh-button").addEventListener("click", () => loadAll().catch(() => {}));
document.querySelectorAll("#create-cat-button, [data-create-cat]").forEach((button) => button.addEventListener("click", () => createCatDialog.showModal()));
document.querySelector("#create-disk-button").addEventListener("click", () => createDiskDialog.showModal());

document.querySelector("#create-cat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    createCatDialog.close();
    return;
  }
  const form = event.currentTarget;
  const values = new FormData(form);
  const button = form.querySelector('button[value="default"]');
  const error = form.querySelector("[data-form-error]");
  error.textContent = "";
  setBusy(button, true);
  try {
    const response = await authenticatedRequest(projectPath("/cats"), {
      method: "POST",
      headers: idempotencyHeaders(),
      body: JSON.stringify({
        name: String(values.get("name")).trim(),
        image: String(values.get("image")).trim(),
        cpus: Number(values.get("cpus")),
        memory_mib: Number(values.get("memory_mib")),
        root_size_bytes: Math.round(Number(values.get("root_gib")) * (1024 ** 3)),
        auto_suspend: true,
        disk: null,
      }),
    });
    toast(t("user.cat.creating"), response.cat.name);
    createCatDialog.close();
    form.reset();
    await waitForOperation(response.operation);
    await loadAll({ quiet: true });
    toast(t("user.cat.ready"), response.cat.name);
  } catch (caught) {
    error.textContent = caught.message;
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#create-disk-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    createDiskDialog.close();
    return;
  }
  const form = event.currentTarget;
  const values = new FormData(form);
  const button = form.querySelector('button[value="default"]');
  const error = form.querySelector("[data-form-error]");
  error.textContent = "";
  setBusy(button, true);
  try {
    const disk = await authenticatedRequest(projectPath("/disks"), {
      method: "POST",
      body: JSON.stringify({ name: String(values.get("name")).trim(), size_bytes: Math.round(Number(values.get("size_gib")) * (1024 ** 3)) }),
    });
    createDiskDialog.close();
    form.reset();
    await loadAll({ quiet: true });
    toast(t("user.disk.created"), `${disk.name} · ${formatBytes(disk.size_bytes)}`);
  } catch (caught) {
    error.textContent = caught.message;
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#exec-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    execDialog.close();
    return;
  }
  const form = event.currentTarget;
  const button = form.querySelector('button[value="default"]');
  const output = document.querySelector("#exec-output");
  output.classList.remove("is-error");
  setBusy(button, true, t("user.execDialog.running"));
  try {
    const command = splitCommand(new FormData(form).get("command"));
    const result = await authenticatedRequest(projectPath(`/cats/${encodeURIComponent(state.execCat)}/exec`), {
      method: "POST",
      body: JSON.stringify({ command }),
    });
    output.classList.toggle("is-error", result.exit_code !== 0);
    output.textContent = `${result.stdout || ""}${result.stderr ? `\n[stderr]\n${result.stderr}` : ""}\n\n[exit ${result.exit_code}]`;
  } catch (caught) {
    output.classList.add("is-error");
    output.textContent = t("user.execDialog.failed", { message: caught.message });
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#cats-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-cat-action]");
  if (!button) return;
  mutateCat(button.dataset.cat, button.dataset.catAction, button).catch((error) => toast(t("user.cat.actionFailed"), error.message, "error"));
});
document.querySelector("#disks-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-disk-action]");
  if (!button) return;
  mutateDisk(button.dataset.disk, button.dataset.diskAction, button).catch((error) => toast(t("user.disk.actionFailed"), error.message, "error"));
});

function updateLoginDescription() {
  if (!state.authConfig) return;
  document.querySelector("#login-description").textContent = state.authConfig.workos_enabled
    ? t("user.login.description")
    : t("user.login.unconfigured");
}

onLocaleChange(() => {
  updateLoginDescription();
  const label = state.project ? workspaceLabel(state.project) : "";
  if (label) {
    document.querySelector("#sidebar-project").textContent = label;
    document.querySelector("#header-project").textContent = label;
  }
  switchView(state.activeView);
  render();
});

async function initializeAuth() {
  const callbackError = consumeAuthError();
  try {
    state.authConfig = await request("/auth/config");
    document.querySelector("#workos-login-button").classList.toggle("is-hidden", !state.authConfig.workos_enabled);
    updateLoginDescription();
    if (state.authConfig.workos_enabled) {
      try {
        const session = await request("/auth/session?site=user");
        state.project = session.project;
        showApp();
        await loadAll({ quiet: true });
        return;
      } catch (_) {
        // No WorkOS session yet; remain on the sign-in screen.
      }
    }
  } catch (error) {
    loginError.textContent = t("user.authConfigFailed", { message: error.message });
  }
  showLogin(loginError.textContent || callbackError);
}

initializeAuth();

window.setInterval(() => {
  if (!document.hidden && state.project && !appShell.classList.contains("is-hidden")) {
    loadAll({ quiet: true }).catch(() => {});
  }
}, 3_000);
