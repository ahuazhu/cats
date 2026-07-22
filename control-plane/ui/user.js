import {
  escapeHtml,
  formatBytes,
  formatTime,
  initNavigation,
  initTokenToggle,
  metricCard,
  request,
  setBusy,
  sleep,
  splitCommand,
  statusBadge,
  toast,
} from "/ui/common.js";

const TOKEN_KEY = "cats.user.token";
const PROJECT_KEY = "cats.user.project";
const state = {
  token: "",
  project: "",
  authMode: "token",
  authConfig: null,
  cats: [],
  disks: [],
  operations: [],
  activeView: "overview",
  execCat: "",
};

const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const loginForm = document.querySelector("#login-form");
const loginError = document.querySelector("#login-error");
const createCatDialog = document.querySelector("#create-cat-dialog");
const createDiskDialog = document.querySelector("#create-disk-dialog");
const execDialog = document.querySelector("#exec-dialog");

initTokenToggle();
initNavigation(
  { overview: "项目概览", cats: "Cats", disks: "Persistent Disks", operations: "Operations" },
  (view) => { state.activeView = view; },
);

function projectPath(path) {
  return `/v1/projects/${encodeURIComponent(state.project)}${path}`;
}

async function authenticatedRequest(path, options) {
  try {
    return await request(path, state.token, options);
  } catch (error) {
    if (state.authMode !== "workos" || error.status !== 401) throw error;
    await request("/auth/session?site=user", "");
    return request(path, "", options);
  }
}

function idempotencyHeaders() {
  return { "Idempotency-Key": globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}` };
}

function showApp() {
  loginScreen.classList.add("is-hidden");
  appShell.classList.remove("is-hidden");
  document.querySelector("#sidebar-project").textContent = state.project;
  document.querySelector("#header-project").textContent = state.project;
}

function showLogin(message = "") {
  appShell.classList.add("is-hidden");
  loginScreen.classList.remove("is-hidden");
  loginError.textContent = message;
}

async function loadAll({ quiet = false } = {}) {
  const button = document.querySelector("#refresh-button");
  if (!quiet) setBusy(button, true, "刷新中…");
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
      sessionStorage.removeItem(TOKEN_KEY);
      showLogin(error.message);
    } else {
      toast("刷新失败", error.message, "error");
    }
    throw error;
  } finally {
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
    metricCard("Total Cats", state.cats.length, `${counts.running || 0} 正在运行`),
    metricCard("Suspended / Warm", (counts.suspended || 0) + (counts.warm || 0), "可快速恢复"),
    metricCard("Persistent Disks", persistentDisks.length, formatBytes(persistentDisks.reduce((sum, disk) => sum + disk.size_bytes, 0))),
    metricCard("Active Operations", activeOperations.length, "控制面异步任务"),
  ].join("");

  const recentCats = [...state.cats].sort((a, b) => b.created_at_unix - a.created_at_unix).slice(0, 5);
  document.querySelector("#recent-cats").innerHTML = recentCats.length
    ? `<div class="compact-list">${recentCats.map((cat) => `<div class="compact-row"><div><strong>${escapeHtml(cat.name)}</strong><small>${escapeHtml(cat.spec.cpus)} CPU · ${escapeHtml(cat.spec.memory_mib)} MiB · ${escapeHtml(cat.node_id || "未调度")}</small></div>${statusBadge(cat.observed_state)}</div>`).join("")}</div>`
    : '<div class="mini-empty">还没有 Cat，点击右上角开始创建。</div>';

  const recentOperations = [...state.operations].sort((a, b) => b.updated_at_unix - a.updated_at_unix).slice(0, 5);
  document.querySelector("#recent-operations").innerHTML = recentOperations.length
    ? `<div class="compact-list">${recentOperations.map((operation) => `<div class="compact-row"><div><strong>${escapeHtml(operation.kind)}</strong><small>${formatTime(operation.updated_at_unix)}</small></div>${statusBadge(operation.phase)}</div>`).join("")}</div>`
    : '<div class="mini-empty">暂无操作记录。</div>';
}

function catActions(cat) {
  const stateActions = {
    running: [["exec", "Exec"], ["suspend", "Suspend"], ["warm", "Warm"], ["stop", "Stop"]],
    suspended: [["resume", "Resume"], ["warm", "Warm"], ["stop", "Stop"]],
    warm: [["resume", "Resume"], ["stop", "Stop"]],
    cold: [["start", "Start"]],
    failed: [["start", "Start"]],
    unknown: [["start", "Start"]],
  };
  const actions = stateActions[cat.observed_state] || [];
  const buttons = actions.map(([action, label]) => `<button class="mini-button" data-cat-action="${action}" data-cat="${escapeHtml(cat.name)}">${label}</button>`);
  if (cat.observed_state === "running") {
    buttons.push(`<button class="mini-button" data-cat-action="expose" data-cat="${escapeHtml(cat.name)}">Expose</button>`);
  }
  buttons.push(`<button class="mini-button danger" data-cat-action="destroy" data-cat="${escapeHtml(cat.name)}">Destroy</button>`);
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
  const buttons = [`<button class="mini-button" data-disk-action="snapshot" data-disk="${escapeHtml(disk.name)}">Snapshot</button>`];
  if (disk.kind === "persistent") {
    if (disk.state === "bound") {
      buttons.push(`<button class="mini-button" data-disk-action="unmount" data-disk="${escapeHtml(disk.name)}">Unmount</button>`);
    } else if (disk.state === "available") {
      buttons.push(`<button class="mini-button" data-disk-action="mount" data-disk="${escapeHtml(disk.name)}">Mount</button>`);
      buttons.push(`<button class="mini-button" data-disk-action="resize" data-disk="${escapeHtml(disk.name)}">Resize</button>`);
      buttons.push(`<button class="mini-button danger" data-disk-action="delete" data-disk="${escapeHtml(disk.name)}">Delete</button>`);
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
    <td>${escapeHtml(disk.kind)}</td><td>${formatBytes(disk.size_bytes)}</td><td>${statusBadge(disk.state)}</td>
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
    <td><div class="resource-name"><span><strong>${escapeHtml(operation.id)}</strong><small>generation ${escapeHtml(operation.resource_generation)}</small></span></div></td>
    <td>${escapeHtml(operation.kind)}</td><td>${escapeHtml(operation.resource_id)}</td><td>${statusBadge(operation.phase)}</td>
    <td>${formatTime(operation.updated_at_unix)}</td><td>${escapeHtml(operation.error?.message || "—")}</td>
  </tr>`).join("");
}

async function waitForOperation(operation) {
  if (!operation?.id) return;
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const current = await authenticatedRequest(`/v1/operations/${encodeURIComponent(operation.id)}`);
    if (current.phase === "succeeded") return current;
    if (current.phase === "failed") throw new Error(current.error?.message || `Operation ${current.id} 失败`);
    await sleep(300);
  }
  throw new Error(`Operation ${operation.id} 等待超时`);
}

async function mutateCat(name, action, button) {
  if (action === "exec") {
    state.execCat = name;
    document.querySelector("#exec-cat-name").textContent = name;
    document.querySelector("#exec-output").textContent = "等待执行…";
    execDialog.showModal();
    return;
  }
  if (action === "expose") {
    const port = window.prompt(`暴露 ${name} 的 guest port`, "8080");
    if (port === null) return;
    const endpointName = window.prompt("Endpoint 名称", "web");
    if (endpointName === null) return;
    setBusy(button, true);
    try {
      const response = await authenticatedRequest(projectPath(`/cats/${encodeURIComponent(name)}/endpoints`), {
        method: "POST",
        body: JSON.stringify({ name: endpointName, target_port: Number(port), protocol: "http", wake_policy: "wake_on_request" }),
      });
      toast("Endpoint 已创建", response.endpoint.hostname);
    } finally {
      setBusy(button, false);
    }
    return;
  }
  if (action === "destroy" && !window.confirm(`确定销毁 Cat “${name}”？RootDisk 将一并删除。`)) return;
  setBusy(button, true);
  try {
    const path = action === "destroy"
      ? projectPath(`/cats/${encodeURIComponent(name)}`)
      : projectPath(`/cats/${encodeURIComponent(name)}/actions/${action}`);
    const response = await authenticatedRequest(path, {
      method: action === "destroy" ? "DELETE" : "POST",
      headers: idempotencyHeaders(),
    });
    toast("操作已接受", `${name} · ${action}`);
    await waitForOperation(response.operation);
    await loadAll({ quiet: true });
    toast("操作完成", `${name} · ${action}`);
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
    if (!state.cats.length) throw new Error("请先创建一个 Cat");
    const cat = window.prompt("挂载到哪个 Cat？", state.cats[0].name);
    if (cat === null) return;
    const mountAt = window.prompt("Guest 挂载路径", "/data");
    if (mountAt === null) return;
    body = { cat_id: cat, mount_at: mountAt };
  } else if (action === "resize") {
    const currentGiB = disk.size_bytes / (1024 ** 3);
    const size = window.prompt("新容量（GiB，只能扩容）", String(currentGiB));
    if (size === null) return;
    body = { size_bytes: Math.round(Number(size) * (1024 ** 3)) };
  } else if (action === "unmount") {
    body = {};
  } else if (action === "snapshot") {
    path = projectPath(`/disks/${encodeURIComponent(name)}/snapshots`);
  } else if (action === "delete") {
    if (!window.confirm(`确定删除 PersistentDisk “${name}”？`)) return;
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
    toast(action === "snapshot" ? "Snapshot 已创建" : "磁盘操作完成", response?.id || `${name} · ${action}`);
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
  const form = new FormData(loginForm);
  const project = String(form.get("project") || "").trim();
  const token = String(form.get("token") || "").trim();
  loginError.textContent = "";
  setBusy(button, true, "正在验证…");
  try {
    await request(`/v1/projects/${encodeURIComponent(project)}/cats`, token);
    state.project = project;
    state.token = token;
    state.authMode = "token";
    sessionStorage.setItem(PROJECT_KEY, project);
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
  const project = document.querySelector("#login-project").value.trim();
  if (!project) {
    loginError.textContent = "Project 不能为空";
    return;
  }
  const query = new URLSearchParams({ site: "user", project, return_to: "/user/" });
  window.location.assign(`/auth/login?${query}`);
}

document.querySelector("#workos-login-button").addEventListener("click", startWorkOsLogin);

document.querySelector("#logout-button").addEventListener("click", () => {
  if (state.authMode === "workos") {
    window.location.assign("/auth/logout?site=user");
    return;
  }
  sessionStorage.removeItem(TOKEN_KEY);
  state.token = "";
  showLogin();
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
        disk: null,
      }),
    });
    toast("Cat 创建中", response.cat.name);
    createCatDialog.close();
    form.reset();
    await waitForOperation(response.operation);
    await loadAll({ quiet: true });
    toast("Cat 已就绪", response.cat.name);
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
    toast("PersistentDisk 已创建", `${disk.name} · ${formatBytes(disk.size_bytes)}`);
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
  const error = form.querySelector("[data-form-error]");
  error.textContent = "";
  setBusy(button, true, "执行中…");
  try {
    const command = splitCommand(new FormData(form).get("command"));
    const result = await authenticatedRequest(projectPath(`/cats/${encodeURIComponent(state.execCat)}/exec`), {
      method: "POST",
      body: JSON.stringify({ command }),
    });
    output.textContent = `${result.stdout || ""}${result.stderr ? `\n[stderr]\n${result.stderr}` : ""}\n\n[exit ${result.exit_code}]`;
  } catch (caught) {
    error.textContent = caught.message;
  } finally {
    setBusy(button, false);
  }
});

document.querySelector("#cats-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-cat-action]");
  if (!button) return;
  mutateCat(button.dataset.cat, button.dataset.catAction, button).catch((error) => toast("Cat 操作失败", error.message, "error"));
});
document.querySelector("#disks-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-disk-action]");
  if (!button) return;
  mutateDisk(button.dataset.disk, button.dataset.diskAction, button).catch((error) => toast("磁盘操作失败", error.message, "error"));
});

async function initializeAuth() {
  state.project = sessionStorage.getItem(PROJECT_KEY) || "default";
  state.token = sessionStorage.getItem(TOKEN_KEY) || "";
  document.querySelector("#login-project").value = state.project;
  try {
    state.authConfig = await request("/auth/config", "");
    document.querySelector("#workos-login-button").classList.toggle("is-hidden", !state.authConfig.workos_enabled);
    document.querySelector("#token-login-section").classList.toggle("is-hidden", !state.authConfig.token_login_enabled);
    document.querySelector("#login-description").textContent = state.authConfig.workos_enabled
      ? "通过 WorkOS 安全登录并进入所属 Project。"
      : "使用 Project Token 登录。凭证仅保存在当前浏览器标签页中。";
    if (state.authConfig.workos_enabled) {
      try {
        const session = await request("/auth/session?site=user", "");
        state.authMode = "workos";
        state.token = "";
        state.project = session.project;
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.setItem(PROJECT_KEY, state.project);
        showApp();
        await loadAll({ quiet: true });
        return;
      } catch (_) {
        // No WorkOS session yet; remain on the sign-in screen.
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
