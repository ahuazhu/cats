export class ApiError extends Error {
  constructor(message, status = 0, code = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export async function request(path, token, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json, text/plain;q=0.9");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response;
  try {
    response = await fetch(path, { ...options, headers });
  } catch (error) {
    throw new ApiError(`无法连接控制面：${error.message}`);
  }

  const body = await response.text();
  const contentType = response.headers.get("content-type") || "";
  let value = null;
  if (body) {
    if (contentType.includes("json")) {
      try {
        value = JSON.parse(body);
      } catch (_) {
        throw new ApiError("控制面返回了无法解析的 JSON", response.status);
      }
    } else {
      value = body;
    }
  }

  if (!response.ok) {
    const message = value && typeof value === "object" && value.message
      ? value.message
      : body || `请求失败（HTTP ${response.status}）`;
    const code = value && typeof value === "object" ? value.code || "" : "";
    throw new ApiError(message, response.status, code);
  }
  return value;
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const scaled = value / (1024 ** index);
  return `${scaled >= 10 || index === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[index]}`;
}

export function formatTime(unixSeconds) {
  if (!unixSeconds) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(Number(unixSeconds) * 1000));
}

export function statusBadge(status) {
  const normalized = String(status || "unknown").toLowerCase().replaceAll("_", "-");
  const safeClass = normalized.replace(/[^a-z0-9-]/g, "");
  return `<span class="badge badge-${safeClass}">${escapeHtml(normalized.replaceAll("-", " "))}</span>`;
}

export function metricCard(label, value, detail) {
  return `<article class="metric-card"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong><span>${escapeHtml(detail)}</span></article>`;
}

export function toast(title, message = "", kind = "success") {
  const region = document.querySelector("#toast-region");
  if (!region) return;
  const item = document.createElement("div");
  item.className = `toast ${kind === "error" ? "error" : ""}`;
  const heading = document.createElement("strong");
  heading.textContent = title;
  const copy = document.createElement("span");
  copy.textContent = message;
  item.append(heading, copy);
  region.append(item);
  window.setTimeout(() => item.remove(), 4500);
}

export function setBusy(button, busy, busyLabel = "处理中…") {
  if (!button) return;
  if (busy) {
    button.dataset.originalLabel = button.textContent;
    button.textContent = busyLabel;
    button.disabled = true;
  } else {
    button.textContent = button.dataset.originalLabel || button.textContent;
    button.disabled = false;
  }
}

export function splitCommand(command) {
  const values = [];
  let current = "";
  let quote = "";
  let escaping = false;
  for (const character of command.trim()) {
    if (escaping) {
      current += character;
      escaping = false;
    } else if (character === "\\" && quote !== "'") {
      escaping = true;
    } else if (quote) {
      if (character === quote) quote = "";
      else current += character;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (/\s/.test(character)) {
      if (current) {
        values.push(current);
        current = "";
      }
    } else {
      current += character;
    }
  }
  if (escaping) current += "\\";
  if (quote) throw new Error("命令中存在未闭合的引号");
  if (current) values.push(current);
  if (!values.length) throw new Error("命令不能为空");
  return values;
}

export function initTokenToggle(root = document) {
  root.querySelectorAll(".token-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const input = button.closest(".password-field")?.querySelector("input");
      if (!input) return;
      input.type = input.type === "password" ? "text" : "password";
      button.textContent = input.type === "password" ? "显示" : "隐藏";
    });
  });
}

export function initNavigation(titles, onChange) {
  const sidebar = document.querySelector(".sidebar");
  document.querySelector("#mobile-menu")?.addEventListener("click", () => sidebar?.classList.toggle("is-open"));
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.view));
  });
  document.querySelectorAll("[data-go]").forEach((button) => {
    button.addEventListener("click", () => switchView(button.dataset.go));
  });

  function switchView(name) {
    if (!titles[name]) return;
    document.querySelectorAll(".view").forEach((view) => view.classList.toggle("is-active", view.id === `view-${name}`));
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.view === name));
    const title = document.querySelector("#view-title");
    if (title) title.textContent = titles[name];
    sidebar?.classList.remove("is-open");
    onChange?.(name);
  }
  return switchView;
}

export function sleep(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}
