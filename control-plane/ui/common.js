import { getLocale, localizedApiMessage, t } from "/ui/i18n.js";

export class ApiError extends Error {
  constructor(message, status = 0, code = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export async function requestWithStatus(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json, text/plain;q=0.9");
  if (options.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response;
  try {
    response = await fetch(path, { ...options, headers });
  } catch (error) {
    throw new ApiError(t("error.network", { message: error.message }));
  }

  const body = await response.text();
  const contentType = response.headers.get("content-type") || "";
  let value = null;
  if (body) {
    if (contentType.includes("json")) {
      try {
        value = JSON.parse(body);
      } catch (_) {
        throw new ApiError(t("error.invalidJson"), response.status);
      }
    } else {
      value = body;
    }
  }

  if (!response.ok) {
    const code = value && typeof value === "object" ? value.code || "" : "";
    const fallback = value && typeof value === "object" && value.message
      ? value.message
      : body || t("error.http", { status: response.status });
    const message = localizedApiMessage(code, fallback);
    throw new ApiError(message, response.status, code);
  }
  return { status: response.status, value, body };
}

export async function request(path, options = {}) {
  const response = await requestWithStatus(path, options);
  return response.value;
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
  const digits = scaled >= 10 || index === 0 ? 0 : 1;
  return `${new Intl.NumberFormat(getLocale(), { maximumFractionDigits: digits }).format(scaled)} ${units[index]}`;
}

export function formatTime(unixSeconds) {
  if (!unixSeconds) return "—";
  return new Intl.DateTimeFormat(getLocale(), {
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
  const key = `status.${normalized.replaceAll("-", "_")}`;
  const label = t(key);
  return `<span class="badge badge-${safeClass}">${escapeHtml(label === key ? normalized.replaceAll("-", " ") : label)}</span>`;
}

export function resourceKind(kind) {
  const normalized = String(kind || "unknown").toLowerCase();
  const key = `kind.${normalized}`;
  const label = t(key);
  return label === key ? normalized : label;
}

export function operationKind(kind) {
  const normalized = String(kind || "unknown").toLowerCase().replaceAll(".", "_");
  const key = `operation.${normalized}`;
  const label = t(key);
  return label === key ? kind : label;
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

export function setBusy(button, busy, busyLabel = t("common.loading")) {
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
  if (quote) throw new Error(t("error.unclosedQuote"));
  if (current) values.push(current);
  if (!values.length) throw new Error(t("error.emptyCommand"));
  return values;
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
    if (title) title.textContent = typeof titles[name] === "function" ? titles[name]() : titles[name];
    sidebar?.classList.remove("is-open");
    onChange?.(name);
  }
  return switchView;
}

export function sleep(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}
