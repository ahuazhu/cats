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
import { getLocale, initI18n, localizedApiMessage, onLocaleChange, t } from "/ui/i18n.js";

initI18n();

const state = {
  project: "",
  accounts: [],
  workspaces: [],
  activeAccountId: "",
  activeWorkspaceId: "",
  authConfig: null,
  cats: [],
  disks: [],
  operations: [],
  billing: null,
  billingBalance: null,
  billingLoading: false,
  billingLoadedAt: 0,
  billingDetail: null,
  selectedBillingCatId: "",
  selectedBillingCatName: "",
  activeView: "overview",
  execCat: "",
  loading: false,
  paymentRedirecting: false,
};

const loginScreen = document.querySelector("#login-screen");
const appShell = document.querySelector("#app-shell");
const loginError = document.querySelector("#login-error");
const createCatDialog = document.querySelector("#create-cat-dialog");
const createDiskDialog = document.querySelector("#create-disk-dialog");
const billingCatDialog = document.querySelector("#billing-cat-dialog");
const execDialog = document.querySelector("#exec-dialog");

const switchView = initNavigation(
  {
    overview: () => t("user.nav.overview"),
    cats: () => t("user.nav.cats"),
    disks: () => t("user.disks.title"),
    billing: () => t("user.nav.billing"),
    operations: () => t("user.nav.operations"),
  },
  (view) => {
    state.activeView = view;
    if (view === "billing" && state.project && !state.billing) {
      loadBilling().catch(() => {});
    }
  },
);

function projectPath(path) {
  return `/v1/projects/${encodeURIComponent(state.project)}${path}`;
}

function workspaceLabel(project) {
  return project.startsWith("personal-user_") ? t("user.workspace.personal") : project;
}

function activeWorkspace() {
  return state.workspaces.find((workspace) => workspace.id === state.activeWorkspaceId);
}

function applySession(session) {
  state.project = session.project || "";
  state.accounts = session.accounts || [];
  state.workspaces = session.workspaces || [];
  state.activeAccountId = session.active_account_id || "";
  state.activeWorkspaceId = session.active_workspace_id || "";
  renderWorkspaceSwitcher();
}

function workspaceUrl(workspace) {
  return `/user/${encodeURIComponent(workspace.account_slug)}/${encodeURIComponent(workspace.slug)}/`;
}

function renderWorkspaceSwitcher() {
  const select = document.querySelector("#workspace-switcher");
  if (!select) return;
  select.innerHTML = state.workspaces.map((workspace) => {
    const label = `${workspace.account_display_name} / ${workspace.display_name}`;
    return `<option value="${escapeHtml(workspace.id)}"${workspace.id === state.activeWorkspaceId ? " selected" : ""}>${escapeHtml(label)}</option>`;
  }).join("");
  const workspace = activeWorkspace();
  const label = workspace
    ? `${workspace.account_display_name} / ${workspace.display_name}`
    : workspaceLabel(state.project);
  document.querySelector("#sidebar-project").textContent = label;
  document.querySelector("#header-project").textContent = label;
}

async function switchWorkspace(workspaceId, { updateUrl = true } = {}) {
  if (!workspaceId || workspaceId === state.activeWorkspaceId) return;
  const session = await request("/auth/workspace", {
    method: "POST",
    body: JSON.stringify({ workspace_id: workspaceId }),
  });
  applySession(session);
  state.cats = [];
  state.disks = [];
  state.operations = [];
  state.billing = null;
  state.billingBalance = null;
  state.billingDetail = null;
  if (updateUrl) {
    const workspace = activeWorkspace();
    if (workspace) window.history.pushState(null, "", workspaceUrl(workspace));
  }
  await loadAll({ quiet: true });
}

async function authenticatedRequest(path, options) {
  try {
    return await request(path, options);
  } catch (error) {
    let failure = error;
    if (failure.status === 401) {
      await request("/auth/session?site=user");
      try {
        return await request(path, options);
      } catch (retryFailure) {
        failure = retryFailure;
      }
    }
    if (failure.status === 402 && !path.includes("/billing/checkout")) {
      redirectForPayment().catch((redirectError) => {
        switchView("billing");
        toast(t("user.billing.topup.failed"), redirectError.message, "error");
      });
    }
    throw failure;
  }
}

function idempotencyHeaders() {
  return { "Idempotency-Key": globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}` };
}

function showApp() {
  loginScreen.classList.add("is-hidden");
  appShell.classList.remove("is-hidden");
  renderWorkspaceSwitcher();
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

function consumeTopupStatus() {
  const url = new URL(window.location.href);
  const status = url.searchParams.get("topup");
  if (!status) return "";
  url.searchParams.delete("topup");
  url.searchParams.delete("session_id");
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
  return status;
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
  renderBillingBalance();
  renderBilling();
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

const BILLING_METERS = {
  cpu_usec: {
    name: () => t("user.billing.meter.cpu"),
    slug: "cats.compute.cpu.v1",
    rate: () => t("user.billing.rate.cpu"),
    denominator: 3_600_000_000n,
    rateNumeratorNanos: 70_000_000n,
    unit: () => t("user.billing.unit.cpuHour"),
  },
  memory_byte_millis: {
    name: () => t("user.billing.meter.memory"),
    slug: "cats.compute.memory.v1",
    rate: () => t("user.billing.rate.memory"),
    denominator: 1_073_741_824n * 3_600_000n,
    rateNumeratorNanos: 45_000_000n,
    unit: () => t("user.billing.unit.gibHour"),
  },
  storage_hot_byte_millis: {
    name: () => t("user.billing.meter.hotStorage"),
    slug: "cats.storage.hot.v1",
    rate: () => t("user.billing.notPriced"),
    denominator: 1_073_741_824n * 3_600_000n,
    unit: () => t("user.billing.unit.gibHour"),
  },
  storage_cold_byte_millis: {
    name: () => t("user.billing.meter.coldStorage"),
    slug: "cats.storage.cold.v1",
    rate: () => t("user.billing.notPriced"),
    denominator: 1_073_741_824n * 3_600_000n,
    unit: () => t("user.billing.unit.gibHour"),
  },
  network_egress_bytes: {
    name: () => t("user.billing.meter.egress"),
    slug: "cats.network.egress.v1",
    rate: () => t("user.billing.notPriced"),
    denominator: 1_073_741_824n,
    unit: () => t("user.billing.unit.gib"),
  },
};

function exactUnsigned(value) {
  const decimal = String(value ?? "0");
  return /^\d+$/.test(decimal) ? BigInt(decimal) : 0n;
}

function formatRatio(quantity, denominator, maximumFractionDigits = 4) {
  const value = exactUnsigned(quantity);
  const scale = 10n ** BigInt(maximumFractionDigits);
  const rounded = (value * scale + denominator / 2n) / denominator;
  const whole = rounded / scale;
  let fraction = (rounded % scale).toString().padStart(maximumFractionDigits, "0");
  fraction = fraction.replace(/0+$/, "");
  const localizedWhole = whole.toLocaleString(getLocale());
  return fraction ? `${localizedWhole}.${fraction}` : localizedWhole;
}

function formatUsdNanos(value, currency = "USD") {
  const decimal = String(value ?? "0");
  const signed = /^-?\d+$/.test(decimal) ? BigInt(decimal) : 0n;
  const negative = signed < 0n;
  const nanos = negative ? -signed : signed;
  const scale = 1_000_000n;
  const roundedMicros = (nanos + 500n) / 1_000n;
  const whole = roundedMicros / scale;
  let fraction = (roundedMicros % scale).toString().padStart(6, "0");
  while (fraction.length > 4 && fraction.endsWith("0")) fraction = fraction.slice(0, -1);
  const prefix = currency === "USD" ? "$" : `${currency} `;
  return `${negative ? "-" : ""}${prefix}${whole.toLocaleString(getLocale())}.${fraction}`;
}

function billingMeter(metric) {
  return BILLING_METERS[metric] || {
    name: () => metric,
    slug: metric,
    rate: () => t("user.billing.notPriced"),
    denominator: 1n,
    unit: () => "",
  };
}

function formatMeterQuantity(item) {
  const meter = billingMeter(item.metric);
  return `${formatRatio(item.quantity, meter.denominator)} ${meter.unit()}`.trim();
}

function formatBillingTime(unixMilliseconds) {
  if (!unixMilliseconds) return t("user.billing.waitingForSamples");
  return new Intl.DateTimeFormat(getLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(Number(unixMilliseconds)));
}

function renderBillingBalance() {
  const balance = state.billingBalance;
  const available = document.querySelector("#billing-available-credit");
  const status = document.querySelector("#billing-balance-status");
  const totalCredit = document.querySelector("#billing-total-credit");
  const totalUsage = document.querySelector("#billing-total-usage");
  const signupCredit = document.querySelector("#billing-signup-credit");
  const options = document.querySelector("#billing-topup-options");
  const note = document.querySelector("#billing-topup-note");
  if (!available || !status || !totalCredit || !totalUsage || !signupCredit || !options || !note) return;
  if (!balance) {
    available.textContent = "—";
    totalCredit.textContent = "—";
    totalUsage.textContent = "—";
    signupCredit.textContent = "—";
    status.textContent = t("user.billing.balance.loading");
    options.innerHTML = "";
    note.textContent = t("user.billing.topup.loading");
    return;
  }
  available.textContent = formatUsdNanos(balance.available_credit_nanos, balance.currency);
  totalCredit.textContent = formatUsdNanos(balance.credit_nanos, balance.currency);
  totalUsage.textContent = formatUsdNanos(balance.provisional_usage_nanos, balance.currency);
  signupCredit.textContent = formatUsdNanos(balance.signup_credit_nanos, balance.currency);
  status.textContent = balance.status === "payment_required"
    ? t("user.billing.balance.exhausted")
    : t("user.billing.balance.active");
  const amounts = balance.topup_options_cents || [];
  options.innerHTML = balance.stripe_enabled
    ? amounts.map((cents) => `<button type="button" data-topup-cents="${Number(cents)}">${escapeHtml(new Intl.NumberFormat(getLocale(), { style: "currency", currency: balance.currency, maximumFractionDigits: 0 }).format(Number(cents) / 100))}</button>`).join("")
    : "";
  note.textContent = balance.stripe_enabled
    ? t("user.billing.topup.secure")
    : t("user.billing.topup.unavailable");
}

function renderBilling() {
  const report = state.billing;
  const metrics = document.querySelector("#billing-metrics");
  const meta = document.querySelector("#billing-meta");
  const meterBody = document.querySelector("#billing-meters-table");
  const catBody = document.querySelector("#billing-cats-table");
  if (!metrics || !meta || !meterBody || !catBody) return;

  if (!report) {
    metrics.innerHTML = [
      metricCard(t("user.billing.estimatedTotal"), "—", t("user.billing.provisionalDetail")),
      metricCard(t("user.billing.cpu"), "—", t("user.billing.unit.cpuHour")),
      metricCard(t("common.memory"), "—", t("user.billing.unit.gibHour")),
      metricCard(t("user.billing.latestData"), "—", t("user.billing.waitingForSamples")),
    ].join("");
    meta.innerHTML = `<span>${escapeHtml(t("user.billing.loading"))}</span>`;
    meterBody.innerHTML = `<tr class="billing-empty"><td colspan="4">${escapeHtml(t("common.loading"))}</td></tr>`;
    catBody.innerHTML = `<tr class="billing-empty"><td colspan="5">${escapeHtml(t("common.loading"))}</td></tr>`;
    return;
  }

  const reportItems = new Map((report.items || []).map((item) => [item.metric, item]));
  const cpu = reportItems.get("cpu_usec") || { metric: "cpu_usec", quantity: "0" };
  const memory = reportItems.get("memory_byte_millis") || { metric: "memory_byte_millis", quantity: "0" };
  const latest = formatBillingTime(report.latest_interval_end_unix_ms);
  metrics.innerHTML = [
    metricCard(t("user.billing.estimatedTotal"), formatUsdNanos(report.amount_nanos, report.currency), t("user.billing.provisionalDetail")),
    metricCard(t("user.billing.cpu"), formatMeterQuantity(cpu), t("user.billing.rate.cpu")),
    metricCard(t("common.memory"), formatMeterQuantity(memory), t("user.billing.rate.memory")),
    metricCard(t("user.billing.latestData"), latest, t("user.billing.visibleThrough")),
  ].join("");

  meta.innerHTML = `<div class="billing-meta-group">
    <span class="billing-provisional">${escapeHtml(t("user.billing.provisional"))}</span>
    <span><strong>${escapeHtml(t("user.billing.account"))}</strong> <code>${escapeHtml(report.billing_account_id)}</code></span>
    <span><strong>${escapeHtml(t("user.billing.rateCard"))}</strong> <code>${escapeHtml(report.rate_card_id)}</code></span>
  </div><span>${escapeHtml(t("user.billing.noInvoice"))}</span>`;

  const orderedItems = ["cpu_usec", "memory_byte_millis"]
    .map((metric) => reportItems.get(metric) || { metric, quantity: "0", amount_nanos: "0" })
    .concat((report.items || []).filter((item) => !["cpu_usec", "memory_byte_millis"].includes(item.metric)));
  meterBody.innerHTML = orderedItems.map((item) => {
    const meter = billingMeter(item.metric);
    const amount = item.amount_nanos === undefined
      ? t("user.billing.notPriced")
      : formatUsdNanos(item.amount_nanos, report.currency);
    return `<tr>
      <td><div class="billing-item"><strong>${escapeHtml(meter.name())}</strong><small>${escapeHtml(meter.slug)}</small></div></td>
      <td>${escapeHtml(formatMeterQuantity(item))}</td>
      <td>${escapeHtml(meter.rate())}</td>
      <td class="align-right billing-amount">${escapeHtml(amount)}</td>
    </tr>`;
  }).join("");

  const catNames = new Map(state.cats.map((cat) => [cat.id, cat.name]));
  const cats = report.cats || [];
  catBody.innerHTML = cats.length
    ? cats.map((cat) => {
      const items = new Map((cat.items || []).map((item) => [item.metric, item]));
      const catCpu = items.get("cpu_usec") || { metric: "cpu_usec", quantity: "0" };
      const catMemory = items.get("memory_byte_millis") || { metric: "memory_byte_millis", quantity: "0" };
      const name = catNames.get(cat.cat_id) || t("user.billing.deletedCat");
      return `<tr>
        <td><div class="resource-name"><span class="resource-avatar">C</span><span><strong>${escapeHtml(name)}</strong><small>${escapeHtml(cat.cat_id)}</small></span></div></td>
        <td>${escapeHtml(formatMeterQuantity(catCpu))}</td>
        <td>${escapeHtml(formatMeterQuantity(catMemory))}</td>
        <td class="align-right billing-amount">${escapeHtml(formatUsdNanos(cat.amount_nanos, report.currency))}</td>
        <td class="align-right"><button class="mini-button" data-billing-cat-detail="${escapeHtml(cat.cat_id)}">${escapeHtml(t("user.billing.viewDetails"))}</button></td>
      </tr>`;
    }).join("")
    : `<tr class="billing-empty"><td colspan="5">${escapeHtml(t("user.billing.noCatUsage"))}</td></tr>`;
}

function billingItem(report, metric) {
  return (report?.items || []).find((item) => item.metric === metric)
    || { metric, quantity: "0", amount_nanos: "0" };
}

function orderedBillingItems(report) {
  const items = new Map((report?.items || []).map((item) => [item.metric, item]));
  return ["cpu_usec", "memory_byte_millis"]
    .map((metric) => items.get(metric) || { metric, quantity: "0", amount_nanos: "0" })
    .concat((report?.items || []).filter((item) => !["cpu_usec", "memory_byte_millis"].includes(item.metric)));
}

function billingBucketSize(fromMs, toMs) {
  const duration = Math.max(1, toMs - fromMs);
  const minimum = Math.ceil(duration / 72);
  const friendlySizes = [
    60_000,
    5 * 60_000,
    15 * 60_000,
    30 * 60_000,
    60 * 60_000,
    3 * 60 * 60_000,
    6 * 60 * 60_000,
    12 * 60 * 60_000,
    24 * 60 * 60_000,
    3 * 24 * 60 * 60_000,
    7 * 24 * 60 * 60_000,
    30 * 24 * 60 * 60_000,
  ];
  return friendlySizes.find((size) => size >= minimum)
    || Math.ceil(minimum / (24 * 60 * 60_000)) * 24 * 60 * 60_000;
}

function formatBillingPeriod(startMs, endMs) {
  const formatter = new Intl.DateTimeFormat(getLocale(), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `${formatter.format(new Date(Number(startMs)))} – ${formatter.format(new Date(Number(endMs)))}`;
}

function formatBillingAxisTime(unixMilliseconds) {
  return new Intl.DateTimeFormat(getLocale(), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(Number(unixMilliseconds)));
}

function bucketMetricAmount(bucket, metric) {
  return exactUnsigned((bucket.items || []).find((item) => item.metric === metric)?.amount_nanos);
}

function renderBillingDetailChart(report) {
  const buckets = report.time_buckets || [];
  if (!buckets.length || buckets.every((bucket) => exactUnsigned(bucket.amount_nanos) === 0n)) {
    return `<div class="mini-empty billing-chart-empty">${escapeHtml(t("user.billing.detail.noChartData"))}</div>`;
  }

  const series = [
    {
      label: t("user.billing.detail.total"),
      className: "billing-chart-total",
      values: buckets.map((bucket) => exactUnsigned(bucket.amount_nanos)),
    },
    {
      label: t("user.billing.meter.cpu"),
      className: "billing-chart-cpu",
      values: buckets.map((bucket) => bucketMetricAmount(bucket, "cpu_usec")),
    },
    {
      label: t("user.billing.meter.memory"),
      className: "billing-chart-memory",
      values: buckets.map((bucket) => bucketMetricAmount(bucket, "memory_byte_millis")),
    },
  ];
  const maximum = series.flatMap((item) => item.values).reduce((max, value) => value > max ? value : max, 0n);
  const width = 900;
  const height = 260;
  const left = 82;
  const right = 22;
  const top = 18;
  const bottom = 42;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const x = (index) => left + (buckets.length === 1 ? plotWidth / 2 : (index / (buckets.length - 1)) * plotWidth);
  const y = (value) => {
    const ratio = maximum === 0n ? 0 : Number((value * 1_000_000n) / maximum) / 1_000_000;
    return top + (1 - ratio) * plotHeight;
  };
  const gridValues = [maximum, maximum / 2n, 0n];
  const grid = gridValues.map((value, index) => {
    const gridY = top + (index / 2) * plotHeight;
    return `<line x1="${left}" y1="${gridY}" x2="${width - right}" y2="${gridY}" class="billing-chart-grid"></line>
      <text x="${left - 10}" y="${gridY + 4}" text-anchor="end" class="billing-chart-axis">${escapeHtml(formatUsdNanos(value, report.currency))}</text>`;
  }).join("");
  const lines = series.map((item) => {
    const points = item.values.map((value, index) => `${x(index).toFixed(2)},${y(value).toFixed(2)}`).join(" ");
    const markers = item.values.map((value, index) => `<circle cx="${x(index).toFixed(2)}" cy="${y(value).toFixed(2)}" r="3" class="${item.className}">
      <title>${escapeHtml(`${formatBillingAxisTime(buckets[index].interval_start_unix_ms)} · ${item.label} · ${formatUsdNanos(value, report.currency)}`)}</title>
    </circle>`).join("");
    return `<polyline points="${points}" class="${item.className}"></polyline>${markers}`;
  }).join("");
  const axisIndexes = [...new Set([0, Math.floor((buckets.length - 1) / 2), buckets.length - 1])];
  const xAxis = axisIndexes.map((index) => `<text x="${x(index).toFixed(2)}" y="${height - 13}" text-anchor="${index === 0 ? "start" : index === buckets.length - 1 ? "end" : "middle"}" class="billing-chart-axis">${escapeHtml(formatBillingAxisTime(buckets[index].interval_start_unix_ms))}</text>`).join("");
  const legend = series.map((item) => `<span><i class="${item.className}"></i>${escapeHtml(item.label)}</span>`).join("");
  return `<div class="billing-chart-legend">${legend}</div>
    <svg class="billing-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(t("user.billing.detail.chartAria"))}">
      ${grid}${lines}${xAxis}
    </svg>`;
}

function renderBillingCatDetail() {
  const report = state.billingDetail;
  const loading = document.querySelector("#billing-detail-loading");
  const error = document.querySelector("#billing-detail-error");
  const content = document.querySelector("#billing-detail-content");
  if (!report) {
    loading.classList.remove("is-hidden");
    content.classList.add("is-hidden");
    return;
  }
  loading.classList.add("is-hidden");
  error.classList.add("is-hidden");
  content.classList.remove("is-hidden");
  document.querySelector("#billing-detail-period").textContent = formatBillingPeriod(
    report.interval_start_unix_ms,
    report.interval_end_unix_ms,
  );

  const cpu = billingItem(report, "cpu_usec");
  const memory = billingItem(report, "memory_byte_millis");
  document.querySelector("#billing-detail-metrics").innerHTML = [
    metricCard(t("user.billing.estimatedTotal"), formatUsdNanos(report.amount_nanos, report.currency), t("user.billing.provisionalDetail")),
    metricCard(t("user.billing.meter.cpu"), formatMeterQuantity(cpu), formatUsdNanos(cpu.amount_nanos, report.currency)),
    metricCard(t("user.billing.meter.memory"), formatMeterQuantity(memory), formatUsdNanos(memory.amount_nanos, report.currency)),
    metricCard(t("user.billing.latestData"), formatBillingTime(report.latest_interval_end_unix_ms), t("user.billing.visibleThrough")),
  ].join("");

  document.querySelector("#billing-detail-chart").innerHTML = renderBillingDetailChart(report);
  document.querySelector("#billing-detail-items-table").innerHTML = orderedBillingItems(report).map((item) => {
    const meter = billingMeter(item.metric);
    const amount = item.amount_nanos === undefined
      ? t("user.billing.notPriced")
      : formatUsdNanos(item.amount_nanos, report.currency);
    return `<tr>
      <td><div class="billing-item"><strong>${escapeHtml(meter.name())}</strong><small>${escapeHtml(meter.slug)}</small></div></td>
      <td>${escapeHtml(formatMeterQuantity(item))}</td>
      <td>${escapeHtml(meter.rate())}</td>
      <td class="align-right billing-amount">${escapeHtml(amount)}</td>
    </tr>`;
  }).join("");

  const buckets = report.time_buckets || [];
  document.querySelector("#billing-detail-periods-table").innerHTML = buckets.length
    ? buckets.map((bucket) => {
      const bucketCpu = (bucket.items || []).find((item) => item.metric === "cpu_usec")
        || { metric: "cpu_usec", quantity: "0", amount_nanos: "0" };
      const bucketMemory = (bucket.items || []).find((item) => item.metric === "memory_byte_millis")
        || { metric: "memory_byte_millis", quantity: "0", amount_nanos: "0" };
      return `<tr>
        <td class="billing-period-time">${escapeHtml(formatBillingPeriod(bucket.interval_start_unix_ms, bucket.interval_end_unix_ms))}</td>
        <td><div class="billing-period-value"><strong>${escapeHtml(formatMeterQuantity(bucketCpu))}</strong><small>${escapeHtml(formatUsdNanos(bucketCpu.amount_nanos, report.currency))}</small></div></td>
        <td><div class="billing-period-value"><strong>${escapeHtml(formatMeterQuantity(bucketMemory))}</strong><small>${escapeHtml(formatUsdNanos(bucketMemory.amount_nanos, report.currency))}</small></div></td>
        <td class="align-right billing-amount">${escapeHtml(formatUsdNanos(bucket.amount_nanos, report.currency))}</td>
      </tr>`;
    }).join("")
    : `<tr class="billing-empty"><td colspan="4">${escapeHtml(t("user.billing.detail.noPeriodData"))}</td></tr>`;
}

async function openBillingCatDetail(catId) {
  const cat = state.cats.find((item) => item.id === catId);
  state.selectedBillingCatId = catId;
  state.selectedBillingCatName = cat?.name || t("user.billing.deletedCat");
  state.billingDetail = null;
  document.querySelector("#billing-detail-name").textContent = state.selectedBillingCatName;
  document.querySelector("#billing-detail-id").textContent = catId;
  const error = document.querySelector("#billing-detail-error");
  error.textContent = "";
  error.classList.add("is-hidden");
  renderBillingCatDetail();
  if (!billingCatDialog.open) billingCatDialog.showModal();

  try {
    const range = billingRange();
    const query = new URLSearchParams({
      from_ms: String(range.fromMs),
      to_ms: String(range.toMs),
      cat_id: catId,
      bucket_ms: String(billingBucketSize(range.fromMs, range.toMs)),
    });
    state.billingDetail = await authenticatedRequest(projectPath(`/billing/usage?${query}`));
    renderBillingCatDetail();
  } catch (caught) {
    document.querySelector("#billing-detail-loading").classList.add("is-hidden");
    error.textContent = caught.message;
    error.classList.remove("is-hidden");
  }
}

function localDateValue(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function initializeBillingRange() {
  const now = new Date();
  document.querySelector("#billing-from").value = localDateValue(new Date(now.getFullYear(), now.getMonth(), 1));
  document.querySelector("#billing-to").value = localDateValue(now);
}

function billingRange() {
  const fromValue = document.querySelector("#billing-from").value;
  const toValue = document.querySelector("#billing-to").value;
  const from = new Date(`${fromValue}T00:00:00`);
  const through = new Date(`${toValue}T00:00:00`);
  if (!fromValue || !toValue || Number.isNaN(from.getTime()) || Number.isNaN(through.getTime()) || from > through) {
    throw new Error(t("user.billing.invalidRange"));
  }
  const to = new Date(through);
  to.setDate(to.getDate() + 1);
  return { fromMs: from.getTime(), toMs: to.getTime() };
}

async function loadBilling({ quiet = false } = {}) {
  if (state.billingLoading || !state.project) return;
  const button = document.querySelector('#billing-range-form button[type="submit"]');
  const error = document.querySelector("#billing-error");
  state.billingLoading = true;
  error.textContent = "";
  if (!quiet) setBusy(button, true);
  try {
    const range = billingRange();
    const query = new URLSearchParams({ from_ms: String(range.fromMs), to_ms: String(range.toMs) });
    const [balance, usage] = await Promise.all([
      authenticatedRequest(projectPath("/billing/balance")),
      authenticatedRequest(projectPath(`/billing/usage?${query}`)),
    ]);
    state.billingBalance = balance;
    state.billing = usage;
    state.billingLoadedAt = Date.now();
    renderBillingBalance();
    renderBilling();
  } catch (caught) {
    error.textContent = caught.message;
    if (!quiet) toast(t("user.billing.loadFailed"), caught.message, "error");
    throw caught;
  } finally {
    state.billingLoading = false;
    if (!quiet) setBusy(button, false);
  }
}

async function beginTopup(amountCents) {
  if (state.paymentRedirecting) return;
  state.paymentRedirecting = true;
  document.querySelectorAll("[data-topup-cents]").forEach((button) => { button.disabled = true; });
  try {
    const checkout = await authenticatedRequest(projectPath("/billing/checkout"), {
      method: "POST",
      headers: idempotencyHeaders(),
      body: JSON.stringify({ amount_cents: Number(amountCents) }),
    });
    const target = new URL(checkout.url);
    if (target.protocol !== "https:" || target.hostname !== "checkout.stripe.com") {
      throw new Error(t("user.billing.topup.invalidUrl"));
    }
    window.location.assign(target.toString());
  } catch (error) {
    state.paymentRedirecting = false;
    document.querySelectorAll("[data-topup-cents]").forEach((button) => { button.disabled = false; });
    throw error;
  }
}

async function redirectForPayment() {
  if (state.paymentRedirecting) return;
  if (!state.billingBalance) {
    state.billingBalance = await authenticatedRequest(projectPath("/billing/balance"));
    renderBillingBalance();
  }
  const amounts = state.billingBalance.topup_options_cents || [];
  if (!state.billingBalance.stripe_enabled || !amounts.length) {
    switchView("billing");
    throw new Error(t("user.billing.topup.unavailable"));
  }
  toast(t("user.billing.balance.exhaustedTitle"), t("user.billing.topup.redirecting"));
  await beginTopup(Math.min(...amounts.map(Number)));
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
document.querySelector("#refresh-button").addEventListener("click", () => {
  const requests = [loadAll()];
  if (state.activeView === "billing") requests.push(loadBilling());
  Promise.all(requests).catch(() => {});
});
document.querySelector("#workspace-switcher").addEventListener("change", (event) => {
  const previous = state.activeWorkspaceId;
  event.currentTarget.disabled = true;
  switchWorkspace(event.currentTarget.value)
    .catch((error) => {
      event.currentTarget.value = previous;
      toast(t("user.workspace.switchFailed"), error.message, "error");
    })
    .finally(() => {
      event.currentTarget.disabled = false;
    });
});
document.querySelectorAll("#create-cat-button, [data-create-cat]").forEach((button) => button.addEventListener("click", () => createCatDialog.showModal()));
document.querySelector("#create-disk-button").addEventListener("click", () => createDiskDialog.showModal());
document.querySelector("#billing-range-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if (billingCatDialog.open) billingCatDialog.close();
  loadBilling().catch(() => {});
});
document.querySelector("#billing-topup-options").addEventListener("click", (event) => {
  const button = event.target.closest("[data-topup-cents]");
  if (!button) return;
  beginTopup(Number(button.dataset.topupCents))
    .catch((error) => toast(t("user.billing.topup.failed"), error.message, "error"));
});

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
document.querySelector("#billing-cats-table").addEventListener("click", (event) => {
  const button = event.target.closest("[data-billing-cat-detail]");
  if (!button) return;
  openBillingCatDetail(button.dataset.billingCatDetail).catch((error) => toast(t("user.billing.detail.loadFailed"), error.message, "error"));
});
billingCatDialog.addEventListener("close", () => {
  state.billingDetail = null;
  state.selectedBillingCatId = "";
  state.selectedBillingCatName = "";
});

function updateLoginDescription() {
  if (!state.authConfig) return;
  document.querySelector("#login-description").textContent = state.authConfig.workos_enabled
    ? t("user.login.description")
    : t("user.login.unconfigured");
}

onLocaleChange(() => {
  updateLoginDescription();
  renderWorkspaceSwitcher();
  switchView(state.activeView);
  render();
  if (billingCatDialog.open && state.billingDetail) {
    const cat = state.cats.find((item) => item.id === state.selectedBillingCatId);
    state.selectedBillingCatName = cat?.name || t("user.billing.deletedCat");
    document.querySelector("#billing-detail-name").textContent = state.selectedBillingCatName;
    renderBillingCatDetail();
  }
});

async function initializeAuth() {
  const callbackError = consumeAuthError();
  const topupStatus = consumeTopupStatus();
  try {
    state.authConfig = await request("/auth/config");
    document.querySelector("#workos-login-button").classList.toggle("is-hidden", !state.authConfig.workos_enabled);
    updateLoginDescription();
    if (state.authConfig.workos_enabled) {
      try {
        const session = await request("/auth/session?site=user");
        applySession(session);
        const path = window.location.pathname.split("/").filter(Boolean);
        if (path[0] === "user" && path.length >= 3) {
          const accountSlug = decodeURIComponent(path[1]);
          const workspaceSlug = decodeURIComponent(path[2]);
          const requested = state.workspaces.find((workspace) =>
            workspace.account_slug === accountSlug && workspace.slug === workspaceSlug);
          if (requested && requested.id !== state.activeWorkspaceId) {
            await switchWorkspace(requested.id, { updateUrl: false });
          }
        }
        const workspace = activeWorkspace();
        if (workspace && window.location.pathname !== workspaceUrl(workspace)) {
          window.history.replaceState(null, "", workspaceUrl(workspace));
        }
        showApp();
        await loadAll({ quiet: true });
        if (topupStatus) {
          switchView("billing");
          await loadBilling({ quiet: true }).catch(() => {});
          if (topupStatus === "success") {
            toast(t("user.billing.topup.returned"), t("user.billing.topup.processing"));
          } else if (topupStatus === "cancelled") {
            toast(t("user.billing.topup.cancelled"), "", "error");
          }
        }
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

initializeBillingRange();
initializeAuth();

window.setInterval(() => {
  if (!document.hidden && state.project && !appShell.classList.contains("is-hidden")) {
    loadAll({ quiet: true }).catch(() => {});
    if (state.activeView === "billing" && Date.now() - state.billingLoadedAt >= 10_000) {
      loadBilling({ quiet: true }).catch(() => {});
    }
  }
}, 3_000);
