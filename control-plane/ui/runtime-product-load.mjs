function assertNotAborted(signal) {
  if (!signal?.aborted) return;
  throw signal.reason instanceof Error
    ? signal.reason
    : new DOMException("aborted", "AbortError");
}

const priorDisabled = new WeakMap();
const runtimeProductControls = [
  "#refresh-button",
  "#create-cat-button",
  "[data-create-cat]",
  "#create-disk-button",
].join(", ");

export function setRuntimeProductLoadingShell(root, loading) {
  const shell = root.querySelector("#app-shell");
  if (loading) {
    shell?.setAttribute("aria-busy", "true");
    for (const selector of ["#cats-table", "#disks-table"]) {
      const table = root.querySelector(selector);
      if (table) table.innerHTML = "";
    }
  } else {
    shell?.removeAttribute("aria-busy");
  }
  root.querySelectorAll(runtimeProductControls).forEach((control) => {
    if (loading) {
      if (!priorDisabled.has(control)) priorDisabled.set(control, Boolean(control.disabled));
      control.disabled = true;
    } else if (priorDisabled.has(control)) {
      control.disabled = priorDisabled.get(control);
      priorDisabled.delete(control);
    }
  });
}

function validatePage(page) {
  if (!page || !Array.isArray(page.items) || !(page.next_cursor === null || typeof page.next_cursor === "string")) {
    throw new Error("invalid runtime product page");
  }
  if (page.next_cursor !== null && page.items.length === 0) {
    throw new Error("runtime product page advanced without an item");
  }
}

async function loadPages({ workspaceId, resource, signal, requestPage }) {
  const items = [];
  const seen = new Set();
  let cursor = "";
  do {
    assertNotAborted(signal);
    const suffix = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
    const page = await requestPage(
      `/v1/workspaces/${encodeURIComponent(workspaceId)}/${resource}?limit=100${suffix}`,
      { signal },
    );
    assertNotAborted(signal);
    validatePage(page);
    items.push(...page.items);
    cursor = page.next_cursor || "";
    if (cursor && seen.has(cursor)) throw new Error("runtime product cursor repeated");
    if (cursor) seen.add(cursor);
  } while (cursor);
  return items;
}

export async function loadAll({ workspaceId, signal, requestPage }) {
  if (typeof workspaceId !== "string" || !workspaceId) {
    throw new Error("runtime product load requires one captured Workspace");
  }
  if (typeof requestPage !== "function") {
    throw new Error("runtime product load requires a request function");
  }
  const [cats, disks] = await Promise.all([
    loadPages({ workspaceId, resource: "cats", signal, requestPage }),
    loadPages({ workspaceId, resource: "disks", signal, requestPage }),
  ]);
  assertNotAborted(signal);
  return { workspaceId, cats, disks };
}
