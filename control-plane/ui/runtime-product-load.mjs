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

async function loadCollection({ workspaceId, resource, signal, requestCollection }) {
  assertNotAborted(signal);
  const items = await requestCollection(
    `/v1/workspaces/${encodeURIComponent(workspaceId)}/${resource}`,
    { signal },
  );
  assertNotAborted(signal);
  if (!Array.isArray(items)) throw new Error(`invalid semantic ${resource} collection`);
  return items;
}

export function runtimeCatView(cat) {
  const actionState = {
    create: "creating",
    run: "starting",
    suspend: "suspending",
    warm: "warming",
    cold: "cooling",
    destroy: "destroying",
  }[cat.current_action];
  return {
    ...cat,
    id: cat.cat_id,
    name: cat.cat_slug,
    spec: { cpus: cat.cpu, memory_mib: Math.floor(Number(cat.memory_bytes) / 1048576) },
    desired_state: cat.current_action || cat.state || "unknown",
    observed_state: actionState || cat.state || "unknown",
    created_at_unix: Math.floor(Number(cat.created_at_unix_ms) / 1000),
    auto_suspend: false,
    expires_at_unix: null,
  };
}

export function runtimeDiskView(disk) {
  return {
    ...disk,
    id: disk.disk_id,
    name: disk.disk_slug,
    kind: "persistent",
    state: disk.status === "deleted" ? "deleted" : (disk.binding ? "bound" : "available"),
    bound_cat_id: disk.binding?.cat_id || null,
    created_at_unix: Math.floor(Number(disk.created_at_unix_ms) / 1000),
  };
}

export async function loadAll({ workspaceId, signal, requestPage }) {
  if (typeof workspaceId !== "string" || !workspaceId) {
    throw new Error("runtime product load requires one captured Workspace");
  }
  if (typeof requestPage !== "function") {
    throw new Error("runtime product load requires a request function");
  }
  const [cats, disks] = await Promise.all([
    loadCollection({ workspaceId, resource: "cats", signal, requestCollection: requestPage }),
    loadCollection({ workspaceId, resource: "disks", signal, requestCollection: requestPage }),
  ]);
  assertNotAborted(signal);
  return { workspaceId, cats, disks };
}
