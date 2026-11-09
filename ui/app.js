/* Desktop MCP tray popup. Settings are stored by Rust, not in the webview. */
const $ = (id) => document.getElementById(id);
const invoke = (command, payload = {}) => {
  const bridge = window.__TAURI__?.core?.invoke;
  if (!bridge) {
    return Promise.reject(new Error("Native app bridge unavailable. Launch with Desktop MCP."));
  }
  return bridge(command, payload);
};

let snapshot = null;
let localAgent = null;
let busy = false;
let toastTimeout;
let mutationChain = Promise.resolve();

function showToast(message) {
  const toast = $("toast");
  toast.textContent = String(message);
  toast.classList.add("visible");
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove("visible"), 3800);
}

function currentView(name) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === name);
  });
  if (name === "activity") {
    renderHistory();
    void refresh();
  }
  if (name === "approvals") void refreshApprovals();
}

async function refreshApprovals() {
  const target = $("approval-list");
  try {
    const result = await invoke("get_pending_approvals");
    const items = Array.isArray(result.pending) ? result.pending : [];
    $("approval-count").textContent = items.length
      ? items.length + " pending request" + (items.length === 1 ? "" : "s")
      : "No pending requests";
    target.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("p");
      empty.className = "empty-history";
      empty.textContent = "No requests waiting for review.";
      target.appendChild(empty);
      return;
    }
    for (const item of items) {
      const entry = document.createElement("div");
      entry.className = "approval-entry";
      const title = document.createElement("strong");
      const permission = item.tool === "request_permission";
      if (permission) {
        const labels = { pairing: "Pair this PC", git_status: "Allow Git status", fs_read: "Allow project file reads", system_volume_status: "Allow Windows system volume checks", admin_command: "Allow requests for elevated PowerShell commands" };
        const durations = { "30m": "30 minutes", "1h": "1 hour", "4h": "4 hours", permanent: "until revoked" };
        const requested = item.arguments.duration;
        const duration = durations[requested] || (requested.endsWith("m") ? requested.slice(0, -1) + " minutes" : requested);
        title.textContent = labels[item.arguments.capability] + " · " + duration;
      } else {
        const labels = { fs_read: "File read request", git_status: "Git status request",
          system_volume_status: "Windows system volume check (requires UAC)", admin_command: "Elevated PowerShell command" };
        title.textContent = labels[item.tool] || "Tool request";
      }
      const info = document.createElement("small");
      info.textContent = "Project " + String(result.workspace_path || item.workspace_id || "") +
        (item.tool === "admin_command" ? "" : " | " + JSON.stringify(item.arguments || {})) +
        " | Host " + String(item.target_host_id || "").slice(0, 16) +
        " | ID " + String(item.request_id || "").slice(0, 8) +
        " | Hash " + String(item.request_hash || "").slice(0, 12) +
        " | Expires in " + String(item.expires_in_seconds || 0) + "s";
      const actions = document.createElement("div");
      actions.className = "approval-actions";
      for (const choice of ["approve", "deny"]) {
        const button = document.createElement("button");
        button.textContent = choice === "approve" ? (permission ? "Accept" : item.execution_enabled ? "Approve once" : "Approve review") : "Deny";
        button.addEventListener("click", async () => {
          actions.querySelectorAll("button").forEach(b => b.disabled = true);
          try {
            const result = await invoke("review_remote_request", {
              requestId: item.request_id, nonce: item.nonce,
              requestHash: item.request_hash, decision: choice
            });
            if (result.executed !== false || result.authorization_granted !== (Boolean(item.execution_enabled) && choice === "approve")) {
              throw new Error("Unexpected execution authorization response");
            }
            showToast(choice === "approve"
              ? (permission ? "Approved this permission request." : item.execution_enabled ? "Approved this operation once." : "Reviewed locally. Remote execution remains disabled.")
              : "Request denied locally.");
          } catch (error) {
            showToast("Review failed: " + String(error));
          }
          await refreshApprovals();
        });
        actions.appendChild(button);
      }
      entry.append(title, info);
      if (item.tool === "admin_command") {
        const command = document.createElement("pre");
        command.className = "approval-command";
        command.tabIndex = 0;
        command.textContent = item.arguments.command;
        entry.append(command);
      }
      entry.append(actions);
      target.appendChild(entry);
    }
  } catch (_) {
    $("approval-count").textContent = "Local agent unavailable";
    target.replaceChildren();
    const empty = document.createElement("p");
    empty.className = "empty-history";
    empty.textContent = "Start the local agent to review incoming requests.";
    target.appendChild(empty);
  }
}
function renderHistory() {
  const target = $("activity-list");
  target.replaceChildren();
  const history = snapshot?.history || [];
  if (!history.length) {
    const note = document.createElement("p");
    note.className = "empty-history";
    note.textContent = "No recorded activity yet.";
    target.appendChild(note);
    return;
  }
  for (const record of history) {
    const row = document.createElement("div");
    row.className = "activity-entry";
    const label = document.createElement("strong");
    label.textContent = record.description;
    const time = document.createElement("small");
    time.textContent = new Date(record.timestamp * 1000).toLocaleString();
    row.append(label, time);
    target.appendChild(row);
  }
}

function render(data) {
  snapshot = data;
  if ($("activity").classList.contains("active")) renderHistory();
  const s = data.settings;
  const alive = localAgent?.running === true;
  const remote = alive && localAgent.policy?.remote_access_enabled === true;
  const writes = alive && localAgent.writes_enabled_at_launch === true;
  $("remote-access").checked = remote;
  $("remote-access").disabled = !alive;
  $("approval-mode").value = s.approval_mode;
  $("local-write-mode").hidden = !writes;
  $("approval-mode").disabled = !writes;
  $("approval-duration").value = s.approval_duration;
  $("local-write-duration").hidden = !writes;
  $("approval-duration").disabled = !writes;

  $("connection-text").textContent = alive ? "Local agent ready" : "Local agent offline";
  $("connection-icon").classList.toggle("offline", !alive);
  renderLocalAgent();
  $("host-name").textContent = data.host_name;
  $("platform-name").textContent = data.platform;
  $("remote-access-status").textContent = remote ? "Read-only requests enabled" : "Disabled";
  const adminReady = alive && localAgent.policy?.administrator_enabled === true;
  $("admin-diagnostics-status").textContent = adminReady
    ? "System volume check available. Approve each run in Request approvals."
    : "Windows helper is inactive.";
  const unattended = localAgent?.unattended_service_installed === true;
  $("unattended-controls").hidden = !unattended;
  const commandsAvailable = !unattended && alive && localAgent.policy?.admin_commands_enabled === true;
  $("admin-command-controls").hidden = !commandsAvailable;
  $("admin-command-status").textContent = localAgent?.admin_command_granted === true
    ? "Command grant active" : "Command grant disabled";
  $("footer-note").textContent = unattended
    ? "Unattended administrator access is managed by the Windows service."
    : "Each remote tool request needs local approval.";
}

function renderLocalAgent() {
  const alive = localAgent?.running === true;
  const autonomous = alive && localAgent.policy?.writes_currently_authorized === true;
  $("status-text").textContent = autonomous ? "Local autonomous"
    : alive ? "Local agent ready" : "Not connected";
  $("local-agent-status").textContent = alive ? "Running" : "Not running";
  $("local-approval-status").textContent = autonomous ? "Autonomous"
    : alive ? "Not active" : "Unavailable";
}

async function refresh() {
  try {
    const data = await invoke("get_app_state");
    localAgent = await invoke("get_local_agent_status");
    render(data);
  } catch (error) {
    $("connection-text").textContent = "Native backend unavailable";
    $("status-text").textContent = "Offline";
    showToast(error);
  }
}

function update(changes) {
  // Queue writes so slow results cannot overwrite newer changes.
  mutationChain = mutationChain
    .catch(() => {})
    .then(async () => {
      busy = true;
      try {
        await invoke("update_settings", { changes });
        await refresh();
      } catch (error) {
        showToast(error);
        await refresh();
      } finally {
        busy = false;
      }
    });
  return mutationChain;
}

$("remote-access").addEventListener("change", (event) => {
  update({ remote_access: event.target.checked });
});
$("approval-mode").addEventListener("change", (event) => {
  update({ approval_mode: event.target.value });
});
$("approval-duration").addEventListener("change", (event) => {
  update({ approval_duration: event.target.value });
});
function confirmInTray(message) {
  const dialog = $("confirmation");
  if (dialog.open) return Promise.resolve(false);
  $("confirmation-message").textContent = message;
  dialog.returnValue = "cancel";
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
    dialog.showModal();
  });
}

for (const [id, action] of [["unattended-grant", "grant"], ["unattended-revoke", "revoke"]]) {
  $(id).addEventListener("click", async () => {
    try {
      await invoke("open_unattended_controls", { action });
    } catch (error) {
      showToast(error);
    }
  });
}

async function setAdminCommandGrant(duration) {
  if (busy) return;
  if (duration && !await confirmInTray("Allow ChatGPT to request elevated PowerShell commands on this PC? Each command still needs your approval.")) return;
  busy = true;
  try {
    await invoke("set_admin_command_grant", { duration });
    await refresh();
    showToast(duration ? "Command grant enabled." : "Command grant revoked.");
  } catch (error) {
    showToast(error);
  } finally {
    busy = false;
  }
}

$("admin-command-timed").addEventListener("click", () => {
  const minutes = $("admin-command-minutes").valueAsNumber;
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) {
    showToast("Enter 1 to 1440 minutes.");
    return;
  }
  void setAdminCommandGrant(minutes + "m");
});
$("admin-command-permanent").addEventListener("click", () => void setAdminCommandGrant("permanent"));
$("admin-command-revoke").addEventListener("click", () => void setAdminCommandGrant(null));
$("revoke-button").addEventListener("click", async () => {
  if (busy) return;
  try {
    await invoke("revoke_access");
    await refresh();
    showToast("Local approvals revoked; remote access disabled.");
  } catch (error) {
    showToast(error);
  }
});
$("approvals-button").addEventListener("click", () => currentView("approvals"));
window.__TAURI__?.event?.listen("approval-request", () => currentView("approvals")).catch(showToast);
$("pairing-button").addEventListener("click", () => { currentView("pairing"); void refreshPairing(); });
$("activity-button").addEventListener("click", () => currentView("activity"));
$("details-button").addEventListener("click", () => currentView("details"));
document.querySelectorAll("[data-back]").forEach((button) => {
  button.addEventListener("click", () => currentView("overview"));
});
document.addEventListener("keydown", async (event) => {
  if (event.key === "Escape") {
    if (!$("overview").classList.contains("active")) {
      currentView("overview");
    } else {
      try { await invoke("hide_popup"); } catch (_) {}
    }
  }
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) void refresh();
});
void refresh();
setInterval(() => {
  if (!document.hidden) {
    if (!busy) void refresh();
    void refreshApprovals();
  }
}, 4000);


let pairingState = null;

async function refreshPairing() {
  const status = $("pair-host-id");
  const code = $("connect-code");
  const copy = $("connect-copy");
  code.value = "";
  copy.disabled = true;
  try {
    pairingState = await invoke("get_pairing_state");
    const identity = pairingState.identity;
    if (!/^[a-f0-9]{64}$/.test(identity.public_key) || !/^[a-f0-9]{32}$/.test(identity.host_id)) {
      throw new Error("Invalid device identity");
    }
    status.textContent = identity.host_id;
    code.value = "DM1-" + identity.public_key;
    copy.disabled = false;
    const parent = $("pair-peers");
    parent.replaceChildren();
    const peers = pairingState.peers || [];
    if (!peers.length) {
      const note = document.createElement("p");
      note.className = "empty-history";
      note.textContent = "No trusted identities yet.";
      parent.appendChild(note);
    }
    for (const peer of peers) {
      const row = document.createElement("div");
      row.className = "pair-peer";
      const info = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = peer.name;
      const details = document.createElement("small");
      details.textContent = peer.host_id.slice(0, 16) + " ? identity only";
      info.append(name, details);
      const revoke = document.createElement("button");
      revoke.textContent = "Remove";
      revoke.addEventListener("click", async () => {
        if (!await confirmInTray("Remove trust for " + peer.name + "?")) return;
        try {
          await invoke("revoke_paired_peer", {hostId: peer.host_id});
          await refreshPairing();
          showToast("Identity removed locally.");
        } catch (e) { showToast(e); }
      });
      row.append(info, revoke);
      parent.appendChild(row);
    }
  } catch (e) {
    pairingState = null;
    status.textContent = "Local agent unavailable. Start it to enroll devices.";
    $("pair-peers").replaceChildren();
  }
}

function pairOutput(data) {
  $("pair-output").value = JSON.stringify(data, null, 2);
}

$("pair-create").addEventListener("click", async () => {
  try {
    const result = await invoke("create_pair_invitation");
    pairOutput(result);
    showToast("10-minute invitation created. Keep the secret private.");
  } catch (e) { showToast(e); }
});

$("pair-cancel").addEventListener("click", async () => {
  try {
    await invoke("cancel_pair_invitation");
    $("pair-output").value = "";
    showToast("Pending invitation cancelled.");
  } catch (e) { showToast(e); }
});

async function copyField(field, successMessage) {
  if (!field.value) return;
  try {
    await navigator.clipboard.writeText(field.value);
    showToast(successMessage);
  } catch (_) {
    field.focus();
    field.select();
    showToast("Text selected. Press Ctrl+C to copy.");
  }
}

$("connect-copy").addEventListener("click", () => {
  void copyField($("connect-code"), "Setup code copied. Send it to the person connecting this PC.");
});

$("pair-copy").addEventListener("click", () => {
  void copyField($("pair-output"), "Exchange output copied. Share only with a trusted device.");
});

$("pair-process").addEventListener("click", async () => {
  try {
    const received = JSON.parse($("pair-input").value);
    const name = $("pair-name").value.trim();
    const action = $("pair-action").value;
    let result;
    if (action === "prepare") {
      result = await invoke("prepare_pair_join", {
        invitation: received.invitation || received,
        name
      });
    } else if (action === "accept") {
      result = await invoke("accept_pair_join", {
        joinRequest: received.join_request || received
      });
    } else {
      result = await invoke("finalize_pair_join", {
        receipt: received.receipt || received,
        name
      });
    }
    pairOutput(result);
    await refreshPairing();
    showToast("Signed exchange verified. No remote access enabled.");
  } catch (e) {
    showToast("Pairing failed: " + String(e));
  }
});


async function checkForUpdates(manual = false) {
  const button = $("check-updates");
  if (button.disabled) return;
  button.disabled = true;
  try {
    const update = await invoke("check_for_updates");
    $("open-release").hidden = !update.available;
    $("update-status").textContent = update.available
      ? `Desktop MCP ${update.latest} is available. Installed version ${update.current}.`
      : `Desktop MCP ${update.current} is up to date.`;
  } catch (error) {
    if (manual) showToast(error);
  } finally {
    button.disabled = false;
  }
}

$("check-updates").addEventListener("click", () => void checkForUpdates(true));
$("open-release").addEventListener("click", () => invoke("open_release_page").catch(showToast));
void checkForUpdates();
setInterval(checkForUpdates, 6 * 60 * 60 * 1000);
