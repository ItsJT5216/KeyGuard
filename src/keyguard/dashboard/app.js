const credentialList = document.querySelector("#credentials");
const credentialCount = document.querySelector("#credential-count");
const form = document.querySelector("#credential-form");
const formMessage = document.querySelector("#form-message");
const globalMessage = document.querySelector("#global-message");
const notificationForm = document.querySelector("#notification-form");
const notificationMessage = document.querySelector("#notification-message");
let sessionToken = window.sessionStorage.getItem("keyguardSession");
let loadSequence = 0;
let saving = false;
let backgroundRefreshError = null;
let globalMessageOwner = null;
const historyRefreshErrors = new Map();
let foregroundRefreshPending = false;

async function api(path, options = {}) {
  const headers = {...(options.headers || {})};
  if (options.body) headers["Content-Type"] = "application/json";
  if (sessionToken) headers.Authorization = `KeyGuard-Session ${sessionToken}`;
  const response = await fetch(path, {...options, headers});
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      sessionToken = null;
      window.sessionStorage.removeItem("keyguardSession");
    }
    const error = new Error(payload?.error?.message || payload?.error?.code || "Request failed");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function button(label, className = "") {
  const node = text("button", label, className);
  node.type = "button";
  return node;
}

function showMessage(value, isError = false, owner = null) {
  globalMessage.textContent = value;
  globalMessage.classList.toggle("error", isError);
  globalMessageOwner = owner;
}

function reportHistoryRefreshError(credentialId, error, panel) {
  if (!panel.isConnected) return;
  const record = {
    message: `Unable to refresh event history: ${error.message}`,
    owner: {},
  };
  historyRefreshErrors.set(credentialId, record);
  showMessage(record.message, true, record.owner);
}

function clearHistoryRefreshError(credentialId, panel) {
  if (!panel.isConnected) return;
  const record = historyRefreshErrors.get(credentialId);
  if (
    record
    && globalMessageOwner === record.owner
    && globalMessage.textContent === record.message
  ) {
    showMessage("");
  }
  historyRefreshErrors.delete(credentialId);
}

function reportBackgroundRefreshError(error) {
  const message = `Unable to refresh daemon state: ${error.message}`;
  backgroundRefreshError = message;
  showMessage(message, true);
}

function clearBackgroundRefreshError() {
  if (backgroundRefreshError && globalMessage.textContent === backgroundRefreshError) {
    showMessage("");
  }
  backgroundRefreshError = null;
}

function number(value, unit) {
  if (value === null || value === undefined) return "Not available";
  const formatted = new Intl.NumberFormat(undefined, {maximumFractionDigits: 4}).format(value);
  return unit === "USD" ? `$${formatted}` : `${formatted} ${unit || ""}`.trim();
}

function when(value) {
  if (!value) return "Not scheduled";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Provider did not supply a date" : date.toLocaleString();
}

function duration(seconds) {
  if (seconds === null || seconds === undefined) return "Not scheduled";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}

function metric(label, value) {
  const wrapper = document.createElement("div");
  wrapper.className = "metric";
  wrapper.append(text("dt", label), text("dd", value));
  return wrapper;
}

function expiryTime(credential) {
  const raw = credential.usage?.expires_at;
  const parsed = raw ? Date.parse(raw) : Number.NaN;
  return Number.isNaN(parsed) ? Number.POSITIVE_INFINITY : parsed;
}

function daysUntil(value, elapsed = "Expired") {
  if (!value) return "Not available";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return "Not available";
  const milliseconds = parsed - Date.now();
  if (milliseconds <= 0) return elapsed;
  const days = Math.ceil(milliseconds / 86_400_000);
  return `${days} day${days === 1 ? "" : "s"} left`;
}

function sortCredentials(left, right) {
  const inactive = (credential) => credential.paused || credential.status === "disabled" ? 1 : 0;
  return inactive(left) - inactive(right)
    || expiryTime(left) - expiryTime(right)
    || left.name.localeCompare(right.name);
}

function displayStatus(credential) {
  if (credential.paused) return {label: "Paused", slug: "paused"};
  if (credential.status === "disabled") return {label: "Disabled", slug: "disabled"};
  const tier = credential.scheduler?.polling_tier || "";
  if (["error", "cleanup_required", "action_failed"].includes(credential.status)
      || tier === "error_retry") {
    return {label: "Error", slug: "error"};
  }
  if (tier.includes("critical") || tier.includes("urgent")) {
    return {label: "Critical", slug: "critical"};
  }
  if (tier === "quiet") return {label: "Healthy", slug: "healthy"};
  return {label: "Watching", slug: "watching"};
}

async function patchCredential(id, values, successMessage) {
  try {
    await api(`/api/credentials/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(values),
    });
    showMessage(successMessage);
    await loadCredentials({quiet: true});
  } catch (error) {
    showMessage(error.message, true);
    throw error;
  }
}

async function setPaused(id, paused) {
  try {
    await api(`/api/credentials/${encodeURIComponent(id)}/${paused ? "pause" : "resume"}`, {
      method: "POST",
      body: "{}",
    });
    showMessage(paused ? "Monitoring paused." : "Monitoring resumed and an immediate check was scheduled.");
    await loadCredentials({quiet: true});
  } catch (error) {
    showMessage(error.message, true);
  }
}

async function runAction(id, action) {
  if (action === "protect" && !window.confirm("Run the configured provider protection action now?")) return;
  try {
    const result = await api(`/api/credentials/${encodeURIComponent(id)}/${action}`, {
      method: "POST",
      body: "{}",
    });
    if (action === "check") {
      showMessage(result.snapshot
        ? `Checked: ${number(result.snapshot.used, result.snapshot.unit)} used.`
        : "Check completed.");
    } else if (result.action === "notify_only") {
      showMessage("Threshold alert recorded; no provider action was taken.");
    } else {
      showMessage(result.action === "already_disabled"
        ? "The provider key was already disabled."
        : "Protection action verified by the provider.");
    }
    await loadCredentials({quiet: true});
  } catch (error) {
    showMessage(error.message, true);
  }
}

async function removeCredential(id) {
  if (!window.confirm("Remove this credential from KeyGuard and GNOME Keyring?")) return;
  try {
    await api(`/api/credentials/${encodeURIComponent(id)}`, {method: "DELETE"});
    showMessage("Credential removed from KeyGuard and GNOME Keyring.");
    await loadCredentials({quiet: true});
  } catch (error) {
    showMessage(error.message, true);
  }
}

function progress(usage) {
  const wrapper = document.createElement("div");
  wrapper.className = "usage-block";
  const percentage = usage?.percent_consumed;
  const label = percentage === null || percentage === undefined
    ? "No provider allocation available"
    : `${percentage.toFixed(1)}% consumed`;
  wrapper.append(text("div", label, "progress-label"));
  const track = document.createElement("progress");
  track.className = "progress-track";
  track.setAttribute("aria-label", "Provider allocation consumed");
  track.max = 100;
  if (percentage !== null && percentage !== undefined) {
    track.value = percentage;
  }
  wrapper.append(track);
  return wrapper;
}

function pollingEditor(credential) {
  const details = document.createElement("details");
  details.className = "polling-editor";
  details.append(text("summary", "Polling thresholds and intervals"));
  const grid = document.createElement("div");
  grid.className = "polling-grid";
  const fields = [
    ["quiet_distance", "Quiet distance"],
    ["watch_distance", "Watch distance"],
    ["accelerated_distance", "Accelerated distance"],
    ["critical_distance", "Critical distance"],
    ["quiet_interval_seconds", "Quiet interval (seconds)"],
    ["watch_interval_seconds", "Watch interval (seconds)"],
    ["accelerated_interval_seconds", "Accelerated interval (seconds)"],
    ["critical_interval_seconds", "Critical interval (seconds)"],
    ["urgent_interval_seconds", "Urgent interval (seconds)"],
    ["safety_margin_seconds", "Safety margin (seconds)"],
    ["jitter_fraction", "Jitter fraction (0–0.5)"],
  ];
  for (const [name, labelText] of fields) {
    const input = document.createElement("input");
    input.name = name;
    input.type = "number";
    input.min = name.includes("interval") ? "1" : "0";
    if (name === "jitter_fraction") input.max = "0.5";
    input.step = "any";
    input.value = credential.polling_config?.[name] ?? "";
    const label = text("label", labelText);
    label.append(input);
    grid.append(label);
  }
  details.append(grid);
  return details;
}

function editForm(credential) {
  const editor = document.createElement("form");
  editor.className = "edit-form";
  editor.hidden = true;

  const allowance = document.createElement("input");
  allowance.name = "starting_allowance";
  allowance.type = "number";
  allowance.min = "0";
  allowance.step = "any";
  allowance.value = credential.starting_allowance ?? "";
  const allowanceLabel = text("label", "Authorized starting allowance");
  allowanceLabel.append(allowance);

  const threshold = document.createElement("input");
  threshold.name = "threshold";
  threshold.type = "number";
  threshold.min = "0";
  threshold.step = "any";
  threshold.value = credential.threshold ?? "";
  const thresholdLabel = text("label", "Kill threshold");
  thresholdLabel.append(threshold);

  const action = document.createElement("select");
  action.name = "protection_action";
  const actions = new Set(["notify_only", ...(credential.available_actions || [])]);
  for (const value of actions) {
    const option = text("option", value.replaceAll("_", " "));
    option.value = value;
    option.selected = value === credential.protection_action;
    action.append(option);
  }
  const actionLabel = text("label", "Protection action");
  actionLabel.append(action);

  const autoProtect = document.createElement("input");
  autoProtect.name = "auto_protect";
  autoProtect.type = "checkbox";
  autoProtect.checked = credential.auto_protect;
  const autoLabel = text("label", "Auto Protect", "check");
  autoLabel.prepend(autoProtect);

  const notificationsMuted = document.createElement("input");
  notificationsMuted.name = "notifications_muted";
  notificationsMuted.type = "checkbox";
  notificationsMuted.checked = credential.notifications_muted;
  const notificationsLabel = text("label", "Mute alerts", "check");
  notificationsLabel.prepend(notificationsMuted);

  const save = text("button", "Save settings");
  save.type = "submit";
  const cancel = button("Cancel", "secondary");
  cancel.addEventListener("click", () => { editor.hidden = true; });

  editor.append(
    allowanceLabel,
    thresholdLabel,
    actionLabel,
    autoLabel,
    notificationsLabel,
    pollingEditor(credential),
  );
  const actionsRow = document.createElement("div");
  actionsRow.className = "controls";
  actionsRow.append(save, cancel);
  editor.append(actionsRow);
  editor.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(editor);
    const polling = {...(credential.polling_config || {})};
    for (const name of [
      "quiet_distance", "watch_distance", "accelerated_distance", "critical_distance",
      "quiet_interval_seconds", "watch_interval_seconds", "accelerated_interval_seconds",
      "critical_interval_seconds", "urgent_interval_seconds",
      "safety_margin_seconds", "jitter_fraction",
    ]) {
      const value = data.get(name);
      if (value !== "") polling[name] = Number(value);
    }
    save.disabled = true;
    try {
      await patchCredential(credential.id, {
        starting_allowance: data.get("starting_allowance") === ""
          ? null
          : Number(data.get("starting_allowance")),
        threshold: data.get("threshold") === "" ? null : Number(data.get("threshold")),
        auto_protect: data.get("auto_protect") === "on",
        notifications_muted: data.get("notifications_muted") === "on",
        protection_action: data.get("protection_action"),
        polling,
      }, "Credential settings saved.");
    } finally {
      save.disabled = false;
    }
  });
  return editor;
}

function usageSparkline(snapshots) {
  const section = document.createElement("section");
  section.className = "usage-trend";
  section.append(text("h4", "Usage trend"));
  const numeric = snapshots
    .map((item) => ({...item, timestamp: Date.parse(item.checked_at)}))
    .filter((item) => (
      Number.isFinite(item.used)
      && Number.isFinite(item.timestamp)
      && typeof item.unit === "string"
      && item.unit
    ));
  if (!numeric.length) {
    section.append(text("p", "No usage history recorded yet.", "muted"));
    return section;
  }
  const unit = numeric.at(-1).unit;
  const series = numeric.filter((item) => item.unit === unit);
  const values = series.map((item) => item.used);
  const timestamps = series.map((item) => item.timestamp);
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const span = maximum - minimum || 1;
  const firstTimestamp = Math.min(...timestamps);
  const timestampSpan = Math.max(...timestamps) - firstTimestamp;
  const width = 120;
  const height = 36;
  const x = (timestamp) => timestampSpan === 0
    ? width / 2
    : ((timestamp - firstTimestamp) / timestampSpan) * width;
  const y = (value) => height - ((value - minimum) / span) * height;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  svg.setAttribute(
    "aria-label",
    `Usage trend across ${series.length} check${series.length === 1 ? "" : "s"}; latest ${number(values.at(-1), unit)}`,
  );
  if (series.length === 1) {
    const point = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    point.setAttribute("cx", String(x(timestamps[0])));
    point.setAttribute("cy", String(y(values[0])));
    point.setAttribute("r", "3");
    svg.append(point);
  } else {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
    line.setAttribute("points", values.map((value, index) => `${x(timestamps[index])},${y(value)}`).join(" "));
    svg.append(line);
  }
  section.append(
    svg,
    text("p", `${series.length} check${series.length === 1 ? "" : "s"} · latest ${number(values.at(-1), unit)}`, "muted"),
  );
  return section;
}

function historyPanel(credential) {
  const details = document.createElement("details");
  details.className = "history";
  details.append(text("summary", "Event history"));
  const content = document.createElement("div");
  details.append(content);
  let loaded = false;
  let loading = false;
  let refreshPending = false;
  async function loadHistory({force = false} = {}) {
    if (!details.open || (loaded && !force)) return;
    if (loading) {
      refreshPending = refreshPending || force;
      return;
    }
    loading = true;
    if (!loaded) content.replaceChildren(text("p", "Loading event history…", "muted"));
    try {
      const {events, usage = []} = await api(`/api/credentials/${encodeURIComponent(credential.id)}/history?limit=12`);
      const list = document.createElement("ol");
      for (const event of events) {
        list.append(text("li", `${when(event.created_at)} · ${event.event_type.replaceAll("_", " ")} · ${event.result}`));
      }
      const eventsSection = document.createElement("section");
      eventsSection.append(
        text("h4", "Recent events"),
        events.length ? list : text("p", "No events recorded yet.", "muted"),
      );
      content.replaceChildren(usageSparkline(usage), eventsSection);
      loaded = true;
      clearHistoryRefreshError(credential.id, details);
    } catch (error) {
      if (loaded) {
        reportHistoryRefreshError(credential.id, error, details);
      } else {
        content.replaceChildren(text("p", `${error.message} Close and reopen this panel to retry.`, "error"));
      }
    } finally {
      loading = false;
      if (refreshPending) {
        refreshPending = false;
        void loadHistory({force: true});
      }
    }
  }
  details.addEventListener("toggle", () => { void loadHistory(); });
  details.addEventListener("keyguard:refresh-history", () => {
    void loadHistory({force: true});
  });
  return details;
}

function card(credential) {
  const display = displayStatus(credential);
  const article = document.createElement("article");
  article.className = `credential-card status-${display.slug}`;
  article.dataset.credentialId = credential.id;
  const top = document.createElement("div");
  top.className = "card-heading";
  const identity = document.createElement("div");
  identity.append(
    text("p", credential.provider, "provider"),
    text("h3", credential.name),
    text("p", credential.masked_identifier, "masked"),
  );
  const status = text("span", display.label, "status-badge");
  top.append(identity, status);
  article.append(top, progress(credential.usage));

  const usage = credential.usage;
  const schedule = credential.scheduler || {};
  const metrics = document.createElement("dl");
  metrics.className = "metrics";
  metrics.append(
    metric("Used", number(usage?.used, usage?.unit)),
    metric("Remaining", number(usage?.remaining, usage?.unit)),
    metric("Allocation", number(usage?.limit, usage?.unit)),
    metric("Credits expire", daysUntil(usage?.expires_at)),
    metric("Limit resets", daysUntil(usage?.period_end, "Reset due")),
    metric(
      "Authorized allowance",
      number(credential.starting_allowance, credential.starting_allowance_unit),
    ),
    metric("Kill threshold", number(credential.threshold, usage?.unit)),
    metric("Burn rate", credential.burn_rate_per_second !== null
        && credential.burn_rate_per_second !== undefined
      ? `${number(credential.burn_rate_per_second * 3600, usage?.unit)}/hour`
      : "Not enough history"),
    metric("Polling", duration(schedule.current_interval_seconds)),
    metric("Last check", when(schedule.last_check_at || usage?.checked_at)),
    metric("Next check", credential.paused ? "Paused" : when(schedule.next_check_at)),
    metric("Auto Protect", credential.auto_protect ? "On" : "Off"),
    metric("Notifications", credential.notifications_muted ? "Muted" : "Active"),
    metric("Provider action", (credential.protection_action || "notify_only").replaceAll("_", " ")),
  );
  article.append(metrics);

  if (credential.last_action) {
    article.append(text(
      "p",
      `Last protection: ${credential.last_action.result} · ${when(credential.last_action.created_at)}`,
      "last-action",
    ));
  }

  const controls = document.createElement("div");
  controls.className = "controls";
  const check = button("Check now");
  check.addEventListener("click", () => runAction(credential.id, "check"));
  const pause = button(credential.paused ? "Resume" : "Pause", "secondary");
  pause.addEventListener("click", () => setPaused(credential.id, !credential.paused));
  const toggle = button(credential.auto_protect ? "Auto Protect off" : "Auto Protect on", "secondary");
  toggle.addEventListener("click", () => patchCredential(
    credential.id,
    {auto_protect: !credential.auto_protect},
    `Auto Protect turned ${credential.auto_protect ? "off" : "on"}.`,
  ).catch(() => {}));
  const mute = button(credential.notifications_muted ? "Unmute alerts" : "Mute alerts", "secondary");
  mute.addEventListener("click", () => patchCredential(
    credential.id,
    {notifications_muted: !credential.notifications_muted},
    "Alerts " + (credential.notifications_muted ? "unmuted" : "muted") + " for " + credential.name + ".",
  ).catch(() => {}));
  const protect = button("Protect now", "danger");
  protect.disabled = !(credential.available_actions || []).includes(credential.protection_action);
  protect.addEventListener("click", () => runAction(credential.id, "protect"));
  const edit = button("Edit settings", "secondary");
  const editor = editForm(credential);
  edit.addEventListener("click", () => { editor.hidden = !editor.hidden; });
  const remove = button("Remove", "ghost-danger");
  remove.addEventListener("click", () => removeCredential(credential.id));
  controls.append(check, pause, toggle, mute, protect, edit, remove);
  article.append(controls, editor, historyPanel(credential));
  return article;
}

function hasActiveInteraction() {
  return credentialList.querySelector(".edit-form:not([hidden])") !== null;
}

async function loadCredentials({quiet = false, background = false} = {}) {
  if (background && (hasActiveInteraction() || foregroundRefreshPending)) return;
  const sequence = ++loadSequence;
  if (!background) foregroundRefreshPending = true;
  if (!quiet) credentialList.replaceChildren(text("p", "Loading daemon state…", "empty"));
  try {
    const {credentials} = await api("/api/credentials");
    if (sequence !== loadSequence) return;
    clearBackgroundRefreshError();
    if (background && hasActiveInteraction()) return;
    const ordered = [...credentials].sort(sortCredentials);
    credentialCount.textContent = `${ordered.length} credential${ordered.length === 1 ? "" : "s"}`;
    const activeElement = document.activeElement;
    const focusedHistoryElement = activeElement?.closest("details.history")
      ? activeElement
      : null;
    const openHistoryByCredential = new Map(
      [...credentialList.querySelectorAll(".credential-card")]
        .map((article) => [
          article.dataset.credentialId,
          article.querySelector(":scope > details.history[open]"),
        ])
        .filter(([, details]) => details),
    );
    const historiesToRefresh = [];
    const cards = ordered.map((credential) => {
      const article = card(credential);
      const openHistory = openHistoryByCredential.get(credential.id);
      if (openHistory) {
        article.querySelector(":scope > details.history").replaceWith(openHistory);
        historiesToRefresh.push(openHistory);
      }
      return article;
    });
    credentialList.replaceChildren(...(cards.length
      ? cards
      : [text("p", "No credentials are being watched yet.", "empty")]));
    historiesToRefresh.forEach((details) => {
      details.dispatchEvent(new Event("keyguard:refresh-history"));
    });
    if (focusedHistoryElement?.isConnected) {
      focusedHistoryElement.focus({preventScroll: true});
    }
  } catch (error) {
    if (sequence !== loadSequence) return;
    if (background && error.status !== 401) {
      reportBackgroundRefreshError(error);
      return;
    }
    if (error.status === 401) clearBackgroundRefreshError();
    credentialList.replaceChildren(text("p", error.message, "error"));
  } finally {
    if (!background && sequence === loadSequence) {
      foregroundRefreshPending = false;
    }
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (saving) return;
  saving = true;
  const controls = [...form.elements];
  controls.forEach((control) => { control.disabled = true; });
  formMessage.textContent = "Saving…";
  const data = new FormData(form);
  const threshold = data.get("threshold");
  const startingAllowance = data.get("starting_allowance");
  const body = {
    provider: data.get("provider"),
    name: data.get("name"),
    api_key: data.get("api_key"),
    starting_allowance: startingAllowance === "" ? null : Number(startingAllowance),
    threshold: threshold === "" ? null : Number(threshold),
    auto_protect: data.get("auto_protect") === "on",
    notifications_muted: data.get("notifications_muted") === "on",
    protection_action: data.get("protection_action"),
  };
  const keyHash = data.get("key_hash").trim();
  if (keyHash) body.metadata = {key_hash: keyHash};
  try {
    await api("/api/credentials", {method: "POST", body: JSON.stringify(body)});
    form.reset();
    formMessage.textContent = "Saved. The raw key was sent directly to GNOME Keyring.";
    await loadCredentials({quiet: true});
  } catch (error) {
    formMessage.textContent = error.message;
  } finally {
    saving = false;
    controls.forEach((control) => { control.disabled = false; });
  }
});

document.querySelector("#refresh").addEventListener("click", () => loadCredentials());
document.querySelector("#test-notification").addEventListener("click", async () => {
  try {
    await api("/api/notifications/test", {method: "POST", body: "{}"});
    showMessage("Test notification sent.");
  } catch (error) {
    showMessage(error.message, true);
  }
});

async function loadNotificationConfig() {
  const {notifications} = await api("/api/notifications");
  notificationForm.elements.server_url.value = notifications.server_url;
  notificationForm.elements.topic.value = notifications.topic;
  notificationForm.elements.enabled.checked = notifications.enabled;
  notificationForm.elements.auth_token.placeholder = notifications.auth_configured
    ? "Saved in GNOME Keyring; leave blank to keep it"
    : "Optional bearer token";
}

notificationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(notificationForm);
  const body = {
    server_url: data.get("server_url"),
    topic: data.get("topic"),
    enabled: data.get("enabled") === "on",
  };
  const authToken = data.get("auth_token");
  if (data.get("clear_auth_token") === "on") body.auth_token = null;
  else if (authToken) body.auth_token = authToken;
  try {
    await api("/api/notifications", {method: "PATCH", body: JSON.stringify(body)});
    notificationForm.elements.auth_token.value = "";
    notificationForm.elements.clear_auth_token.checked = false;
    notificationMessage.textContent = "ntfy settings saved.";
    await loadNotificationConfig();
  } catch (error) {
    notificationMessage.textContent = error.message;
  }
});

async function start() {
  const bootstrap = new URLSearchParams(window.location.hash.slice(1)).get("token");
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  if (bootstrap) {
    try {
      const response = await fetch("/api/session", {
        method: "POST",
        headers: {Authorization: `KeyGuard-Bootstrap ${bootstrap}`},
      });
      const payload = await response.json();
      if (!response.ok || !payload.session_token) throw new Error("KeyGuard authentication failed");
      sessionToken = payload.session_token;
      window.sessionStorage.setItem("keyguardSession", sessionToken);
    } catch (error) {
      showMessage(error.message, true);
      return;
    }
  }
  if (!sessionToken) {
    showMessage("Open KeyGuard from its launcher to authenticate.", true);
    return;
  }
  await loadCredentials();
  try {
    await loadNotificationConfig();
  } catch (error) {
    notificationMessage.textContent = error.message;
  }
  window.setInterval(() => loadCredentials({quiet: true, background: true}), 30_000);
}

start();


