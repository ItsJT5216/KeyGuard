import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const source = readFileSync("src/keyguard/dashboard/app.js", "utf8");
const showMessageSource = source.match(
  /function showMessage\(value, isError = false, owner = null\) \{[\s\S]*?\n\}/,
)?.[0];
assert.ok(showMessageSource, "production showMessage function was not found");
const reportHistoryRefreshErrorSource = source.match(
  /function reportHistoryRefreshError\(credentialId, error, panel\) \{[\s\S]*?\n\}/,
)?.[0];
assert.ok(
  reportHistoryRefreshErrorSource,
  "production reportHistoryRefreshError function was not found",
);
const clearHistoryRefreshErrorSource = source.match(
  /function clearHistoryRefreshError\(credentialId, panel\) \{[\s\S]*?\n\}/,
)?.[0];
assert.ok(
  clearHistoryRefreshErrorSource,
  "production clearHistoryRefreshError function was not found",
);

const globalMessage = {
  textContent: "",
  classList: {toggle() {}},
};
let globalMessageOwner = null;
const historyRefreshErrors = new Map();
const {reportHistoryRefreshError, clearHistoryRefreshError} = eval(`(() => {
  ${showMessageSource}
  ${reportHistoryRefreshErrorSource}
  ${clearHistoryRefreshErrorSource}
  return {reportHistoryRefreshError, clearHistoryRefreshError};
})()`);

const message = "Unable to refresh event history: unavailable";
const firstPanel = {isConnected: true};
const secondPanel = {isConnected: true};
reportHistoryRefreshError("first", new Error("unavailable"), firstPanel);
reportHistoryRefreshError("second", new Error("unavailable"), secondPanel);

clearHistoryRefreshError("first", firstPanel);
assert.equal(globalMessage.textContent, message);
assert.equal(globalMessageOwner, historyRefreshErrors.get("second").owner);
assert.equal(historyRefreshErrors.has("first"), false);

const replacementPanel = {isConnected: true};
secondPanel.isConnected = false;
reportHistoryRefreshError("second", new Error("replacement unavailable"), replacementPanel);
reportHistoryRefreshError("second", new Error("stale"), secondPanel);
clearHistoryRefreshError("second", secondPanel);
assert.equal(
  globalMessage.textContent,
  "Unable to refresh event history: replacement unavailable",
);
assert.equal(globalMessageOwner, historyRefreshErrors.get("second").owner);

clearHistoryRefreshError("second", replacementPanel);
assert.equal(globalMessage.textContent, "");
assert.equal(globalMessageOwner, null);
assert.equal(historyRefreshErrors.size, 0);

const runActionSource = source.slice(
  source.indexOf("async function runAction"),
  source.indexOf("async function removeCredential"),
);
assert.ok(runActionSource, "production runAction function was not found");
let actionResult = {action: "notify_only", snapshot: {used: 5.2, unit: "USD"}};
let actionMessage = null;
const {runAction} = eval(`(() => {
  const api = async () => actionResult;
  const showMessage = (value) => { actionMessage = value; };
  const loadCredentials = async () => {};
  const number = () => { throw new Error("generic check branch was used"); };
  ${runActionSource}
  return {runAction};
})()`);

await runAction("credential", "check");
assert.equal(
  actionMessage,
  "Notify-only action recorded; no provider action was taken.",
);

actionResult = {action: "notify_only_already_alerted", snapshot: {used: 5.3}};
await runAction("credential", "check");
assert.equal(
  actionMessage,
  "Threshold warning was already recorded; no provider action was taken.",
);
const displayStatusSource = source.slice(
  source.indexOf("function displayStatus"),
  source.indexOf("async function patchCredential"),
);
const cardSource = source.slice(
  source.indexOf("function card"),
  source.indexOf("function hasActiveInteraction"),
);
assert.ok(displayStatusSource.startsWith("function displayStatus"));
assert.ok(cardSource.startsWith("function card"));

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.dataset = {};
    this.className = "";
    this.textContent = "";
    this.disabled = false;
    this.hidden = false;
  }

  append(...children) {
    this.children.push(...children);
  }

  prepend(...children) {
    this.children.unshift(...children);
  }

  addEventListener() {}

  setAttribute(name, value) {
    this[name] = value;
  }
}

const {card} = eval(`(() => {
  const document = {createElement: (tagName) => new FakeElement(tagName)};
  const text = (tagName, value, className = "") => {
    const element = new FakeElement(tagName);
    element.textContent = value;
    element.className = className;
    return element;
  };
  const button = (label, className = "") => {
    const element = text("button", label, className);
    element.type = "button";
    return element;
  };
  const metric = (label, value) => ({label, value});
  const progress = () => new FakeElement("div");
  const editForm = () => {
    const editor = new FakeElement("form");
    editor.hidden = true;
    return editor;
  };
  const historyPanel = () => new FakeElement("details");
  const number = (value) => value ?? "Unavailable";
  const daysUntil = () => "Unavailable";
  const duration = (value) => String(value ?? "");
  const when = (value) => value ?? "Never";
  const runAction = () => {};
  const setPaused = () => {};
  const patchCredential = async () => {};
  const removeCredential = () => {};
  ${displayStatusSource}
  ${cardSource}
  return {card};
})()`);

const baseCredential = {
  id: "credential",
  provider: "OpenRouter",
  name: "Test credential",
  masked_identifier: "••••1234",
  status: "watching",
  paused: false,
  usage: {
    used: 1,
    remaining: 9,
    limit: 10,
    unit: "USD",
    checked_at: "2026-10-30T10:00:00Z",
    expires_at: null,
    period_end: null,
  },
  scheduler: {
    polling_tier: "quiet",
    current_interval_seconds: 3600,
    last_check_at: "2026-10-30T10:00:00Z",
    next_check_at: "2026-10-30T11:00:00Z",
  },
  starting_allowance: null,
  starting_allowance_unit: "USD",
  threshold: 9,
  burn_rate_per_second: null,
  auto_protect: false,
  notifications_muted: false,
  protection_action: "disable",
  available_actions: ["disable"],
  polling_config: {},
  last_action: null,
};

function renderedState(status) {
  const article = card({...baseCredential, status});
  const controls = article.children.find((child) => child.className === "controls");
  const metrics = article.children.find((child) => child.className === "metrics");
  assert.ok(controls, "rendered controls were not found");
  assert.ok(metrics, "rendered metrics were not found");
  return {
    article,
    nextCheck: metrics.children.find((entry) => entry.label === "Next check")?.value,
    disabled: Object.fromEntries(
      controls.children.map((control) => [control.textContent, control.disabled]),
    ),
  };
}

for (const [status, label] of [
  ["provisioning", "Recovery pending"],
  ["cleanup_required", "Cleanup pending"],
]) {
  const rendered = renderedState(status);
  assert.equal(rendered.article.className, "credential-card status-pending");
  assert.equal(rendered.nextCheck, label);
  assert.deepEqual(rendered.disabled, {
    "Check now": true,
    "Pause": true,
    "Auto Protect on": true,
    "Mute alerts": true,
    "Protect now": true,
    "Edit settings": true,
    "Remove": false,
  });
}

const normal = renderedState("watching");
assert.equal(normal.article.className, "credential-card status-healthy");
assert.equal(normal.nextCheck, "2026-10-30T11:00:00Z");
assert.deepEqual(normal.disabled, {
  "Check now": false,
  "Pause": false,
  "Auto Protect on": false,
  "Mute alerts": false,
  "Protect now": false,
  "Edit settings": false,
  "Remove": false,
});
