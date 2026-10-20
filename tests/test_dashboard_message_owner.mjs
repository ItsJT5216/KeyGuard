import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const source = readFileSync("src/keyguard/dashboard/app.js", "utf8");
const showMessageSource = source.match(
  /function showMessage\(value, isError = false, owner = null\) \{[\s\S]*?\n\}/,
)?.[0];
assert.ok(showMessageSource, "production showMessage function was not found");
const reportHistoryRefreshErrorSource = source.match(
  /function reportHistoryRefreshError\(credentialId, error\) \{[\s\S]*?\n\}/,
)?.[0];
assert.ok(
  reportHistoryRefreshErrorSource,
  "production reportHistoryRefreshError function was not found",
);
const clearHistoryRefreshErrorSource = source.match(
  /function clearHistoryRefreshError\(credentialId\) \{[\s\S]*?\n\}/,
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
reportHistoryRefreshError("first", new Error("unavailable"));
reportHistoryRefreshError("second", new Error("unavailable"));

clearHistoryRefreshError("first");
assert.equal(globalMessage.textContent, message);
assert.equal(globalMessageOwner, historyRefreshErrors.get("second").owner);
assert.equal(historyRefreshErrors.has("first"), false);

clearHistoryRefreshError("second");
assert.equal(globalMessage.textContent, "");
assert.equal(globalMessageOwner, null);
assert.equal(historyRefreshErrors.size, 0);
