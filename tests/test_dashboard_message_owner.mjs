import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const source = readFileSync("src/keyguard/dashboard/app.js", "utf8");
const showMessageSource = source.match(
  /function showMessage\(value, isError = false, owner = null\) \{[\s\S]*?\n\}/,
)?.[0];
assert.ok(showMessageSource, "production showMessage function was not found");

const globalMessage = {
  textContent: "",
  classList: {toggle() {}},
};
let globalMessageOwner = null;
const showMessage = eval(`(${showMessageSource})`);

const message = "Unable to refresh event history: unavailable";
const firstPanelOwner = {};
const secondPanelOwner = {};

showMessage(message, true, firstPanelOwner);
showMessage(message, true, secondPanelOwner);

if (
  message
  && globalMessageOwner === firstPanelOwner
  && globalMessage.textContent === message
) {
  showMessage("");
}
assert.equal(globalMessage.textContent, message);
assert.equal(globalMessageOwner, secondPanelOwner);

if (
  message
  && globalMessageOwner === secondPanelOwner
  && globalMessage.textContent === message
) {
  showMessage("");
}
assert.equal(globalMessage.textContent, "");
assert.equal(globalMessageOwner, null);
