const credentialList = document.querySelector("#credentials");
const form = document.querySelector("#credential-form");
const message = document.querySelector("#form-message");
let sessionToken = window.sessionStorage.getItem("keyguardSession");

async function api(path, options = {}) {
  const headers = {...(options.headers || {})};
  if (options.body) headers["Content-Type"] = "application/json";
  if (sessionToken) headers.Authorization = `KeyGuard-Session ${sessionToken}`;
  const response = await fetch(path, {
    ...options,
    headers,
  });
  const payload = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      sessionToken = null;
      window.sessionStorage.removeItem("keyguardSession");
    }
    throw new Error(payload?.error?.message || payload?.error?.code || "Request failed");
  }
  return payload;
}

function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

async function setPaused(id, paused) {
  try {
    await api(`/api/credentials/${encodeURIComponent(id)}/${paused ? "pause" : "resume"}`, {
      method: "POST",
      body: "{}",
    });
    await loadCredentials();
  } catch (error) {
    message.textContent = error.message;
  }
}

async function removeCredential(id) {
  if (!window.confirm("Remove this credential from KeyGuard and GNOME Keyring?")) return;
  try {
    await api(`/api/credentials/${encodeURIComponent(id)}`, {method: "DELETE"});
    await loadCredentials();
  } catch (error) {
    message.textContent = error.message;
  }
}

function card(credential) {
  const article = document.createElement("article");
  article.append(
    text("p", credential.provider, "provider"),
    text("h3", credential.name),
    text("p", credential.masked_identifier, "masked"),
    text("p", credential.paused ? "Paused" : credential.status, "status"),
  );
  const controls = document.createElement("div");
  controls.className = "controls";

  const pause = text("button", credential.paused ? "Resume" : "Pause");
  pause.type = "button";
  pause.addEventListener("click", () => setPaused(credential.id, !credential.paused));

  const remove = text("button", "Remove", "danger");
  remove.type = "button";
  remove.addEventListener("click", () => removeCredential(credential.id));

  controls.append(pause, remove);
  article.append(controls);
  return article;
}

async function loadCredentials() {
  credentialList.replaceChildren(text("p", "Loading…"));
  try {
    const {credentials} = await api("/api/credentials");
    if (!credentials.length) {
      credentialList.replaceChildren(text("p", "No credentials are being watched yet.", "empty"));
      return;
    }
    credentialList.replaceChildren(...credentials.map(card));
  } catch (error) {
    credentialList.replaceChildren(text("p", error.message, "error"));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "Saving…";
  const data = new FormData(form);
  const threshold = data.get("threshold");
  const body = {
    provider: data.get("provider"),
    name: data.get("name"),
    api_key: data.get("api_key"),
    threshold: threshold === "" ? null : Number(threshold),
    auto_protect: data.get("auto_protect") === "on",
  };
  try {
    await api("/api/credentials", {method: "POST", body: JSON.stringify(body)});
    form.reset();
    message.textContent = "Saved. The raw key was sent directly to GNOME Keyring.";
    await loadCredentials();
  } catch (error) {
    message.textContent = error.message;
  }
});

document.querySelector("#refresh").addEventListener("click", loadCredentials);

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
      if (!response.ok || !payload.session_token) {
        throw new Error("KeyGuard authentication failed");
      }
      sessionToken = payload.session_token;
      window.sessionStorage.setItem("keyguardSession", sessionToken);
    } catch (error) {
      message.textContent = error.message;
      return;
    }
  }
  if (!sessionToken) {
    message.textContent = "Open KeyGuard from its launcher to authenticate.";
    return;
  }
  try {
    await loadCredentials();
  } catch (error) {
    message.textContent = error.message;
  }
}

start();
