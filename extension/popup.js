// popup.js

function render(result, url) {
  document.getElementById("url").textContent = url;
  const statusEl = document.getElementById("status");
  const statusText = document.getElementById("status-text");
  const errEl = document.getElementById("err");
  errEl.textContent = "";

  if (!result || result.error) {
    statusEl.className = "unknown";
    statusText.textContent = "Could not reach detection server";
    errEl.textContent =
      "Make sure the local API is running: python3 server/app.py (see README).";
    return;
  }

  const pct = Math.round(result.phishing_probability * 100);

  if (result.prediction === "phishing") {
    statusEl.className = "danger";
    statusText.textContent = `Likely phishing (${pct}% risk)`;
  } else {
    statusEl.className = "safe";
    statusText.textContent = `Looks legitimate (${pct}% risk)`;
  }

  document.getElementById("details").style.display = "table";
  document.getElementById("ml-score").textContent =
    Math.round(result.ml_model_probability * 100) + "%";
  document.getElementById("heur-score").textContent =
    Math.round(result.heuristic_score * 100) + "%";
  document.getElementById("final-score").textContent = pct + "%";

  const sig = result.heuristic_signals || {};
  const notes = [];
  if (sig.is_ip_host) notes.push("URL uses a raw IP address instead of a domain name");
  if (sig.brand_impersonation) notes.push(`Possible impersonation of "${sig.impersonated_brand}"`);
  if (sig.many_hyphens_domain) notes.push("Domain contains many hyphens");
  if (sig.many_subdomains) notes.push("Unusually deep sub-domain structure");
  if (sig.no_https) notes.push("Connection is not using HTTPS");
  if (sig.suspicious_word_count > 0) notes.push("Contains sensitive/action keywords (login, verify, etc.)");

  document.getElementById("signals").textContent = notes.length
    ? "Flags: " + notes.join(" · ")
    : "No obvious red flags detected in the URL structure.";
}

function checkActiveTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) return;
    document.getElementById("url").textContent = tab.url;
    chrome.runtime.sendMessage({ type: "CHECK_URL", url: tab.url }, (result) => {
      render(result, tab.url);
    });
  });
}

document.addEventListener("DOMContentLoaded", checkActiveTab);
document.getElementById("rescan")?.addEventListener("click", checkActiveTab);
