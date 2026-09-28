// background.js
// Manifest V3 service worker. Talks to the local Flask API (server/app.py)
// running at http://127.0.0.1:5000, checks whichever URL the active tab
// navigates to, and sets the toolbar badge / icon color accordingly.

const API_BASE = "http://127.0.0.1:5000";
const cache = new Map(); // url -> result, to avoid re-scoring the same tab repeatedly

async function checkUrl(url) {
  if (cache.has(url)) return cache.get(url);
  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`API returned ${res.status}`);
    const data = await res.json();
    cache.set(url, data);
    return data;
  } catch (err) {
    return { error: String(err) };
  }
}

function setBadge(tabId, result) {
  if (!result || result.error) {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#9ca3af" });
    return;
  }
  if (result.prediction === "phishing") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#dc2626" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "OK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#16a34a" });
  }
}

async function scanTab(tabId, url) {
  if (!url || !url.startsWith("http")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const result = await checkUrl(url);
  setBadge(tabId, result);
  // Stash the latest result so popup.js can read it without re-calling the API.
  chrome.storage.session.set({ [`result_${tabId}`]: result });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url) {
    scanTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab && tab.url) scanTab(tabId, tab.url);
  });
});

// Let the popup or content script ask for an on-demand check.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "CHECK_URL") {
    checkUrl(msg.url).then(sendResponse);
    return true; // keep the message channel open for the async response
  }
});
