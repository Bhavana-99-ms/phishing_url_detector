// content.js
// Asks the background worker to score this page's URL, and if it's flagged
// as phishing with reasonably high confidence, injects a dismissible
// warning banner at the top of the page.

(function () {
  const url = window.location.href;

  chrome.runtime.sendMessage({ type: "CHECK_URL", url }, (result) => {
    if (!result || result.error) return;
    if (result.prediction !== "phishing") return;
    if (result.phishing_probability < 0.6) return; // avoid noisy low-confidence banners

    injectBanner(result);
  });

  function injectBanner(result) {
    if (document.getElementById("__phish_detector_banner__")) return;

    const banner = document.createElement("div");
    banner.id = "__phish_detector_banner__";
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: #dc2626; color: #fff; font-family: system-ui, sans-serif;
      font-size: 14px; padding: 10px 16px; display: flex; align-items: center;
      justify-content: space-between; box-shadow: 0 2px 6px rgba(0,0,0,.3);
    `;

    const pct = Math.round(result.phishing_probability * 100);
    const text = document.createElement("span");
    text.textContent =
      `⚠ This page looks like it might be a phishing site (risk score: ${pct}%). ` +
      `Be careful entering passwords or personal information.`;

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Dismiss";
    closeBtn.style.cssText = `
      margin-left: 12px; background: #fff; color: #dc2626; border: none;
      padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: 600;
    `;
    closeBtn.onclick = () => banner.remove();

    banner.appendChild(text);
    banner.appendChild(closeBtn);

    const attach = () => document.documentElement.prepend(banner);
    if (document.body) attach();
    else document.addEventListener("DOMContentLoaded", attach);
  }
})();
