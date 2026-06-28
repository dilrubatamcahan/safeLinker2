(function () {
  if (window.hasSafeLinkerBanner) return;
  window.hasSafeLinkerBanner = true;

  try {
    const currentUrl = window.location.href;
    if (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://")) return;
    if (typeof isValidUrl !== "function" || typeof analyzeUrl !== "function") return;

    const normalized = normalizeUrl(currentUrl);
    const result = analyzeUrl(normalized);
    if (result.level !== "Şüpheli" && result.level !== "Yüksek risk") return;

    const isDanger  = result.level === "Yüksek risk";
    const color     = isDanger ? "#cf222e" : "#bc4c00";
    const bgColor   = isDanger ? "rgba(207,34,46,.06)" : "rgba(188,76,0,.05)";
    const borderCol = isDanger ? "rgba(207,34,46,.25)" : "rgba(188,76,0,.2)";
    const label     = isDanger ? "Yüksek Risk" : "Şüpheli";

    const topReasons = (result.reasons || []).slice(0, 2).join(" · ");

    const banner = document.createElement("div");
    banner.id = "safelinker-banner";
    Object.assign(banner.style, {
      position:   "fixed",
      top:        "16px",
      right:      "16px",
      zIndex:     "2147483647",
      maxWidth:   "340px",
      width:      "calc(100vw - 32px)",
      background: "#ffffff",
      border:     `1px solid ${borderCol}`,
      borderLeft: `3px solid ${color}`,
      borderRadius: "10px",
      padding:    "12px 14px",
      fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif",
      boxShadow:  "0 4px 20px rgba(0,0,0,.12), 0 1px 4px rgba(0,0,0,.06)",
      color:      "#1f2328",
      background: bgColor,
      transform:  "translateY(-10px)",
      opacity:    "0",
      transition: "transform .3s cubic-bezier(.34,1.56,.64,1), opacity .25s"
    });

    banner.innerHTML = `
      <div style="display:flex;align-items:flex-start;gap:10px">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px">
            <div style="display:flex;align-items:center;gap:6px">
              <div style="width:6px;height:6px;border-radius:50%;background:${color};flex-shrink:0"></div>
              <strong style="font-size:12px;font-weight:700;color:${color};letter-spacing:.1px">${label} — SafeLinker</strong>
            </div>
            <button id="sl-close" style="background:none;border:none;color:#9198a1;cursor:pointer;font-size:14px;line-height:1;padding:0 0 0 8px;flex-shrink:0">✕</button>
          </div>
          <div style="font-size:11px;color:#656d76;margin-bottom:${topReasons ? '5px' : '0'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            ${result.features.hostname}
          </div>
          ${topReasons ? `
          <div style="font-size:11px;color:#1f2328;line-height:1.5;border-top:1px solid rgba(0,0,0,.06);padding-top:5px">
            ${topReasons}
          </div>` : ""}
        </div>
      </div>`;

    document.documentElement.appendChild(banner);
    requestAnimationFrame(() => {
      banner.style.transform = "translateY(0)";
      banner.style.opacity   = "1";
    });

    banner.querySelector("#sl-close").addEventListener("click", () => {
      banner.style.transform = "translateY(-10px)";
      banner.style.opacity   = "0";
      setTimeout(() => banner.remove(), 250);
    });

    setTimeout(() => {
      if (banner.isConnected) {
        banner.style.transform = "translateY(-10px)";
        banner.style.opacity   = "0";
        setTimeout(() => banner.remove(), 250);
      }
    }, 8000);

  } catch (err) {
    console.error("SafeLinker content script hatası:", err);
  }
})();
