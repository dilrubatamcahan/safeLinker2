document.addEventListener("DOMContentLoaded", () => {
  const urlInput       = document.getElementById("urlInput");
  const analyzeBtn     = document.getElementById("analyzeBtn");
  const deepAnalyzeBtn = document.getElementById("deepAnalyzeBtn");
  const pasteBtn       = document.getElementById("pasteBtn");
  const clearBtn       = document.getElementById("clearBtn");
  const resultBody     = document.getElementById("resultBody");
  const historyPanel   = document.getElementById("historyPanel");

  let cache = {};

  // ── Level metadata ────────────────────────────────────────────────────────
  function levelMeta(level) {
    const l = (level || "").toLowerCase();
    if (l.includes("güvenli")) return { color:"#1a7f37", alphaBg:"rgba(26,127,55,.1)"  };
    if (l.includes("düşük"))   return { color:"#9a6700", alphaBg:"rgba(154,103,0,.1)"  };
    if (l.includes("şüpheli")) return { color:"#bc4c00", alphaBg:"rgba(188,76,0,.1)"   };
    if (l.includes("yüksek"))  return { color:"#cf222e", alphaBg:"rgba(207,34,46,.1)"  };
    if (l.includes("yerel"))   return { color:"#0969da", alphaBg:"rgba(9,105,218,.1)"  };
    return { color:"#9a6700", alphaBg:"rgba(154,103,0,.1)" };
  }

  // ── Severity → color ──────────────────────────────────────────────────────
  const sevColor = {
    critical:"#cf222e", high:"#bc4c00", medium:"#9a6700", low:"#656d76", safe:"#1a7f37"
  };

  // ── Verdict metni (hızlı analiz için tek cümle) ───────────────────────────
  function verdictText(score, f) {
    if (f.isDenylisted)    return "Bu alan adı kara listede. Kesinlikle ziyaret etmeyin.";
    if (f.hasIpAddress)    return "URL bir IP adresi kullanıyor — phishing saldırısı olabilir.";
    if (f.brandSpoof?.isSpoof) return "Bilinen bir markayı taklit eden domain tespit edildi.";
    if (f.idnHomograph?.isIDN) return "Unicode karakter sahteciliği tespit edildi (homograph saldırısı).";
    if (score <= 5)  return "Bilinen risk işareti tespit edilmedi. Güvenli görünüyor.";
    if (score <= 15) return "Düşük düzeyde risk sinyali var. Dikkatli olmanız önerilir.";
    if (score <= 35) return "Şüpheli işaretler tespit edildi. Bu URL'yi ziyaret etmemenizi öneririz.";
    return "Yüksek risk tespit edildi. Bu bağlantıya tıklamayın.";
  }

  // ── Tags ──────────────────────────────────────────────────────────────────
  function buildTags(f) {
    const tags = [];
    tags.push(f.hasHttps ? {t:"HTTPS",c:"tag-good"} : {t:"HTTP",c:"tag-bad"});
    if (f.isTrustedDomain)  tags.push({t:"Güvenilir",c:"tag-good"});
    if (f.isDenylisted)     tags.push({t:"Kara Liste",c:"tag-bad"});
    if (f.isShortener)      tags.push({t:"Kısa Link",c:"tag-warn"});
    if (f.hasIpAddress)     tags.push({t:"IP Adresi",c:"tag-bad"});
    if (f.brandSpoof?.isSpoof)             tags.push({t:"Marka Taklidi",c:"tag-bad"});
    if (f.typosquat?.isTyposquat)          tags.push({t:"Typosquat",c:"tag-bad"});
    if (f.idnHomograph?.isIDN)             tags.push({t:"Homograph",c:"tag-bad"});
    if (f.subdomainTakeover?.isSuspicious) tags.push({t:"DGA/Takeover",c:"tag-bad"});
    if (f.hasSuspiciousExtension && !f.isAllowlisted) tags.push({t:"Şüpheli Uzantı",c:"tag-warn"});
    return tags.map(x => `<span class="tag ${x.c}">${x.t}</span>`).join("");
  }

  // ── Score block (her iki modda da ortak) ──────────────────────────────────
  function buildScoreBlock(score, result, f, normalizedUrl) {
    const meta = levelMeta(result.level);
    return `
    <div class="score-block" style="--accent:${meta.color};--accent-bg:${meta.alphaBg}">
      <div class="score-left">
        <div class="score-num">${score}</div>
        <div class="score-sub">/ 100</div>
        <div class="score-bar-wrap">
          <div class="score-bar" data-pct="${Math.min(score, 100)}"></div>
        </div>
      </div>
      <div class="score-right">
        <div class="level-pill">${result.level}</div>
        <div class="domain-text" title="${normalizedUrl}">${f.hostname || normalizedUrl}</div>
        <div class="tag-row">${buildTags(f)}</div>
      </div>
    </div>`;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // HIZLI ANALİZ — renderQuick
  // Gösterim: Skor + Tek cümle karar + En önemli 3 sinyal
  // ══════════════════════════════════════════════════════════════════════════
  function renderQuick(normalizedUrl, result) {
    const score  = result.riskScore;
    const f      = result.features;
    const reasons = result.reasons || [];
    const verdict = verdictText(score, f);
    const top3    = reasons.slice(0, 3);
    const extra   = reasons.length - top3.length;

    resultBody.innerHTML =
      buildScoreBlock(score, result, f, normalizedUrl) +
      `<div class="verdict-box">
        <div class="verdict-label">Sonuç</div>
        <div class="verdict-text">${verdict}</div>
      </div>` +
      `<div class="quick-signals">
        <div class="qs-label">Tespit edilen sinyaller</div>
        ${top3.length > 0
          ? top3.map(r => `<div class="qs-item">
              <div class="qs-dot ${signalDotCls(r)}"></div>
              <span>${r}</span>
            </div>`).join("")
          : `<div class="qs-item">
              <div class="qs-dot sig-good"></div>
              <span>Belirgin risk işareti bulunamadı.</span>
            </div>`
        }
      </div>` +
      `<div class="quick-cta" id="quickCta" style="cursor:pointer">
        <span>${extra > 0 ? `+${extra} sinyal daha var` : "Tüm sinyaller gösterildi"}</span>
        <strong>Derin Analiz ile tüm detayları gör →</strong>
      </div>`;

    requestAnimationFrame(animateBars);
    document.getElementById("quickCta")?.addEventListener("click", () => {
      runDeepAnalysis();
    });
    saveToHistory(normalizedUrl, result);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // DERİN ANALİZ — renderDeep
  // Gösterim: Skor + Tehdit kartı + Etkiler + Aksiyonlar + URL detay + Tüm sinyaller + Backend
  // ══════════════════════════════════════════════════════════════════════════
  function renderDeep(normalizedUrl, result, deepExtra) {
    const score = result.riskScore;
    const ta    = result.threatAssessment;
    const f     = result.features;

    resultBody.innerHTML =
      buildScoreBlock(score, result, f, normalizedUrl) +
      buildThreatRow(ta) +
      buildRiskScenario(ta) +
      buildActions(ta.actions) +
      buildDetailGrid(f) +
      buildSignals(result.reasons) +
      (deepExtra ? buildDeepPanel(deepExtra) : "");

    requestAnimationFrame(animateBars);
    attachToggles();
    saveToHistory(normalizedUrl, result);
  }

  // ── Signal dot sınıfı ─────────────────────────────────────────────────────
  function signalDotCls(t) {
    const l = t.toLowerCase();
    if (l.includes("allowlist") || l.includes("güvenilir kaynak") || l.includes("risk işareti bulunmadı")) return "sig-good";
    if (l.includes("denylist") || l.includes("ip adresi") || l.includes("takeover") ||
        l.includes("punycode") || l.includes("homograph") || l.includes("typosquat") || l.includes("dga")) return "sig-danger";
    if (l.includes("şüpheli") || l.includes("kısa link") || l.includes("yönlendirme") ||
        l.includes("login") || l.includes("marka")) return "sig-warn";
    return "sig-info";
  }

  // ── Derin analiz bileşenleri ──────────────────────────────────────────────

  function buildThreatRow(ta) {
    const color = sevColor[ta.severity] || sevColor.low;
    return `
    <div class="threat-row" style="--t-color:${color}">
      <div class="threat-icon">${ta.threatIcon}</div>
      <div class="threat-body">
        <div class="threat-name">${ta.threatLabel}</div>
        <div class="threat-sub">Tehdit sınıflandırması</div>
        <div class="conf-row">
          <div class="conf-bar-wrap">
            <div class="conf-bar" data-pct="${ta.confidence}" style="background:${color}"></div>
          </div>
          <span class="conf-pct">${ta.confidence}% güven</span>
        </div>
      </div>
    </div>`;
  }

  function buildRiskScenario(ta) {
    const impacts = ta.impacts || [];
    if (!impacts.length) return "";

    const cfg = {
      critical: { color:"#cf222e", bg:"rgba(207,34,46,.05)", border:"rgba(207,34,46,.15)", icon:`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`, title:"Bu siteye girerseniz başınıza neler gelebilir?" },
      high:     { color:"#bc4c00", bg:"rgba(188,76,0,.05)",  border:"rgba(188,76,0,.15)",  icon:`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`, title:"Bu siteye girerseniz başınıza neler gelebilir?" },
      medium:   { color:"#9a6700", bg:"rgba(154,103,0,.05)", border:"rgba(154,103,0,.15)", icon:`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`, title:"Dikkat etmeniz gereken durumlar" },
      low:      { color:"#656d76", bg:"rgba(101,109,118,.04)", border:"rgba(101,109,118,.12)", icon:`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`, title:"Olası durumlar" },
      safe:     { color:"#1a7f37", bg:"rgba(26,127,55,.05)", border:"rgba(26,127,55,.15)", icon:`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`, title:"Güvenlik durumu" }
    };
    const c = cfg[ta.severity] || cfg.low;

    const items = impacts.map((imp, i) =>
      `<div class="rs-item">
        <div class="rs-num" style="background:${c.color}">${i + 1}</div>
        <span>${imp}</span>
      </div>`
    ).join("");

    return `
    <div class="risk-scenario" style="--rs-color:${c.color};--rs-bg:${c.bg};--rs-border:${c.border}">
      <div class="rs-header">
        <span class="rs-icon">${c.icon}</span>
        <div class="rs-title-wrap">
          <div class="rs-title">${c.title}</div>
          <div class="rs-subtitle">${ta.threatLabel} · ${ta.confidence}% güven</div>
        </div>
      </div>
      <div class="rs-items">${items}</div>
    </div>`;
  }

  function buildActions(actions) {
    if (!actions?.length) return "";
    const items = actions.map(act =>
      `<div class="info-item"><div class="info-dot dot-act"></div><span>${act}</span></div>`
    ).join("");
    return `
    <div class="section">
      <div class="section-head" data-toggle="action-list">
        <span>Önerilen Adımlar</span>
        <span class="chevron">▾</span>
      </div>
      <div class="section-body" id="action-list">${items}</div>
    </div>`;
  }

  function buildDetailGrid(f) {
    const cells = [
      { key:"Şifreleme",      val: f.hasHttps ? "HTTPS" : "HTTP",
        color: f.hasHttps ? "#1a7f37" : "#cf222e" },
      { key:"URL Uzunluğu",   val: (f.urlLength || 0) + " karakter",
        color: f.urlLength > 75 ? "#9a6700" : "#656d76" },
      { key:"Alt Domain",     val: (f.subdomainCount || 0) + " adet",
        color: f.subdomainCount >= 3 ? "#9a6700" : "#656d76" },
      { key:"TLD",            val: f.riskyTld ? "." + f.riskyTld : (f.hostname || "").split(".").pop() || "—",
        color: f.riskyTld ? "#9a6700" : "#656d76"},
      { key:"Şüpheli Kelime", val: f.foundSuspiciousWords?.length > 0 ? f.foundSuspiciousWords.join(", ") : "Yok",
        color: f.foundSuspiciousWords?.length > 0 ? "#9a6700" : "#656d76" },
      { key:"Path Derinliği", val: (f.pathDepth || 0) + " seviye",
        color: f.pathDepth >= 4 ? "#9a6700" : "#656d76" },
      { key:"Port",           val: f.nonStandardPort ? f.nonStandardPort : "Standart",
        color: f.nonStandardPort ? "#9a6700" : "#656d76" },
      { key:"Kodlama",        val: f.hasEncodedChars ? "Var" : "Yok",
        color: f.hasEncodedChars ? "#9a6700" : "#656d76" }
    ];
    return `
    <div class="section">
      <div class="section-head" data-toggle="detail-grid">
        <span>URL Teknik Detayları</span>
        <span class="chevron">▾</span>
      </div>
      <div class="section-body" id="detail-grid">
        <div class="detail-grid">
          ${cells.map(c => `
            <div class="detail-cell">
              <div class="dc-key">${c.key}</div>
              <div class="dc-val" style="color:${c.color}">${c.val}</div>
            </div>`).join("")}
        </div>
      </div>
    </div>`;
  }

  function buildSignals(reasons) {
    const count = (reasons || []).length;
    const items = count > 0
      ? reasons.map(r =>
          `<div class="signal-item"><div class="signal-dot ${signalDotCls(r)}"></div><span>${r}</span></div>`
        ).join("")
      : `<div class="signal-item"><div class="signal-dot sig-good"></div><span>Belirgin risk işareti bulunamadı.</span></div>`;
    return `
    <div class="section">
      <div class="section-head" data-toggle="signals-list">
        <span>Tüm Teknik Sinyaller</span>
        <span style="display:flex;align-items:center;gap:6px">
          <span class="signal-count">${count}</span>
          <span class="chevron">▾</span>
        </span>
      </div>
      <div class="section-body" id="signals-list">${items}</div>
    </div>`;
  }

  function buildDeepPanel(deepExtra) {
    if (!deepExtra) return "";
    const repLabels = {
      high_risk:"Yüksek Risk", suspicious:"Şüpheli",
      clean:"Temiz", unknown:"Bilinmiyor", not_checked:"—"
    };
    const repColor = deepExtra.reputationLevel === "high_risk" ? "#cf222e"
      : deepExtra.reputationLevel === "suspicious" ? "#9a6700"
      : deepExtra.reputationLevel === "clean" ? "#1a7f37" : "#656d76";
    const repLabel   = repLabels[deepExtra.reputationLevel] || "—";
    const redirColor = deepExtra.hasRedirect ? "#9a6700" : "#1a7f37";
    const redirText  = deepExtra.hasRedirect
      ? `${deepExtra.redirectCount} adım yönlendirme tespit edildi`
      : "Yönlendirme zinciri yok";

    return `
    <div class="deep-section">
      <div class="deep-head">Sunucu Analizi — Derin Tarama</div>
      <div class="deep-body">
        <div class="deep-row">
          <span class="dr-key">Domain itibarı</span>
          <span class="dr-val" style="color:${repColor}">${repLabel}</span>
        </div>
        <div class="deep-row">
          <span class="dr-key">Yönlendirme zinciri</span>
          <span class="dr-val" style="color:${redirColor}">${redirText}</span>
        </div>
        ${deepExtra.finalUrl ? `
        <div class="deep-row">
          <span class="dr-key">Gerçek hedef URL</span>
          <span class="dr-val" style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;display:inline-block" title="${deepExtra.finalUrl}">${deepExtra.finalUrl.substring(0, 45)}…</span>
        </div>` : ""}
        ${deepExtra.purposeInfo ? `
        <div class="deep-row" style="flex-direction:column;gap:3px">
          <span class="dr-key">Sitenin olası amacı</span>
          <span style="font-size:12px;color:#1f2328;line-height:1.5;margin-top:2px">${deepExtra.purposeInfo}</span>
        </div>` : ""}
        ${deepExtra.possibleRisk ? `
        <div class="deep-row" style="flex-direction:column;gap:3px">
          <span class="dr-key">Kullanıcı için risk</span>
          <span style="font-size:12px;color:#cf222e;line-height:1.5;margin-top:2px">${deepExtra.possibleRisk}</span>
        </div>` : ""}
      </div>
    </div>`;
  }

  // ── Animasyon ─────────────────────────────────────────────────────────────
  function animateBars() {
    document.querySelectorAll("[data-pct]").forEach(el => {
      const pct = el.dataset.pct;
      requestAnimationFrame(() => { el.style.width = pct + "%"; });
    });
  }

  function attachToggles() {
    document.querySelectorAll("[data-toggle]").forEach(el => {
      el.addEventListener("click", () => {
        const target = document.getElementById(el.dataset.toggle);
        if (!target) return;
        const hidden = target.style.display === "none";
        target.style.display = hidden ? "" : "none";
        const chevron = el.querySelector(".chevron");
        if (chevron) chevron.textContent = hidden ? "▾" : "▸";
        el.classList.toggle("collapsed", !hidden);
      });
    });
  }

  // ── Loading / Error ───────────────────────────────────────────────────────
  function showLoading(msg) {
    resultBody.innerHTML = `<div class="loading"><div class="spinner"></div><div style="color:var(--text3);font-size:12px">${msg}</div></div>`;
  }
  function showError(msg) {
    resultBody.innerHTML = `<div class="error-msg">${msg}</div>`;
  }

  // ── Hızlı analiz ─────────────────────────────────────────────────────────
  function runAnalysis() {
    const url = urlInput.value.trim();
    if (!url) return showError("Bir URL girin.");
    if (!isValidUrl(url)) return showError("Geçerli bir URL girin. Örnek: https://example.com");
    const normalized = normalizeUrl(url);
    if (cache[normalized]) { renderQuick(normalized, cache[normalized]); return; }
    const result = analyzeUrl(normalized);
    cache[normalized] = result;
    renderQuick(normalized, result);
  }

  // ── Derin analiz ──────────────────────────────────────────────────────────
  async function runDeepAnalysis() {
    const url = urlInput.value.trim();
    if (!url) return showError("Bir URL girin.");
    if (!isValidUrl(url)) return showError("Geçerli bir URL girin.");
    showLoading("Sunucu sorgulanıyor, derin analiz yapılıyor…");
    deepAnalyzeBtn.disabled = true;
    const normalized = normalizeUrl(url);
    const result = analyzeUrl(normalized);
    try {
      const [repData, redirData] = await Promise.all([
        postJson("http://127.0.0.1:8010/api/reputation",     { url: normalized }),
        postJson("http://127.0.0.1:8010/api/redirect-check", { url: normalized })
      ]);
      let deepScore = result.riskScore;
      const deepReasons = [...result.reasons];
      const repLevel = repData.reputation_level;
      if (repLevel === "high_risk")       { deepScore += 35; deepReasons.push("Sunucu: domain itibarı yüksek risk sinyali verdi."); }
      else if (repLevel === "suspicious") { deepScore += 20; deepReasons.push("Sunucu: domain itibarı şüpheli sinyal verdi."); }
      else if (repLevel === "clean")      { deepReasons.push("Sunucu: domain itibarı temiz görünüyor."); }
      else                                { deepReasons.push("Sunucu: yeterli itibar verisi bulunamadı."); }
      if (redirData.has_redirect) {
        deepScore += Math.min(redirData.redirect_count * 5, 20);
        deepReasons.push(`Yönlendirme zinciri: ${redirData.redirect_count} adım tespit edildi.`);
        if (redirData.final_url && isValidUrl(redirData.final_url)) {
          const finalRes = analyzeUrl(normalizeUrl(redirData.final_url));
          if (finalRes.level === "Yüksek risk") { deepScore += 35; deepReasons.push("Final URL yüksek riskli olarak değerlendirildi."); }
          else if (finalRes.level === "Şüpheli") { deepScore += 25; deepReasons.push("Final URL şüpheli olarak değerlendirildi."); }
        }
      }
      deepScore = Math.min(deepScore, 100);
      const deepLevel  = repLevel === "high_risk" ? "Yüksek risk" : calcLevel(result.features, deepScore);
      const deepResult = { ...result, riskScore: deepScore, level: deepLevel, reasons: deepReasons,
                           threatAssessment: assessThreat(result.features, deepScore) };
      renderDeep(normalized, deepResult, {
        reputationLevel: repLevel,
        hasRedirect:     redirData.has_redirect,
        redirectCount:   redirData.redirect_count || 0,
        finalUrl:        redirData.final_url || "",
        purposeInfo:     repData.possible_purpose || "",
        possibleRisk:    repData.possible_risk || ""
      });
    } catch {
      result.reasons.push("Sunucuya ulaşılamadı — statik analiz sonuçları gösteriliyor.");
      renderDeep(normalized, result, null);
    } finally {
      deepAnalyzeBtn.disabled = false;
    }
  }

  function calcLevel(features, score) {
    if (features.isPrivateIp && score <= 10) return "Yerel ağ adresi";
    if (score <= 5)  return "Güvenli görünüyor";
    if (score <= 15) return "Düşük risk";
    if (score <= 35) return "Şüpheli";
    return "Yüksek risk";
  }

  async function postJson(url, body) {
    const res = await fetch(url, {
      method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  // ── Geçmiş ───────────────────────────────────────────────────────────────
  function saveToHistory(normalizedUrl, result) {
    chrome.storage.local.get(["analysisHistory"], data => {
      const hist = Array.isArray(data.analysisHistory) ? data.analysisHistory : [];
      const item = { normalizedUrl, hostname: result.features.hostname,
                     level: result.level, riskScore: result.riskScore, savedAt: Date.now() };
      const updated = [item, ...hist.filter(h => h.normalizedUrl !== normalizedUrl)].slice(0, 8);
      chrome.storage.local.set({ analysisHistory: updated }, () => renderHistory(updated));
    });
  }

  function renderHistory(items) {
    if (!items?.length) {
      historyPanel.innerHTML = `<div class="empty"><p>Henüz kayıt yok</p></div>`;
      return;
    }
    historyPanel.innerHTML = `<div class="history-list">${
      items.map(item => {
        const m = levelMeta(item.level);
        return `<div class="hist-item" data-url="${item.normalizedUrl}">
          <div class="hist-dot" style="background:${m.color}"></div>
          <div class="hist-info">
            <div class="hist-host">${item.hostname || item.normalizedUrl}</div>
            <div class="hist-level">${item.level}</div>
          </div>
          <div class="hist-score" style="color:${m.color}">${item.riskScore}</div>
        </div>`;
      }).join("")
    }</div>`;
    historyPanel.querySelectorAll(".hist-item").forEach(el => {
      el.addEventListener("click", () => {
        urlInput.value = el.dataset.url;
        document.querySelector('.tab[data-tab="result"]')?.click();
        runAnalysis();
      });
    });
  }

  // ── Sekmeler ──────────────────────────────────────────────────────────────
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab,.tab-content").forEach(el => el.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("tab-" + tab.dataset.tab)?.classList.add("active");
    });
  });

  // ── Butonlar ──────────────────────────────────────────────────────────────
  pasteBtn.addEventListener("click", async () => {
    try {
      const t = await navigator.clipboard.readText();
      if (t) { urlInput.value = t.trim(); runAnalysis(); }
    } catch { urlInput.focus(); }
  });

  clearBtn.addEventListener("click", () => {
    urlInput.value = "";
    cache = {};
    resultBody.innerHTML = `<div class="empty"><p>Bir URL girin ve analiz edin</p></div>`;
  });

  analyzeBtn.addEventListener("click", runAnalysis);
  deepAnalyzeBtn.addEventListener("click", runDeepAnalysis);
  urlInput.addEventListener("keydown", e => { if (e.key === "Enter") runAnalysis(); });

  // ── Başlangıç ─────────────────────────────────────────────────────────────
  chrome.storage.local.get(["analysisHistory"], data => {
    renderHistory(Array.isArray(data.analysisHistory) ? data.analysisHistory : []);
  });
  chrome.tabs.query({ active:true, currentWindow:true }, tabs => {
    const url = tabs[0]?.url;
    if (url?.startsWith("http")) { urlInput.value = url; runAnalysis(); }
  });
});
