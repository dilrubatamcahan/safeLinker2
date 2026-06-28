// ─── Typosquatting: bilinen markalar ve resmi domain'leri ────────────────────
const TYPOSQUAT_BRANDS = [
  { name: "google",    minLen: 5, official: ["google.com", "googleapis.com", "gstatic.com"] },
  { name: "microsoft", minLen: 5, official: ["microsoft.com", "live.com", "outlook.com", "microsoftonline.com", "office.com"] },
  { name: "apple",     minLen: 5, official: ["apple.com", "icloud.com"] },
  { name: "paypal",    minLen: 5, official: ["paypal.com", "paypalobjects.com"] },
  { name: "github",    minLen: 5, official: ["github.com", "githubassets.com", "githubusercontent.com", "github.blog", "github.io"] },
  { name: "linkedin",  minLen: 5, official: ["linkedin.com"] },
  { name: "facebook",  minLen: 5, official: ["facebook.com", "fb.com", "fbcdn.net"] },
  { name: "instagram", minLen: 5, official: ["instagram.com"] },
  { name: "amazon",    minLen: 5, official: ["amazon.com", "amazon.com.tr", "amazon.co.uk", "amazonaws.com"] },
  { name: "netflix",   minLen: 5, official: ["netflix.com"] },
  { name: "twitter",   minLen: 5, official: ["twitter.com", "x.com", "twimg.com"] },
  { name: "youtube",   minLen: 5, official: ["youtube.com", "youtu.be"] },
  { name: "dropbox",   minLen: 5, official: ["dropbox.com"] },
  { name: "discord",   minLen: 5, official: ["discord.com", "discordapp.com"] },
  { name: "spotify",   minLen: 5, official: ["spotify.com"] },
  { name: "openai",    minLen: 5, official: ["openai.com", "chatgpt.com"] }
];

// ─── Subdomain takeover: bilinen kullanıcı subdomain servisleri ─────────────
const SUBDOMAIN_HOSTING_DOMAINS = [
  "github.io", "gitlab.io", "s3.amazonaws.com", "azurewebsites.net",
  "cloudapp.net", "azurestaticapps.net", "herokuapp.com", "netlify.app",
  "vercel.app", "pages.dev", "surge.sh", "firebaseapp.com", "web.app",
  "readthedocs.io", "000webhostapp.com", "wpcomstaging.com"
];

const RULES = {
  trustedDomains: [
    // Arama & Google
    "google.com", "youtube.com", "googleapis.com", "gstatic.com",
    "dl.google.com", "storage.googleapis.com",
    // Microsoft
    "microsoft.com", "microsoftonline.com", "office.com", "live.com",
    "outlook.com", "azure.com",
    // Apple
    "apple.com", "icloud.com",
    // GitHub & Dev
    "github.com", "githubassets.com", "githubusercontent.com",
    "github.blog", "gitlab.com",
    "nodejs.org", "npmjs.com", "python.org",
    // Mozilla
    "mozilla.org", "firefox.com", "download.mozilla.org",
    // Sosyal Medya
    "facebook.com", "fb.com", "fbcdn.net",
    "instagram.com", "twitter.com", "x.com", "twimg.com",
    "reddit.com", "redd.it",
    "linkedin.com",
    // Mesajlaşma
    "discord.com", "discordapp.com",
    "whatsapp.com", "wa.me", "telegram.org",
    // Medya & Müzik
    "spotify.com", "netflix.com",
    "youtube.com", "youtu.be",
    // Ödeme & E-ticaret
    "paypal.com", "paypalobjects.com", "paypal-community.com",
    "aliexpress.com", "amazon.com", "amazon.com.tr",
    // Eğitim
    "coursera.org", "udemy.com", "khanacademy.org",
    // İçerik & CDN
    "medium.com", "wikipedia.org",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    // AI
    "openai.com", "chatgpt.com"
  ],

  allowlistedDomains: [
    // Arama & Google
    "google.com", "youtube.com", "googleapis.com", "gstatic.com",
    "dl.google.com", "storage.googleapis.com",
    // Microsoft
    "microsoft.com", "microsoftonline.com", "office.com", "live.com",
    "outlook.com", "azure.com",
    // Apple
    "apple.com", "icloud.com",
    // GitHub & Dev
    "github.com", "githubassets.com", "githubusercontent.com",
    "github.blog", "gitlab.com",
    "nodejs.org", "npmjs.com", "python.org",
    // Mozilla
    "mozilla.org", "firefox.com", "download.mozilla.org",
    // Sosyal Medya
    "facebook.com", "fb.com", "fbcdn.net",
    "instagram.com", "twitter.com", "x.com", "twimg.com",
    "reddit.com", "redd.it", "linkedin.com",
    // Mesajlaşma
    "discord.com", "discordapp.com", "whatsapp.com", "wa.me",
    // Medya & Müzik
    "spotify.com", "netflix.com", "youtu.be",
    // Ödeme & E-ticaret
    "paypal.com", "paypalobjects.com", "paypal-community.com",
    "aliexpress.com", "amazon.com", "amazon.com.tr",
    // Eğitim & İçerik
    "coursera.org", "udemy.com", "medium.com", "wikipedia.org",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    // AI
    "openai.com", "chatgpt.com"
  ],

  denylistedDomains: [
    "google-login-secure.com",
    "paypal-account-check.net",
    "microsoft-account-check.com"
  ],

  shortenerDomains: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "buff.ly"
  ],

  suspiciousWords: [
    "login", "verify", "secure", "account", "update", "confirm", "password",
    "bank", "wallet", "signin", "free", "gift", "card", "win", "bonus",
    "claim", "prize", "reset", "unlock", "payment", "suspend",
    "verification", "authorize", "authentication", "invoice", "download",
    "security", "support", "limited", "urgent", "alert"
  ],

  brandDomains: {
    google:    ["google.com", "googleapis.com", "gstatic.com", "withgoogle.com", "dl.google.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com", "microsoftonline.com", "office.com", "azure.com"],
    apple:     ["apple.com", "icloud.com"],
    paypal:    ["paypal.com", "paypalobjects.com", "paypal-community.com"],
    github:    ["github.com", "githubassets.com", "githubusercontent.com", "github.blog", "github.io"],
    linkedin:  ["linkedin.com"],
    facebook:  ["facebook.com", "fb.com", "fbcdn.net"],
    instagram: ["instagram.com"],
    twitter:   ["twitter.com", "x.com", "twimg.com"],
    whatsapp:  ["whatsapp.com", "wa.me"],
    amazon:    ["amazon.com", "amazon.com.tr", "amazon.co.uk", "amazon.de", "amazonaws.com"],
    netflix:   ["netflix.com"],
    spotify:   ["spotify.com"],
    discord:   ["discord.com", "discordapp.com"],
    openai:    ["openai.com", "chatgpt.com"]
  },

  thresholds: {
    safeMax: 5,
    lowMax: 15,
    suspiciousMax: 35
  }
};

function normalizeUrl(value) {
  const trimmedValue = value.trim();
  const url = new URL(trimmedValue);

  url.protocol = url.protocol.toLowerCase();
  url.hostname = url.hostname.toLowerCase();

  if (
    (url.protocol === "https:" && url.port === "443") ||
    (url.protocol === "http:" && url.port === "80")
  ) {
    url.port = "";
  }

  url.hash = "";

  if (!url.pathname) {
    url.pathname = "/";
  }

  url.pathname = url.pathname.replace(/\/{2,}/g, "/");

  const params = Array.from(url.searchParams.entries());
  params.sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));
  url.search = "";

  for (const [key, val] of params) {
    url.searchParams.append(key, val);
  }

  return url.toString();
}

function isValidUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isDomainMatch(hostname, domains) {
  return domains.some(domain => hostname === domain || hostname.endsWith("." + domain));
}

function isTrustedDomain(hostname) {
  return isDomainMatch(hostname, RULES.trustedDomains);
}

function isAllowlistedDomain(hostname) {
  return isDomainMatch(hostname, RULES.allowlistedDomains);
}

function isDenylistedDomain(hostname) {
  return isDomainMatch(hostname, RULES.denylistedDomains);
}

function isShortenerDomain(hostname) {
  return isDomainMatch(hostname, RULES.shortenerDomains);
}

function getSubdomainCount(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return 0;
  return parts.length - 2;
}

function isIpAddress(hostname) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return false;

  const parts = hostname.split(".").map(Number);
  return parts.every(part => part >= 0 && part <= 255);
}

function isPrivateIpAddress(hostname) {
  const lowerHostname = hostname.toLowerCase();

  if (lowerHostname === "localhost") return true;
  if (!isIpAddress(lowerHostname)) return false;

  const parts = lowerHostname.split(".").map(Number);

  if (parts[0] === 10) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

  return false;
}

function detectBrandSpoof(hostname) {
  const lowerHostname = hostname.toLowerCase();

  for (const [brand, officialDomains] of Object.entries(RULES.brandDomains)) {
    const hostnameParts = lowerHostname.split(/[^a-z0-9]+/).filter(Boolean);

    const mentionsBrand =
      hostnameParts.includes(brand) ||
      lowerHostname.includes(brand + "-") ||
      lowerHostname.includes("-" + brand) ||
      lowerHostname.includes(brand);

    if (!mentionsBrand) continue;

    const isOfficial = officialDomains.some(domain => {
      return lowerHostname === domain || lowerHostname.endsWith("." + domain);
    });

    if (!isOfficial) {
      return {
        isSpoof: true,
        brand: brand
      };
    }
  }

  return {
    isSpoof: false,
    brand: null
  };
}

// ─── Rule 1: Typosquatting Detection ────────────────────────────────────────
function levenshteinDistance(a, b) {
  const m = a.length, n = b.length;
  const dp = [];
  for (let i = 0; i <= m; i++) {
    dp[i] = new Array(n + 1).fill(0);
    dp[i][0] = i;
  }
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function detectTyposquatting(hostname) {
  const parts = hostname.split(".");
  if (parts.length < 2) return { isTyposquat: false };

  // Registrable domain kısmı (TLD hariç tüm parçalar)
  const domainBody = parts.slice(0, -1).join(".");
  // Token'lar: tire/nokta/alt çizgi ile bölünmüş ve ≥4 karakter olanlar
  const tokens = domainBody
    .split(/[-_.]+/)
    .filter(t => t.length >= 4)
    .map(t => t.toLowerCase());

  // Full domain body'yi de token olarak ekle (bölünmemiş versiyon)
  const fullToken = parts.slice(0, -1).join("").toLowerCase();
  if (fullToken.length >= 4 && !tokens.includes(fullToken)) {
    tokens.push(fullToken);
  }

  for (const entry of TYPOSQUAT_BRANDS) {
    const brand = entry.name;
    // Resmi domain ise typosquat değil
    const isOfficial = entry.official.some(
      d => hostname === d || hostname.endsWith("." + d)
    );
    if (isOfficial) continue;

    for (const token of tokens) {
      // Tam eşleşme zaten detectBrandSpoof kapsamında
      if (token === brand) continue;
      // Uzunluk farkı fazlaysa karşılaştırma anlamsız
      if (Math.abs(token.length - brand.length) > 2) continue;

      // Eşik: brand ≥8 karakter ise dist≤2, aksi halde dist≤1
      const threshold = brand.length >= 8 ? 2 : 1;
      const dist = levenshteinDistance(token, brand);

      if (dist > 0 && dist <= threshold) {
        return { isTyposquat: true, brand, token, distance: dist };
      }
    }
  }
  return { isTyposquat: false };
}

// ─── Rule 2: IDN / Punycode Homograph Attack Detection ──────────────────────
function detectIDNHomograph(hostname) {
  const parts = hostname.split(".");

  // xn-- prefix: Punycode encoded domain label
  if (parts.some(p => p.toLowerCase().startsWith("xn--"))) {
    return {
      isIDN: true,
      reason: "Punycode (xn--) kodlamalı domain etiketi tespit edildi."
    };
  }

  // Non-ASCII karakter: Kiril, Yunan veya diğer Unicode confusable'lar
  if (/[^\x00-\x7F]/.test(hostname)) {
    return {
      isIDN: true,
      reason: "Domain içinde ASCII olmayan (Kiril/Yunan/Unicode) karakter bulundu."
    };
  }

  // Görsel homoglyph: ASCII içinde bile sıkça kullanılan l/1/I karışımları
  // (ek sinyal — sadece şüpheli kelimelerle birlikte değerlendirmek için)
  const homoglyphPattern = /[0O]{2,}|[1lI]{3,}/;
  if (homoglyphPattern.test(hostname)) {
    return {
      isIDN: true,
      reason: "Görsel olarak yanıltıcı karakter dizisi (0/O veya 1/l/I karışımı) tespit edildi."
    };
  }

  return { isIDN: false };
}

// ─── Rule 3: Subdomain Takeover Göstergesi ──────────────────────────────────
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((acc, f) => {
    const p = f / str.length;
    return acc + p * Math.log2(p);
  }, 0);
}

const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function detectSubdomainTakeover(hostname, urlString) {
  const parts = hostname.split(".");
  if (parts.length < 3) return { isSuspicious: false };

  // Bilinen subdomain hosting servisi üzerinde rastgele subdomain?
  for (const hostingDomain of SUBDOMAIN_HOSTING_DOMAINS) {
    if (hostname.endsWith("." + hostingDomain)) {
      const subPart = hostname.slice(0, -(hostingDomain.length + 1));
      const firstLabel = subPart.split(".").pop() || "";
      const cleanLabel = firstLabel.replace(/[-_]/g, "");

      if (cleanLabel.length >= 8) {
        const entropy = shannonEntropy(cleanLabel);
        if (entropy >= 3.0) {
          return {
            isSuspicious: true,
            reason: `Bilinen hosting servisi (${hostingDomain}) üzerinde rastgele görünümlü subdomain.`,
            signal: "hosting_random_subdomain"
          };
        }
      }
      break;
    }
  }

  // UUID benzeri path + çok seviyeli subdomain → DGA / malware C2 göstergesi
  const subdomainCount = parts.length - 2;
  if (subdomainCount >= 2 && UUID_PATTERN.test(urlString)) {
    return {
      isSuspicious: true,
      reason: "Çok seviyeli subdomain yapısı ile UUID benzeri path bir arada tespit edildi.",
      signal: "dga_uuid_path"
    };
  }

  // Herhangi bir subdomain label'ı çok yüksek entropi → rastgele üretilmiş gibi
  const subLabels = parts.slice(0, -2);
  for (const label of subLabels) {
    const cleanLabel = label.replace(/[-_]/g, "");
    if (cleanLabel.length >= 8) {
      const entropy = shannonEntropy(cleanLabel);
      if (entropy >= 3.5) {
        return {
          isSuspicious: true,
          reason: `Yüksek entropi (${entropy.toFixed(2)}) subdomain label tespit edildi: "${label}" — DGA veya subdomain takeover olabilir.`,
          signal: "high_entropy_subdomain"
        };
      }
    }
  }

  return { isSuspicious: false };
}

function hasSuspiciousFileExtension(urlString) {
  const suspiciousExtensions = [
    ".exe", ".zip", ".rar", ".7z", ".msi", ".vbs", ".scr",
    ".apk", ".dll", ".bat", ".cmd", ".ps1", ".jar"
  ];

  const lowerUrl = urlString.toLowerCase();
  return suspiciousExtensions.some(ext => lowerUrl.includes(ext));
}

function hasEncodedCharacters(urlString) {
  return /%[0-9a-fA-F]{2}/.test(urlString);
}

function getPathDepth(urlString) {
  try {
    const url = new URL(urlString);
    return url.pathname.split("/").filter(Boolean).length;
  } catch {
    return 0;
  }
}

function hasUnusualPort(urlString) {
  try {
    const url = new URL(urlString);
    if (!url.port) return false;

    const port = Number(url.port);

    if (url.protocol === "http:" && port === 80) return false;
    if (url.protocol === "https:" && port === 443) return false;

    return true;
  } catch {
    return false;
  }
}

function countDigits(text) {
  return (text.match(/\d/g) || []).length;
}

function countHyphens(text) {
  return (text.match(/-/g) || []).length;
}

function getRiskyTld(hostname) {
  const riskyTlds = [
    "xyz", "top", "click", "shop", "online", "site",
    "live", "monster", "quest", "icu", "buzz", "rest"
  ];

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length === 0) return "";

  const tld = parts[parts.length - 1].toLowerCase();
  return riskyTlds.includes(tld) ? tld : "";
}

function hasRiskyQueryParam(urlString) {
  try {
    const url = new URL(urlString);
    const riskyParams = [
      "redirect", "url", "next", "continue", "dest", "destination",
      "return", "returnurl", "callback", "target", "goto", "to"
    ];

    for (const key of url.searchParams.keys()) {
      if (riskyParams.includes(key.toLowerCase())) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

function extractFeatures(urlString) {
  const url = new URL(urlString);
  const hostname = url.hostname.toLowerCase();
  const fullUrl = urlString.toLowerCase();

  return {
    hasHttps: url.protocol === "https:",
    isLongUrl: urlString.length > 75,
    hasAtSymbol: (() => {
      try {
        const u = new URL(urlString);
        return u.username !== "" || u.password !== "";
      } catch { return fullUrl.includes("@"); }
    })(),
    hasIpAddress: isIpAddress(hostname),
    isPrivateIp: isPrivateIpAddress(hostname),
    foundSuspiciousWords: RULES.suspiciousWords.filter(word => fullUrl.includes(word)),
    urlLength: urlString.length,
    hostname: hostname,
    isTrustedDomain: isTrustedDomain(hostname),
    isAllowlisted: isAllowlistedDomain(hostname),
    isDenylisted: isDenylistedDomain(hostname),
    isShortener: isShortenerDomain(hostname),
    subdomainCount: getSubdomainCount(hostname),
    brandSpoof: detectBrandSpoof(hostname),
    typosquat: detectTyposquatting(hostname),
    idnHomograph: detectIDNHomograph(hostname),
    subdomainTakeover: detectSubdomainTakeover(hostname, urlString),
    pathDepth: getPathDepth(urlString),
    hasEncodedChars: hasEncodedCharacters(urlString),
    hasSuspiciousExtension: hasSuspiciousFileExtension(urlString),
    hasUnusualPort: hasUnusualPort(urlString),
    digitCount: countDigits(hostname),
    hyphenCount: countHyphens(hostname),
    riskyTld: getRiskyTld(hostname),
    hasRiskyQueryParam: hasRiskyQueryParam(urlString)
  };
}

function analyzeUrl(urlString) {
  const normalizedUrl = normalizeUrl(urlString);
  const features = extractFeatures(normalizedUrl);

  let riskScore = 0;
  const reasons = [];

  if (features.isDenylisted) {
    return {
      normalizedUrl,
      riskScore: 100,
      level: "Yüksek risk",
      reasons: ["Bu alan adı denylist içinde yer alıyor."],
      features
    };
  }

  if (features.isPrivateIp) {
    if (!features.hasHttps) {
      riskScore += 5;
      reasons.push("Yerel ağ adresi HTTPS kullanmıyor.");
    }

    if (features.hasIpAddress) {
      riskScore += 5;
      reasons.push("Yerel/özel IP adresi kullanılıyor.");
    } else {
      reasons.push("Yerel geliştirme adresi kullanılıyor.");
    }

    if (features.hasUnusualPort) {
      reasons.push("Yerel adreste standart dışı port kullanılıyor; bu tek başına zararlı kabul edilmedi.");
    }

    if (features.foundSuspiciousWords.length > 0) {
      reasons.push(
        "Yerel ağ adresinde giriş/doğrulama ifadesi bulundu; modem, router veya geliştirme paneli olabileceği için risk sınırlı tutuldu: " +
        features.foundSuspiciousWords.join(", ")
      );
    }

    if (riskScore < 0) riskScore = 0;
    if (riskScore > 100) riskScore = 100;

    return {
      normalizedUrl,
      riskScore,
      level: riskScore <= 10 ? "Yerel ağ adresi" : "Düşük risk",
      reasons: reasons.length ? reasons : ["Yerel ağ/geliştirme adresi olarak değerlendirildi."],
      features
    };
  }

  if (features.isAllowlisted) {
    riskScore -= 5;
    reasons.push("Alan adı allowlist içinde yer alıyor.");
  }

  if (!features.hasHttps) {
    riskScore += 18;
    reasons.push("HTTPS kullanmıyor.");
  }

  if (features.isLongUrl) {
    riskScore += 12;
    reasons.push("URL normalden uzun.");
  }

  if (features.hasAtSymbol) {
    riskScore += 35;
    reasons.push("URL içinde @ işareti var.");
  }

  if (features.hasIpAddress) {
    riskScore += 40;
    reasons.push("Alan adı yerine genel IP adresi kullanılıyor.");
  }

  if (features.hasSuspiciousExtension) {
    if (features.isAllowlisted) {
      riskScore += 8;
      reasons.push("Yürütülebilir dosya uzantısı bulundu — güvenilir kaynaktan indirme.");
    } else {
      riskScore += 40;
      reasons.push("Şüpheli dosya uzantısı bulundu.");
    }
  }

  if (features.hasEncodedChars) {
    riskScore += 12;
    reasons.push("Encoded karakterler içeriyor.");
  }

  if (features.pathDepth >= 4) {
    riskScore += 14;
    reasons.push("URL path yapısı aşırı derin.");
  }

  if (features.hasUnusualPort) {
    riskScore += 22;
    reasons.push("Standart dışı port kullanılıyor.");
  }

  if (features.digitCount >= 5) {
    riskScore += 10;
    reasons.push("Alan adında fazla sayıda rakam var.");
  }

  if (features.hyphenCount >= 3) {
    riskScore += 12;
    reasons.push("Alan adında fazla tire kullanımı var.");
  }

  if (features.riskyTld) {
    riskScore += 12;
    reasons.push(`Riskli veya sık suistimal edilen üst alan adı kullanılıyor: .${features.riskyTld}`);
  }

  if (features.hasRiskyQueryParam) {
    riskScore += 20;
    reasons.push("Şüpheli yönlendirme parametresi içeriyor.");
  }

  if (features.isShortener) {
    riskScore += 25;
    reasons.push("Kısa link servisi kullanılıyor. Gerçek hedef adres gizlenmiş olabilir.");
  }

  if (features.subdomainCount >= 3) {
    riskScore += 18;
    reasons.push("Alışılmadık derecede fazla alt alan adı kullanılıyor.");
  }

  if (features.brandSpoof.isSpoof) {
    riskScore += 40;
    reasons.push("Alan adı resmi görünmeden marka taklidi izlenimi veriyor: " + features.brandSpoof.brand);
  }

  // ── Yeni Kural 1: Typosquatting ─────────────────────────────────────────
  if (features.typosquat.isTyposquat && !features.brandSpoof.isSpoof) {
    const scoreAdd = features.typosquat.distance === 1 ? 30 : 20;
    riskScore += scoreAdd;
    reasons.push(
      `Typosquatting: "${features.typosquat.token}" → "${features.typosquat.brand}" ` +
      `(edit distance: ${features.typosquat.distance}).`
    );
  }

  // ── Yeni Kural 2: IDN / Punycode Homograph ───────────────────────────────
  if (features.idnHomograph.isIDN) {
    riskScore += 35;
    reasons.push("IDN/Homograph saldırısı: " + features.idnHomograph.reason);
  }

  // ── Yeni Kural 3: Subdomain Takeover / DGA ───────────────────────────────
  if (features.subdomainTakeover.isSuspicious) {
    riskScore += 20;
    reasons.push("Subdomain takeover / DGA göstergesi: " + features.subdomainTakeover.reason);
  }

  const hasOtherRiskSignals =
    !features.hasHttps ||
    features.isLongUrl ||
    features.hasAtSymbol ||
    (features.hasIpAddress && !features.isPrivateIp) ||
    features.isShortener ||
    features.subdomainCount >= 3 ||
    features.brandSpoof.isSpoof ||
    features.hasRiskyQueryParam ||
    features.hasSuspiciousExtension ||
    features.riskyTld;

  if (features.foundSuspiciousWords.length > 0) {
    if (hasOtherRiskSignals) {
      riskScore += 15;
      reasons.push("Şüpheli kelimeler diğer risk işaretleriyle birlikte bulundu: " + features.foundSuspiciousWords.join(", "));
    } else if (!features.isTrustedDomain) {
      riskScore += 12;
      reasons.push("Güvenilir olmayan alan adında dikkat gerektiren kelimeler bulundu: " + features.foundSuspiciousWords.join(", "));
    } else {
      reasons.push("Dikkat gerektiren kelimeler bulundu ancak alan adı güvenilir olduğu için sınırlı risk uygulandı: " + features.foundSuspiciousWords.join(", "));
    }
  }

  if (
    features.brandSpoof.isSpoof &&
    features.foundSuspiciousWords.includes("login")
  ) {
    riskScore += 20;
    reasons.push("Marka taklidi + login kombinasyonu tespit edildi.");
  }

  if (
    features.isShortener &&
    features.hasRiskyQueryParam
  ) {
    riskScore += 25;
    reasons.push("Kısa link + yönlendirme parametresi birlikte bulundu.");
  }

  if (
    riskScore > 20 &&
    features.foundSuspiciousWords.length >= 2 &&
    !features.isTrustedDomain
  ) {
    riskScore += 10;
    reasons.push("Birden fazla şüpheli sinyal bulundu, risk artırıldı.");
  }

  if (
    features.foundSuspiciousWords.includes("login") &&
    !features.isTrustedDomain
  ) {
    riskScore += 15;
    reasons.push("Güvenilir olmayan domain üzerinde login ifadesi bulundu.");
  }

  if (
    features.foundSuspiciousWords.includes("download") &&
    features.hasSuspiciousExtension
  ) {
    riskScore += 15;
    reasons.push("Download ifadesi ve şüpheli dosya uzantısı birlikte bulundu.");
  }

  // Güvenilir domain'lerde URL parametresi / uzunluk kuralları FP üretir;
  // domain doğrulandıktan sonra skoru 5 ile sınırla.
  if (features.isTrustedDomain && riskScore > 5) {
    riskScore = 5;
  }

  if (riskScore < 0) riskScore = 0;
  if (riskScore > 100) riskScore = 100;

  let level;

  if (riskScore <= RULES.thresholds.safeMax) {
    level = "Güvenli görünüyor";
  } else if (riskScore <= RULES.thresholds.lowMax) {
    level = "Düşük risk";
  } else if (riskScore <= RULES.thresholds.suspiciousMax) {
    level = "Şüpheli";
  } else {
    level = "Yüksek risk";
  }

  const threatAssessment = assessThreat(features, riskScore);

  return {
    normalizedUrl,
    riskScore,
    level,
    reasons: reasons.length ? reasons : ["Belirgin bir risk işareti bulunmadı."],
    features,
    threatAssessment
  };
}

// ─── Tehdit Profili: kullanıcıya ne olabilir? ────────────────────────────────
function assessThreat(features, riskScore) {
  let threatType   = "unknown";
  let threatLabel  = "Analiz Edildi";
  let threatIcon   = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;
  let severity     = "low";
  let confidence   = 20;
  const impacts    = [];
  const actions    = [];

  // ── 1. Kara liste ──────────────────────────────────────────────────────────
  if (features.isDenylisted) {
    threatType  = "blacklisted";
    threatLabel = "Kara Listede Kayıtlı";
    threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
    severity    = "critical";
    confidence  = 100;
    impacts.push("Bu alan adı zararlı içerik barındırdığı için kara listeye alınmış.");
    impacts.push("Giriş yaptığınızda şifreniz, kredi kartı bilgileriniz veya kimliğiniz çalınabilir.");
    impacts.push("Cihazınıza fark etmeden kötü amaçlı yazılım yüklenebilir.");
    actions.push("Bu siteye kesinlikle gitmeyin.");
    actions.push("Linki size gönderen kişiyi ya da kaynağı uyarın.");
    actions.push("Bu adresi tarayıcı geçmişinizden ve yer imlerinizden silin.");
    return { threatType, threatLabel, threatIcon, severity, confidence, impacts, actions };
  }

  // ── 2. IDN / Punycode Homograph ────────────────────────────────────────────
  if (features.idnHomograph && features.idnHomograph.isIDN) {
    threatType  = "homograph";
    threatLabel = "Görsel Aldatmaca Saldırısı";
    threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    severity    = "high";
    confidence  = Math.max(confidence, 82);
    impacts.push("Alan adı, tanıdık bir markaya görsel olarak birebir benziyor — ama farklı harfler kullanıyor.");
    impacts.push("Adres çubuğuna bakarak fark etmek neredeyse imkânsız.");
    impacts.push("Sahte sayfada girilen her bilgi saldırganların eline geçer.");
    actions.push("Adres çubuğundaki her karakteri tek tek inceleyin.");
    actions.push("Adresi elle yazmak yerine resmi siteni yer imlerinizden açın.");
  }

  // ── 3. Marka taklidi (Brand Spoof) ─────────────────────────────────────────
  if (features.brandSpoof && features.brandSpoof.isSpoof) {
    const brand = features.brandSpoof.brand;
    threatType  = "phishing_brand";
    threatLabel = "Marka Sahtekarlığı (Phishing)";
    threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    severity    = "critical";
    confidence  = Math.max(confidence, 88);
    impacts.push(`Bu site ${brand ? '"' + brand + '"' : "tanınan bir marka"} gibi görünerek sizi kandırmaya çalışıyor.`);
    impacts.push("Kullanıcı adı, şifre veya ödeme bilgileriniz doğrudan saldırganlara iletilir.");
    impacts.push("Hesabınız ele geçirilerek başkalarına zararlı mesaj gönderilebilir veya mali kayıp yaşatılabilir.");
    if (!actions.some(a => a.includes("gitmeyin"))) actions.push("Bu siteye girmeyin, hiçbir bilgi girmeyin.");
    actions.push(`Resmi ${brand || "marka"} sitesini adres çubuğuna elle yazarak veya yer iminizden açın.`);
    actions.push("Eğer bilgi girdiyseniz şifrenizi hemen değiştirin ve iki faktörlü doğrulamayı açın.");
  }

  // ── 4. Typosquatting ───────────────────────────────────────────────────────
  if (features.typosquat && features.typosquat.isTyposquat && threatType === "unknown") {
    const brand = features.typosquat.brand;
    threatType  = "typosquat";
    threatLabel = "Yazım Hatası Tuzağı";
    threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    severity    = "high";
    confidence  = Math.max(confidence, features.typosquat.distance === 1 ? 78 : 62);
    impacts.push(`"${features.typosquat.token}" adresi, resmi "${brand}" sitesine çok benziyor — bir harf farkı var.`);
    impacts.push("Yanlışlıkla bu adrese gittiğinizde sahte giriş ekranıyla karşılaşabilirsiniz.");
    impacts.push("Girdiğiniz şifre ve kişisel bilgiler çalınabilir.");
    if (!actions.some(a => a.includes("gitmeyin"))) actions.push("Bu siteye girmeyin.");
    actions.push(`Resmi adres: ${brand ? brand + ".com" : "orijinal site"} — adres çubuğuna elle yazın.`);
  }

  // ── 5. DGA / Subdomain Takeover ───────────────────────────────────────────
  if (features.subdomainTakeover && features.subdomainTakeover.isSuspicious) {
    if (threatType === "unknown" || severity === "low") {
      threatType  = "malware_c2";
      threatLabel = "Zararlı Yazılım Dağıtım Ağı";
      threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`;
      severity    = "high";
    }
    confidence = Math.max(confidence, 74);
    impacts.push("Bu URL, otomatik oluşturulan (DGA) veya ele geçirilmiş bir subdomain kullanıyor — yaygın bir zararlı yazılım dağıtım yöntemi.");
    impacts.push("Sayfayı açmanız bile bazı durumlarda cihazınıza kötü amaçlı kod yükleyebilir.");
    impacts.push("Cihazınız bir saldırı ağına (botnet) dahil edilebilir, verileriniz şifrelenebilir (fidye yazılımı).");
    if (!actions.some(a => a.includes("gitmeyin"))) actions.push("Bu siteye gitmeyin.");
    actions.push("Antivirüs yazılımınızın güncel olduğundan emin olun.");
    actions.push("Bu URL'e tıkladıysanız cihazınızda tam tarama başlatın.");
  }

  // ── 6. Zararlı dosya indirme ──────────────────────────────────────────────
  if (features.hasSuspiciousExtension && !features.isAllowlisted) {
    if (threatType === "unknown") {
      threatType  = "malware_download";
      threatLabel = "Zararlı Dosya İndirme Riski";
      threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;
      severity    = "high";
    }
    confidence = Math.max(confidence, 68);
    impacts.push("Bu link doğrudan yürütülebilir bir dosya (.exe, .msi, .apk vb.) indirtiyor.");
    impacts.push("Dosya cihazınıza virüs, casus yazılım veya fidye yazılımı yükleyebilir.");
    impacts.push("Yüklenen program uzaktan kontrol yazılımı içerebilir — cihazınız ele geçirilebilir.");
    if (!actions.some(a => a.includes("İndirmeyin"))) actions.push("Bu linkten dosya indirmeyin.");
    actions.push("Dosyayı indirmeden önce virustotal.com adresinde taratın.");
    actions.push("Dosyayı sadece resmi kaynaklardan (üretici sitesi) indirin.");
  }

  // ── 7. IP adresi (raw sunucu) ──────────────────────────────────────────────
  if (features.hasIpAddress && !features.isPrivateIp) {
    if (threatType === "unknown") {
      threatType  = "ip_server";
      threatLabel = "Şüpheli Sunucu Bağlantısı";
      threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><circle cx="6" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="6" cy="18" r="1" fill="currentColor" stroke="none"/></svg>`;
      severity    = "medium";
    }
    confidence = Math.max(confidence, 55);
    impacts.push("Meşru web siteleri alan adı kullanır; ham IP adresleri çoğunlukla geçici saldırı altyapısıdır.");
    impacts.push("Sunucu konumu ve sahibi doğrulanamaz — bilgileriniz güvende olmayabilir.");
    if (!actions.some(a => a.includes("gitmeyin") || a.includes("İndirmeyin")))
      actions.push("Ham IP adresi içeren bilinmeyen linklere tıklamaktan kaçının.");
  }

  // ── 8. Kısa link ──────────────────────────────────────────────────────────
  if (features.isShortener) {
    if (threatType === "unknown") {
      threatType  = "obfuscated";
      threatLabel = "Hedefi Gizlenmiş Bağlantı";
      threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>`;
      severity    = "medium";
    }
    confidence = Math.max(confidence, 40);
    impacts.push("Kısa link gerçek hedefi gizler — nereye gittiğinizi tıklamadan bilemezsiniz.");
    impacts.push("Zararlı bir siteye, kimlik avı sayfasına veya kötü amaçlı dosyaya yönlendirilebilirsiniz.");
    if (!actions.some(a => a.includes("kontrol")))
      actions.push("checkshorturl.com veya unshorten.it gibi araçlarla önce kontrol edin.");
  }

  // ── 9. Açık yönlendirme ───────────────────────────────────────────────────
  if (features.hasRiskyQueryParam && threatType === "unknown") {
    threatType  = "open_redirect";
    threatLabel = "Açık Yönlendirme Tuzağı";
    threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 10 20 15 15 20"/><path d="M4 4v7a4 4 0 004 4h12"/></svg>`;
    severity    = "medium";
    confidence  = Math.max(confidence, 48);
    impacts.push("URL sizi, adresin göründüğünden tamamen farklı bir siteye yönlendirebilir.");
    impacts.push("Güvenilir bir sitenin adresi üzerinden sahte sayfaya taşınabilirsiniz.");
    actions.push("Final hedef adresini görmeden bu linke tıklamayın.");
  }

  // ── 10. Şüpheli kelimeler (düşük risk, tek başına) ─────────────────────────
  if (features.foundSuspiciousWords.length > 0 && threatType === "unknown" && riskScore > 10) {
    threatType  = "suspicious_content";
    threatLabel = "Dikkat Gerektiren İçerik";
    threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    severity    = "low";
    confidence  = Math.max(confidence, 30);
    impacts.push("URL'de dolandırıcılık veya kimlik avıyla ilişkili ifadeler tespit edildi.");
    impacts.push("Site gerçek olmayan teklifler, sahte ödüller veya yanıltıcı içerik barındırıyor olabilir.");
    actions.push("Siteyi kimin gönderdiğini doğrulayın, acele etmeyin.");
    actions.push("Kişisel ya da finansal bilgi girmeden önce iki kez düşünün.");
  }

  // ── 11. Güvenli ───────────────────────────────────────────────────────────
  if (threatType === "unknown") {
    if (features.isTrustedDomain) {
      threatType  = "safe_trusted";
      threatLabel = "Güvenilir Alan Adı";
      threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;
      severity    = "safe";
      confidence  = 95;
      impacts.push("Bu alan adı bilinen ve güvenilir bir kaynak olarak tanınıyor.");
      impacts.push("Herhangi bir risk sinyali tespit edilmedi.");
      actions.push("Normal şekilde kullanabilirsiniz.");
      actions.push("Yine de şifrelerinizi güçlü tutun ve iki faktörlü doğrulamayı açık bırakın.");
    } else {
      threatType  = "low_risk";
      threatLabel = "Belirgin Tehdit Tespit Edilmedi";
      threatIcon  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
      severity    = "low";
      confidence  = 65;
      impacts.push("Bilinen bir saldırı kalıbıyla eşleşme bulunamadı.");
      impacts.push("Bu, sitenin %100 güvenli olduğu anlamına gelmez — statik analiz sınırlıdır.");
      actions.push("Kişisel bilgi girecekseniz adres çubuğundaki kilide tıklayarak sertifikayı kontrol edin.");
      actions.push("Siteye yönlendiren kaynağın güvenilirliğini doğrulayın.");
    }
  }

  // Duplikatları temizle
  const uniqueImpacts = [...new Set(impacts)];
  const uniqueActions = [...new Set(actions)];

  return { threatType, threatLabel, threatIcon, severity, confidence,
           impacts: uniqueImpacts, actions: uniqueActions };
}

if (typeof module !== "undefined") {
  module.exports = {
    analyzeUrl,
    normalizeUrl,
    isValidUrl,
    assessThreat
  };
}
