from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

app = FastAPI(title="SafeLinker Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DomainRequest(BaseModel):
    domain: str


class UrlRequest(BaseModel):
    url: str


def is_domain_match(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


def is_ip_address(hostname: str) -> bool:
    parts = hostname.split(".")
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def is_private_or_local_host(hostname: str) -> bool:
    hostname = (hostname or "").lower()

    if hostname == "localhost":
        return True

    if not is_ip_address(hostname):
        return False

    parts = [int(part) for part in hostname.split(".")]

    if parts[0] == 10:
        return True
    if parts[0] == 127:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True

    return False


KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "instagram", "netflix", "twitter", "ebay",
]

SHORTENER_HOSTS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly",
]

LOGIN_WORDS = ["login", "verify", "account", "signin", "password", "secure", "auth", "confirm"]

RISKY_EXTENSIONS = [".exe", ".zip", ".rar", ".7z", ".apk", ".dll", ".bat", ".cmd", ".msi"]


def explain_url_risk(url: str):
    lower_url = url.lower()
    parsed = urlparse(lower_url)
    hostname = (parsed.hostname or "").lower()
    full_path = (parsed.path or "").lower()

    has_ip       = is_ip_address(hostname)
    has_shortener = any(is_domain_match(hostname, s) for s in SHORTENER_HOSTS)
    has_file_ext  = any(lower_url.endswith(ext) or (ext + "?") in lower_url for ext in RISKY_EXTENSIONS)
    has_login     = any(w in lower_url for w in LOGIN_WORDS)
    has_no_https  = not lower_url.startswith("https://")

    matched_brand = next(
        (b for b in KNOWN_BRANDS if b in hostname or b in full_path),
        None
    )

    if has_ip and has_login:
        return {
            "possible_purpose": "IP adresli geçici sunucu üzerinden sahte giriş ekranı gösterme",
            "possible_risk": "Kullanıcı adı ve şifreniz doğrudan saldırganların sunucusuna iletilir; hesabınız ele geçirilebilir.",
            "analysis_summary": "Ham IP adresi ile giriş/doğrulama ifadelerinin birlikteliği phishing altyapısına işaret ediyor.",
        }

    if matched_brand and has_ip:
        return {
            "possible_purpose": f"'{matched_brand}' markasını taklit eden sahte sayfa (IP sunucu üzerinde)",
            "possible_risk": f"Sahte {matched_brand} sayfasına girilen tüm bilgiler (şifre, kart numarası) çalınır.",
            "analysis_summary": f"Tanınan marka adı ({matched_brand}) ham IP adresiyle birlikte kullanılmış — güçlü phishing sinyali.",
        }

    if matched_brand:
        return {
            "possible_purpose": f"'{matched_brand}' markasını taklit ederek kullanıcı bilgisi toplama",
            "possible_risk": f"Sahte {matched_brand} giriş ekranında şifrenizi veya ödeme bilgilerinizi girmeniz sağlanabilir.",
            "analysis_summary": f"URL'de tanınan marka adı ({matched_brand}) tespit edildi; resmi site olup olmadığı doğrulanmalı.",
        }

    if has_shortener:
        return {
            "possible_purpose": "Gerçek hedef adresi gizleyerek yönlendirme",
            "possible_risk": "Zararlı bir siteye, kimlik avı sayfasına veya kötü amaçlı dosyaya yönlendirilebilirsiniz.",
            "analysis_summary": "Kısa link servisi gerçek hedef adresi gizliyor; tıklamadan önce genişletilmesi önerilir.",
        }

    if has_file_ext:
        return {
            "possible_purpose": "Kullanıcının cihazına yürütülebilir dosya indirtme",
            "possible_risk": "İndirilen dosya virüs, casus yazılım veya fidye yazılımı içerebilir; cihazınız uzaktan kontrol edilebilir.",
            "analysis_summary": "URL doğrudan çalıştırılabilir dosya uzantısıyla bitiyor.",
        }

    if has_ip:
        return {
            "possible_purpose": "Geçici saldırı sunucusuna bağlantı kurma",
            "possible_risk": "Sunucunun sahibi doğrulanamaz; iletişimleriniz izlenebilir veya kişisel verileriniz ele geçirilebilir.",
            "analysis_summary": "Meşru web siteleri alan adı kullanır; ham IP adresi geçici saldırı altyapısının işareti olabilir.",
        }

    if has_login and has_no_https:
        return {
            "possible_purpose": "Şifrelenmemiş kanal üzerinden kimlik bilgisi toplama",
            "possible_risk": "HTTP üzerinden gönderilen giriş bilgileri ağ trafiği dinlenerek (man-in-the-middle) ele geçirilebilir.",
            "analysis_summary": "Şifresiz bağlantı (HTTP) ve giriş ifadelerinin birlikteliği risk oluşturuyor.",
        }

    if has_login:
        return {
            "possible_purpose": "Kullanıcıdan giriş veya doğrulama bilgisi isteme",
            "possible_risk": "Sayfa sahte ise hesap bilgileriniz (kullanıcı adı, şifre) ele geçirilebilir.",
            "analysis_summary": "URL'de giriş veya doğrulama çağrıştıran ifadeler bulundu.",
        }

    return {
        "possible_purpose": "Amacı URL yapısından kesin olarak belirlenemedi.",
        "possible_risk": "Yeterli sinyal olmadığı için dikkatli olunması önerilir.",
        "analysis_summary": "URL yapısı, reputation sonucu ve yönlendirme kontrolü birlikte değerlendirilmiştir.",
    }


def resolve_redirect_chain(url: str):
    original_url = url.strip()
    chain = []
    final_url = original_url
    error = None
    technical_error = None
    user_message = None

    parsed_original = urlparse(original_url)
    hostname = (parsed_original.hostname or "").lower()

    if is_private_or_local_host(hostname):
        return {
            "original_url": original_url,
            "final_url": original_url,
            "has_redirect": False,
            "redirect_count": 0,
            "chain": [],
            "error": None,
            "technical_error": None,
            "user_message": "Yerel ağ/geliştirme adreslerinde yönlendirme kontrolü atlandı.",
            "checked_at": datetime.now(timezone.utc).isoformat()
        }

    headers = {
        "User-Agent": "SafeLinker/1.0 URL Security Research Prototype"
    }

    try:
        response = requests.get(
            original_url,
            headers=headers,
            allow_redirects=True,
            timeout=6,
            verify=True,
            stream=True
        )

        for item in response.history:
            chain.append({
                "status_code": item.status_code,
                "url": item.url,
                "location": item.headers.get("location", "")
            })

        final_url = response.url
        response.close()

    except requests.exceptions.SSLError as exc:
        error = "redirect_check_failed"
        technical_error = str(exc)
        user_message = "SSL doğrulama hatası nedeniyle yönlendirme zinciri çözümlenemedi. Bu durum nihai risk kararını engellemez."
    except requests.exceptions.Timeout as exc:
        error = "redirect_check_failed"
        technical_error = str(exc)
        user_message = "Yönlendirme kontrolü zaman aşımına uğradı. Bu durum nihai risk kararını engellemez."
    except requests.exceptions.TooManyRedirects as exc:
        error = "too_many_redirects"
        technical_error = str(exc)
        user_message = "Çok fazla yönlendirme tespit edildi. Bu durum ek risk sinyali olarak değerlendirilebilir."
    except requests.exceptions.RequestException as exc:
        error = "redirect_check_failed"
        technical_error = str(exc)
        user_message = "Yönlendirme kontrolü tamamlanamadı. URL çözümlenemiyor veya erişilebilir değil. Bu durum nihai risk kararını engellemez."

    has_redirect = len(chain) > 0 or final_url != original_url

    return {
        "original_url": original_url,
        "final_url": final_url,
        "has_redirect": has_redirect,
        "redirect_count": len(chain),
        "chain": chain,
        "error": error,
        "technical_error": technical_error,
        "user_message": user_message,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }


@app.get("/")
def root():
    return {"message": "SafeLinker backend çalışıyor."}


@app.post("/api/domain-age")
def get_domain_age(data: DomainRequest):
    domain = data.domain.strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    fake_ages = {
        "google.com": 8000,
        "github.com": 6000,
        "openai.com": 3000,
        "chatgpt.com": 2000
    }

    age_days = fake_ages.get(domain, 120)

    if age_days < 30:
        risk_note = "Alan adı çok yeni."
    elif age_days < 180:
        risk_note = "Alan adı nispeten yeni."
    else:
        risk_note = "Alan adı yaşı normal görünüyor."

    return {
        "domain": domain,
        "age_days": age_days,
        "risk_note": risk_note,
        "checked_at": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/reputation")
def get_reputation(data: UrlRequest):
    url = data.url.strip()
    lower_url = url.lower()
    parsed = urlparse(lower_url)
    hostname = (parsed.hostname or "").lower()

    explanation = explain_url_risk(lower_url)

    denylisted_domains = [
        "google-login-secure.com",
        "paypal-account-check.net",
        "microsoft-account-check.com"
    ]

    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "cutt.ly",
        "ow.ly",
        "rb.gy",
        "shorturl.at",
        "rebrand.ly",
        "t.ly",
        "buff.ly"
    ]

    allowlisted_domains = [
        "google.com",
        "github.com",
        "chatgpt.com",
        "openai.com",
        "youtube.com",
        "microsoft.com",
        "apple.com",
        "linkedin.com",
        "wikipedia.org"
    ]

    if any(is_domain_match(hostname, domain) for domain in denylisted_domains):
        return {
            "url": lower_url,
            "reputation_level": "high_risk",
            "malicious": 8,
            "suspicious": 2,
            "harmless": 0,
            "note": "Bu URL için güçlü zararlı sinyal bulundu.",
            "possible_purpose": explanation["possible_purpose"],
            "possible_risk": explanation["possible_risk"],
            "analysis_summary": explanation["analysis_summary"]
        }

    if any(is_domain_match(hostname, domain) for domain in shortener_domains):
        return {
            "url": lower_url,
            "reputation_level": "suspicious",
            "malicious": 1,
            "suspicious": 3,
            "harmless": 0,
            "note": "Kısa link servisi nedeniyle ek inceleme önerilir.",
            "possible_purpose": explanation["possible_purpose"],
            "possible_risk": explanation["possible_risk"],
            "analysis_summary": explanation["analysis_summary"]
        }

    if any(is_domain_match(hostname, domain) for domain in allowlisted_domains):
        return {
            "url": lower_url,
            "reputation_level": "clean",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 10,
            "note": "Bilinen zararlı sinyal bulunmadı.",
            "possible_purpose": explanation["possible_purpose"],
            "possible_risk": explanation["possible_risk"],
            "analysis_summary": explanation["analysis_summary"]
        }

    return {
        "url": lower_url,
        "reputation_level": "unknown",
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "note": "Yeterli reputation verisi bulunamadı.",
        "possible_purpose": explanation["possible_purpose"],
        "possible_risk": explanation["possible_risk"],
        "analysis_summary": explanation["analysis_summary"]
    }


@app.post("/api/redirect-check")
def redirect_check(data: UrlRequest):
    url = data.url.strip()

    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]:
        return {
            "original_url": url,
            "final_url": url,
            "has_redirect": False,
            "redirect_count": 0,
            "chain": [],
            "error": "unsupported_scheme",
            "technical_error": "Sadece http/https URL'leri desteklenir.",
            "user_message": "Sadece http/https URL'leri için yönlendirme kontrolü yapılabilir.",
            "checked_at": datetime.now(timezone.utc).isoformat()
        }

    return resolve_redirect_chain(url)


