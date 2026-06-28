import csv
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

INPUT_FILE = PROJECT_DIR / "data" / "evaluation_dataset.csv"
if not INPUT_FILE.exists():
    INPUT_FILE = PROJECT_DIR / "evaluation_dataset.csv"

OUTPUT_FILE = PROJECT_DIR / "evaluation_results_deep.csv"

ANALYZE_SCRIPT = PROJECT_DIR / "extension" / "analyze.js"
BACKEND_REPUTATION_URL = "http://127.0.0.1:8010/api/reputation"
BACKEND_REDIRECT_URL = "http://127.0.0.1:8010/api/redirect-check"

SHORTENER_DOMAINS = {
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
}

RISKY_QUERY_PARAMS = {
    "redirect",
    "url",
    "next",
    "continue",
    "dest",
    "destination",
    "return",
    "returnurl",
    "callback",
    "target",
    "goto",
    "to"
}


def post_json(url: str, payload: dict, timeout: int = 8):
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw)


def analyze_with_js(url: str):
    if not ANALYZE_SCRIPT.exists():
        raise FileNotFoundError(f"analyze.js bulunamadı: {ANALYZE_SCRIPT}")

    result = subprocess.run(
        ["node", str(ANALYZE_SCRIPT), url],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )

    if result.returncode != 0:
        raise RuntimeError(f"Node analiz hatası: {result.stderr.strip()}")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError("Node analiz çıktısı boş döndü.")

    return json.loads(stdout)


def hostname_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_domain_match(hostname: str, domain: str) -> bool:
    return hostname == domain or hostname.endswith("." + domain)


def is_shortener_url(url: str) -> bool:
    hostname = hostname_of(url)
    return any(is_domain_match(hostname, domain) for domain in SHORTENER_DOMAINS)


def has_risky_query_param(url: str) -> bool:
    try:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        return any(key.lower() in RISKY_QUERY_PARAMS for key, _ in params)
    except Exception:
        return False


def should_check_redirect(url: str) -> bool:
    """
    Güvenlik ve hız için her URL'de network isteği yapmıyoruz.
    Sadece kısa link veya açık yönlendirme parametresi içeren URL'lerde redirect analizi yapılır.
    """
    return is_shortener_url(url) or has_risky_query_param(url)


def normalize_level(level: str) -> str:
    if not level:
        return "Bilinmiyor"

    lowered = level.lower()

    if "yüksek" in lowered:
        return "Yüksek risk"
    if "şüpheli" in lowered:
        return "Şüpheli"
    if "düşük" in lowered:
        return "Düşük risk"
    if "yerel" in lowered:
        return "Yerel ağ adresi"
    if "güvenli" in lowered:
        return "Güvenli görünüyor"

    return level


def level_from_score(score: int, is_private_ip: bool = False) -> str:
    if is_private_ip and score <= 10:
        return "Yerel ağ adresi"
    if score <= 5:
        return "Güvenli görünüyor"
    if score <= 15:
        return "Düşük risk"
    if score <= 35:
        return "Şüpheli"
    return "Yüksek risk"


def apply_reputation_signal(base_result: dict, reputation_data: dict):
    score = int(base_result.get("riskScore", 0))
    reasons = list(base_result.get("reasons", []))

    reputation_level = reputation_data.get("reputation_level", "unknown")

    if reputation_level == "high_risk":
        score += 35
        reasons.append("Deep evaluation: reputation yüksek risk sinyali verdi.")
    elif reputation_level == "suspicious":
        score += 20
        reasons.append("Deep evaluation: reputation şüpheli sinyal verdi.")
    elif reputation_level == "clean":
        reasons.append("Deep evaluation: reputation temiz sinyal verdi.")
    else:
        reasons.append("Deep evaluation: reputation verisi bulunamadı.")

    score = max(0, min(score, 100))

    features = base_result.get("features", {})
    level = level_from_score(score, bool(features.get("isPrivateIp", False)))

    if reputation_level == "high_risk":
        level = "Yüksek risk"
    elif reputation_level == "suspicious" and level in ["Güvenli görünüyor", "Düşük risk"]:
        level = "Şüpheli"

    return score, level, reasons, reputation_level


def apply_redirect_signal(original_url: str, current_score: int, current_level: str, current_reasons: list):
    redirect_checked = False
    redirect_error = ""
    has_redirect = False
    redirect_count = 0
    final_url = ""
    final_level = ""
    final_score = ""
    final_domain_changed = False

    score = current_score
    level = current_level
    reasons = list(current_reasons)

    if not should_check_redirect(original_url):
        return {
            "risk_score": score,
            "level": level,
            "reasons": reasons,
            "redirect_checked": redirect_checked,
            "redirect_error": redirect_error,
            "has_redirect": has_redirect,
            "redirect_count": redirect_count,
            "final_url": final_url,
            "final_level": final_level,
            "final_score": final_score,
            "final_domain_changed": final_domain_changed
        }

    redirect_checked = True

    try:
        redirect_data = post_json(BACKEND_REDIRECT_URL, {"url": original_url}, timeout=8)
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, ConnectionError) as exc:
        redirect_error = str(exc)
        reasons.append("Deep evaluation: redirect kontrolü yapılamadı.")
        return {
            "risk_score": score,
            "level": level,
            "reasons": reasons,
            "redirect_checked": redirect_checked,
            "redirect_error": redirect_error,
            "has_redirect": has_redirect,
            "redirect_count": redirect_count,
            "final_url": final_url,
            "final_level": final_level,
            "final_score": final_score,
            "final_domain_changed": final_domain_changed
        }

    has_redirect = bool(redirect_data.get("has_redirect", False))
    redirect_count = int(redirect_data.get("redirect_count", 0) or 0)
    final_url = redirect_data.get("final_url", "") or ""

    if has_redirect:
        score += min(redirect_count * 5, 20)
        reasons.append("Deep evaluation: yönlendirme zinciri tespit edildi.")

    if final_url:
        original_host = hostname_of(original_url)
        final_host = hostname_of(final_url)
        final_domain_changed = bool(original_host and final_host and original_host != final_host)

        try:
            final_result = analyze_with_js(final_url)
            final_level = normalize_level(final_result.get("level", ""))
            final_score = int(final_result.get("riskScore", 0))
            reasons.append(f"Deep evaluation: final URL analiz edildi: {final_level} / {final_score}")

            if final_domain_changed:
                score += 10
                reasons.append("Deep evaluation: ilk URL ile final URL farklı alan adlarına yönleniyor.")

            if final_level == "Yüksek risk":
                score += 40
            elif final_level == "Şüpheli":
                score += 25
            elif final_level == "Düşük risk":
                score += 10

        except Exception as exc:
            redirect_error = str(exc)
            reasons.append("Deep evaluation: final URL analiz edilemedi.")

    score = max(0, min(score, 100))
    features_private_ip = False
    level = level_from_score(score, features_private_ip)

    if final_level == "Yüksek risk":
        level = "Yüksek risk"
    elif final_level == "Şüpheli" and level in ["Güvenli görünüyor", "Düşük risk"]:
        level = "Şüpheli"

    return {
        "risk_score": score,
        "level": level,
        "reasons": reasons,
        "redirect_checked": redirect_checked,
        "redirect_error": redirect_error,
        "has_redirect": has_redirect,
        "redirect_count": redirect_count,
        "final_url": final_url,
        "final_level": final_level,
        "final_score": final_score,
        "final_domain_changed": final_domain_changed
    }


def analyze_deep(url: str):
    base_result = analyze_with_js(url)

    base_score = int(base_result.get("riskScore", 0))
    base_level = normalize_level(base_result.get("level", ""))
    base_reasons = list(base_result.get("reasons", []))

    reputation_level = "not_checked"
    reputation_error = ""

    try:
        reputation_data = post_json(BACKEND_REPUTATION_URL, {"url": url}, timeout=8)
        score, level, reasons, reputation_level = apply_reputation_signal(base_result, reputation_data)
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, ConnectionError) as exc:
        reputation_error = str(exc)
        score, level, reasons = base_score, base_level, base_reasons
        reasons.append("Deep evaluation: reputation kontrolü yapılamadı.")

    redirect_result = apply_redirect_signal(url, score, level, reasons)

    return {
        "base_level": base_level,
        "base_score": base_score,
        "predicted_level": redirect_result["level"],
        "risk_score": redirect_result["risk_score"],
        "reasons": redirect_result["reasons"],
        "reputation_level": reputation_level,
        "reputation_error": reputation_error,
        "redirect_checked": redirect_result["redirect_checked"],
        "redirect_error": redirect_result["redirect_error"],
        "has_redirect": redirect_result["has_redirect"],
        "redirect_count": redirect_result["redirect_count"],
        "final_url": redirect_result["final_url"],
        "final_level": redirect_result["final_level"],
        "final_score": redirect_result["final_score"],
        "final_domain_changed": redirect_result["final_domain_changed"]
    }


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Dataset bulunamadı: {INPUT_FILE}")

    rows = []

    with open(INPUT_FILE, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for index, row in enumerate(reader, start=1):
            url = row.get("url", "").strip()
            label = row.get("label", "").strip()
            source = row.get("source", "").strip()
            category = row.get("category", "").strip()

            if not url:
                continue

            try:
                result = analyze_deep(url)
            except Exception as exc:
                result = {
                    "base_level": "Bilinmiyor",
                    "base_score": "",
                    "predicted_level": "Bilinmiyor",
                    "risk_score": "",
                    "reasons": [f"Deep evaluation ana hata: {exc}"],
                    "reputation_level": "error",
                    "reputation_error": str(exc),
                    "redirect_checked": False,
                    "redirect_error": "",
                    "has_redirect": False,
                    "redirect_count": 0,
                    "final_url": "",
                    "final_level": "",
                    "final_score": "",
                    "final_domain_changed": False
                }

            rows.append({
                "url": url,
                "true_label": label,
                "source": source,
                "category": category,
                "base_level": result["base_level"],
                "base_score": result["base_score"],
                "predicted_level": result["predicted_level"],
                "risk_score": result["risk_score"],
                "reputation_level": result["reputation_level"],
                "reputation_error": result["reputation_error"],
                "redirect_checked": result["redirect_checked"],
                "has_redirect": result["has_redirect"],
                "redirect_count": result["redirect_count"],
                "final_url": result["final_url"],
                "final_level": result["final_level"],
                "final_score": result["final_score"],
                "final_domain_changed": result["final_domain_changed"],
                "redirect_error": result["redirect_error"],
                "reasons": " | ".join(result["reasons"])
            })

            if index % 25 == 0:
                print(f"{index} URL analiz edildi...")

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "url",
            "true_label",
            "source",
            "category",
            "base_level",
            "base_score",
            "predicted_level",
            "risk_score",
            "reputation_level",
            "reputation_error",
            "redirect_checked",
            "has_redirect",
            "redirect_count",
            "final_url",
            "final_level",
            "final_score",
            "final_domain_changed",
            "redirect_error",
            "reasons"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("\nDeep evaluation tamamlandı.")
    print(f"Toplam analiz edilen URL: {len(rows)}")
    print(f"Sonuç dosyası: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
