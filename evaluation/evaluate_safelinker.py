import csv
import json
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
INPUT_FILE = PROJECT_ROOT / "data" / "evaluation_dataset.csv"
OUTPUT_FILE = PROJECT_ROOT / "data" / "evaluation_results.csv"
ANALYZER_SCRIPT = PROJECT_ROOT / "extension" / "analyze.js"


def analyze_with_js(url: str):
    result = subprocess.run(
        ["node", str(ANALYZER_SCRIPT), url],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    if result.returncode != 0:
        raise RuntimeError(f"Node analiz hatası: {result.stderr.strip()}")

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError("Node analiz çıktısı boş döndü.")

    return json.loads(stdout)


def main():
    rows = []

    with open(INPUT_FILE, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["url"].strip()
            label = row["label"].strip()
            source = row.get("source", "").strip()
            category = row.get("category", "").strip()

            result = analyze_with_js(url)

            rows.append(
                {
                    "url": url,
                    "normalized_url": result["normalizedUrl"],
                    "true_label": label,
                    "source": source,
                    "category": category,
                    "predicted_level": result["level"],
                    "risk_score": result["riskScore"],
                    "reasons": " | ".join(result["reasons"]) if isinstance(result["reasons"], list) else str(result["reasons"]),
                }
            )

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "url",
            "normalized_url",
            "true_label",
            "source",
            "category",
            "predicted_level",
            "risk_score",
            "reasons",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Toplam test edilen URL sayısı: {len(rows)}")
    print(f"Sonuç dosyası oluşturuldu: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
