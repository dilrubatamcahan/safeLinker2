import csv
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

DEFAULT_INPUT = PROJECT_DIR / "evaluation_results_deep.csv"
FALLBACK_INPUT = PROJECT_DIR / "evaluation_results.csv"


def map_prediction_to_label(predicted_level: str):
    predicted_level = (predicted_level or "").lower()

    if "yüksek" in predicted_level or "şüpheli" in predicted_level:
        return "malicious"
    elif "güvenli" in predicted_level or "düşük risk" in predicted_level or "yerel ağ" in predicted_level:
        return "benign"
    else:
        return "unknown"


def calculate_metrics(input_file: Path):
    total = 0
    correct = 0

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0
    unknown = 0

    with open(input_file, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            total += 1

            true_label = row.get("true_label", "").strip()
            predicted_level = row.get("predicted_level", "").strip()

            predicted_label = map_prediction_to_label(predicted_level)

            if predicted_label == "unknown":
                unknown += 1

            if predicted_label == true_label:
                correct += 1

            if true_label == "malicious":
                if predicted_label == "malicious":
                    true_positive += 1
                else:
                    false_negative += 1

            elif true_label == "benign":
                if predicted_label == "benign":
                    true_negative += 1
                else:
                    false_positive += 1

    accuracy = correct / total if total else 0
    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else 0
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else 0
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    false_positive_rate = false_positive / (false_positive + true_negative) if (false_positive + true_negative) else 0
    false_negative_rate = false_negative / (false_negative + true_positive) if (false_negative + true_positive) else 0

    print("\n===== SONUÇLAR =====")
    print(f"Kullanılan sonuç dosyası: {input_file}")
    print(f"Toplam URL: {total}")
    print(f"Doğru tahmin: {correct}")
    print(f"Accuracy: {accuracy:.2f}")

    print("\n--- Detaylı ---")
    print(f"True Positive (Doğru zararlı): {true_positive}")
    print(f"True Negative (Doğru temiz): {true_negative}")
    print(f"False Positive (Yanlış alarm): {false_positive}")
    print(f"False Negative (Kaçırılan saldırı): {false_negative}")
    print(f"Unknown tahmin: {unknown}")

    print("\n--- Ek Metrikler ---")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"F1 Score: {f1_score:.2f}")
    print(f"False Positive Rate: {false_positive_rate:.2f}")
    print(f"False Negative Rate: {false_negative_rate:.2f}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_file = Path(sys.argv[1]).resolve()
    elif DEFAULT_INPUT.exists():
        input_file = DEFAULT_INPUT
    else:
        input_file = FALLBACK_INPUT

    if not input_file.exists():
        raise FileNotFoundError(f"Sonuç dosyası bulunamadı: {input_file}")

    calculate_metrics(input_file)
