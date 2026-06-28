# SafeLinker

**İstemci Taraflı URL Güvenlik Analizi için Kural Tabanlı Chrome Eklentisi**

SafeLinker, ziyaret edilen veya yapıştırılan URL'lerin güvenlik riskini hiçbir sunucuya veri göndermeden, tamamen tarayıcı içinde analiz eden bir Chrome eklentisidir. Atatürk Üniversitesi Yönetim Bilişim Sistemleri bölümü lisans bitirme projesi olarak geliştirilmiştir.

---

## Özellikler

- **Tamamen istemci taraflı:** Temel analiz için hiçbir harici sunucuya bağlanmaz; kullanıcı gizliliği korunur.
- **16+ kural kategorisi:** Marka taklidi, typosquatting, IDN/Punycode homograf, IP adresi, HTTPS yokluğu, kısa link, şüpheli TLD ve daha fazlası.
- **Sıfır yanlış pozitif (v4.0):** Güvenilir domain'ler kesinlikle yanlış işaretlenmez.
- **İki analiz modu:** Hızlı (statik) ve Derin (backend + yönlendirme zinciri).
- **Açıklanabilir kararlar:** Hangi kural tetiklendi, kaç puan eklendi — kullanıcıya gösterilir.
- **İsteğe bağlı backend:** FastAPI servisi ile domain itibarı ve redirect zinciri kontrolü.

---

## Performans (v4.0 — 521 URL)

| Metrik | Sonuç |
|---|---|
| Doğruluk (Accuracy) | %90,8 |
| Hassasiyet (Precision) | **%100** |
| Duyarlılık (Recall) | %80,8 |
| F1 Puanı | %89,4 |
| Yanlış Pozitif Oranı | **%0** |
| Yanlış Negatif Oranı | %19,2 |

> Veri seti: URLhaus'tan derlenen 250 zararlı + 271 zararsız URL (toplam 521 URL).

---

## Klasör Yapısı

```
safeLinker2/
├── extension/
│   ├── analyzer.js        # Karar motoru — tüm kurallar burada
│   ├── popup.html/js      # Eklenti arayüzü
│   ├── content.js         # Sayfa içi uyarı kartı
│   ├── service_worker.js
│   └── manifest.json
├── backend/
│   ├── app.py             # FastAPI — reputation + redirect servisi
│   └── requirements.txt
├── evaluation/
│   ├── evaluate_safelinker.py       # Statik değerlendirme
│   ├── evaluate_safelinker_deep.py  # Backend dahil derin değerlendirme
│   └── calculate_metrics.py         # Metrik hesaplama
└── data/
    ├── evaluation_dataset.csv
    ├── benign_urls.csv
    ├── malicious_urls.csv
    └── hard_cases.csv
```

---

## Kurulum ve Çalıştırma

### Chrome Eklentisi

1. Chrome'da `chrome://extensions/` adresine gidin.
2. Sağ üstten **Geliştirici modu**nu açın.
3. **Paketlenmemiş öğe yükle** → `extension/` klasörünü seçin.
4. Eklenti araç çubuğunda SafeLinker simgesi belirecektir.

### Backend (İsteğe Bağlı)

```bash
pip install -r backend/requirements.txt
uvicorn backend.app:app --host 127.0.0.1 --port 8010 --reload
```

Backend çalıştırılmadan da eklenti statik modda tam işlevlidir.

### Değerlendirme

Node.js kurulu olmalıdır.

```bash
# Statik analiz (tüm dataset, ~30 sn)
python evaluation/evaluate_safelinker.py
python evaluation/calculate_metrics.py data/evaluation_results.csv

# Tek URL testi
node extension/analyze.js "https://example.com"
```

---

## Skor → Risk Seviyesi Eşlemesi

| Skor | Seviye |
|---|---|
| 0 – 5 | Güvenli görünüyor |
| 6 – 15 | Düşük risk |
| 16 – 35 | Şüpheli |
| 36 – 100 | Yüksek risk |

---

## Kullanılan Teknolojiler

- **Chrome Extension Manifest V3** — servis worker, declarativeNetRequest
- **Vanilla JavaScript** — sıfır bağımlılık, tarayıcı içi analiz
- **Python / FastAPI** — opsiyonel backend servisi
- **Node.js** — değerlendirme hattı

---

## Sınırlılıklar

- Gerçek zamanlı tehdit istihbaratı veritabanı entegrasyonu yoktur.
- Dinamik içerik analizi (JavaScript render) yapılmamaktadır.
- WHOIS / domain yaşı canlı sorgulanmamaktadır.
- Kural seti saldırganlar tarafından tersine mühendislikle aşılabilir.

---

## Geliştirici

**Dilruba Tamcahan**
Atatürk Üniversitesi — Yönetim Bilişim Sistemleri
Danışman: Doç. Dr. Ahmet Kamil Kabakuş
