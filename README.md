# Phishing URL Detector (ML + Browser Extension)

A complete mini-project that extracts lexical/structural features from a URL
and classifies it as **phishing** or **legitimate** using a trained
scikit-learn model, served over a local Flask API and wrapped in a
Manifest V3 browser extension that flags dangerous pages as you browse.

```
phishing_url_detector/
├── data/
│   ├── raw_urls1.csv                    # ~420k real URLs, labeled good/bad
│   └── phishing_features_from_raw.csv   # engineered feature table (generated)
├── server/
│   ├── feature_extraction.py            # URL -> 32 lexical features + heuristics
│   ├── build_dataset.py                 # raw URLs -> feature CSV
│   ├── train_model.py                   # trains + evaluates the model
│   ├── app.py                           # Flask REST API + web dashboard
│   └── templates/index.html             # "URL Inspection" report-style dashboard
├── model/
│   ├── phishing_model.pkl               # trained pipeline (scaler + RandomForest)
│   ├── metrics.json                     # accuracy/precision/recall/F1/ROC-AUC
│   └── feature_importance.png
├── extension/
│   ├── manifest.json                    # Manifest V3
│   ├── background.js                    # calls the API, sets tab badge
│   ├── content.js                       # injects warning banner on flagged pages
│   ├── popup.html / popup.js            # click-to-inspect UI
│   └── icons/
└── requirements.txt
```

## 1. How it works

1. **Feature extraction** (`server/feature_extraction.py`): given any URL
   string, computes 32 features purely from its text — length, counts of
   `. - _ / ? = @ & ! ~ , + * %`, domain length, vowel count, whether the
   host is a raw IP, directory/file/query-string structure, presence of an
   email address, whether it's a known URL shortener, etc. No network
   calls, so it runs instantly client-side or server-side.
2. **Heuristic layer** (same file, `heuristic_signals()`): a small set of
   transparent, human-readable rules — brand-name impersonation
   (`appleid.apple.com.verify-login.info`), excessive hyphens/subdomains,
   sensitive keywords (`login`, `verify`, `secure`, ...), missing HTTPS,
   raw-IP hosts. Used to explain *why* something was flagged and to nudge
   the final score.
3. **Model** (`server/train_model.py`): a `StandardScaler + RandomForest`
   pipeline trained on ~225k real URLs (150k legitimate / 76k
   malicious/phishing, sourced from a public labeled URL corpus). Final
   score = `0.75 * model_probability + 0.25 * heuristic_score`.
4. **API** (`server/app.py`): a Flask server that loads the trained model
   once and exposes `/predict` for the extension (or `curl`, Postman, etc.)
   to call.
5. **Browser extension** (`extension/`): on every page load, the background
   service worker asks the local API for a score, colors the toolbar badge
   green/red, and the content script injects a warning banner on pages
   flagged with high confidence. The popup shows the full breakdown
   (ML score, heuristic score, which red flags fired).
6. **Web dashboard** (`server/templates/index.html`): a standalone
   "URL Inspection" report page served straight from the Flask app at `/`,
   so you can demo the model without installing the extension — paste a
   URL, get a stamped verdict, the risk breakdown, plain-language findings,
   and the full technical feature readout, with a running case log kept in
   the browser for the session.

## 2. Model performance

Trained on a held-out 20% test split (see `model/metrics.json` for exact numbers):

| Metric              | Value |
|---------------------|-------|
| Accuracy            | ~0.86 |
| Precision (phishing)| ~0.75 |
| Recall (phishing)   | ~0.88 |
| F1 (phishing)       | ~0.81 |
| ROC-AUC             | ~0.95 |

**Honest limitation:** the model only looks at the URL string itself (no
domain age, SSL certificate, hosting reputation, or page content), which is
what keeps the whole thing fast enough to run instantly in a browser
extension. That means a small number of legitimate URLs with unusual
structure can score as moderately risky, and very well-crafted phishing
URLs that closely mimic normal link structure can slip through. See
"Possible improvements" below for how a real product would close that gap.

## 3. Setup & execution commands

### Prerequisites
- Python 3.9+
- Google Chrome / Edge / Brave (or any Chromium-based browser) for the extension

### Step 1 — install dependencies
```bash
cd phishing_url_detector
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — (optional) rebuild the dataset and retrain the model
The trained model is already included at `model/phishing_model.pkl`, so
this step is optional — only needed if you want to reproduce training or
change the feature set.
```bash
cd server
python3 build_dataset.py     # data/raw_urls1.csv -> data/phishing_features_from_raw.csv
python3 train_model.py       # trains model, writes model/phishing_model.pkl + metrics.json
```

### Step 3 — run the API server (and web dashboard)
```bash
cd server
python3 app.py
# Server starts on http://127.0.0.1:5000
```

Open **http://127.0.0.1:5000/** in your browser for the built-in web
dashboard ("URL Inspection" report UI) — paste a URL, click **Inspect**,
and see the verdict, risk score, plain-language findings, and the full
32-feature technical readout, plus a running case log for the session.

Or test the raw JSON API from another terminal:
```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"http://appleid.apple.com.verify-secure-login.info/signin"}'

curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.wikipedia.org/wiki/Machine_learning"}'
```

### Step 4 — load the browser extension
1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `extension/` folder.
4. Make sure `server/app.py` is running (Step 3) — the extension calls
   `http://127.0.0.1:5000`.
5. Browse normally. The toolbar icon shows **OK** (green) or **!** (red)
   for the current tab; click it for the full breakdown. Pages flagged with
   high confidence get a red warning banner injected at the top.

## 4. API reference

`POST /predict`
```json
// request
{ "url": "http://paypal-secure-login.verify-account.ru/update" }

// response
{
  "url": "...",
  "prediction": "phishing",
  "phishing_probability": 0.83,
  "legitimate_probability": 0.17,
  "ml_model_probability": 0.87,
  "heuristic_score": 0.72,
  "heuristic_signals": { "is_ip_host": 0, "brand_impersonation": 1, ... },
  "features": { "length_url": 58, "qty_dot_url": 4, ... }
}
```

`POST /predict_batch` — `{"urls": ["...", "..."]}` → array of lighter-weight results.
`GET /health` — liveness check.

## 5. Possible improvements (good "future work" talking points)

- Add WHOIS/domain-age and SSL-certificate-issuer checks (needs network
  calls, so best done server-side, not in the extension's hot path).
- Add a Safe-Browsing / blocklist lookup as an extra signal.
- Add page-content features (form action mismatches, favicon mismatch,
  login-form detection) for a second, content-based model.
- Periodically retrain on fresh PhishTank/OpenPhish feeds to track new
  campaigns.
- Replace the fixed 0.75/0.25 ML/heuristic blend with a small logistic
  regression "stacking" layer trained on both scores.
