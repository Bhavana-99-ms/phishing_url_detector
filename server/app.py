"""
app.py
------
Flask REST API for the phishing URL detector.

Endpoints:
  GET  /health              -> {"status": "ok"}
  POST /predict  {"url": "..."} -> {
        "url": ...,
        "prediction": "phishing" | "legitimate",
        "phishing_probability": 0.0-1.0,
        "features": {...}
  }

Run:
    python3 app.py
Then:
    curl -X POST http://127.0.0.1:5000/predict -H "Content-Type: application/json" \
         -d '{"url":"http://paypal-secure-login.verify-account.ru/update"}'
"""

import os
import joblib
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from feature_extraction import extract_features, heuristic_signals, FEATURE_NAMES

# Weight given to the rule-based heuristic score vs. the ML model's
# probability when computing the final blended risk score.
HEURISTIC_WEIGHT = 0.25

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "..", "model", "phishing_model.pkl")

app = Flask(__name__, template_folder="templates")
# CORS is needed so the browser extension (running as an extension origin)
# can call this local API from content/background scripts.
CORS(app)

print(f"Loading model from {MODEL_PATH} ...")
bundle = joblib.load(MODEL_PATH)
pipeline = bundle["pipeline"]
feature_names = bundle["feature_names"]
print("Model loaded.")


@app.route("/", methods=["GET"])
def index():
    """Serves the inspection-report style web dashboard."""
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not url or not isinstance(url, str):
        return jsonify({"error": "Please provide a non-empty 'url' string."}), 400

    feats = extract_features(url)
    vector = [[feats[name] for name in feature_names]]

    proba = pipeline.predict_proba(vector)[0]
    ml_proba = float(proba[1])

    heur = heuristic_signals(url)
    blended = (1 - HEURISTIC_WEIGHT) * ml_proba + HEURISTIC_WEIGHT * heur["heuristic_score"]
    label = "phishing" if blended >= 0.5 else "legitimate"

    return jsonify({
        "url": url,
        "prediction": label,
        "phishing_probability": round(blended, 4),
        "legitimate_probability": round(1 - blended, 4),
        "ml_model_probability": round(ml_proba, 4),
        "heuristic_score": heur["heuristic_score"],
        "heuristic_signals": {k: v for k, v in heur.items() if k != "heuristic_score"},
        "features": feats,
    })


@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Please provide a non-empty 'urls' list."}), 400

    results = []
    for url in urls:
        feats = extract_features(url)
        vector = [[feats[name] for name in feature_names]]
        proba = pipeline.predict_proba(vector)[0]
        ml_proba = float(proba[1])
        heur = heuristic_signals(url)
        blended = (1 - HEURISTIC_WEIGHT) * ml_proba + HEURISTIC_WEIGHT * heur["heuristic_score"]
        results.append({
            "url": url,
            "prediction": "phishing" if blended >= 0.5 else "legitimate",
            "phishing_probability": round(blended, 4),
        })
    return jsonify({"results": results})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
