"""
build_dataset.py
-----------------
Builds the training table by running feature_extraction.extract_features()
over a large, real-world corpus of raw URLs labelled "good" / "bad"
(malicious - phishing, malware, spam domains). Using RAW URLs (rather than
a pre-engineered feature table) lets us extract exactly the features our
own extractor computes, so training and inference stay perfectly
consistent - including realistic legitimate URLs that contain paths,
query strings, etc. (avoiding the "legit URLs are always bare domains"
bias you get from some public feature-only datasets).

Source corpus: data/raw_urls1.csv  (columns: url,label ; label in {good,bad})

Run:
    python3 build_dataset.py
Output:
    data/phishing_features_from_raw.csv
"""

import os
import pandas as pd
from feature_extraction import extract_features, FEATURE_NAMES

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "data", "raw_urls1.csv")
OUT = os.path.join(HERE, "..", "data", "phishing_features_from_raw.csv")

# Cap + balance so training stays fast and the classes aren't wildly skewed
MAX_GOOD = 150_000
MAX_BAD = 90_000
RANDOM_STATE = 42


def main():
    print(f"Reading {SRC} ...")
    df = pd.read_csv(SRC)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].str.strip().str.lower()
    df = df[df["label"].isin(["good", "bad"])]

    good = df[df.label == "good"]
    bad = df[df.label == "bad"]
    print(f"Available: good={len(good)}  bad={len(bad)}")

    if len(good) > MAX_GOOD:
        good = good.sample(MAX_GOOD, random_state=RANDOM_STATE)
    if len(bad) > MAX_BAD:
        bad = bad.sample(MAX_BAD, random_state=RANDOM_STATE)

    sample = pd.concat([good, bad]).sample(frac=1, random_state=RANDOM_STATE)
    print(f"Using: good={len(good)}  bad={len(bad)}  total={len(sample)}")

    rows = []
    for i, url in enumerate(sample["url"].astype(str)):
        rows.append(extract_features(url))
        if i % 50000 == 0:
            print(f"  extracted {i}/{len(sample)}")

    feat_df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    feat_df["phishing"] = (sample["label"].values == "bad").astype(int)
    feat_df["source_url"] = sample["url"].values

    feat_df.to_csv(OUT, index=False)
    print(f"Saved {feat_df.shape} -> {OUT}")


if __name__ == "__main__":
    main()
