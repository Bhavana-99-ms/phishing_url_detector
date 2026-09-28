"""
feature_extraction.py
----------------------
Extracts purely lexical / structural features from a URL string.

Design goal: every feature can be computed instantly from the URL text alone
(no DNS lookup, no WHOIS, no network call). That's what lets the exact same
logic run inside a browser extension (see extension/content.js, which is a
1:1 JavaScript port of this file) as well as on the server.

Convention (kept identical to how the model was trained):
  * If a URL component (directory / file / query params) is absent, the
    features that describe it are set to -1 instead of 0, so the model can
    tell "component missing" apart from "component present but empty".
"""

import re
import math
from urllib.parse import urlsplit

# Common public URL-shortening services
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "tiny.cc", "shorte.st",
    "rb.gy", "lnkd.in", "soo.gd", "clck.ru", "v.gd",
}

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

FEATURE_NAMES = [
    "length_url", "qty_dot_url", "qty_hyphen_url", "qty_underline_url",
    "qty_slash_url", "qty_questionmark_url", "qty_equal_url", "qty_at_url",
    "qty_and_url", "qty_exclamation_url", "qty_tilde_url", "qty_comma_url",
    "qty_plus_url", "qty_asterisk_url", "qty_percent_url",
    "domain_length", "qty_dot_domain", "qty_hyphen_domain",
    "qty_underline_domain", "qty_vowels_domain", "domain_in_ip",
    "directory_length", "qty_dot_directory", "qty_hyphen_directory",
    "qty_slash_directory",
    "file_length",
    "params_length", "qty_params", "qty_equal_params", "qty_and_params",
    "email_in_url", "url_shortened",
]


def _count(s, ch):
    return s.count(ch) if s else 0


def _is_ip(host: str) -> int:
    if not host:
        return 0
    if IPV4_RE.match(host):
        return 1
    # crude IPv6 check
    if host.count(":") >= 2:
        return 1
    return 0


def extract_features(url: str) -> dict:
    """Return an ordered dict of features for a single URL string."""
    if not isinstance(url, str) or not url.strip():
        url = ""
    url = url.strip()

    # Make sure urlsplit treats it as an absolute URL
    candidate = url
    if "://" not in candidate:
        candidate = "http://" + candidate

    try:
        parts = urlsplit(candidate)
    except ValueError:
        parts = urlsplit("http://invalid")

    host = (parts.hostname or "")
    path = parts.path or ""
    query = parts.query or ""

    # directory / file split of the path
    if path and path != "/":
        if "/" in path.rstrip("/"):
            directory = path.rsplit("/", 1)[0]
        else:
            directory = ""
        file_ = path.rsplit("/", 1)[-1] if not path.endswith("/") else ""
    else:
        directory = ""
        file_ = ""

    has_directory = bool(directory)
    has_file = bool(file_)
    has_query = bool(query)

    feats = {}
    full = url

    feats["length_url"] = len(full)
    feats["qty_dot_url"] = _count(full, ".")
    feats["qty_hyphen_url"] = _count(full, "-")
    feats["qty_underline_url"] = _count(full, "_")
    feats["qty_slash_url"] = _count(full, "/")
    feats["qty_questionmark_url"] = _count(full, "?")
    feats["qty_equal_url"] = _count(full, "=")
    feats["qty_at_url"] = _count(full, "@")
    feats["qty_and_url"] = _count(full, "&")
    feats["qty_exclamation_url"] = _count(full, "!")
    feats["qty_tilde_url"] = _count(full, "~")
    feats["qty_comma_url"] = _count(full, ",")
    feats["qty_plus_url"] = _count(full, "+")
    feats["qty_asterisk_url"] = _count(full, "*")
    feats["qty_percent_url"] = _count(full, "%")

    feats["domain_length"] = len(host)
    feats["qty_dot_domain"] = _count(host, ".")
    feats["qty_hyphen_domain"] = _count(host, "-")
    feats["qty_underline_domain"] = _count(host, "_")
    feats["qty_vowels_domain"] = sum(1 for c in host.lower() if c in "aeiou")
    feats["domain_in_ip"] = _is_ip(host)

    if has_directory:
        feats["directory_length"] = len(directory)
        feats["qty_dot_directory"] = _count(directory, ".")
        feats["qty_hyphen_directory"] = _count(directory, "-")
        feats["qty_slash_directory"] = _count(directory, "/")
    else:
        feats["directory_length"] = -1
        feats["qty_dot_directory"] = -1
        feats["qty_hyphen_directory"] = -1
        feats["qty_slash_directory"] = -1

    feats["file_length"] = len(file_) if has_file else -1

    if has_query:
        feats["params_length"] = len(query)
        params = query.split("&") if query else []
        feats["qty_params"] = len(params)
        feats["qty_equal_params"] = _count(query, "=")
        feats["qty_and_params"] = _count(query, "&")
    else:
        feats["params_length"] = -1
        feats["qty_params"] = -1
        feats["qty_equal_params"] = -1
        feats["qty_and_params"] = -1

    feats["email_in_url"] = 1 if EMAIL_RE.search(full) else 0
    feats["url_shortened"] = 1 if host in SHORTENERS else 0

    return feats


# --- Explainable rule-based layer -----------------------------------------
# Pure lexical ML features can't "know" that google.com is a reputable
# 20-year-old domain. These simple, transparent heuristics catch classic
# social-engineering tricks (brand name + hyphen, fake sub-domains,
# suspicious action words) and are blended with the ML probability in
# app.py to produce the final risk score, and to give a human-readable
# "why was this flagged" explanation.

SUSPICIOUS_WORDS = [
    "login", "secure", "verify", "update", "confirm", "account", "banking",
    "signin", "webscr", "suspend", "unlock", "password", "billing",
    "security", "authenticate", "wallet", "recover",
]

WELL_KNOWN_BRANDS = [
    "google", "paypal", "apple", "microsoft", "amazon", "facebook",
    "instagram", "whatsapp", "netflix", "chase", "wellsfargo", "ebay",
    "linkedin", "bankofamerica", "dropbox", "outlook", "office365", "icloud",
]


def heuristic_signals(url: str) -> dict:
    """Return a dict of boolean/int rule-based signals plus a 0-1 score."""
    u = (url or "").lower()
    candidate = u if "://" in u else "http://" + u
    parts = urlsplit(candidate)
    host = parts.hostname or ""
    path_qs = (parts.path or "") + "?" + (parts.query or "")

    signals = {}
    signals["is_ip_host"] = _is_ip(host)
    signals["no_https"] = 0 if parts.scheme == "https" else 1
    signals["many_hyphens_domain"] = 1 if host.count("-") >= 2 else 0
    signals["many_subdomains"] = 1 if host.count(".") >= 3 else 0
    signals["suspicious_word_count"] = sum(1 for w in SUSPICIOUS_WORDS if w in path_qs or w in host)

    brand_hit = None
    for brand in WELL_KNOWN_BRANDS:
        if brand in host:
            # crude check: brand should be the registrable domain's main label,
            # not just embedded inside a longer, unrelated hostname
            labels = host.split(".")
            if brand not in labels and (len(labels) > 2 or "-" in host):
                brand_hit = brand
                break
    signals["brand_impersonation"] = 1 if brand_hit else 0
    signals["impersonated_brand"] = brand_hit

    raw_score = (
        2.0 * signals["is_ip_host"]
        + 0.5 * signals["no_https"]
        + 1.0 * signals["many_hyphens_domain"]
        + 1.0 * signals["many_subdomains"]
        + 0.6 * min(signals["suspicious_word_count"], 3)
        + 2.0 * signals["brand_impersonation"]
    )
    signals["heuristic_score"] = round(min(raw_score / 6.0, 1.0), 4)
    return signals


def extract_feature_vector(url: str):
    """Return features as an ordered list matching FEATURE_NAMES."""
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]


if __name__ == "__main__":
    import sys, json
    test_url = sys.argv[1] if len(sys.argv) > 1 else "http://paypal-secure.login.verify-account.ru/update?user=1&x=2"
    print(json.dumps(extract_features(test_url), indent=2))
