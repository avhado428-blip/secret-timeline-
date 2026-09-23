"""Secret detection for a single line of text.

scanner.py calls scan_line() on every line a commit ADDED. Two detectors run:

  1. pattern - regexes for secrets with a recognisable format (AWS, GitHub, Slack, ...)
  2. entropy - Shannon entropy of values assigned to key/token/secret-style names,
               which catches custom or unknown formats

Both detectors hash the secret VALUE (not the whole line), so the same secret found
by both gets the same hash and storage.py collapses it into one finding.
The raw secret is hashed immediately and never leaves this module.
"""
import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass
class LineFinding:
    secret_type: str        # e.g. "AWS Access Key"
    detection_method: str   # "pattern" or "entropy"
    secret_hash: str        # SHA-256 hex digest of the secret value


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1. Pattern detector
# ---------------------------------------------------------------------------
# If a pattern has a capture group, group 1 is the secret; otherwise the whole match is.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("AWS Secret Key", re.compile(
        r"aws_?secret_?(?:access_?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        re.IGNORECASE)),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub Fine-Grained Token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("Slack Token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Slack Webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe Secret Key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")),
    ("JSON Web Token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    # A private key spans many lines, but a per-line scanner only sees the BEGIN line,
    # so every key with the same header hashes the same and dedupes into one finding.
    ("Private Key Block", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----")),
]


# ---------------------------------------------------------------------------
# 2. Entropy detector
# ---------------------------------------------------------------------------
# Matches  name = value,  name: value,  "name": "value",  name := value,  name => value
# where the name contains a secret-ish word.
ASSIGNMENT_RE = re.compile(
    r"""
    (?:key|token|secret|passwd|password|pwd|credential|auth)   # name contains a secret-ish word
    [\w.\-]{0,40}                                              # rest of the name
    ['"]? \s* (?:=>|:=|=|:) \s* ['"]?                          # closing quote, operator, opening quote
    (?P<value>[A-Za-z0-9+/=_\-]{16,})                          # candidate secret, at least 16 chars
    (?=['"\s,;&)}\]]|$)                                        # must end cleanly: rejects get_secret_key()
    """,
    re.IGNORECASE | re.VERBOSE,
)

HEX_ONLY = re.compile(r"[0-9a-fA-F]+")
HEX_THRESHOLD = 3.0     # hex has only 16 symbols, so random hex tops out near 4.0 bits/char
OTHER_THRESHOLD = 4.0   # base64-style tokens: random ones land around 4.5-5.5 bits/char


def shannon_entropy(text: str) -> float:
    """Bits of randomness per character (0 = 'aaaa', higher = more random)."""
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_like_secret(value: str) -> bool:
    # Identifiers like "get_secret_key_name" or "MY_SECRET_KEY" use one character class;
    # real tokens mix at least two of lowercase / uppercase / digits.
    classes = (
        any(c.islower() for c in value)
        + any(c.isupper() for c in value)
        + any(c.isdigit() for c in value)
    )
    if classes < 2:
        return False
    threshold = HEX_THRESHOLD if HEX_ONLY.fullmatch(value) else OTHER_THRESHOLD
    return shannon_entropy(value) >= threshold


# ---------------------------------------------------------------------------
# Entry point used by scanner.py
# ---------------------------------------------------------------------------
def scan_line(line: str) -> list[LineFinding]:
    findings: list[LineFinding] = []

    for secret_type, pattern in PATTERNS:
        for match in pattern.finditer(line):
            secret = match.group(1) if pattern.groups else match.group(0)
            findings.append(LineFinding(secret_type, "pattern", sha256_hex(secret)))

    for match in ASSIGNMENT_RE.finditer(line):
        value = match.group("value")
        if looks_like_secret(value):
            findings.append(LineFinding("High-Entropy String", "entropy", sha256_hex(value)))

    return findings