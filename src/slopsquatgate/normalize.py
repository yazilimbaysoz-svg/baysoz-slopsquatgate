"""Unicode, name-similarity, and source classification. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlsplit

CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "χ": "x", "κ": "k",
        "ε": "e", "ι": "i", "η": "n", "υ": "u", "ζ": "z", "µ": "u",
        "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
        "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
        "⼀": "1", "⼁": "l", "Ⓐ": "a", "ⓑ": "b",
    }
)
HAZARD_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
WILDCARDS = frozenset({"*", "x", "X", "latest", "HEAD", "head"})
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
VERSION_RE = re.compile(r"^(?:==|=|@|v)?([0-9][0-9A-Za-z.!+\-]*)$")


def fold_name(name: str, ecosystem: str = "") -> str:
    """Apply UnicodeNFKC and ecosystem package-name normalization."""
    text = unicodedata.normalize("NFKC", name).translate(CONFUSABLES)
    text = "".join(char for char in text if unicodedata.category(char) not in HAZARD_CATEGORIES)
    text = text.lower()
    if ecosystem == "go":
        return text
    if ecosystem == "cargo":
        return re.sub(r"[-_]+", "-", text)
    return re.sub(r"[-_.]+", "-", text)


def unicode_hazards(value: str) -> tuple[tuple[str, str, str], ...]:
    """Return (character, code point, Unicode name) for control and confusable characters."""
    hazards: list[tuple[str, str, str]] = []
    for char in value:
        category = unicodedata.category(char)
        translated = char.translate(CONFUSABLES)
        if category in HAZARD_CATEGORIES or translated != char:
            hazards.append((char, f"U+{ord(char):04X}", unicodedata.name(char, "UNNAMED")))
    return tuple(hazards)


def damerau_levenshtein(left: str, right: str, max_distance: int = 3) -> int:
    """Unrestricted Damerau-Levenshtein distance, bounded by max_distance."""
    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    width = len(right) + 1
    previous_two = list(range(width))
    previous = list(range(width))
    for row in range(1, len(left) + 1):
        current = [row] + [0] * (len(right))
        for column in range(1, width):
            substitution_cost = int(left[row - 1] != right[column - 1])
            current[column] = min(
                previous[column] + 1,
                current[column - 1] + 1,
                previous[column - 1] + substitution_cost,
            )
            if (
                row > 1
                and column > 1
                and left[row - 1] == right[column - 2]
                and left[row - 2] == right[column - 1]
            ):
                current[column] = min(current[column], previous_two[column - 2] + 1)
        previous_two, previous = previous, current
    return min(previous[-1], max_distance + 1)


def is_transposition(left: str, right: str) -> bool:
    """True when two equal-length strings differ by exactly one adjacent swap."""
    if len(left) != len(right) or left == right:
        return False
    differences = [index for index, pair in enumerate(zip(left, right, strict=True)) if pair[0] != pair[1]]
    if len(differences) != 2 or differences[1] - differences[0] != 1:
        return False
    first, second = differences
    swapped = list(left)
    swapped[first], swapped[second] = swapped[second], swapped[first]
    return "".join(swapped) == right


def similarity_candidates(
    name: str,
    candidates: frozenset[str] | set[str],
    ecosystem: str,
    max_distance: int,
) -> tuple[dict[str, str | int], ...]:
    """Rank near-miss package names against a trusted baseline."""
    folded = fold_name(name, ecosystem)
    if len(folded) < 4:
        return ()
    ranked: list[dict[str, str | int]] = []
    for candidate in sorted(candidates):
        folded_candidate = fold_name(candidate, ecosystem)
        if folded_candidate == folded:
            continue
        distance = damerau_levenshtein(folded, folded_candidate, max_distance)
        if distance < 1 or distance > max_distance:
            continue
        if unicode_hazards(name):
            reason = "unicode-confusable"
        elif is_transposition(folded, folded_candidate):
            reason = "transposition"
        elif distance == 1:
            reason = "single-edit"
        else:
            reason = "double-edit"
        ranked.append({"name": candidate, "distance": distance, "reason": reason})
    ranked.sort(key=lambda item: (int(item["distance"]), str(item["name"])))
    return tuple(ranked)


def extract_host(value: str) -> str:
    """Extract a normalized host from a URL, SCP-style Git ref, or Go module path."""
    text = value.strip()
    if not text:
        return ""
    url_match = re.search(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", text)
    if url_match:
        return (urlsplit(url_match.group(0)).hostname or "").lower()
    if text.startswith("git@") and ":" in text:
        return text[4:].split(":", 1)[0].lower()
    for token in text.split():
        if token.startswith("v") and token[1:2].isdigit():
            continue
        head = token.split("/", 1)[0]
        if "." in head and not head.startswith(".") and head != "=>":
            return head.lower()
    return ""


def exact_version(version_spec: str) -> str:
    """Return a pinned version for exact specs, or an empty string for ranges."""
    spec = version_spec.strip()
    if not spec or any(token in spec for token in ("*", ">", "<", "~", "^", "||", ",")):
        return ""
    match = VERSION_RE.fullmatch(spec)
    return match.group(1) if match else ""


def mutable_reasons(version_spec: str, source_kind: str, source_value: str) -> tuple[str, ...]:
    """Classify mutable version references and unresolved source locations."""
    reasons: list[str] = []
    spec = version_spec.strip()
    if not spec or spec in WILDCARDS:
        reasons.append("missing-or-wildcard-version")
    if spec in ("master", "main", "develop", "trunk") or "branch=" in spec or "tag=" in spec:
        reasons.append("mutable-branch-reference")
    if source_kind in {"git", "url", "path", "file"}:
        immutable_rev = any(HEX40.fullmatch(token) for token in source_value.replace("=", "#").split("#"))
        if source_kind == "git" and not immutable_rev:
            reasons.append("git-ref-is-not-an-immutable-commit")
        if source_kind in {"url", "file"} and ("/latest/" in source_value or source_value.endswith("/latest")):
            reasons.append("mutable-artifact-url")
        if source_kind == "path" and any(part == ".." for part in source_value.split("/")):
            reasons.append("path-escapes-project-root")
    return tuple(dict.fromkeys(reasons))
