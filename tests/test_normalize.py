"""Normalization tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import pytest

from slopsquatgate.normalize import (
    damerau_levenshtein,
    exact_version,
    extract_host,
    fold_name,
    is_transposition,
    mutable_reasons,
    similarity_candidates,
    unicode_hazards,
)

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"


def test_attribution_constant() -> None:
    import slopsquatgate

    assert slopsquatgate.ATTRIBUTION == ATTRIBUTION


@pytest.mark.parametrize(
    ("raw", "ecosystem", "expected"),
    [
        ("Requests", "pypi", "requests"),
        ("req.uests", "pypi", "req-uests"),
        ("serde_json", "cargo", "serde-json"),
        ("github.com/Org/Repo", "go", "github.com/org/repo"),
        ("rеquests", "pypi", "requests"),
    ],
)
def test_fold_name(raw: str, ecosystem: str, expected: str) -> None:
    assert fold_name(raw, ecosystem) == expected


def test_unicode_hazards_detect_cyrillic_and_zero_width() -> None:
    hazards = unicode_hazards("req\u200bеsts")
    labels = [item[2] for item in hazards]
    assert any("CYRILLIC" in label for label in labels)
    assert any("ZERO WIDTH" in label for label in labels)


def test_damerau_levenshtein_transposition_and_bounds() -> None:
    assert damerau_levenshtein("reqeusts", "requests") == 1
    assert damerau_levenshtein("lodahs", "lodash") == 1
    assert damerau_levenshtein("abc", "xyz", 1) == 2
    assert damerau_levenshtein("same", "same") == 0


def test_is_transposition() -> None:
    assert is_transposition("lodahs", "lodash") is True
    assert is_transposition("abc", "acb") is True
    assert is_transposition("abc", "abd") is False
    assert is_transposition("ab", "abc") is False


def test_similarity_candidates_ranks_confusable_and_single_edit() -> None:
    matches = similarity_candidates("urllb3", frozenset({"urllib3", "requests"}), "pypi", 2)
    assert matches[0]["name"] == "urllib3"
    assert matches[0]["reason"] == "single-edit"
    confusable = similarity_candidates("rеquests", frozenset({"requests"}), "pypi", 2)
    assert confusable == ()


def test_extract_host_variants() -> None:
    assert extract_host("https://cdn.evil.invalid/pkg.whl") == "cdn.evil.invalid"
    assert extract_host("--extra-index-url https://mirror.evil.invalid/simple") == "mirror.evil.invalid"
    assert extract_host("git@github.com:org/repo.git") == "github.com"
    assert extract_host("github.com/google/uuid v1.6.0") == "github.com"
    assert extract_host("replace github.com/a/b => github.com/c/d v1.0.0") == "github.com"
    assert extract_host("@scope/pkg") == ""


def test_exact_version_only_accepts_pins() -> None:
    assert exact_version("==1.2.3") == "1.2.3"
    assert exact_version("v1.6.0") == "1.6.0"
    assert exact_version("^1.2.3") == ""
    assert exact_version(">=1.0,<2.0") == ""
    assert exact_version("*") == ""


@pytest.mark.parametrize(
    ("spec", "kind", "source", "expected"),
    [
        ("*", "registry", "", "missing-or-wildcard-version"),
        ("main", "git", "https://github.com/a/b", "mutable-branch-reference"),
        ("", "git", "https://github.com/a/b", "git-ref-is-not-an-immutable-commit"),
        ("", "git", "https://github.com/a/b#rev=" + "a" * 40, ""),
        ("", "path", "../outside", "path-escapes-project-root"),
    ],
)
def test_mutable_reasons(spec: str, kind: str, source: str, expected: str) -> None:
    reasons = mutable_reasons(spec, kind, source)
    if expected:
        assert expected in reasons
    else:
        assert "git-ref-is-not-an-immutable-commit" not in reasons
