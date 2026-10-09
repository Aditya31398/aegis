"""Keys the data guard must recognise as they are issued today, and words it must not mistake for one."""
import pytest

from aegis.guards.data import scan_pii

KEYS = ["sk-ant-api03-" + "aB3" * 30, "sk-ant-admin01-" + "Zq7" * 30, "sk-proj-" + "Xy9_-" * 12,
        "sk-svcacct-" + "Q1w" * 15, "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "rk_test_" + "51Hx" * 6,
        "ghp_" + "a1" * 18, "gho_" + "Z9" * 18, "github_pat_" + "11ABC" * 9, "xoxb-1234567890-1234567890-AbCdEf",
        "AKIAIOSFODNN7EXAMPLE", "AIza" + "Sy" * 17 + "x"]
WORDS = ["sk-loading-spinner-container-big", "task-runner-config", "desk_lamp_and_chair_set",
         "ask-me-anything-0123456789abcdef", "risk-assessment-2024-quarterly", "pk-table-primary-key-column"]


@pytest.mark.parametrize("key", KEYS)
def test_issued_keys_are_found(key):
    assert scan_pii(f"use {key} for this", frozenset({"api_key"})), key


@pytest.mark.parametrize("word", WORDS)
def test_hyphenated_words_are_not_keys(word):
    assert not scan_pii(f"see {word} here", frozenset({"api_key"})), word
