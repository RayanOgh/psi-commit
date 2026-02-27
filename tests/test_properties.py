#!/usr/bin/env python3
"""
Property-based tests using Hypothesis.
Run with: pytest tests/test_properties.py -v
"""

import pytest
from hypothesis import given, strategies as st, assume
import secrets

from psi_commit.core import seal, verify


# Strategy for generating random messages
messages = st.text(min_size=0, max_size=10000)

# Strategy for generating context strings
contexts = st.text(
    min_size=1, 
    max_size=50, 
    alphabet=st.characters(whitelist_categories=('L', 'N', 'P'))
)


@given(message=messages)
def test_seal_verify_roundtrip(message):
    """Any message should seal and verify correctly."""
    commitment, key = seal(message)
    assert verify(message, key, commitment)


@given(message=messages, context=contexts)
def test_seal_verify_with_context(message, context):
    """Messages with different contexts should work."""
    commitment, key = seal(message, context=context)
    assert verify(message, key, commitment)


@given(message=messages, tamper=st.text(min_size=1, max_size=100))
def test_tampered_message_fails(message, tamper):
    """Tampering with message should fail verification."""
    assume(message != message + tamper)
    
    commitment, key = seal(message)
    assert not verify(message + tamper, key, commitment)


@given(message=messages)
def test_wrong_key_fails(message):
    """Wrong key should fail verification."""
    commitment, correct_key = seal(message)
    wrong_key = secrets.token_bytes(32)
    
    assume(correct_key != wrong_key)
    assert not verify(message, wrong_key, commitment)


@given(message=messages)
def test_same_message_different_commitments(message):
    """Same message should produce different commitments (different nonces)."""
    commitment1, key1 = seal(message)
    commitment2, key2 = seal(message)
    
    # Nonces should differ
    assert commitment1["nonce"] != commitment2["nonce"]
    # MACs should differ (because nonces differ)
    assert commitment1["mac"] != commitment2["mac"]


@given(message=messages)
def test_commitment_structure(message):
    """Commitment should have correct structure."""
    commitment, key = seal(message)
    
    assert commitment["v"] == 1
    assert commitment["alg"] == "HMAC-SHA256"
    assert commitment["domain"].startswith("psi-commit.v1.")
    assert len(commitment["nonce"]) == 64  # 32 bytes = 64 hex chars
    assert len(commitment["mac"]) == 64    # 32 bytes = 64 hex chars
    assert len(key) == 32


@given(message=messages)
def test_key_is_32_bytes(message):
    """Generated key should always be 32 bytes."""
    commitment, key = seal(message)
    assert len(key) == 32


# Run basic tests even without Hypothesis
def test_basic_seal_verify():
    """Basic test without Hypothesis."""
    message = "Hello World"
    commitment, key = seal(message)
    assert verify(message, key, commitment)
    assert not verify("Wrong message", key, commitment)


def test_empty_message():
    """Empty message should work."""
    commitment, key = seal("")
    assert verify("", key, commitment)


def test_unicode_message():
    """Unicode messages should work."""
    message = "Hello 世界 🌍 مرحبا"
    commitment, key = seal(message)
    assert verify(message, key, commitment)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])