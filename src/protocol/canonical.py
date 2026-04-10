"""
protocol.canonical
==================
Deterministic, canonical serialization for data to be digitally signed.

The fundamental requirement for digital signatures is that the exact same
bytes must be produced on both the signing side and the verification side.
Standard json.dumps() does NOT guarantee key ordering, whitespace, or
floating-point representation across implementations and Python versions.

This module provides a single function, canonicalize(), which produces
a stable byte representation of a dict that is:
    - Alphabetically key-ordered (sort_keys=True)
    - Whitespace-free (separators=(",", ":"))
    - UTF-8 encoded with non-ASCII characters preserved (ensure_ascii=False)
    - Deterministic across Python versions and platforms for the same input

Usage in the signing workflow:
    # Signer:
    canonical_bytes = canonicalize({"alg": "ML-DSA", "data": "..."})
    signature = dsa_sign(canonical_bytes, priv_key)

    # Verifier:
    canonical_bytes = canonicalize({"alg": "ML-DSA", "data": "..."})  # SAME bytes
    valid = dsa_verify(canonical_bytes, signature, pub_key)

Note on floating point: This module intentionally does not handle float
serialization normalization. Callers should avoid including floats in
data destined for signing; use strings or integers instead.
"""

import json


def canonicalize(obj: dict) -> bytes:
    """
    Produces deterministic UTF-8 bytes from a dictionary for use in signing.

    Args:
        obj: Dictionary to serialize. Values must be JSON-serializable.
             Floats are discouraged — prefer str or int for signed content.

    Returns:
        Stable UTF-8 bytes with sorted keys and no whitespace.

    Raises:
        TypeError: if obj contains non-JSON-serializable values.

    Example:
        >>> canonicalize({"z": 1, "a": 2})
        b'{"a":2,"z":1}'
    """
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def canonicalize_bytes(data: bytes) -> bytes:
    """
    Wraps raw bytes as a canonical JSON object for signing.

    Used when the data being signed is not a dict (e.g., a raw plaintext
    or a concatenated binary blob).

    Args:
        data: Raw bytes to wrap.

    Returns:
        Canonical bytes of {"data": "<hex>"}.
    """
    return canonicalize({"data": data.hex()})
