"""
protocol.envelope
=================
Token payload builder and parser for Encrypt PQC Suite v3.0.

Payload v3.0 schema (JSON, then base64-encoded for transport):
    {
        "v":       "3.0",               # version string — always first key (canonical)
        "kem":     "ML-KEM-768",         # KEM algorithm UI name
        "kem_ct":  "<base64>",           # KEM ciphertext (encapsulated entropy)
        "nonce":   "<base64>",           # AES-GCM nonce (12 bytes)
        "ct":      "<base64>",           # AES-GCM ciphertext + 16-byte tag
        "sig_alg": "<str | null>",       # Optional — signature algorithm UI name
        "sig":     "<base64 | null>"     # Optional — signature over canonical(envelope)
    }

Design decisions:
    - v3.0 is strictly incompatible with v2.0 (password-KEM) by design.
    - parse_envelope() fails closed: raises ValueError for unknown versions.
    - The payload is stored as base64(json) to remain copy-paste friendly.
    - Keys are sorted when building (canonical) so the payload itself can be
      signed without re-canonicalization.

Versioning policy:
    - Bump minor version (3.x) for backward-compatible additions.
    - Bump major version (x.0) for breaking changes.
    - This module only accepts v3.x tokens.
"""

import base64
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_VERSION        = "3.0"
_VERSION_MAJOR  = "3"      # accepted major version family

_REQUIRED_FIELDS = {"v", "kem", "kem_ct", "nonce", "ct"}


def build_envelope(
    kem_algo: str,
    kem_ciphertext: bytes,
    nonce: bytes,
    aes_ciphertext: bytes,
    sig_algo: Optional[str] = None,
    signature: Optional[bytes] = None,
) -> str:
    """
    Builds a v3.0 encrypted token envelope.

    Args:
        kem_algo:       UI name of the KEM algorithm (e.g. "ML-KEM-768").
        kem_ciphertext: Raw KEM ciphertext bytes from encap_secret().
        nonce:          12-byte AES-GCM nonce.
        aes_ciphertext: AES-GCM ciphertext + authentication tag bytes.
        sig_algo:       Optional — UI name of signature algorithm.
        signature:      Optional — raw signature bytes from DSA sign().

    Returns:
        Base64-encoded canonical JSON string (safe for copy-paste, QR, storage).
    """
    payload = {
        "v":       _VERSION,
        "kem":     kem_algo,
        "kem_ct":  base64.b64encode(kem_ciphertext).decode(),
        "nonce":   base64.b64encode(nonce).decode(),
        "ct":      base64.b64encode(aes_ciphertext).decode(),
        "sig_alg": sig_algo,
        "sig":     base64.b64encode(signature).decode() if signature else None,
    }

    # Canonical JSON: sorted keys, no whitespace
    canonical_json = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    token = base64.b64encode(canonical_json).decode()
    logger.debug("build_envelope: kem=%s, payload_bytes=%d, token_len=%d",
                 kem_algo, len(canonical_json), len(token))
    return token


def parse_envelope(token: str) -> dict:
    """
    Parses and validates a v3.0 encrypted token envelope.

    Performs strict validation:
        1. Must be valid base64.
        2. Inner content must be valid JSON.
        3. Must contain all required fields.
        4. Version must be in the v3.x family.

    Args:
        token: Base64-encoded envelope string produced by build_envelope().

    Returns:
        Dictionary with decoded fields, including pre-decoded byte fields:
            - "kem_ct_bytes":  bytes
            - "nonce_bytes":   bytes
            - "aes_ct_bytes":  bytes
            - "sig_bytes":     bytes | None
        All original base64 string fields are also retained.

    Raises:
        ValueError: if token is malformed, version is unsupported, or required
                    fields are missing. Always fails closed — no silent fallback.
    """
    try:
        raw_json = base64.b64decode(token.strip().encode())
        payload  = json.loads(raw_json)
    except Exception:
        raise ValueError(
            "Token is corrupted or has an invalid format (base64/JSON decode failed)."
        )

    # Version check — strict, fail-closed
    version = payload.get("v", "")
    if not version.startswith(_VERSION_MAJOR + "."):
        raise ValueError(
            f"Unsupported token version '{version}'. "
            f"This application only accepts v{_VERSION_MAJOR}.x tokens. "
            f"Tokens created with older versions (e.g. v2.0 password-KEM) "
            f"are not compatible with this system."
        )

    # Required field check
    missing = _REQUIRED_FIELDS - set(payload.keys())
    if missing:
        raise ValueError(
            f"Token payload is incomplete. Missing required fields: {missing}"
        )

    # Decode binary fields eagerly — fail fast if any are corrupted
    try:
        payload["kem_ct_bytes"] = base64.b64decode(payload["kem_ct"])
        payload["nonce_bytes"]  = base64.b64decode(payload["nonce"])
        payload["aes_ct_bytes"] = base64.b64decode(payload["ct"])
        payload["sig_bytes"]    = (
            base64.b64decode(payload["sig"])
            if payload.get("sig")
            else None
        )
    except Exception:
        raise ValueError(
            "Token payload contains corrupted binary fields (base64 decode failed)."
        )

    logger.debug("parse_envelope: version=%s, kem=%s, kem_ct=%d bytes",
                 version, payload.get("kem"), len(payload["kem_ct_bytes"]))
    return payload
