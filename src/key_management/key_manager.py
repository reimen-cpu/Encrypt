"""
key_management.key_manager
===========================
Generation, serialization, and deserialization of PQC keypairs.

Supported operations:
    - Generate random KEM keypairs  (for ML-KEM-768, HQC-KEM)
    - Generate random DSA keypairs  (for ML-DSA, SLH-DSA)
    - Encode raw key bytes to base64 url-safe string
    - Decode base64 url-safe string to raw key bytes

Design principles:
    - This module has NO knowledge of encryption, decryption, or signing.
    - All keypairs are randomly generated — no deterministic/seeded generation.
    - Keys are serialized as base64 url-safe strings for UI and storage.
    - decode_key() is resilient to copy-paste artifacts (whitespace, newlines).

Key sizes at a glance (for reference when displaying in UI):
    ML-KEM-768:  public=1184 bytes (~1592 chars b64), secret=2400 bytes (~3200 chars)
    ML-DSA-65:   public=1952 bytes (~2604 chars b64), secret=4032 bytes (~5376 chars)
    SLH-DSA-*:  public=32 bytes (~44 chars b64), secret=64 bytes (~88 chars)
"""

import base64
import logging

from liboqs_runtime import (
    get_oqs_module,
    resolve_kem_name,
    resolve_sig_name,
    OQS_AVAILABLE,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Serialization utilities
# ─────────────────────────────────────────────────────────────────────────────

def encode_key(key_bytes: bytes) -> str:
    """
    Serializes raw key bytes to a base64 url-safe string.

    Args:
        key_bytes: Raw bytes of a public or private key.

    Returns:
        Base64 url-safe encoded string (no padding).
    """
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


def decode_key(key_b64: str) -> bytes:
    """
    Deserializes a base64 url-safe string to raw key bytes.

    Resilient to copy-paste artifacts: strips leading/trailing whitespace,
    internal spaces, and newlines before decoding.

    Args:
        key_b64: Base64 url-safe encoded key string (with or without padding).

    Returns:
        Raw key bytes.

    Raises:
        ValueError: if the string is not valid base64.
    """
    # Strip whitespace and newlines introduced by copy-paste
    cleaned = "".join(key_b64.split())

    # Add padding if needed
    padding_needed = len(cleaned) % 4
    if padding_needed:
        cleaned += "=" * (4 - padding_needed)

    try:
        return base64.urlsafe_b64decode(cleaned)
    except Exception as e:
        raise ValueError(f"Invalid base64 key encoding: {e}") from e


# ─────────────────────────────────────────────────────────────────────────────
#  KEM keypair generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_kem_keypair(ui_algorithm: str) -> tuple[str, str]:
    """
    Generates a random KEM keypair for the specified algorithm.

    The keypair is fully random — there is no seed or deterministic generation.
    If you need to persist the keypair, store the returned base64 strings securely.

    Args:
        ui_algorithm: Algorithm name as displayed in UI.
                      Supported: "ML-KEM-768", "HQC-KEM".

    Returns:
        Tuple (public_key_b64, private_key_b64) in base64 url-safe format.
        - public_key_b64:  Share with the party who will encrypt data to you.
        - private_key_b64: Keep secret — required to decrypt.

    Raises:
        RuntimeError: if liboqs is unavailable or algorithm not in this build.
        KeyError:     if ui_algorithm is not a known KEM algorithm name.
    """
    oqs      = get_oqs_module()
    oqs_name = resolve_kem_name(ui_algorithm)

    with oqs.KeyEncapsulation(oqs_name) as kem:
        public_key  = kem.generate_keypair()
        private_key = kem.export_secret_key()

    logger.info("generate_kem_keypair: algo=%s, pub=%d bytes, priv=%d bytes",
                oqs_name, len(public_key), len(private_key))

    return encode_key(public_key), encode_key(private_key)


# ─────────────────────────────────────────────────────────────────────────────
#  DSA keypair generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_sig_keypair(ui_algorithm: str) -> tuple[str, str]:
    """
    Generates a random DSA (signature) keypair for the specified algorithm.

    Args:
        ui_algorithm: Algorithm name as displayed in UI.
                      Supported: "ML-DSA", "SLH-DSA".

    Returns:
        Tuple (public_key_b64, private_key_b64) in base64 url-safe format.
        - public_key_b64:  Share publicly — used to verify your signatures.
        - private_key_b64: Keep secret — required to sign.

    Raises:
        RuntimeError: if liboqs is unavailable or algorithm not in this build.
        KeyError:     if ui_algorithm is not a known signature algorithm name.
    """
    oqs      = get_oqs_module()
    oqs_name = resolve_sig_name(ui_algorithm)

    with oqs.Signature(oqs_name) as sig:
        public_key  = sig.generate_keypair()
        private_key = sig.export_secret_key()

    logger.info("generate_sig_keypair: algo=%s, pub=%d bytes, priv=%d bytes",
                oqs_name, len(public_key), len(private_key))

    return encode_key(public_key), encode_key(private_key)


# ─────────────────────────────────────────────────────────────────────────────
#  Algorithm info queries
# ─────────────────────────────────────────────────────────────────────────────

def get_kem_info(ui_algorithm: str) -> dict:
    """
    Returns technical parameters of the specified KEM algorithm.

    Args:
        ui_algorithm: Algorithm UI name.

    Returns:
        Dict with keys: name, claimed_nist_level, length_public_key,
        length_secret_key, length_ciphertext, length_shared_secret.
    """
    oqs      = get_oqs_module()
    oqs_name = resolve_kem_name(ui_algorithm)

    with oqs.KeyEncapsulation(oqs_name) as kem:
        return {
            "name":                 kem.details["name"],
            "claimed_nist_level":   kem.details["claimed_nist_level"],
            "length_public_key":    kem.details["length_public_key"],
            "length_secret_key":    kem.details["length_secret_key"],
            "length_ciphertext":    kem.details["length_ciphertext"],
            "length_shared_secret": kem.details["length_shared_secret"],
        }


def get_sig_info(ui_algorithm: str) -> dict:
    """
    Returns technical parameters of the specified signature algorithm.

    Args:
        ui_algorithm: Algorithm UI name.

    Returns:
        Dict with keys: name, claimed_nist_level, length_public_key,
        length_secret_key, length_signature.
    """
    oqs      = get_oqs_module()
    oqs_name = resolve_sig_name(ui_algorithm)

    with oqs.Signature(oqs_name) as sig:
        return {
            "name":               sig.details["name"],
            "claimed_nist_level": sig.details["claimed_nist_level"],
            "length_public_key":  sig.details["length_public_key"],
            "length_secret_key":  sig.details["length_secret_key"],
            "length_signature":   sig.details["length_signature"],
        }
