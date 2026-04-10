"""
crypto_core.dsa
===============
Post-Quantum Digital Signatures (NIST FIPS 204 / FIPS 205).

Implements sign and verify for:
    - ML-DSA (Dilithium-65, NIST Level 3) — balanced performance/security
    - SLH-DSA (SPHINCS+ SHA2-128S, NIST FIPS 205) — conservative, hash-based

Security design:
    - Signing is always performed over canonical bytes produced by
      protocol.canonical.canonicalize() to guarantee deterministic, stable
      representations across platforms and JSON serializers.
    - No print() statements — uses structured logging only.
    - Verification is fail-closed: any exception → return False + log warning.
    - No information about key length or internal state is leaked in exceptions.

DSA is strictly for authentication and integrity — NOT for confidentiality.
Never mix DSA keys with KEM. They are mathematically unrelated constructions.
"""

import logging
from typing import Literal

from liboqs_runtime import get_oqs_module, resolve_sig_name
from key_management.key_manager import decode_key, encode_key

logger = logging.getLogger(__name__)

SupportedDSA = Literal["ML-DSA", "SLH-DSA"]


def dsa_sign(data: bytes, private_key_b64: str, ui_algo: SupportedDSA) -> str:
    """
    Signs data with a post-quantum signature algorithm.

    The data should be the canonical representation of the content being signed
    (use protocol.canonical.canonicalize() for structured payloads).

    Args:
        data:            Raw bytes to sign. Callers are responsible for canonical
                         preparation before calling this function.
        private_key_b64: Signer's private key in base64 url-safe encoding.
        ui_algo:         "ML-DSA" or "SLH-DSA".

    Returns:
        Signature in base64 url-safe encoding.

    Raises:
        RuntimeError: if liboqs is unavailable or algorithm not in this build.
        ValueError:   if private_key_b64 is not valid base64 or key is wrong size.
    """
    oqs         = get_oqs_module()
    oqs_name    = resolve_sig_name(ui_algo)
    private_key = decode_key(private_key_b64)

    logger.info("dsa_sign: algo=%s, data_len=%d", oqs_name, len(data))

    with oqs.Signature(oqs_name, secret_key=private_key) as sig:
        signature = sig.sign(data)

    logger.debug("dsa_sign: signature_len=%d bytes", len(signature))
    return encode_key(signature)


def dsa_verify(
    data: bytes,
    signature_b64: str,
    public_key_b64: str,
    ui_algo: SupportedDSA,
) -> bool:
    """
    Verifies a post-quantum digital signature.

    Args:
        data:           Raw bytes that were signed. Must be identical (byte-for-byte)
                        to what was passed to dsa_sign(). Use the same canonical
                        preparation function on both sides.
        signature_b64:  Signature from dsa_sign() in base64 url-safe encoding.
        public_key_b64: Signer's public key in base64 url-safe encoding.
        ui_algo:        Must match the algorithm used for signing.

    Returns:
        True if signature is valid and data is authentic.
        False if signature is invalid, data was tampered, or key is wrong.

    Note:
        This function never raises on verification failure — it returns False.
        It only raises on configuration errors (liboqs unavailable, etc.)
        which represent programming errors rather than invalid signatures.
    """
    oqs        = get_oqs_module()
    oqs_name   = resolve_sig_name(ui_algo)

    try:
        public_key = decode_key(public_key_b64)
        signature  = decode_key(signature_b64)
    except ValueError as e:
        logger.warning("dsa_verify: failed to decode key/signature: %s", e)
        return False

    logger.info("dsa_verify: algo=%s, data_len=%d, sig_len=%d, pub_key_len=%d",
                oqs_name, len(data), len(signature), len(public_key))

    with oqs.Signature(oqs_name) as sig:
        try:
            result = sig.verify(data, signature, public_key)
            logger.info("dsa_verify: result=%s", result)
            return result
        except Exception as e:
            logger.warning("dsa_verify: verification exception (invalid key/sig): %s", e)
            return False
