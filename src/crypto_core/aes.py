"""
crypto_core.aes
===============
AES-256-GCM authenticated encryption.

Single responsibility: encrypt and decrypt arbitrary bytes with a provided key.
No key derivation, no key management — this module only handles the symmetric
cipher primitive used as the DEM layer in the hybrid KEM-DEM construction.

Security notes:
    - Nonce is 12 bytes (96-bit), randomly generated per encryption call.
    - GCM authentication tag is 128-bit (appended to ciphertext by cryptography lib).
    - AES key MUST be exactly 32 bytes (256-bit). Callers are responsible for
      proper key derivation before passing keys to these functions.
    - Additional Authenticated Data (AAD) is supported for binding ciphertext to
      a specific context (e.g., the KEM ciphertext bytes).
"""

import os
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

_NONCE_LENGTH: int = 12  # bytes — 96-bit, GCM standard
_KEY_LENGTH:   int = 32  # bytes — AES-256


def aes_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: Optional[bytes] = None,
) -> tuple[bytes, bytes]:
    """
    Encrypts plaintext with AES-256-GCM.

    Args:
        key:       32-byte AES key. Must be derived via HKDF or equivalent KDF —
                   never pass raw KEM shared_secret directly.
        plaintext: Arbitrary data to encrypt.
        aad:       Optional Additional Authenticated Data. This data is
                   authenticated but NOT encrypted. Use to bind ciphertext to
                   context (e.g., KEM ciphertext or algorithm identifier).

    Returns:
        Tuple (nonce, ciphertext_with_tag) where:
        - nonce:              12 random bytes, must be stored alongside ciphertext.
        - ciphertext_with_tag: encrypted data concatenated with 16-byte GCM tag.

    Raises:
        ValueError: if key is not exactly 32 bytes.
    """
    if len(key) != _KEY_LENGTH:
        raise ValueError(
            f"AES key must be {_KEY_LENGTH} bytes, got {len(key)}."
        )

    nonce     = os.urandom(_NONCE_LENGTH)
    aesgcm    = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    logger.debug("aes_encrypt: plaintext=%d bytes, ciphertext=%d bytes",
                 len(plaintext), len(ciphertext))
    return nonce, ciphertext


def aes_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext and verifies authentication tag.

    Args:
        key:        32-byte AES key.
        nonce:      12-byte nonce used during encryption.
        ciphertext: Encrypted data including 16-byte GCM authentication tag.
        aad:        Must match the AAD used during encryption (if any).

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: if authentication fails (wrong key, tampered data, wrong AAD)
                    or if nonce length is incorrect.
    """
    if len(key) != _KEY_LENGTH:
        raise ValueError(
            f"AES key must be {_KEY_LENGTH} bytes, got {len(key)}."
        )
    if len(nonce) != _NONCE_LENGTH:
        raise ValueError(
            f"Nonce must be {_NONCE_LENGTH} bytes, got {len(nonce)}."
        )

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        # Fail closed — do not reveal whether key or data was wrong
        raise ValueError(
            "AES-GCM authentication failed: incorrect key, corrupted data, "
            "or AAD mismatch."
        )

    logger.debug("aes_decrypt: ciphertext=%d bytes, plaintext=%d bytes",
                 len(ciphertext), len(plaintext))
    return plaintext
