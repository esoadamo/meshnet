"""Cryptographic primitives for MeshNet VPN.

Provides X25519 key exchange, ChaCha20-Poly1305 AEAD encryption,
HKDF-SHA256 key derivation, and BLAKE2s keyed MACs — matching the
WireGuard cryptographic suite.
"""

from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass
from hashlib import blake2s

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Key pair
# ---------------------------------------------------------------------------

PRIVATE_KEY_LEN = 32
PUBLIC_KEY_LEN = 32
PSK_LEN = 32
TAG_LEN = 16  # Poly1305 tag appended by ChaCha20Poly1305
NONCE_LEN = 12  # ChaCha20-Poly1305 nonce length


@dataclass(frozen=True)
class KeyPair:
    """An X25519 key pair (Curve25519 Diffie-Hellman)."""

    private: X25519PrivateKey
    public: X25519PublicKey

    # -- constructors -------------------------------------------------------

    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a fresh random X25519 key pair."""
        priv = X25519PrivateKey.generate()
        return cls(private=priv, public=priv.public_key())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> KeyPair:
        """Reconstruct a key pair from 32 raw private-key bytes."""
        priv = X25519PrivateKey.from_private_bytes(raw)
        return cls(private=priv, public=priv.public_key())

    @classmethod
    def from_base64(cls, b64: str) -> KeyPair:
        """Reconstruct a key pair from a base64-encoded private key."""
        return cls.from_private_bytes(base64.b64decode(b64))

    # -- serialisation ------------------------------------------------------

    def private_bytes(self) -> bytes:
        """Return the 32-byte raw private key."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        return self.private.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

    def public_bytes(self) -> bytes:
        """Return the 32-byte raw public key."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return self.public.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )

    def private_base64(self) -> str:
        """Base64-encoded private key string."""
        return base64.b64encode(self.private_bytes()).decode()

    def public_base64(self) -> str:
        """Base64-encoded public key string."""
        return base64.b64encode(self.public_bytes()).decode()


def public_key_from_bytes(raw: bytes) -> X25519PublicKey:
    """Load an X25519 public key from 32 raw bytes."""
    return X25519PublicKey.from_public_bytes(raw)


def public_key_from_base64(b64: str) -> X25519PublicKey:
    """Load an X25519 public key from a base64 string."""
    return public_key_from_bytes(base64.b64decode(b64))


# ---------------------------------------------------------------------------
# Diffie-Hellman
# ---------------------------------------------------------------------------


def dh(private: X25519PrivateKey, public: X25519PublicKey) -> bytes:
    """Compute the X25519 shared secret (32 bytes)."""
    return private.exchange(public)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def kdf(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """HKDF-SHA256 key derivation."""
    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_transport_keys(
    dh_ee: bytes,
    dh_se: bytes,
    dh_es: bytes,
    psk: bytes | None,
    is_initiator: bool,
) -> tuple[bytes, bytes]:
    """Derive directional transport keys from three DH outputs + optional PSK.

    Returns ``(send_key, recv_key)`` — each 32 bytes.  The *initiator*
    and *responder* get mirrored key pairs so that the initiator's send key
    equals the responder's receive key and vice-versa.
    """
    ikm = dh_ee + dh_se + dh_es
    salt = psk if psk else b"\x00" * PSK_LEN
    key_material = kdf(ikm, salt, b"meshnet-transport-keys", length=64)
    key_i_to_r = key_material[:32]
    key_r_to_i = key_material[32:]
    if is_initiator:
        return (key_i_to_r, key_r_to_i)
    return (key_r_to_i, key_i_to_r)


# ---------------------------------------------------------------------------
# Symmetric AEAD
# ---------------------------------------------------------------------------


def encrypt(key: bytes, counter: int, plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305 AEAD encrypt.

    Nonce is an 8-byte little-endian *counter* zero-padded to 12 bytes.
    Returns ``ciphertext || tag`` (16-byte Poly1305 tag appended).

    :raises OverflowError: if *counter* exceeds the 8-byte nonce space.
    """
    if counter < 0 or counter >= 2**64:
        raise OverflowError(
            f"Nonce counter out of range: {counter} (must be 0..2^64-1)"
        )
    nonce = counter.to_bytes(8, "little") + b"\x00" * 4
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, associated_data=None)


def decrypt(key: bytes, counter: int, ciphertext: bytes) -> bytes:
    """ChaCha20-Poly1305 AEAD decrypt.

    Raises ``cryptography.exceptions.InvalidTag`` on authentication failure.

    :raises OverflowError: if *counter* exceeds the 8-byte nonce space.
    """
    if counter < 0 or counter >= 2**64:
        raise OverflowError(
            f"Nonce counter out of range: {counter} (must be 0..2^64-1)"
        )
    nonce = counter.to_bytes(8, "little") + b"\x00" * 4
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# BLAKE2s MAC
# ---------------------------------------------------------------------------


def mac_blake2s(key: bytes, data: bytes) -> bytes:
    """Compute a 16-byte BLAKE2s keyed MAC."""
    return blake2s(data, key=key, digest_size=16).digest()


def verify_mac(key: bytes, data: bytes, expected: bytes) -> bool:
    """Constant-time BLAKE2s MAC verification."""
    return hmac.compare_digest(mac_blake2s(key, data), expected)


# ---------------------------------------------------------------------------
# PSK generation
# ---------------------------------------------------------------------------


def generate_psk() -> bytes:
    """Generate a random 32-byte preshared key."""
    return os.urandom(PSK_LEN)


def derive_symmetric_key(psk: bytes) -> bytes:
    """Derive a 32-byte ChaCha20-Poly1305 key from a PSK for symmetric mode.

    Uses HKDF-SHA256 with a fixed salt so that both peers deterministically
    arrive at the same transport key without a handshake.
    """
    return kdf(ikm=psk, salt=b"symmetric", info=b"meshnet-symmetric-key", length=32)
