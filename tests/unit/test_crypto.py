"""Unit tests for meshnet.vpn.crypto — key generation, DH, AEAD, MAC, KDF."""

from __future__ import annotations

import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from meshnet.vpn.crypto import (
    NONCE_LEN,
    PRIVATE_KEY_LEN,
    PSK_LEN,
    PUBLIC_KEY_LEN,
    TAG_LEN,
    KeyPair,
    decrypt,
    derive_symmetric_key,
    derive_transport_keys,
    dh,
    encrypt,
    generate_psk,
    kdf,
    mac_blake2s,
    public_key_from_base64,
    public_key_from_bytes,
    verify_mac,
)


class TestKeyPair:
    """Tests for X25519 KeyPair generation and serialisation."""

    def test_generate_produces_32_byte_keys(self):
        kp = KeyPair.generate()
        assert len(kp.private_bytes()) == PRIVATE_KEY_LEN
        assert len(kp.public_bytes()) == PUBLIC_KEY_LEN

    def test_two_generated_keys_differ(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        assert kp1.private_bytes() != kp2.private_bytes()

    def test_from_private_bytes_roundtrip(self):
        kp = KeyPair.generate()
        raw = kp.private_bytes()
        kp2 = KeyPair.from_private_bytes(raw)
        assert kp2.private_bytes() == raw
        assert kp2.public_bytes() == kp.public_bytes()

    def test_from_base64_roundtrip(self):
        kp = KeyPair.generate()
        b64 = kp.private_base64()
        kp2 = KeyPair.from_base64(b64)
        assert kp2.private_base64() == b64
        assert kp2.public_base64() == kp.public_base64()

    def test_private_base64_is_valid_base64(self):
        kp = KeyPair.generate()
        raw = base64.b64decode(kp.private_base64())
        assert len(raw) == PRIVATE_KEY_LEN

    def test_public_base64_is_valid_base64(self):
        kp = KeyPair.generate()
        raw = base64.b64decode(kp.public_base64())
        assert len(raw) == PUBLIC_KEY_LEN


class TestPublicKeyHelpers:
    """Tests for public_key_from_bytes and public_key_from_base64."""

    def test_from_bytes(self):
        kp = KeyPair.generate()
        pub = public_key_from_bytes(kp.public_bytes())
        # Verify it's usable for DH
        kp2 = KeyPair.generate()
        shared = dh(kp2.private, pub)
        assert len(shared) == 32

    def test_from_base64(self):
        kp = KeyPair.generate()
        pub = public_key_from_base64(kp.public_base64())
        kp2 = KeyPair.generate()
        shared = dh(kp2.private, pub)
        assert len(shared) == 32


class TestDiffieHellman:
    """Tests for X25519 Diffie-Hellman key exchange."""

    def test_shared_secret_is_32_bytes(self, keypair_a, keypair_b):
        secret = dh(keypair_a.private, keypair_b.public)
        assert len(secret) == 32

    def test_commutative(self, keypair_a, keypair_b):
        s1 = dh(keypair_a.private, keypair_b.public)
        s2 = dh(keypair_b.private, keypair_a.public)
        assert s1 == s2

    def test_different_pairs_different_secrets(self):
        a = KeyPair.generate()
        b = KeyPair.generate()
        c = KeyPair.generate()
        assert dh(a.private, b.public) != dh(a.private, c.public)


class TestKDF:
    """Tests for HKDF-SHA256 key derivation."""

    def test_output_length(self):
        result = kdf(b"ikm", b"salt", b"info", length=64)
        assert len(result) == 64

    def test_deterministic(self):
        r1 = kdf(b"ikm", b"salt", b"info")
        r2 = kdf(b"ikm", b"salt", b"info")
        assert r1 == r2

    def test_different_inputs_different_output(self):
        r1 = kdf(b"ikm1", b"salt", b"info")
        r2 = kdf(b"ikm2", b"salt", b"info")
        assert r1 != r2

    def test_default_length_32(self):
        result = kdf(b"ikm", b"salt", b"info")
        assert len(result) == 32


class TestDeriveTransportKeys:
    """Tests for directional transport key derivation."""

    def test_key_lengths(self):
        dh_ee = os.urandom(32)
        dh_se = os.urandom(32)
        dh_es = os.urandom(32)
        send, recv = derive_transport_keys(dh_ee, dh_se, dh_es, None, True)
        assert len(send) == 32
        assert len(recv) == 32

    def test_initiator_responder_mirrored(self):
        dh_ee = os.urandom(32)
        dh_se = os.urandom(32)
        dh_es = os.urandom(32)
        psk = generate_psk()
        i_send, i_recv = derive_transport_keys(dh_ee, dh_se, dh_es, psk, True)
        r_send, r_recv = derive_transport_keys(dh_ee, dh_se, dh_es, psk, False)
        assert i_send == r_recv
        assert i_recv == r_send

    def test_without_psk(self):
        dh_ee = os.urandom(32)
        dh_se = os.urandom(32)
        dh_es = os.urandom(32)
        i_send, i_recv = derive_transport_keys(dh_ee, dh_se, dh_es, None, True)
        r_send, r_recv = derive_transport_keys(dh_ee, dh_se, dh_es, None, False)
        assert i_send == r_recv
        assert i_recv == r_send

    def test_psk_changes_keys(self):
        dh_ee = os.urandom(32)
        dh_se = os.urandom(32)
        dh_es = os.urandom(32)
        s1, _ = derive_transport_keys(dh_ee, dh_se, dh_es, None, True)
        s2, _ = derive_transport_keys(dh_ee, dh_se, dh_es, generate_psk(), True)
        assert s1 != s2


class TestAEAD:
    """Tests for ChaCha20-Poly1305 encrypt/decrypt."""

    def test_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"hello world"
        ct = encrypt(key, 0, plaintext)
        pt = decrypt(key, 0, ct)
        assert pt == plaintext

    def test_ciphertext_longer_than_plaintext(self):
        key = os.urandom(32)
        plaintext = b"x" * 100
        ct = encrypt(key, 0, plaintext)
        assert len(ct) == len(plaintext) + TAG_LEN

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        ct = encrypt(key1, 0, b"secret")
        with pytest.raises(InvalidTag):
            decrypt(key2, 0, ct)

    def test_wrong_counter_fails(self):
        key = os.urandom(32)
        ct = encrypt(key, 0, b"secret")
        with pytest.raises(InvalidTag):
            decrypt(key, 1, ct)

    def test_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        ct = bytearray(encrypt(key, 0, b"secret"))
        ct[0] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt(key, 0, bytes(ct))

    def test_different_counters_different_ciphertext(self):
        key = os.urandom(32)
        ct0 = encrypt(key, 0, b"same")
        ct1 = encrypt(key, 1, b"same")
        assert ct0 != ct1

    def test_empty_plaintext(self):
        key = os.urandom(32)
        ct = encrypt(key, 0, b"")
        pt = decrypt(key, 0, ct)
        assert pt == b""

    def test_large_counter(self):
        key = os.urandom(32)
        ct = encrypt(key, 2**32, b"large counter")
        pt = decrypt(key, 2**32, ct)
        assert pt == b"large counter"


class TestMAC:
    """Tests for BLAKE2s keyed MAC."""

    def test_mac_length(self):
        m = mac_blake2s(os.urandom(32), b"data")
        assert len(m) == 16

    def test_verify_correct(self):
        key = os.urandom(32)
        data = b"test data"
        m = mac_blake2s(key, data)
        assert verify_mac(key, data, m) is True

    def test_verify_wrong_key(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = b"test data"
        m = mac_blake2s(key1, data)
        assert verify_mac(key2, data, m) is False

    def test_verify_wrong_data(self):
        key = os.urandom(32)
        m = mac_blake2s(key, b"data1")
        assert verify_mac(key, b"data2", m) is False

    def test_verify_tampered_mac(self):
        key = os.urandom(32)
        m = bytearray(mac_blake2s(key, b"data"))
        m[0] ^= 0xFF
        assert verify_mac(key, b"data", bytes(m)) is False

    def test_deterministic(self):
        key = os.urandom(32)
        m1 = mac_blake2s(key, b"data")
        m2 = mac_blake2s(key, b"data")
        assert m1 == m2


class TestGeneratePSK:
    """Tests for PSK generation."""

    def test_length(self):
        psk = generate_psk()
        assert len(psk) == PSK_LEN

    def test_unique(self):
        assert generate_psk() != generate_psk()


class TestDeriveSymmetricKey:
    """Tests for derive_symmetric_key (HKDF from PSK for symmetric mode)."""

    def test_output_length(self):
        key = derive_symmetric_key(os.urandom(32))
        assert len(key) == 32

    def test_deterministic(self):
        psk = os.urandom(32)
        k1 = derive_symmetric_key(psk)
        k2 = derive_symmetric_key(psk)
        assert k1 == k2

    def test_different_psk_different_key(self):
        k1 = derive_symmetric_key(os.urandom(32))
        k2 = derive_symmetric_key(os.urandom(32))
        assert k1 != k2

    def test_differs_from_raw_psk(self):
        psk = os.urandom(32)
        key = derive_symmetric_key(psk)
        assert key != psk
