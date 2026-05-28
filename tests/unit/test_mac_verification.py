"""Unit tests for MAC verification edge cases — partial corruption, field
tampering, length validation, degenerate keys, and domain separation.

These tests target the HandshakeInit/HandshakeResponse MAC verification
paths in ``meshnet.vpn.session`` and the underlying ``verify_mac`` in
``meshnet.vpn.crypto``.
"""

from __future__ import annotations

import os

import pytest

from meshnet.vpn.crypto import (
    KeyPair,
    dh,
    kdf,
    mac_blake2s,
    verify_mac,
)
from meshnet.vpn.session import PeerSession, SessionState
from meshnet.vpn.transport import (
    HandshakeInit,
    HandshakeResponse,
    parse_packet,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session_pair(
    psk: bytes | None = None,
) -> tuple[PeerSession, PeerSession]:
    """Create a pair of PeerSessions with matching static keys."""
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    a = PeerSession("!b", kp_b.public_bytes(), kp_a, preshared_key=psk)
    b = PeerSession("!a", kp_a.public_bytes(), kp_b, preshared_key=psk)
    return a, b


def _do_handshake(a: PeerSession, b: PeerSession) -> None:
    """Run a full handshake between two sessions."""
    init_bytes = a.initiate_handshake()
    init_pkt = parse_packet(init_bytes)
    resp_bytes = b.respond_to_handshake(init_pkt)
    resp_pkt = parse_packet(resp_bytes)
    a.complete_handshake(resp_pkt)


# ---------------------------------------------------------------------------
# INIT MAC edge cases
# ---------------------------------------------------------------------------


class TestInitMACPartialCorruption:
    """Verify that flipping individual bytes in the MAC is detected."""

    def test_each_mac_byte_flipped(self):
        """Flip each of the 16 MAC bytes individually — every one must fail."""
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        for i in range(16):
            tampered = bytearray(init_pkt.mac)
            tampered[i] ^= 0x01  # minimal single-bit flip in byte i
            bad_init = HandshakeInit(
                sender_session=init_pkt.sender_session,
                ephemeral_pubkey=init_pkt.ephemeral_pubkey,
                mac=bytes(tampered),
            )
            with pytest.raises(ValueError, match="MAC verification failed"):
                b.respond_to_handshake(bad_init)


class TestInitMACSessionIdTampering:
    """Verify that session_id is authenticated by the MAC."""

    def test_changed_session_id_fails_mac(self):
        """Alter the session_id while keeping the original MAC → must fail."""
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        tampered_init = HandshakeInit(
            sender_session=init_pkt.sender_session ^ 0x00000001,
            ephemeral_pubkey=init_pkt.ephemeral_pubkey,
            mac=init_pkt.mac,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(tampered_init)


class TestInitMACSingleBitEphemeralFlip:
    """Verify that a single-bit flip in the ephemeral key is caught by the MAC."""

    def test_one_bit_flip_in_ephemeral_key(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        tampered_eph = bytearray(init_pkt.ephemeral_pubkey)
        tampered_eph[0] ^= 0x01
        bad_init = HandshakeInit(
            sender_session=init_pkt.sender_session,
            ephemeral_pubkey=bytes(tampered_eph),
            mac=init_pkt.mac,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(bad_init)


class TestInitMACAllZeroMAC:
    """Verify that an all-zero MAC is rejected."""

    def test_all_zero_mac_rejected(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        bad_init = HandshakeInit(
            sender_session=init_pkt.sender_session,
            ephemeral_pubkey=init_pkt.ephemeral_pubkey,
            mac=b"\x00" * 16,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(bad_init)


class TestInitMACAllOnesMAC:
    """Verify that an all-0xFF MAC is rejected."""

    def test_all_ones_mac_rejected(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        bad_init = HandshakeInit(
            sender_session=init_pkt.sender_session,
            ephemeral_pubkey=init_pkt.ephemeral_pubkey,
            mac=b"\xff" * 16,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(bad_init)


# ---------------------------------------------------------------------------
# RESPONSE MAC edge cases
# ---------------------------------------------------------------------------


class TestResponseMACPartialCorruption:
    """Verify that flipping individual bytes in the response MAC is detected."""

    def test_each_response_mac_byte_flipped(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        for i in range(16):
            tampered = bytearray(resp_pkt.mac)
            tampered[i] ^= 0x01
            bad_resp = HandshakeResponse(
                sender_session=resp_pkt.sender_session,
                receiver_session=resp_pkt.receiver_session,
                ephemeral_pubkey=resp_pkt.ephemeral_pubkey,
                mac=bytes(tampered),
            )
            with pytest.raises(ValueError, match="MAC verification failed"):
                a.complete_handshake(bad_resp)


class TestResponseMACSwappedSessionIds:
    """Verify that swapping sender/receiver session IDs fails MAC check."""

    def test_swapped_session_ids_fails(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        # Swap sender and receiver — the MAC won't match.
        swapped = HandshakeResponse(
            sender_session=resp_pkt.receiver_session,
            receiver_session=resp_pkt.sender_session,
            ephemeral_pubkey=resp_pkt.ephemeral_pubkey,
            mac=resp_pkt.mac,
        )
        # The receiver_session check fires first if swapped receiver != local session
        with pytest.raises(ValueError):
            a.complete_handshake(swapped)


class TestResponseMACAllZero:
    """Verify that an all-zero response MAC is rejected."""

    def test_all_zero_response_mac(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        bad_resp = HandshakeResponse(
            sender_session=resp_pkt.sender_session,
            receiver_session=resp_pkt.receiver_session,
            ephemeral_pubkey=resp_pkt.ephemeral_pubkey,
            mac=b"\x00" * 16,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            a.complete_handshake(bad_resp)


class TestResponseMACEphemeralKeyTampered:
    """Verify that tampering the ephemeral key in the response fails MAC."""

    def test_tampered_response_ephemeral_key(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        bad_resp = HandshakeResponse(
            sender_session=resp_pkt.sender_session,
            receiver_session=resp_pkt.receiver_session,
            ephemeral_pubkey=os.urandom(32),
            mac=resp_pkt.mac,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            a.complete_handshake(bad_resp)


# ---------------------------------------------------------------------------
# Cross-key and domain separation
# ---------------------------------------------------------------------------


class TestCrossKeyMACAttacks:
    """Verify that MAC keys are isolated per peer and per direction."""

    def test_init_mac_from_peer_a_rejected_by_peer_c(self):
        """An INIT destined for B cannot be accepted by C (different static key)."""
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        kp_c = KeyPair.generate()

        a_to_b = PeerSession("!b", kp_b.public_bytes(), kp_a)
        c_as_b = PeerSession("!a", kp_a.public_bytes(), kp_c)

        init_bytes = a_to_b.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        # C has a different static key from B, so MAC verification must fail
        with pytest.raises(ValueError, match="MAC verification failed"):
            c_as_b.respond_to_handshake(init_pkt)

    def test_init_mac_key_differs_from_response_mac_key(self):
        """The INIT MAC key (DH of statics) differs from the RESPONSE MAC key
        (KDF over DH mix), ensuring domain separation."""
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()

        # INIT MAC key = DH(static_a, static_b)
        init_mac_key = dh(kp_a.private, kp_b.public)

        # RESPONSE MAC key requires ephemeral DH values — it cannot equal
        # init_mac_key for any real handshake.  Verify structure here:
        # resp_mac_key = KDF(dh_ee || dh_se || dh_es, "meshnet-hs-mac", "response-mac")
        fake_dh = os.urandom(96)  # 3 * 32
        resp_mac_key = kdf(fake_dh, b"meshnet-hs-mac", b"response-mac")
        assert init_mac_key != resp_mac_key

    def test_wrong_kdf_context_produces_wrong_response_mac(self):
        """Using the wrong KDF info string must produce a different key."""
        dh_mix = os.urandom(96)
        correct = kdf(dh_mix, b"meshnet-hs-mac", b"response-mac")
        wrong_info = kdf(dh_mix, b"meshnet-hs-mac", b"wrong-mac")
        wrong_salt = kdf(dh_mix, b"wrong-salt", b"response-mac")
        assert correct != wrong_info
        assert correct != wrong_salt


# ---------------------------------------------------------------------------
# Replay of old valid INIT after session established
# ---------------------------------------------------------------------------


class TestInitReplayAfterEstablished:
    """Verify that replaying a previously valid INIT does not hijack the session."""

    def test_replayed_init_with_same_session_id_ignored_by_daemon_logic(self):
        """After a handshake completes, replaying the original INIT
        with the same sender_session should be detected as a duplicate.

        Note: The daemon checks ``pkt.sender_session == session._remote_session_id``
        and ignores duplicates.  Here we verify that *if* the responder were to
        process it again, it would re-establish (the daemon's duplicate guard
        prevents this; see test_daemon_mac_handling for integration coverage).
        """
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        # First response → ESTABLISHED
        b.respond_to_handshake(init_pkt)
        assert b.state == SessionState.ESTABLISHED
        old_send_key = b.send_key

        # If the same INIT were re-processed (without daemon guard),
        # session would re-establish with new ephemeral → different keys.
        b.respond_to_handshake(init_pkt)
        assert b.state == SessionState.ESTABLISHED
        assert b.send_key != old_send_key  # new ephemeral → new keys


# ---------------------------------------------------------------------------
# Low-level verify_mac edge cases
# ---------------------------------------------------------------------------


class TestVerifyMACEdgeCases:
    """Direct tests on verify_mac for edge-case inputs."""

    def test_empty_data(self):
        key = os.urandom(32)
        tag = mac_blake2s(key, b"")
        assert verify_mac(key, b"", tag) is True

    def test_large_data(self):
        key = os.urandom(32)
        data = os.urandom(10_000)
        tag = mac_blake2s(key, data)
        assert verify_mac(key, data, tag) is True

    def test_mac_is_exactly_16_bytes(self):
        key = os.urandom(32)
        tag = mac_blake2s(key, b"data")
        assert len(tag) == 16

    def test_truncated_expected_mac_fails(self):
        """A shorter-than-16-byte expected value must not match."""
        key = os.urandom(32)
        tag = mac_blake2s(key, b"data")
        assert verify_mac(key, b"data", tag[:15]) is False

    def test_extended_expected_mac_fails(self):
        """A longer-than-16-byte expected value must not match."""
        key = os.urandom(32)
        tag = mac_blake2s(key, b"data")
        assert verify_mac(key, b"data", tag + b"\x00") is False
