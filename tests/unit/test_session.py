"""Unit tests for meshnet.vpn.session — PeerSession handshake + encrypt/decrypt."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidTag

from meshnet.vpn.crypto import KeyPair
from meshnet.vpn.session import (
    REKEY_AFTER_MESSAGES,
    REKEY_AFTER_SECONDS,
    REJECT_AFTER_MESSAGES,
    PeerSession,
    SessionState,
)
from meshnet.vpn.transport import (
    HandshakeInit,
    HandshakeResponse,
    TransportData,
    parse_packet,
)


def _make_session_pair(
    psk: bytes | None = None,
) -> tuple[PeerSession, PeerSession]:
    """Create a pair of PeerSessions with matching keys."""
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    session_a = PeerSession(
        peer_node_id="!bbbbbbbb",
        peer_static_public=kp_b.public_bytes(),
        local_keypair=kp_a,
        preshared_key=psk,
    )
    session_b = PeerSession(
        peer_node_id="!aaaaaaaa",
        peer_static_public=kp_a.public_bytes(),
        local_keypair=kp_b,
        preshared_key=psk,
    )
    return session_a, session_b


class TestPeerSessionInit:
    """Test initial state of PeerSession."""

    def test_initial_state(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession(
            peer_node_id="!aabbccdd",
            peer_static_public=peer_kp.public_bytes(),
            local_keypair=kp,
        )
        assert session.state == SessionState.IDLE
        assert session.is_established is False
        assert session.send_key is None
        assert session.recv_key is None
        assert session.send_counter == 0
        assert session.needs_rekey() is False


class TestHandshakeFlow:
    """Test the full handshake flow between two peers."""

    def test_full_handshake(self):
        a, b = _make_session_pair()

        # A initiates
        init_bytes = a.initiate_handshake()
        assert a.state == SessionState.INIT_SENT

        # B receives and responds
        init_pkt = parse_packet(init_bytes)
        assert isinstance(init_pkt, HandshakeInit)
        resp_bytes = b.respond_to_handshake(init_pkt)
        assert b.state == SessionState.ESTABLISHED

        # A completes
        resp_pkt = parse_packet(resp_bytes)
        assert isinstance(resp_pkt, HandshakeResponse)
        a.complete_handshake(resp_pkt)
        assert a.state == SessionState.ESTABLISHED

        # Keys should be mirrored
        assert a.send_key == b.recv_key
        assert a.recv_key == b.send_key

    def test_handshake_with_psk(self):
        from meshnet.vpn.crypto import generate_psk

        psk = generate_psk()
        a, b = _make_session_pair(psk=psk)

        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)
        a.complete_handshake(resp_pkt)

        assert a.is_established
        assert b.is_established
        assert a.send_key == b.recv_key

    def test_wrong_static_key_fails_init_mac(self):
        """HandshakeInit from a peer with the wrong static key should fail MAC verification."""
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        kp_wrong = KeyPair.generate()

        a = PeerSession("!b", kp_b.public_bytes(), kp_a)
        # b thinks a's public key is kp_wrong, not kp_a
        b = PeerSession("!a", kp_wrong.public_bytes(), kp_b)

        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(init_pkt)

    def test_session_id_mismatch(self):
        a, b = _make_session_pair()
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        # Tamper with the receiver_session to cause mismatch
        tampered = HandshakeResponse(
            sender_session=resp_pkt.sender_session,
            receiver_session=resp_pkt.receiver_session ^ 0xFFFFFFFF,
            ephemeral_pubkey=resp_pkt.ephemeral_pubkey,
            mac=resp_pkt.mac,
        )
        with pytest.raises(ValueError, match="Session mismatch"):
            a.complete_handshake(tampered)

    def test_complete_without_initiate(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        fake_resp = HandshakeResponse(
            sender_session=1,
            receiver_session=0,
            ephemeral_pubkey=peer_kp.public_bytes(),
            mac=b"\x00" * 16,
        )
        with pytest.raises(ValueError):
            session.complete_handshake(fake_resp)


class TestTransportEncryptDecrypt:
    """Test encrypt_frame / decrypt_frame after handshake."""

    def _establish(self, psk=None) -> tuple[PeerSession, PeerSession]:
        a, b = _make_session_pair(psk=psk)
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)
        a.complete_handshake(resp_pkt)
        return a, b

    def test_encrypt_decrypt_roundtrip(self):
        a, b = self._establish()
        frame = b"\x00" * 14 + b"\x45" + b"\x00" * 19  # minimal eth+ip
        transport = a.encrypt_frame(frame)
        assert isinstance(transport, TransportData)
        decrypted = b.decrypt_frame(transport)
        assert decrypted == frame

    def test_multiple_frames(self):
        a, b = self._establish()
        for i in range(10):
            frame = bytes([i]) * 50
            transport = a.encrypt_frame(frame)
            decrypted = b.decrypt_frame(transport)
            assert decrypted == frame

    def test_counter_increments(self):
        a, b = self._establish()
        frame = b"\x00" * 20
        t1 = a.encrypt_frame(frame)
        t2 = a.encrypt_frame(frame)
        assert t1.counter == 0
        assert t2.counter == 1

    def test_encrypt_not_established_raises(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        with pytest.raises(RuntimeError, match="not established"):
            session.encrypt_frame(b"\x00" * 20)

    def test_decrypt_not_established_raises(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        td = TransportData(counter=0, ciphertext=b"\x00" * 32)
        with pytest.raises(RuntimeError, match="not established"):
            session.decrypt_frame(td)

    def test_bidirectional(self):
        """Both sides can send and receive."""
        a, b = self._establish()
        frame_ab = b"from A to B"
        frame_ba = b"from B to A"

        transport_ab = a.encrypt_frame(frame_ab)
        assert b.decrypt_frame(transport_ab) == frame_ab

        transport_ba = b.encrypt_frame(frame_ba)
        assert a.decrypt_frame(transport_ba) == frame_ba


class TestRekey:
    """Test rekeying triggers."""

    def test_needs_rekey_after_time(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        # Force established state
        session.state = SessionState.ESTABLISHED
        session._established_at = time.monotonic() - REKEY_AFTER_SECONDS - 1
        assert session.needs_rekey() is True

    def test_needs_rekey_after_messages(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        session.state = SessionState.ESTABLISHED
        session.send_counter = REKEY_AFTER_MESSAGES
        session._established_at = time.monotonic()
        assert session.needs_rekey() is True

    def test_no_rekey_when_fresh(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        session.state = SessionState.ESTABLISHED
        session._established_at = time.monotonic()
        session.send_counter = 0
        assert session.needs_rekey() is False

    def test_no_rekey_when_idle(self):
        kp = KeyPair.generate()
        peer_kp = KeyPair.generate()
        session = PeerSession("!peer", peer_kp.public_bytes(), kp)
        assert session.needs_rekey() is False
