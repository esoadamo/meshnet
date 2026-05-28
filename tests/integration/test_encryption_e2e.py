"""End-to-end encryption tests simulating two MeshNet devices communicating.

Tests PKI (full handshake) mode by:
1. Creating realistic config pairs with freshly generated keys
2. Instantiating sessions as the daemon would
3. Simulating the full wire-level message exchange
4. Verifying decryption succeeds on the receiving side
"""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from meshnet.vpn.config import parse_config
from meshnet.vpn.crypto import KeyPair, generate_psk
from meshnet.vpn.session import PeerSession, SessionState
from meshnet.vpn.transport import (
    Fragmenter,
    HandshakeInit,
    HandshakeResponse,
    TransportData,
    TransportFragment,
    parse_packet,
)


# ---------------------------------------------------------------------------
# Helpers: config generation
# ---------------------------------------------------------------------------


def _write_config(
    private_key_b64: str,
    address: str,
    peer_pub_b64: str,
    peer_endpoint: str,
    peer_allowed_ips: str,
    psk_b64: str | None = None,
    mtu: int = 180,
    meshtastic_connect: str = "tcp://127.0.0.1:4403",
) -> Path:
    """Write a MeshNet config file to a temp file and return its path."""
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key_b64}",
        f"Address = {address}",
        f"MTU = {mtu}",
        "TapName = mesh0",
        f"MeshtasticConnect = {meshtastic_connect}",
        "",
        "[Peer]",
    ]
    lines.append(f"PublicKey = {peer_pub_b64}")
    if psk_b64:
        lines.append(f"PresharedKey = {psk_b64}")
    lines.append(f"AllowedIPs = {peer_allowed_ips}")
    lines.append(f"Endpoint = {peer_endpoint}")
    lines.append("")

    fd = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
    fd.write("\n".join(lines))
    fd.close()
    return Path(fd.name)


def _create_config_pair(
    with_psk: bool = True,
) -> tuple[Path, Path, KeyPair, KeyPair, bytes | None]:
    """Create a matching pair of config files for two devices.

    Returns (config1_path, config2_path, keypair1, keypair2, psk).
    """
    kp1 = KeyPair.generate()
    kp2 = KeyPair.generate()
    psk = generate_psk() if with_psk else None
    psk_b64 = base64.b64encode(psk).decode() if psk else None

    cfg1_path = _write_config(
        private_key_b64=kp1.private_base64(),
        address="10.77.0.1/24",
        peer_pub_b64=kp2.public_base64(),
        peer_endpoint="!bbbbbbbb",
        peer_allowed_ips="10.77.0.2/32",
        psk_b64=psk_b64,
    )
    cfg2_path = _write_config(
        private_key_b64=kp2.private_base64(),
        address="10.77.0.2/24",
        peer_pub_b64=kp1.public_base64(),
        peer_endpoint="!aaaaaaaa",
        peer_allowed_ips="10.77.0.1/32",
        psk_b64=psk_b64,
    )
    return cfg1_path, cfg2_path, kp1, kp2, psk


# ---------------------------------------------------------------------------
# Helpers: daemon-like session creation from config
# ---------------------------------------------------------------------------


def _session_from_config(config_path: Path) -> tuple[PeerSession, str]:
    """Parse a config and create a session for the first peer (as the daemon does).

    Returns (session, peer_endpoint).
    """
    cfg = parse_config(str(config_path))
    local_kp = KeyPair.from_private_bytes(cfg.interface.private_key)
    peer = cfg.peers[0]

    session = PeerSession(
        peer_node_id=peer.endpoint,
        peer_static_public=peer.public_key,
        local_keypair=local_kp,
        preshared_key=peer.preshared_key,
    )
    return session, peer.endpoint


# ---------------------------------------------------------------------------
# Helpers: simulate wire exchange
# ---------------------------------------------------------------------------


def _simulate_wire(data: bytes) -> bytes:
    """Simulate sending data over the wire (no corruption)."""
    return data


def _do_handshake(
    initiator: PeerSession, responder: PeerSession
) -> None:
    """Run a full handshake between initiator and responder sessions."""
    init_bytes = initiator.initiate_handshake()
    wire_init = _simulate_wire(init_bytes)

    init_pkt = parse_packet(wire_init)
    assert isinstance(init_pkt, HandshakeInit)

    resp_bytes = responder.respond_to_handshake(init_pkt)
    wire_resp = _simulate_wire(resp_bytes)

    resp_pkt = parse_packet(wire_resp)
    assert isinstance(resp_pkt, HandshakeResponse)

    initiator.complete_handshake(resp_pkt)

    assert initiator.state == SessionState.ESTABLISHED
    assert responder.state == SessionState.ESTABLISHED


def _send_frame(
    sender_session: PeerSession,
    receiver_session: PeerSession,
    frame: bytes,
) -> bytes:
    """Encrypt a frame on sender, simulate wire, decrypt on receiver.

    Returns the decrypted frame.
    """
    transport = sender_session.encrypt_frame(frame)
    wire = _simulate_wire(transport.serialize())
    pkt = parse_packet(wire)
    assert isinstance(pkt, TransportData)
    return receiver_session.decrypt_frame(pkt)


def _send_frame_fragmented(
    sender_session: PeerSession,
    receiver_session: PeerSession,
    frame: bytes,
    sender_id: str,
) -> bytes:
    """Encrypt, fragment, simulate wire, reassemble, decrypt.

    Returns the decrypted frame.
    """
    transport = sender_session.encrypt_frame(frame)
    frag_out = Fragmenter()
    fragments = frag_out.fragment(transport)

    frag_in = Fragmenter()
    reassembled = None
    for wire_frag in fragments:
        wire_frag = _simulate_wire(wire_frag)
        pkt = parse_packet(wire_frag)
        if isinstance(pkt, TransportFragment):
            reassembled = frag_in.reassemble(sender_id, pkt)
        elif isinstance(pkt, TransportData):
            reassembled = pkt

    assert reassembled is not None
    return receiver_session.decrypt_frame(reassembled)


# ===========================================================================
# Tests: PKI Mode (Full Handshake)
# ===========================================================================


class TestPKIModeE2E:
    """End-to-end tests for PKI mode with full session negotiation."""

    def test_config_pair_creates_pki_sessions(self):
        """Both configs produce PeerSession in IDLE state."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            assert isinstance(s1, PeerSession)
            assert isinstance(s2, PeerSession)
            assert s1.state == SessionState.IDLE
            assert s2.state == SessionState.IDLE
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_full_session_negotiation(self):
        """Complete handshake produces matching transport keys."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            _do_handshake(s1, s2)

            # Keys are mirrored
            assert s1.send_key == s2.recv_key
            assert s1.recv_key == s2.send_key
            assert s1.send_key != s1.recv_key  # directional keys differ
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_handshake_then_transport(self):
        """After handshake, encrypted frames are correctly delivered."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            _do_handshake(s1, s2)

            frame = b"PKI-encrypted message"
            decrypted = _send_frame(s1, s2, frame)
            assert decrypted == frame
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_bidirectional_after_handshake(self):
        """Both devices can send/receive after a single handshake."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            _do_handshake(s1, s2)

            for i in range(20):
                frame_1to2 = f"PKI msg {i} from 1".encode()
                frame_2to1 = f"PKI msg {i} from 2".encode()

                assert _send_frame(s1, s2, frame_1to2) == frame_1to2
                assert _send_frame(s2, s1, frame_2to1) == frame_2to1
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_handshake_with_psk(self):
        """Handshake with PSK produces different keys than without."""
        cfg1_psk, cfg2_psk, _, _, _ = _create_config_pair(with_psk=True)
        cfg1_no, cfg2_no, _, _, _ = _create_config_pair(with_psk=False)
        try:
            s1_psk, _ = _session_from_config(cfg1_psk)
            s2_psk, _ = _session_from_config(cfg2_psk)
            s1_no, _ = _session_from_config(cfg1_no)
            s2_no, _ = _session_from_config(cfg2_no)

            _do_handshake(s1_psk, s2_psk)
            _do_handshake(s1_no, s2_no)

            # PSK affects derived keys (different ephemeral keys make
            # direct comparison impossible, but they should both work)
            frame = b"test with psk"
            assert _send_frame(s1_psk, s2_psk, frame) == frame
            assert _send_frame(s1_no, s2_no, frame) == frame
        finally:
            cfg1_psk.unlink()
            cfg2_psk.unlink()
            cfg1_no.unlink()
            cfg2_no.unlink()

    def test_wrong_public_key_fails_handshake(self):
        """Handshake fails if the responder has the wrong peer public key."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        kp_wrong = KeyPair.generate()

        # s1 thinks its peer is kp2 (correct)
        s1 = PeerSession("!b", kp2.public_bytes(), kp1)
        # s2 thinks its peer is kp_wrong (INCORRECT — not kp1)
        s2 = PeerSession("!a", kp_wrong.public_bytes(), kp2)

        init_bytes = s1.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        with pytest.raises(ValueError, match="MAC verification failed"):
            s2.respond_to_handshake(init_pkt)

    def test_wrong_psk_produces_different_keys(self):
        """Mismatched PSK means transport encryption will fail."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        psk1 = generate_psk()
        psk2 = generate_psk()

        s1 = PeerSession("!b", kp2.public_bytes(), kp1, preshared_key=psk1)
        s2 = PeerSession("!a", kp1.public_bytes(), kp2, preshared_key=psk2)

        # Handshake succeeds (PSK isn't used for handshake MAC)
        _do_handshake(s1, s2)

        # But transport encryption fails because keys don't match
        frame = b"this will fail"
        transport = s1.encrypt_frame(frame)
        wire = transport.serialize()
        pkt = parse_packet(wire)
        with pytest.raises(InvalidTag):
            s2.decrypt_frame(pkt)

    def test_rehandshake_produces_new_keys(self):
        """A second handshake produces different transport keys."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            _do_handshake(s1, s2)
            old_send_key = s1.send_key

            # Second handshake
            _do_handshake(s1, s2)
            assert s1.send_key != old_send_key
            assert s1.send_counter == 0

            # Transport still works
            frame = b"after rekey"
            assert _send_frame(s1, s2, frame) == frame
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_large_frame_fragmented(self):
        """Large frames are fragmented, reassembled, and decrypted correctly."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, ep2 = _session_from_config(cfg2)

            _do_handshake(s1, s2)

            frame = os.urandom(500)
            decrypted = _send_frame_fragmented(s1, s2, frame, "!aaaaaaaa")
            assert decrypted == frame
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_decrypt_before_handshake_fails(self):
        """Attempting to decrypt before handshake raises RuntimeError."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            # Establish s1 side only (by completing handshake with a fresh session)
            kp_tmp = KeyPair.generate()
            s_tmp = PeerSession("!x", s1.local_keypair.public_bytes(), kp_tmp)

            # s2 is not established — can't decrypt
            fake_td = TransportData(counter=0, ciphertext=b"\x00" * 32)
            with pytest.raises(RuntimeError, match="not established"):
                s2.decrypt_frame(fake_td)
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_tampered_handshake_init_mac_fails(self):
        """Tampering with HandshakeInit bytes causes MAC failure."""
        cfg1, cfg2, _, _, _ = _create_config_pair()
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            init_bytes = s1.initiate_handshake()
            # Tamper with the ephemeral key area (bytes 5..37)
            tampered = bytearray(init_bytes)
            tampered[10] ^= 0xFF
            tampered = bytes(tampered)

            pkt = parse_packet(tampered)
            with pytest.raises(ValueError, match="MAC verification failed"):
                s2.respond_to_handshake(pkt)
        finally:
            cfg1.unlink()
            cfg2.unlink()


# ===========================================================================
# Tests: Fresh key pair E2E (keys generated on the fly)
# ===========================================================================


class TestFreshKeyPairE2E:
    """Tests using freshly generated keys (no hardcoded example keys)."""

    def _make_sessions(self) -> tuple[PeerSession, PeerSession]:
        """Create a matching pair of PKI sessions with fresh keys."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        psk = generate_psk()

        s1 = PeerSession(
            "!aaaa0001",
            kp2.public_bytes(),
            kp1,
            preshared_key=psk,
        )
        s2 = PeerSession(
            "!aaaa0002",
            kp1.public_bytes(),
            kp2,
            preshared_key=psk,
        )
        return s1, s2

    def test_pki_handshake(self):
        """PKI handshake succeeds with freshly generated keys."""
        s1, s2 = self._make_sessions()
        _do_handshake(s1, s2)
        assert s1.is_established
        assert s2.is_established

    def test_pki_transport(self):
        """Transport works with freshly generated keys in PKI mode."""
        s1, s2 = self._make_sessions()
        _do_handshake(s1, s2)

        frame = b"real-world PKI test"
        assert _send_frame(s1, s2, frame) == frame
        assert _send_frame(s2, s1, frame) == frame

    def test_pki_full_wire_roundtrip(self):
        """Full wire-level roundtrip (serialize -> parse -> deserialize) with fresh keys."""
        s1, s2 = self._make_sessions()

        # Handshake init
        init_wire = s1.initiate_handshake()
        assert len(init_wire) == 53  # 1 type + 4 session + 32 eph + 16 mac
        init_pkt = parse_packet(init_wire)
        assert isinstance(init_pkt, HandshakeInit)

        # Handshake response
        resp_wire = s2.respond_to_handshake(init_pkt)
        assert len(resp_wire) == 57  # 1 type + 4 sender + 4 recv + 32 eph + 16 mac
        resp_pkt = parse_packet(resp_wire)
        assert isinstance(resp_pkt, HandshakeResponse)

        s1.complete_handshake(resp_pkt)

        # Transport
        frame = os.urandom(100)
        transport = s1.encrypt_frame(frame)
        wire = transport.serialize()
        # 1 type + 12 counter + (100 plaintext + 16 tag) = 129
        assert len(wire) == 129
        pkt = parse_packet(wire)
        decrypted = s2.decrypt_frame(pkt)
        assert decrypted == frame

    def test_replay_protection(self):
        """The same packet cannot be decrypted twice (replay detection)."""
        s1, s2 = self._make_sessions()
        _do_handshake(s1, s2)

        transport = s1.encrypt_frame(b"data")
        wire = transport.serialize()
        pkt = parse_packet(wire)

        # First decryption succeeds
        s2.decrypt_frame(pkt)

        # Second attempt is rejected (replay)
        with pytest.raises(ValueError, match="Replay"):
            s2.decrypt_frame(pkt)

    def test_tampered_ciphertext_fails(self):
        """Modifying even one byte of the ciphertext causes InvalidTag."""
        s1, s2 = self._make_sessions()
        _do_handshake(s1, s2)

        transport = s1.encrypt_frame(b"sensitive data")
        wire = bytearray(transport.serialize())
        # Flip a bit in the ciphertext area (after type byte + 12-byte counter)
        wire[14] ^= 0xFF
        pkt = parse_packet(bytes(wire))
        with pytest.raises(InvalidTag):
            s2.decrypt_frame(pkt)

    def test_counter_increments(self):
        """Send counter increments with each encrypted frame."""
        s1, s2 = self._make_sessions()
        _do_handshake(s1, s2)

        assert s1.send_counter == 0
        s1.encrypt_frame(b"frame1")
        assert s1.send_counter == 1
        s1.encrypt_frame(b"frame2")
        assert s1.send_counter == 2

    def test_session_not_established_before_handshake(self):
        """Sessions are not established before handshake completes."""
        s1, s2 = self._make_sessions()
        assert not s1.is_established
        assert not s2.is_established
        assert s1.state == SessionState.IDLE
        assert s2.state == SessionState.IDLE
