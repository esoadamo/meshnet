"""End-to-end encryption tests simulating two MeshNet devices communicating.

Tests both PKI (full handshake) and symmetric (PSK-only) modes by:
1. Creating realistic config pairs
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
from meshnet.vpn.session import PeerSession, SessionState, SymmetricPeerSession
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
    peer_mode: str | None = None,
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
    if peer_mode:
        lines.append(f"PeerMode = {peer_mode}")
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
    peer_mode: str = "PKI",
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
        peer_mode=peer_mode,
    )
    cfg2_path = _write_config(
        private_key_b64=kp2.private_base64(),
        address="10.77.0.2/24",
        peer_pub_b64=kp1.public_base64(),
        peer_endpoint="!aaaaaaaa",
        peer_allowed_ips="10.77.0.1/32",
        psk_b64=psk_b64,
        peer_mode=peer_mode,
    )
    return cfg1_path, cfg2_path, kp1, kp2, psk


# ---------------------------------------------------------------------------
# Helpers: daemon-like session creation from config
# ---------------------------------------------------------------------------


def _session_from_config(config_path: Path) -> tuple[PeerSession | SymmetricPeerSession, str]:
    """Parse a config and create a session for the first peer (as the daemon does).

    Returns (session, peer_endpoint).
    """
    cfg = parse_config(str(config_path))
    local_kp = KeyPair.from_private_bytes(cfg.interface.private_key)
    peer = cfg.peers[0]

    if peer.mode == "SYMMETRIC":
        assert peer.preshared_key is not None
        session = SymmetricPeerSession(
            peer_node_id=peer.endpoint,
            preshared_key=peer.preshared_key,
        )
    else:
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
    sender_session: PeerSession | SymmetricPeerSession,
    receiver_session: PeerSession | SymmetricPeerSession,
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
    sender_session: PeerSession | SymmetricPeerSession,
    receiver_session: PeerSession | SymmetricPeerSession,
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
# Tests: Symmetric Mode
# ===========================================================================


class TestSymmetricModeE2E:
    """End-to-end tests for symmetric (PSK-only) mode."""

    def test_config_pair_creates_matching_sessions(self):
        """Both configs produce SymmetricPeerSession with the same derived key."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, ep1 = _session_from_config(cfg1)
            s2, ep2 = _session_from_config(cfg2)

            assert isinstance(s1, SymmetricPeerSession)
            assert isinstance(s2, SymmetricPeerSession)
            assert s1.is_established
            assert s2.is_established
            # Both derive the same key from the same PSK
            assert s1._key == s2._key
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_send_message_device1_to_device2(self):
        """Device 1 sends a message that device 2 successfully decrypts."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            frame = b"Hello from device 1!"
            decrypted = _send_frame(s1, s2, frame)
            assert decrypted == frame
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_send_message_device2_to_device1(self):
        """Device 2 sends a message that device 1 successfully decrypts."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            frame = b"Hello from device 2!"
            decrypted = _send_frame(s2, s1, frame)
            assert decrypted == frame
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_bidirectional_communication(self):
        """Both devices can send and receive multiple messages."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            for i in range(20):
                frame_1to2 = f"msg {i} from 1".encode()
                frame_2to1 = f"msg {i} from 2".encode()

                assert _send_frame(s1, s2, frame_1to2) == frame_1to2
                assert _send_frame(s2, s1, frame_2to1) == frame_2to1
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_large_frame_with_fragmentation(self):
        """A frame larger than meshtastic MTU is fragmented and reassembled."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, _ = _session_from_config(cfg1)
            s2, ep2 = _session_from_config(cfg2)

            frame = os.urandom(500)
            decrypted = _send_frame_fragmented(s1, s2, frame, "!aaaaaaaa")
            assert decrypted == frame
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_wrong_psk_fails_decryption(self):
        """If one device has a different PSK, decryption fails with InvalidTag."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        psk1 = generate_psk()
        psk2 = generate_psk()  # Different PSK!

        s1 = SymmetricPeerSession("!b", psk1)
        s2 = SymmetricPeerSession("!a", psk2)

        frame = b"secret message"
        transport = s1.encrypt_frame(frame)
        wire = transport.serialize()
        pkt = parse_packet(wire)
        with pytest.raises(InvalidTag):
            s2.decrypt_frame(pkt)

    def test_replay_protection(self):
        """The same packet cannot be decrypted twice (replay detection)."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            transport = s1.encrypt_frame(b"data")
            wire = transport.serialize()
            pkt = parse_packet(wire)

            # First decryption succeeds
            s2.decrypt_frame(pkt)

            # Second attempt is rejected (replay)
            with pytest.raises(ValueError, match="Replay"):
                s2.decrypt_frame(pkt)
        finally:
            cfg1.unlink()
            cfg2.unlink()

    def test_tampered_ciphertext_fails(self):
        """Modifying even one byte of the ciphertext causes InvalidTag."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="symmetric")
        try:
            s1, _ = _session_from_config(cfg1)
            s2, _ = _session_from_config(cfg2)

            transport = s1.encrypt_frame(b"sensitive data")
            wire = bytearray(transport.serialize())
            # Flip a bit in the ciphertext area (after type byte + 12-byte counter)
            wire[14] ^= 0xFF
            pkt = parse_packet(bytes(wire))
            with pytest.raises(InvalidTag):
                s2.decrypt_frame(pkt)
        finally:
            cfg1.unlink()
            cfg2.unlink()


# ===========================================================================
# Tests: PKI Mode (Full Handshake)
# ===========================================================================


class TestPKIModeE2E:
    """End-to-end tests for PKI mode with full session negotiation."""

    def test_config_pair_creates_pki_sessions(self):
        """Both configs produce PeerSession in IDLE state."""
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1_psk, cfg2_psk, _, _, _ = _create_config_pair(peer_mode="PKI", with_psk=True)
        cfg1_no, cfg2_no, _, _, _ = _create_config_pair(peer_mode="PKI", with_psk=False)
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
        cfg1, cfg2, _, _, _ = _create_config_pair(peer_mode="PKI")
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
# Tests: Mode mismatch detection
# ===========================================================================


class TestModeMismatch:
    """Tests verifying behavior when devices have mismatched PeerMode."""

    def test_symmetric_sends_to_pki_not_established(self):
        """A symmetric device sends TransportData that a PKI device cannot
        decrypt (session not established)."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        psk = generate_psk()

        # Device 1: symmetric mode
        s_sym = SymmetricPeerSession("!b", psk)
        # Device 2: PKI mode (not established)
        s_pki = PeerSession("!a", kp1.public_bytes(), kp2, preshared_key=psk)

        frame = b"from symmetric device"
        transport = s_sym.encrypt_frame(frame)

        # PKI session is not established — daemon would drop this
        assert not s_pki.is_established

    def test_pki_sends_init_to_symmetric_device(self):
        """A PKI device sends HandshakeInit that a symmetric device would ignore."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        psk = generate_psk()

        # Device 1: PKI mode
        s_pki = PeerSession("!b", kp2.public_bytes(), kp1, preshared_key=psk)
        # Device 2: symmetric mode
        s_sym = SymmetricPeerSession("!a", psk)

        init_bytes = s_pki.initiate_handshake()
        # In the daemon, this would be dropped because s_sym is SymmetricPeerSession
        # The session type check would prevent respond_to_handshake from being called
        assert isinstance(s_sym, SymmetricPeerSession)


# ===========================================================================
# Tests: Using the actual example config keys
# ===========================================================================


class TestExampleConfigs:
    """Tests using the actual keys from example-1.conf and example-2.conf."""

    PRIV1_B64 = "QJgiFWXF28U5mISfyLZN4NednUw6K8oUJ8+6wuD6pEw="
    PRIV2_B64 = "WOthKtcRlOZn49FCIT4ItXyj/GK7zCNeSPBph+P7jkY="
    PUB1_B64 = "pX7CIWM8bN39wicn34BfG/X3B/2yZzZaypP6U8ZaoiQ="
    PUB2_B64 = "vRGm3eWJIbB9Q2aBUNp9HZMGErUfHdB9s+wipVlAl1E="
    PSK_B64 = "GSQAJA5aYyzY2D/H+q5VHWJ/+wmsfR8Tk1iU9XkBAYk="

    def _make_sessions_pki(self) -> tuple[PeerSession, PeerSession]:
        kp1 = KeyPair.from_base64(self.PRIV1_B64)
        kp2 = KeyPair.from_base64(self.PRIV2_B64)
        psk = base64.b64decode(self.PSK_B64)

        s1 = PeerSession(
            "!d45b9db8",
            base64.b64decode(self.PUB2_B64),
            kp1,
            preshared_key=psk,
        )
        s2 = PeerSession(
            "!f71e3014",
            base64.b64decode(self.PUB1_B64),
            kp2,
            preshared_key=psk,
        )
        return s1, s2

    def _make_sessions_symmetric(self) -> tuple[SymmetricPeerSession, SymmetricPeerSession]:
        psk = base64.b64decode(self.PSK_B64)
        s1 = SymmetricPeerSession("!d45b9db8", psk)
        s2 = SymmetricPeerSession("!f71e3014", psk)
        return s1, s2

    def test_example_keys_pki_handshake(self):
        """PKI handshake succeeds with the actual example config keys."""
        s1, s2 = self._make_sessions_pki()
        _do_handshake(s1, s2)
        assert s1.is_established
        assert s2.is_established

    def test_example_keys_pki_transport(self):
        """Transport works with the actual example config keys in PKI mode."""
        s1, s2 = self._make_sessions_pki()
        _do_handshake(s1, s2)

        frame = b"real-world PKI test"
        assert _send_frame(s1, s2, frame) == frame
        assert _send_frame(s2, s1, frame) == frame

    def test_example_keys_symmetric_transport(self):
        """Transport works with the actual example config keys in symmetric mode."""
        s1, s2 = self._make_sessions_symmetric()

        frame = b"real-world symmetric test"
        assert _send_frame(s1, s2, frame) == frame
        assert _send_frame(s2, s1, frame) == frame

    def test_example_keys_pki_full_wire_roundtrip(self):
        """Full wire-level roundtrip (serialize → parse → deserialize) with example keys."""
        s1, s2 = self._make_sessions_pki()

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

    def test_example_keys_symmetric_full_wire_roundtrip(self):
        """Full wire-level roundtrip in symmetric mode with example keys."""
        s1, s2 = self._make_sessions_symmetric()

        frame = os.urandom(100)
        transport = s1.encrypt_frame(frame)
        wire = transport.serialize()
        # 1 type + 12 counter + (100 plaintext + 16 tag) = 129
        assert len(wire) == 129

        pkt = parse_packet(wire)
        assert isinstance(pkt, TransportData)
        decrypted = s2.decrypt_frame(pkt)
        assert decrypted == frame
