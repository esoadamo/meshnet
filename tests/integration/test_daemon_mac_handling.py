"""Integration tests for daemon-level MAC error handling.

Verifies that the daemon's ``_process_incoming`` properly catches and logs
MAC verification failures for HandshakeInit and HandshakeResponse packets,
and that rapid-fire bad packets do not crash the daemon or corrupt state.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from meshnet.vpn.crypto import KeyPair
from meshnet.vpn.session import PeerSession, SessionState
from meshnet.vpn.transport import (
    HandshakeInit,
    HandshakeResponse,
    parse_packet,
)
from meshnet.vpn.daemon import MeshVPN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _MockMeshtastic:
    """Minimal mock Meshtastic client."""

    def __init__(self, connect: str = "tcp://127.0.0.1:4403"):
        self.sent_packets: list[tuple[str, bytes]] = []

    async def connect(self):
        pass

    def _register_listener(self, filter_fn, queue):
        return lambda: None

    async def _send_data_with_ack(self, payload, port_num, destination_id, **kwargs):
        self.sent_packets.append((destination_id, payload))

    def close(self):
        pass


class _MockTapDevice:
    """Minimal mock TAP device."""

    def __init__(self, name: str = "mesh0", mtu: int = 180):
        self._name = name
        self._mtu = mtu
        self.written_frames: list[bytes] = []

    @property
    def name(self):
        return self._name

    @property
    def mtu(self):
        return self._mtu

    async def open(self, address: str):
        pass

    async def read_frame(self) -> bytes:
        await asyncio.sleep(999)  # block forever
        return b""

    async def write_frame(self, frame: bytes):
        self.written_frames.append(frame)

    def close(self):
        pass


def _write_config(kp_local: KeyPair, kp_peer: KeyPair, tmp_dir: Path) -> Path:
    config_text = (
        "[Interface]\n"
        f"PrivateKey = {kp_local.private_base64()}\n"
        "Address = 10.0.0.1/24\n"
        "MTU = 180\n"
        "TapName = mesh0\n"
        "MeshtasticConnect = tcp://127.0.0.1:4403\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {kp_peer.public_base64()}\n"
        "AllowedIPs = 10.0.0.2/32\n"
        "Endpoint = !aabbccdd\n"
    )
    config_path = tmp_dir / "mesh0.conf"
    config_path.write_text(config_text)
    return config_path


def _setup_daemon(kp_local: KeyPair, kp_peer: KeyPair, tmp_path: Path) -> MeshVPN:
    """Create a MeshVPN daemon with sessions manually wired up."""
    config_path = _write_config(kp_local, kp_peer, tmp_path)
    vpn = MeshVPN(str(config_path))
    vpn.config = None
    vpn._mesh = _MockMeshtastic()
    vpn._tap = _MockTapDevice()
    vpn._routing = MagicMock()
    from meshnet.vpn.transport import Fragmenter

    vpn._fragmenter = Fragmenter()
    vpn._vpn_queue = asyncio.Queue()
    vpn._tasks = []

    session = PeerSession("!aabbccdd", kp_peer.public_bytes(), kp_local)
    vpn._sessions["!aabbccdd"] = session
    return vpn


# ---------------------------------------------------------------------------
# Tests: INIT with bad MAC
# ---------------------------------------------------------------------------


class TestDaemonBadInitMAC:
    """Daemon receives HandshakeInit with invalid MAC."""

    @pytest.mark.asyncio
    async def test_bad_init_mac_does_not_establish_session(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        # Create a legitimate INIT from the peer
        peer_session = PeerSession("!local", kp_local.public_bytes(), kp_peer)
        init_bytes = peer_session.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        # Tamper with the MAC
        tampered_mac = bytearray(init_pkt.mac)
        tampered_mac[0] ^= 0xFF
        bad_init = HandshakeInit(
            sender_session=init_pkt.sender_session,
            ephemeral_pubkey=init_pkt.ephemeral_pubkey,
            mac=bytes(tampered_mac),
        )
        bad_init_bytes = bad_init.serialize()

        # _process_incoming raises ValueError; the daemon's _mesh_to_tap_loop
        # catches it and logs a warning.  Verify the error propagates and
        # the session is NOT established.
        with pytest.raises(ValueError, match="MAC verification failed"):
            await vpn._process_incoming("!aabbccdd", bad_init_bytes)

        # Session must remain IDLE
        assert vpn._sessions["!aabbccdd"].state == SessionState.IDLE
        # No response should have been sent
        assert len(vpn._mesh.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_bad_init_mac_from_unknown_peer_ignored(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        # INIT from unknown peer
        kp_stranger = KeyPair.generate()
        stranger = PeerSession("!local", kp_local.public_bytes(), kp_stranger)
        init_bytes = stranger.initiate_handshake()

        # Should not crash — unknown peer is silently ignored
        await vpn._process_incoming("!unknown", init_bytes)
        assert "!unknown" not in vpn._sessions


# ---------------------------------------------------------------------------
# Tests: RESPONSE with bad MAC
# ---------------------------------------------------------------------------


class TestDaemonBadResponseMAC:
    """Daemon receives HandshakeResponse with invalid MAC."""

    @pytest.mark.asyncio
    async def test_bad_response_mac_does_not_establish(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        session = vpn._sessions["!aabbccdd"]

        # Initiate handshake from the daemon side
        init_bytes = session.initiate_handshake()
        assert session.state == SessionState.INIT_SENT

        # Peer generates a legitimate response
        peer_session = PeerSession("!local", kp_local.public_bytes(), kp_peer)
        init_pkt = parse_packet(init_bytes)
        resp_bytes = peer_session.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        # Tamper with the response MAC
        tampered_mac = bytearray(resp_pkt.mac)
        tampered_mac[0] ^= 0xFF
        bad_resp = HandshakeResponse(
            sender_session=resp_pkt.sender_session,
            receiver_session=resp_pkt.receiver_session,
            ephemeral_pubkey=resp_pkt.ephemeral_pubkey,
            mac=bytes(tampered_mac),
        )
        bad_resp_bytes = bad_resp.serialize()

        # Process the bad response — should log, not crash
        await vpn._process_incoming("!aabbccdd", bad_resp_bytes)

        # Session must remain INIT_SENT (not ESTABLISHED)
        assert session.state == SessionState.INIT_SENT

    @pytest.mark.asyncio
    async def test_stale_response_when_not_init_sent_ignored(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        # Session is IDLE — a response without a prior INIT should be ignored
        fake_resp = HandshakeResponse(
            sender_session=1,
            receiver_session=0,
            ephemeral_pubkey=os.urandom(32),
            mac=os.urandom(16),
        )
        await vpn._process_incoming("!aabbccdd", fake_resp.serialize())
        assert vpn._sessions["!aabbccdd"].state == SessionState.IDLE


# ---------------------------------------------------------------------------
# Tests: DoS resistance — rapid-fire bad handshakes
# ---------------------------------------------------------------------------


class TestDaemonBadMACDoSResistance:
    """Rapid-fire bad handshakes must not crash or corrupt state."""

    @pytest.mark.asyncio
    async def test_rapid_fire_bad_init_macs(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        # Send 20 INIT packets with random (invalid) MACs.
        # Each raises ValueError (caught by _mesh_to_tap_loop in production).
        for _ in range(20):
            bad_init = HandshakeInit(
                sender_session=int.from_bytes(os.urandom(4), "little"),
                ephemeral_pubkey=os.urandom(32),
                mac=os.urandom(16),
            )
            with pytest.raises(ValueError, match="MAC verification failed"):
                await vpn._process_incoming("!aabbccdd", bad_init.serialize())

        # Daemon must not have crashed; session still IDLE
        assert vpn._sessions["!aabbccdd"].state == SessionState.IDLE
        assert len(vpn._mesh.sent_packets) == 0

    @pytest.mark.asyncio
    async def test_good_handshake_succeeds_after_bad_ones(self, tmp_path):
        """After many bad INITs, a legitimate handshake still works."""
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        # Send 10 bad INITs (each raises ValueError)
        for _ in range(10):
            bad_init = HandshakeInit(
                sender_session=int.from_bytes(os.urandom(4), "little"),
                ephemeral_pubkey=os.urandom(32),
                mac=os.urandom(16),
            )
            with pytest.raises(ValueError, match="MAC verification failed"):
                await vpn._process_incoming("!aabbccdd", bad_init.serialize())

        # Now send a legitimate INIT
        peer_session = PeerSession("!local", kp_local.public_bytes(), kp_peer)
        init_bytes = peer_session.initiate_handshake()
        await vpn._process_incoming("!aabbccdd", init_bytes)

        # Session should now be ESTABLISHED
        assert vpn._sessions["!aabbccdd"].state == SessionState.ESTABLISHED
        # A response should have been sent
        assert len(vpn._mesh.sent_packets) == 1


# ---------------------------------------------------------------------------
# Tests: Duplicate INIT detection (daemon-level)
# ---------------------------------------------------------------------------


class TestDaemonDuplicateInit:
    """Verify daemon ignores duplicate INIT when session already established
    with the same sender_session."""

    @pytest.mark.asyncio
    async def test_duplicate_init_ignored_after_established(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        # Legitimate handshake
        peer_session = PeerSession("!local", kp_local.public_bytes(), kp_peer)
        init_bytes = peer_session.initiate_handshake()
        await vpn._process_incoming("!aabbccdd", init_bytes)

        assert vpn._sessions["!aabbccdd"].state == SessionState.ESTABLISHED
        established_send_key = vpn._sessions["!aabbccdd"].send_key

        # Replay the same INIT — daemon should detect duplicate and ignore
        sent_before = len(vpn._mesh.sent_packets)
        await vpn._process_incoming("!aabbccdd", init_bytes)

        # Session should remain established with same keys
        assert vpn._sessions["!aabbccdd"].state == SessionState.ESTABLISHED
        assert vpn._sessions["!aabbccdd"].send_key == established_send_key
        # No additional response sent
        assert len(vpn._mesh.sent_packets) == sent_before


# ---------------------------------------------------------------------------
# Tests: Collision tiebreaker still validates MAC
# ---------------------------------------------------------------------------


class TestDaemonCollisionMACCheck:
    """Verify that MAC is still checked during handshake collision scenarios."""

    @pytest.mark.asyncio
    async def test_collision_responder_still_checks_mac(self, tmp_path):
        """When the daemon becomes responder due to tiebreaker,
        it must still validate the MAC."""
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        vpn = _setup_daemon(kp_local, kp_peer, tmp_path)

        session = vpn._sessions["!aabbccdd"]

        # Put session in INIT_SENT to trigger collision logic
        session.initiate_handshake()
        assert session.state == SessionState.INIT_SENT

        # Determine if the daemon would become responder or stay initiator
        local_pub = session.local_keypair.public_bytes()
        peer_pub = session.peer_static_public.public_bytes_raw()

        if local_pub < peer_pub:
            # Daemon stays initiator — incoming INIT is ignored
            # This path doesn't check MAC (it ignores the packet), which is fine
            pass
        else:
            # Daemon becomes responder — MUST check MAC
            bad_init = HandshakeInit(
                sender_session=int.from_bytes(os.urandom(4), "little"),
                ephemeral_pubkey=os.urandom(32),
                mac=os.urandom(16),  # bad MAC
            )
            await vpn._process_incoming("!aabbccdd", bad_init.serialize())
            # Must NOT have established
            assert session.state != SessionState.ESTABLISHED
