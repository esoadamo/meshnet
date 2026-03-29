"""Integration tests for the MeshVPN daemon with mocked TAP and Meshtastic."""

from __future__ import annotations

import asyncio
import base64
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from meshnet.vpn.crypto import KeyPair
from meshnet.vpn.daemon import MeshVPN
from meshnet.vpn.session import SessionState
from meshnet.vpn.transport import (
    HandshakeInit,
    HandshakeResponse,
    TransportData,
    parse_packet,
)


def _write_config(kp_local: KeyPair, kp_peer: KeyPair, tmp_dir: Path) -> Path:
    """Write a minimal MeshNet config and return its path."""
    config_text = (
        "[Interface]\n"
        f"PrivateKey = {kp_local.private_base64()}\n"
        "Address = 10.0.0.1/24\n"
        "MTU = 180\n"
        "TapName = mesh0\n"
        "MeshtasticHost = 127.0.0.1\n"
        "MeshtasticPort = 4403\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {kp_peer.public_base64()}\n"
        "AllowedIPs = 10.0.0.2/32\n"
        "Endpoint = !aabbccdd\n"
    )
    config_path = tmp_dir / "mesh0.conf"
    config_path.write_text(config_text)
    return config_path


class _MockMeshtastic:
    """Mock Meshtastic client for daemon integration tests."""

    def __init__(self, ip: str, port: int = 4403):
        self.ip = ip
        self.port = port
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
    """Mock TAP device for daemon integration tests."""

    def __init__(self, name: str = "mesh0", mtu: int = 180):
        self._name = name
        self._mtu = mtu
        self._frames: asyncio.Queue[bytes] = asyncio.Queue()

    @property
    def name(self):
        return self._name

    @property
    def mtu(self):
        return self._mtu

    async def open(self, address: str):
        pass

    async def read_frame(self) -> bytes:
        return await self._frames.get()

    async def write_frame(self, frame: bytes):
        pass

    def close(self):
        pass


class TestDaemonStartStop:
    """Test that the daemon can start and stop cleanly."""

    @pytest.mark.asyncio
    async def test_start_and_stop(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        config_path = _write_config(kp_local, kp_peer, tmp_path)

        mock_mesh = _MockMeshtastic(ip="127.0.0.1")
        mock_tap = _MockTapDevice()

        vpn = MeshVPN(str(config_path))

        with (
            patch("meshnet.vpn.daemon.TapDevice", return_value=mock_tap),
            patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp,
            patch("meshnet.meshtastic_core.pub"),
        ):
            mock_tcp.TCPInterface = MagicMock()

            # Patch the Meshtastic import in daemon.start()
            with patch(
                "meshnet.meshtastic_core.Meshtastic",
                return_value=mock_mesh,
            ):
                # Run start in background and cancel after a short delay
                task = asyncio.create_task(vpn.start())
                await asyncio.sleep(0.1)
                await vpn.stop()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        assert vpn.config is not None
        assert len(vpn._sessions) == 1
        assert "!aabbccdd" in vpn._sessions


class TestDaemonProcessIncoming:
    """Test daemon's _process_incoming with mocked sessions."""

    @pytest.mark.asyncio
    async def test_process_handshake_init_from_known_peer(self, tmp_path):
        kp_local = KeyPair.generate()
        kp_peer = KeyPair.generate()
        config_path = _write_config(kp_local, kp_peer, tmp_path)

        # Manually set up just enough state
        vpn2 = MeshVPN(str(config_path))
        vpn2.config = None
        vpn2._mesh = _MockMeshtastic("127.0.0.1")
        vpn2._tap = _MockTapDevice()
        vpn2._routing = MagicMock()
        vpn2._fragmenter = MagicMock()
        vpn2._sessions = {}
        vpn2._vpn_queue = asyncio.Queue()
        vpn2._tasks = []

        from meshnet.vpn.session import PeerSession

        session = PeerSession("!aabbccdd", kp_peer.public_bytes(), kp_local)
        vpn2._sessions["!peer_sender"] = session

        # Create a fake HandshakeInit from the peer
        peer_session = PeerSession("!local", kp_local.public_bytes(), kp_peer)
        init_bytes = peer_session.initiate_handshake()

        await vpn2._process_incoming("!peer_sender", init_bytes)

        # The session should now be established
        assert vpn2._sessions["!peer_sender"].state == SessionState.ESTABLISHED
        # A response should have been sent
        assert len(vpn2._mesh.sent_packets) == 1
