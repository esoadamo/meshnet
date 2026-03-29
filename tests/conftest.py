"""Shared fixtures for the MeshNet test suite."""

from __future__ import annotations

import base64
import ipaddress
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from meshnet.vpn.crypto import KeyPair, generate_psk


# ---------------------------------------------------------------------------
# Crypto fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair_a() -> KeyPair:
    """A deterministic-looking key pair (freshly generated per test)."""
    return KeyPair.generate()


@pytest.fixture
def keypair_b() -> KeyPair:
    """A second key pair, different from *keypair_a*."""
    return KeyPair.generate()


@pytest.fixture
def preshared_key() -> bytes:
    """A 32-byte PSK."""
    return generate_psk()


# ---------------------------------------------------------------------------
# Config file fixtures
# ---------------------------------------------------------------------------


def _make_config_text(
    private_key_b64: str,
    address: str = "10.0.0.1/24",
    mtu: int = 180,
    tap_name: str = "mesh0",
    meshtastic_connect: str = "tcp://10.1.5.3:4403",
    peers: list[dict] | None = None,
) -> str:
    """Build a valid MeshNet config string."""
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key_b64}",
        f"Address = {address}",
        f"MTU = {mtu}",
        f"TapName = {tap_name}",
        f"MeshtasticConnect = {meshtastic_connect}",
        "",
    ]
    if peers is None:
        # Generate one default peer.
        peer_kp = KeyPair.generate()
        peer_pub_b64 = peer_kp.public_base64()
        peers = [
            {
                "public_key": peer_pub_b64,
                "allowed_ips": "10.0.0.2/32",
                "endpoint": "!aabbccdd",
            }
        ]
    for peer in peers:
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['public_key']}")
        if "preshared_key" in peer:
            lines.append(f"PresharedKey = {peer['preshared_key']}")
        lines.append(f"AllowedIPs = {peer['allowed_ips']}")
        lines.append(f"Endpoint = {peer['endpoint']}")
        lines.append("")
    return "\n".join(lines)


@pytest.fixture
def config_file(keypair_a: KeyPair) -> Path:
    """Write a minimal valid config to a temp file and return its path."""
    peer_kp = KeyPair.generate()
    text = _make_config_text(
        private_key_b64=keypair_a.private_base64(),
        peers=[
            {
                "public_key": peer_kp.public_base64(),
                "allowed_ips": "10.0.0.2/32",
                "endpoint": "!aabbccdd",
            }
        ],
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    ) as fh:
        fh.write(text)
        fh.flush()
        yield Path(fh.name)
    os.unlink(fh.name)


@pytest.fixture
def config_file_with_psk(keypair_a: KeyPair, preshared_key: bytes) -> Path:
    """Config file that includes a PresharedKey for the peer."""
    peer_kp = KeyPair.generate()
    psk_b64 = base64.b64encode(preshared_key).decode()
    text = _make_config_text(
        private_key_b64=keypair_a.private_base64(),
        peers=[
            {
                "public_key": peer_kp.public_base64(),
                "preshared_key": psk_b64,
                "allowed_ips": "10.0.0.2/32",
                "endpoint": "!aabbccdd",
            }
        ],
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    ) as fh:
        fh.write(text)
        fh.flush()
        yield Path(fh.name)
    os.unlink(fh.name)


# ---------------------------------------------------------------------------
# Helper: make_config_text accessible to tests
# ---------------------------------------------------------------------------


@pytest.fixture
def make_config_text():
    """Return the _make_config_text helper for custom config construction."""
    return _make_config_text


# ---------------------------------------------------------------------------
# Mock Meshtastic interface
# ---------------------------------------------------------------------------


class _FakePacket:
    """Minimal stub for a meshtastic sendData return value."""

    def __init__(self, packet_id: int = 42):
        self.id = packet_id


class _FakeChannel:
    """Minimal stub for a channel object."""

    def __init__(self, index: int, name: str):
        self.index = index
        self.settings = MagicMock()
        self.settings.name = name


class _FakeLocalNode:
    """Minimal stub for interface.localNode."""

    def __init__(self, channels: list[_FakeChannel] | None = None):
        self.channels = channels or [_FakeChannel(0, "jacomms")]


class _FakeTCPInterface:
    """Minimal stub replacing meshtastic.tcp_interface.TCPInterface."""

    def __init__(self, hostname: str = "", portNumber: int = 4403):
        self.hostname = hostname
        self.portNumber = portNumber
        self.localNode = _FakeLocalNode()
        self.nodes = {
            "!d45b9db8": {"user": {"longName": "postar", "shortName": "PST"}},
        }
        self._next_id = 100

    def sendData(self, data, **kwargs):
        pkt = _FakePacket(self._next_id)
        self._next_id += 1
        return pkt

    def close(self):
        pass


@pytest.fixture
def fake_tcp_interface():
    """Return a _FakeTCPInterface class for patching."""
    return _FakeTCPInterface


@pytest.fixture
def fake_packet():
    """Return a _FakePacket factory."""
    return _FakePacket


class _FakeSerialInterface:
    """Minimal stub replacing meshtastic.serial_interface.SerialInterface."""

    def __init__(self, devPath: str = ""):
        self.devPath = devPath
        self.localNode = _FakeLocalNode()
        self.nodes = {
            "!d45b9db8": {"user": {"longName": "postar", "shortName": "PST"}},
        }
        self._next_id = 100

    def sendData(self, data, **kwargs):
        pkt = _FakePacket(self._next_id)
        self._next_id += 1
        return pkt

    def close(self):
        pass


@pytest.fixture
def fake_serial_interface():
    """Return a _FakeSerialInterface class for patching."""
    return _FakeSerialInterface
