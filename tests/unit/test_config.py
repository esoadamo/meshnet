"""Unit tests for meshnet.vpn.config — configuration file parsing."""

from __future__ import annotations

import base64
import ipaddress
import os
import tempfile
from pathlib import Path

import pytest

from meshnet.vpn.config import (
    InterfaceConfig,
    MeshnetConfig,
    PeerConfig,
    parse_config,
)
from meshnet.vpn.crypto import KeyPair


class TestParseConfigValid:
    """Test successful parsing of valid configuration files."""

    def test_basic_config(self, config_file: Path):
        cfg = parse_config(config_file)
        assert isinstance(cfg, MeshnetConfig)
        assert isinstance(cfg.interface, InterfaceConfig)
        assert len(cfg.peers) == 1

    def test_interface_fields(self, config_file: Path, keypair_a: KeyPair):
        cfg = parse_config(config_file)
        iface = cfg.interface
        assert iface.private_key == keypair_a.private_bytes()
        assert iface.address == ipaddress.IPv4Interface("10.0.0.1/24")
        assert iface.mtu == 180
        assert iface.tap_name == "mesh0"
        assert iface.meshtastic_connect == "tcp://10.1.5.3:4403"

    def test_peer_fields(self, config_file: Path):
        cfg = parse_config(config_file)
        peer = cfg.peers[0]
        assert isinstance(peer, PeerConfig)
        assert len(peer.public_key) == 32
        assert peer.preshared_key is None
        assert peer.endpoint == "!aabbccdd"
        assert ipaddress.IPv4Network("10.0.0.2/32") in peer.allowed_ips

    def test_config_with_psk(self, config_file_with_psk: Path, preshared_key: bytes):
        cfg = parse_config(config_file_with_psk)
        assert cfg.peers[0].preshared_key == preshared_key

    def test_multiple_peers(self, make_config_text):
        kp = KeyPair.generate()
        peer1 = KeyPair.generate()
        peer2 = KeyPair.generate()
        text = make_config_text(
            private_key_b64=kp.private_base64(),
            peers=[
                {
                    "public_key": peer1.public_base64(),
                    "allowed_ips": "10.0.0.2/32",
                    "endpoint": "!11111111",
                },
                {
                    "public_key": peer2.public_base64(),
                    "allowed_ips": "10.0.0.3/32",
                    "endpoint": "!22222222",
                },
            ],
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            cfg = parse_config(f.name)
        os.unlink(f.name)
        assert len(cfg.peers) == 2
        assert cfg.peers[0].endpoint == "!11111111"
        assert cfg.peers[1].endpoint == "!22222222"

    def test_multiple_allowed_ips(self, make_config_text):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = make_config_text(
            private_key_b64=kp.private_base64(),
            peers=[
                {
                    "public_key": peer.public_base64(),
                    "allowed_ips": "10.0.0.0/24, 192.168.1.0/24",
                    "endpoint": "!aabbccdd",
                },
            ],
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            cfg = parse_config(f.name)
        os.unlink(f.name)
        assert len(cfg.peers[0].allowed_ips) == 2

    def test_default_mtu(self, make_config_text):
        """MTU defaults to 180 if not specified."""
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            cfg = parse_config(f.name)
        os.unlink(f.name)
        assert cfg.interface.mtu == 180

    def test_comments_and_blanks(self, make_config_text):
        """Lines starting with # and blank lines are ignored."""
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "# This is a comment\n"
            "\n"
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "# Another comment\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            cfg = parse_config(f.name)
        os.unlink(f.name)
        assert cfg.interface.meshtastic_connect == "tcp://10.1.5.3:4403"


class TestParseConfigErrors:
    """Test error handling for invalid configuration files."""

    def _write_and_parse(self, text: str) -> MeshnetConfig:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            try:
                return parse_config(f.name)
            finally:
                os.unlink(f.name)

    def test_missing_interface_section(self):
        kp = KeyPair.generate()
        text = (
            "[Peer]\n"
            f"PublicKey = {kp.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="Missing.*Interface"):
            self._write_and_parse(text)

    def test_duplicate_interface_section(self):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="Duplicate"):
            self._write_and_parse(text)

    def test_no_peers(self):
        kp = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
        )
        with pytest.raises(ValueError, match="At least one.*Peer"):
            self._write_and_parse(text)

    def test_unknown_section(self):
        kp = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Bogus]\n"
            "Key = value\n"
        )
        with pytest.raises(ValueError, match="Unknown section"):
            self._write_and_parse(text)

    def test_invalid_private_key_length(self):
        bad_key = base64.b64encode(b"\x00" * 16).decode()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {bad_key}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="PrivateKey must be 32"):
            self._write_and_parse(text)

    def test_invalid_public_key_length(self):
        kp = KeyPair.generate()
        bad_pub = base64.b64encode(b"\x00" * 16).decode()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Peer]\n"
            f"PublicKey = {bad_pub}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="PublicKey must be 32"):
            self._write_and_parse(text)

    def test_endpoint_missing_bang(self):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = d45b9db8\n"
        )
        with pytest.raises(ValueError, match="starts with '!'"):
            self._write_and_parse(text)

    def test_missing_private_key(self):
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(KeyError):
            self._write_and_parse(text)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_config("/nonexistent/path/mesh.conf")

    def test_invalid_connect_scheme(self):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = http://10.1.5.3\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="tcp:// or serial://"):
            self._write_and_parse(text)

    def test_tcp_connect_missing_hostname(self):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://:4403\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="hostname"):
            self._write_and_parse(text)

    def test_tcp_connect_with_path(self):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = tcp://10.1.5.3:4403/extra\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="path/query/fragment"):
            self._write_and_parse(text)

    def test_serial_connect_missing_device(self):
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = (
            "[Interface]\n"
            f"PrivateKey = {kp.private_base64()}\n"
            "Address = 10.0.0.1/24\n"
            "MeshtasticConnect = serial://\n"
            "[Peer]\n"
            f"PublicKey = {peer.public_base64()}\n"
            "AllowedIPs = 10.0.0.2/32\n"
            "Endpoint = !aabbccdd\n"
        )
        with pytest.raises(ValueError, match="device path"):
            self._write_and_parse(text)

    def test_serial_connect_valid_linux(self, make_config_text):
        """serial:///dev/ttyUSB0 should parse successfully."""
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = make_config_text(
            private_key_b64=kp.private_base64(),
            meshtastic_connect="serial:///dev/ttyUSB0",
            peers=[
                {
                    "public_key": peer.public_base64(),
                    "allowed_ips": "10.0.0.2/32",
                    "endpoint": "!aabbccdd",
                },
            ],
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            cfg = parse_config(f.name)
        os.unlink(f.name)
        assert cfg.interface.meshtastic_connect == "serial:///dev/ttyUSB0"

    def test_serial_connect_valid_windows(self, make_config_text):
        """serial://COM3 should parse successfully."""
        kp = KeyPair.generate()
        peer = KeyPair.generate()
        text = make_config_text(
            private_key_b64=kp.private_base64(),
            meshtastic_connect="serial://COM3",
            peers=[
                {
                    "public_key": peer.public_base64(),
                    "allowed_ips": "10.0.0.2/32",
                    "endpoint": "!aabbccdd",
                },
            ],
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
            f.write(text)
            f.flush()
            cfg = parse_config(f.name)
        os.unlink(f.name)
        assert cfg.interface.meshtastic_connect == "serial://COM3"
