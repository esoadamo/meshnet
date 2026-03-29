"""Unit tests for meshnet.meshtastic_core — Meshtastic client with mocked library."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.conftest import _FakeChannel, _FakeLocalNode, _FakePacket, _FakeTCPInterface


class TestMeshtasticClient:
    """Tests for the Meshtastic class with mocked meshtastic library."""

    @pytest.mark.asyncio
    async def test_connect_and_close(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub") as mock_pub:
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                assert mesh._connected is True
                assert mesh.interface is not None
                # pub.subscribe should have been called 3 times
                assert mock_pub.subscribe.call_count == 3
                mesh.close()
                assert mesh._connected is False

    @pytest.mark.asyncio
    async def test_require_connected_raises(self):
        from meshnet.meshtastic_core import Meshtastic

        mesh = Meshtastic("tcp://127.0.0.1")
        with pytest.raises(ConnectionError, match="Not connected"):
            mesh._require_connected()

    @pytest.mark.asyncio
    async def test_channel_requires_connection(self):
        from meshnet.meshtastic_core import Meshtastic

        mesh = Meshtastic("tcp://127.0.0.1")
        with pytest.raises(ConnectionError):
            mesh.channel("test")

    @pytest.mark.asyncio
    async def test_peer_requires_connection(self):
        from meshnet.meshtastic_core import Meshtastic

        mesh = Meshtastic("tcp://127.0.0.1")
        with pytest.raises(ConnectionError):
            mesh.peer("!aabbccdd")

    @pytest.mark.asyncio
    async def test_find_channel_index(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                idx = mesh._find_channel_index("jacomms")
                assert idx == 0

    @pytest.mark.asyncio
    async def test_find_channel_index_not_found(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                with pytest.raises(ValueError, match="not found"):
                    mesh._find_channel_index("nonexistent")

    @pytest.mark.asyncio
    async def test_resolve_node_id_by_id(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                assert mesh._resolve_node_id("!d45b9db8") == "!d45b9db8"

    @pytest.mark.asyncio
    async def test_resolve_node_id_by_name(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                assert mesh._resolve_node_id("postar") == "!d45b9db8"

    @pytest.mark.asyncio
    async def test_resolve_node_id_not_found(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                with pytest.raises(ValueError, match="not found"):
                    mesh._resolve_node_id("unknown_node")


class TestMeshtasticDispatch:
    """Test the internal listener dispatch mechanism."""

    @pytest.mark.asyncio
    async def test_register_and_dispatch(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()

                queue: asyncio.Queue = asyncio.Queue()
                unreg = mesh._register_listener(lambda p: True, queue)
                assert len(mesh._listeners) == 1

                packet = {
                    "fromId": "!aabb",
                    "decoded": {"text": "hello", "payload": b"hello", "portnum": "TEXT_MESSAGE_APP"},
                    "channel": 0,
                }
                mesh._dispatch(packet)

                # Give the event loop a chance to process
                await asyncio.sleep(0.05)
                assert not queue.empty()
                msg = queue.get_nowait()
                assert msg["text"] == "hello"
                assert msg["sender"] == "!aabb"

                unreg()
                assert len(mesh._listeners) == 0

    @pytest.mark.asyncio
    async def test_filter_rejects(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()

                queue: asyncio.Queue = asyncio.Queue()
                mesh._register_listener(lambda p: False, queue)

                packet = {"fromId": "!x", "decoded": {"text": "drop me"}, "channel": 0}
                mesh._dispatch(packet)
                await asyncio.sleep(0.05)
                assert queue.empty()


class TestMeshtasticACK:
    """Test ACK/NAK routing processing."""

    @pytest.mark.asyncio
    async def test_ack_resolves_future(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()

                fut = asyncio.get_running_loop().create_future()
                mesh._ack_futures[42] = fut

                routing_packet = {
                    "decoded": {
                        "routing": {"errorReason": "NONE"},
                        "requestId": 42,
                    },
                }
                mesh._on_receive_routing(routing_packet, interface=None)
                await asyncio.sleep(0.05)
                assert fut.done()
                assert fut.result() is True

    @pytest.mark.asyncio
    async def test_nak_sets_exception(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()

                fut = asyncio.get_running_loop().create_future()
                mesh._ack_futures[42] = fut

                routing_packet = {
                    "decoded": {
                        "routing": {"errorReason": "NO_RESPONSE"},
                        "requestId": 42,
                    },
                }
                mesh._on_receive_routing(routing_packet, interface=None)
                await asyncio.sleep(0.05)
                assert fut.done()
                with pytest.raises(ConnectionError, match="NAK"):
                    fut.result()

    @pytest.mark.asyncio
    async def test_early_ack(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()

                # ACK arrives before future is registered
                routing_packet = {
                    "decoded": {
                        "routing": {"errorReason": "NONE"},
                        "requestId": 99,
                    },
                }
                mesh._on_receive_routing(routing_packet, interface=None)
                assert 99 in mesh._early_acks
                assert mesh._early_acks[99] == "NONE"


class TestChannelSocket:
    """Test ChannelSocket send and receive."""

    @pytest.mark.asyncio
    async def test_channel_filter(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                ch = mesh.channel("jacomms")
                # Channel index 0 should match
                assert ch._filter({"channel": 0}) is True
                assert ch._filter({"channel": 1}) is False

    @pytest.mark.asyncio
    async def test_channel_recv_timeout(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                ch = mesh.channel("jacomms")
                result = await ch.recv(timeout=0.01)
                assert result is None

    @pytest.mark.asyncio
    async def test_channel_has_data(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                ch = mesh.channel("jacomms")
                assert ch.has_data() is False
                ch._queue.put_nowait({"text": "hi"})
                assert ch.has_data() is True

    @pytest.mark.asyncio
    async def test_channel_close(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                ch = mesh.channel("jacomms")
                listener_count = len(mesh._listeners)
                ch.close()
                assert len(mesh._listeners) == listener_count - 1


class TestPeerSocket:
    """Test PeerSocket send and receive."""

    @pytest.mark.asyncio
    async def test_peer_filter(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                peer = mesh.peer("!d45b9db8")
                assert peer._filter({"fromId": "!d45b9db8"}) is True
                assert peer._filter({"fromId": "!other"}) is False

    @pytest.mark.asyncio
    async def test_peer_by_name(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                peer = mesh.peer("postar")
                assert peer.node_id == "!d45b9db8"

    @pytest.mark.asyncio
    async def test_peer_recv_timeout(self):
        with patch("meshnet.meshtastic_core.tcp_interface") as mock_tcp:
            mock_tcp.TCPInterface = _FakeTCPInterface
            with patch("meshnet.meshtastic_core.pub"):
                from meshnet.meshtastic_core import Meshtastic

                mesh = Meshtastic("tcp://127.0.0.1")
                await mesh.connect()
                peer = mesh.peer("!d45b9db8")
                result = await peer.recv(timeout=0.01)
                assert result is None
