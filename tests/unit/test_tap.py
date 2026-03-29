"""Unit tests for meshnet.vpn.tap — TapDevice with mocked OS calls."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from meshnet.vpn.tap import TapDevice


class TestTapDeviceInit:
    def test_defaults(self):
        tap = TapDevice()
        assert tap.name == "mesh0"
        assert tap.mtu == 180

    def test_custom_name_and_mtu(self):
        tap = TapDevice(name="vpn0", mtu=1400)
        assert tap.name == "vpn0"
        assert tap.mtu == 1400


class TestTapDeviceOpen:
    @pytest.mark.asyncio
    async def test_open_calls_ioctl_and_ip_commands(self):
        tap = TapDevice(name="test0", mtu=180)

        mock_fd = 42
        with (
            patch("meshnet.vpn.tap.os.open", return_value=mock_fd) as mock_os_open,
            patch("meshnet.vpn.tap.fcntl.ioctl") as mock_ioctl,
            patch("meshnet.vpn.tap.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            await tap.open("10.0.0.1/24")

        mock_os_open.assert_called_once()
        mock_ioctl.assert_called_once()
        # Should have called ip addr add, ip link set mtu, ip link set up
        assert mock_run.call_count == 3


class TestTapDeviceReadWrite:
    @pytest.mark.asyncio
    async def test_write_frame(self):
        tap = TapDevice()
        tap._fd = 99
        with patch("meshnet.vpn.tap.os.write") as mock_write:
            await tap.write_frame(b"\x00" * 20)
        mock_write.assert_called_once_with(99, b"\x00" * 20)


class TestTapDeviceClose:
    def test_close(self):
        tap = TapDevice()
        tap._fd = 99
        with patch("meshnet.vpn.tap.os.close") as mock_close:
            tap.close()
        mock_close.assert_called_once_with(99)
        assert tap._fd == -1

    def test_close_already_closed(self):
        tap = TapDevice()
        tap._fd = -1
        # Should not raise
        tap.close()

    def test_close_oserror(self):
        tap = TapDevice()
        tap._fd = 99
        with patch("meshnet.vpn.tap.os.close", side_effect=OSError("bad fd")):
            tap.close()
        assert tap._fd == -1
