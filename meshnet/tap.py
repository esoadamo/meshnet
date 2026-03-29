"""Linux TAP device management via raw ioctl.

Creates a virtual Ethernet (TAP) interface that the OS treats like a real
NIC.  Frames written to the fd appear on the interface and vice-versa.
Uses ``O_NONBLOCK`` + ``asyncio.add_reader`` for non-blocking async reads.

Requires ``CAP_NET_ADMIN`` (typically root).
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import struct
import subprocess

log = logging.getLogger(__name__)

# ioctl constants (Linux specific).
TUNSETIFF: int = 0x400454CA
IFF_TAP: int = 0x0002
IFF_NO_PI: int = 0x1000  # no extra 4-byte packet-info header


class TapDevice:
    """Async-friendly Linux TAP device."""

    def __init__(self, name: str = "mesh0", mtu: int = 180) -> None:
        self._name: str = name
        self._mtu: int = mtu
        self._fd: int = -1

    @property
    def name(self) -> str:
        return self._name

    @property
    def mtu(self) -> int:
        return self._mtu

    # -- lifecycle ----------------------------------------------------------

    async def open(self, address: str) -> None:
        """Create the TAP device, assign *address* (CIDR), set MTU, bring up.

        *address* should be e.g. ``"10.0.0.1/24"``.
        """
        self._fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)

        # Request a TAP device with the given name, no PI header.
        ifr = struct.pack("16sH14s", self._name.encode(), IFF_TAP | IFF_NO_PI, b"\x00" * 14)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)
        log.info("TAP device %s created (fd=%d)", self._name, self._fd)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["ip", "addr", "add", address, "dev", self._name],
                check=True,
                capture_output=True,
            ),
        )
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["ip", "link", "set", self._name, "mtu", str(self._mtu)],
                check=True,
                capture_output=True,
            ),
        )
        await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["ip", "link", "set", self._name, "up"],
                check=True,
                capture_output=True,
            ),
        )
        log.info("TAP %s up: address=%s mtu=%d", self._name, address, self._mtu)

    async def read_frame(self) -> bytes:
        """Read one Ethernet frame from the TAP device (async).

        Blocks until data is available using the event loop's fd reader.
        """
        loop = asyncio.get_running_loop()
        event = asyncio.Event()
        loop.add_reader(self._fd, event.set)
        try:
            await event.wait()
            # MTU + Ethernet header (14) + safety margin
            return os.read(self._fd, self._mtu + 32)
        finally:
            loop.remove_reader(self._fd)

    async def write_frame(self, frame: bytes) -> None:
        """Write an Ethernet frame to the TAP device."""
        os.write(self._fd, frame)

    def close(self) -> None:
        """Close the TAP file descriptor (the kernel destroys the interface)."""
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
            log.info("TAP device %s closed", self._name)
