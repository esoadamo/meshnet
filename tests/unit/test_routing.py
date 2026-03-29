"""Unit tests for meshnet.vpn.routing — RoutingTable and Ethernet frame parsing."""

from __future__ import annotations

import ipaddress
import struct

import pytest

from meshnet.vpn.routing import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    RoutingTable,
)


def _build_eth_header(dst: bytes, src: bytes, ethertype: int) -> bytes:
    """Build a 14-byte Ethernet header."""
    return dst + src + struct.pack("!H", ethertype)


def _build_ipv4_frame(src_ip: str, dst_ip: str) -> bytes:
    """Build a minimal Ethernet+IPv4 frame (34 bytes: 14 eth + 20 ip)."""
    eth = _build_eth_header(b"\x00" * 6, b"\x00" * 6, ETHERTYPE_IPV4)
    # Minimal IPv4 header: 20 bytes. Src at offset 12, Dst at offset 16.
    ip_header = bytearray(20)
    ip_header[0] = 0x45  # version + IHL
    src_bytes = ipaddress.IPv4Address(src_ip).packed
    dst_bytes = ipaddress.IPv4Address(dst_ip).packed
    ip_header[12:16] = src_bytes
    ip_header[16:20] = dst_bytes
    return eth + bytes(ip_header)


def _build_arp_frame(target_ip: str) -> bytes:
    """Build a minimal Ethernet+ARP frame (42 bytes: 14 eth + 28 arp)."""
    eth = _build_eth_header(b"\xFF" * 6, b"\x00" * 6, ETHERTYPE_ARP)
    arp = bytearray(28)
    # ARP: target protocol address at offset 24 (within ARP payload)
    arp[24:28] = ipaddress.IPv4Address(target_ip).packed
    return eth + bytes(arp)


def _build_ipv6_frame(dst_ip: str) -> bytes:
    """Build a minimal Ethernet+IPv6 frame (54 bytes: 14 eth + 40 ipv6)."""
    eth = _build_eth_header(b"\x00" * 6, b"\x00" * 6, ETHERTYPE_IPV6)
    ip6 = bytearray(40)
    ip6[0] = 0x60  # version
    dst_bytes = ipaddress.IPv6Address(dst_ip).packed
    ip6[24:40] = dst_bytes
    return eth + bytes(ip6)


class TestRoutingTableLookup:
    """Direct IP address lookup tests."""

    def test_single_route_match(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer1")
        assert rt.lookup(ipaddress.IPv4Address("10.0.0.5")) == "!peer1"

    def test_no_match(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer1")
        assert rt.lookup(ipaddress.IPv4Address("192.168.1.1")) is None

    def test_longest_prefix_match(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer_broad")
        rt.add_route(ipaddress.IPv4Network("10.0.0.5/32"), "!peer_specific")
        assert rt.lookup(ipaddress.IPv4Address("10.0.0.5")) == "!peer_specific"
        assert rt.lookup(ipaddress.IPv4Address("10.0.0.6")) == "!peer_broad"

    def test_multiple_routes(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer1")
        rt.add_route(ipaddress.IPv4Network("192.168.1.0/24"), "!peer2")
        assert rt.lookup(ipaddress.IPv4Address("10.0.0.1")) == "!peer1"
        assert rt.lookup(ipaddress.IPv4Address("192.168.1.1")) == "!peer2"

    def test_ipv6_route(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv6Network("fd00::/64"), "!peer_v6")
        assert rt.lookup(ipaddress.IPv6Address("fd00::1")) == "!peer_v6"
        assert rt.lookup(ipaddress.IPv6Address("fe80::1")) is None

    def test_empty_table(self):
        rt = RoutingTable()
        assert rt.lookup(ipaddress.IPv4Address("1.2.3.4")) is None


class TestRoutingTableLookupFromFrame:
    """Ethernet frame → IP lookup tests."""

    def test_ipv4_frame(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer1")
        frame = _build_ipv4_frame("10.0.0.1", "10.0.0.2")
        assert rt.lookup_from_frame(frame) == "!peer1"

    def test_arp_frame(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer1")
        frame = _build_arp_frame("10.0.0.5")
        assert rt.lookup_from_frame(frame) == "!peer1"

    def test_ipv6_frame(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv6Network("fd00::/64"), "!peer_v6")
        frame = _build_ipv6_frame("fd00::1")
        assert rt.lookup_from_frame(frame) == "!peer_v6"

    def test_frame_too_short(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("0.0.0.0/0"), "!peer1")
        assert rt.lookup_from_frame(b"\x00" * 5) is None

    def test_unsupported_ethertype(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("0.0.0.0/0"), "!peer1")
        # Ethertype 0x9999 = unknown
        frame = _build_eth_header(b"\x00" * 6, b"\x00" * 6, 0x9999) + b"\x00" * 40
        assert rt.lookup_from_frame(frame) is None

    def test_ipv4_frame_too_short_for_ip(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("0.0.0.0/0"), "!peer1")
        # 14-byte eth header with IPv4 ethertype, but only 15 bytes total (need 34)
        frame = _build_eth_header(b"\x00" * 6, b"\x00" * 6, ETHERTYPE_IPV4) + b"\x00"
        assert rt.lookup_from_frame(frame) is None

    def test_no_route_for_dest(self):
        rt = RoutingTable()
        rt.add_route(ipaddress.IPv4Network("10.0.0.0/24"), "!peer1")
        frame = _build_ipv4_frame("10.0.0.1", "192.168.1.1")
        assert rt.lookup_from_frame(frame) is None
