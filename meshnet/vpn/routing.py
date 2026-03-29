"""AllowedIPs routing table and Ethernet frame parsing.

Maps destination IP addresses extracted from Ethernet frames to the
meshtastic node ID of the peer responsible for that address range.
Uses longest-prefix-match so that more specific routes take priority.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

ETHERTYPE_IPV4: int = 0x0800
ETHERTYPE_ARP: int = 0x0806
ETHERTYPE_IPV6: int = 0x86DD

# Minimum Ethernet header length (dst[6] + src[6] + ethertype[2]).
_ETH_HEADER_LEN = 14


@dataclass(frozen=True, slots=True)
class Route:
    """A single network → peer mapping."""

    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    peer_node_id: str


class RoutingTable:
    """Longest-prefix-match routing table built from peer AllowedIPs."""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add_route(
        self,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        peer_node_id: str,
    ) -> None:
        """Add a route, keeping the list sorted by prefix length descending."""
        self._routes.append(Route(network=network, peer_node_id=peer_node_id))
        self._routes.sort(key=lambda r: r.network.prefixlen, reverse=True)

    def lookup(self, dest_ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        """Return the peer node ID for *dest_ip*, or ``None`` if no route matches."""
        for route in self._routes:
            if dest_ip in route.network:
                return route.peer_node_id
        return None

    def lookup_from_frame(self, frame: bytes) -> str | None:
        """Extract the destination IP from an Ethernet frame and look up.

        Handles IPv4, IPv6, and ARP (target protocol address).
        Returns ``None`` for unsupported ethertypes or malformed frames.
        """
        if len(frame) < _ETH_HEADER_LEN:
            return None

        (ethertype,) = struct.unpack_from("!H", frame, 12)

        if ethertype == ETHERTYPE_IPV4 and len(frame) >= 34:
            # IPv4 dest: IP header starts at byte 14, dest IP at offset +16 = byte 30..34
            dest = ipaddress.IPv4Address(frame[30:34])
            return self.lookup(dest)

        if ethertype == ETHERTYPE_ARP and len(frame) >= 42:
            # ARP target protocol address at offset 14 + 24 = byte 38..42
            dest = ipaddress.IPv4Address(frame[38:42])
            return self.lookup(dest)

        if ethertype == ETHERTYPE_IPV6 and len(frame) >= 54:
            # IPv6 dest: IP header starts at byte 14, dest IP at offset +24 = byte 38..54
            dest = ipaddress.IPv6Address(frame[38:54])
            return self.lookup(dest)

        return None
