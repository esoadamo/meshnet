"""WireGuard-style configuration file parser.

Handles the ``[Interface]`` section and multiple ``[Peer]`` sections.
Standard ``configparser`` cannot handle duplicate section names, so we
parse the file manually by splitting on section headers.

Example configuration::

    [Interface]
    PrivateKey = <base64 X25519 private key>
    Address = 10.0.0.1/24
    MTU = 180
    TapName = mesh0
    MeshtasticHost = 10.1.5.3
    MeshtasticPort = 4403

    [Peer]
    PublicKey = <base64 X25519 public key>
    PresharedKey = <base64 32-byte PSK>
    AllowedIPs = 10.0.0.2/32
    Endpoint = !d45b9db8
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class InterfaceConfig:
    """``[Interface]`` section."""

    private_key: bytes  # 32-byte raw X25519 private key
    address: ipaddress.IPv4Interface | ipaddress.IPv6Interface
    mtu: int
    tap_name: str
    meshtastic_host: str
    meshtastic_port: int


@dataclass(frozen=True, slots=True)
class PeerConfig:
    """One ``[Peer]`` section."""

    public_key: bytes  # 32-byte raw X25519 public key
    preshared_key: bytes | None  # 32-byte PSK or None
    allowed_ips: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    endpoint: str  # meshtastic node ID, e.g. "!d45b9db8"


@dataclass(frozen=True, slots=True)
class MeshnetConfig:
    """Complete parsed configuration file."""

    interface: InterfaceConfig
    peers: list[PeerConfig]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\[(\w+)\]\s*$")


def _parse_kv_block(lines: list[str]) -> dict[str, str]:
    """Parse ``key = value`` lines into a dict, ignoring blanks and comments."""
    kv: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        kv[key.strip()] = value.strip()
    return kv


def _split_sections(text: str) -> list[tuple[str, list[str]]]:
    """Split config text into ``(section_name, [lines])`` pairs."""
    sections: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in text.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            if current_name is not None:
                sections.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        sections.append((current_name, current_lines))

    return sections


def _parse_interface(kv: dict[str, str]) -> InterfaceConfig:
    raw_key = base64.b64decode(kv["PrivateKey"])
    if len(raw_key) != 32:
        raise ValueError(f"PrivateKey must be 32 bytes, got {len(raw_key)}")

    addr_str = kv["Address"]
    try:
        address: ipaddress.IPv4Interface | ipaddress.IPv6Interface = ipaddress.IPv4Interface(addr_str)
    except ipaddress.AddressValueError:
        address = ipaddress.IPv6Interface(addr_str)

    return InterfaceConfig(
        private_key=raw_key,
        address=address,
        mtu=int(kv.get("MTU", "180")),
        tap_name=kv.get("TapName", "mesh0"),
        meshtastic_host=kv["MeshtasticHost"],
        meshtastic_port=int(kv.get("MeshtasticPort", "4403")),
    )


def _parse_peer(kv: dict[str, str]) -> PeerConfig:
    raw_pub = base64.b64decode(kv["PublicKey"])
    if len(raw_pub) != 32:
        raise ValueError(f"PublicKey must be 32 bytes, got {len(raw_pub)}")

    psk: bytes | None = None
    if "PresharedKey" in kv:
        psk = base64.b64decode(kv["PresharedKey"])
        if len(psk) != 32:
            raise ValueError(f"PresharedKey must be 32 bytes, got {len(psk)}")

    allowed_raw = kv["AllowedIPs"]
    allowed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in allowed_raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            allowed.append(ipaddress.IPv4Network(part, strict=False))
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            allowed.append(ipaddress.IPv6Network(part, strict=False))

    endpoint = kv["Endpoint"]
    if not endpoint.startswith("!"):
        raise ValueError(f"Endpoint must be a meshtastic node ID (starts with '!'): {endpoint}")

    return PeerConfig(
        public_key=raw_pub,
        preshared_key=psk,
        allowed_ips=allowed,
        endpoint=endpoint,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_config(path: str | Path) -> MeshnetConfig:
    """Parse a MeshNet configuration file.

    Raises ``ValueError`` on malformed input and ``KeyError`` on missing
    required keys.
    """
    text = Path(path).read_text()
    sections = _split_sections(text)

    interface: InterfaceConfig | None = None
    peers: list[PeerConfig] = []

    for name, lines in sections:
        kv = _parse_kv_block(lines)
        if name == "Interface":
            if interface is not None:
                raise ValueError("Duplicate [Interface] section")
            interface = _parse_interface(kv)
        elif name == "Peer":
            peers.append(_parse_peer(kv))
        else:
            raise ValueError(f"Unknown section: [{name}]")

    if interface is None:
        raise ValueError("Missing [Interface] section")
    if not peers:
        raise ValueError("At least one [Peer] section is required")

    return MeshnetConfig(interface=interface, peers=peers)
