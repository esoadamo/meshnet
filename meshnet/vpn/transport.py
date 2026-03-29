"""Wire protocol: packet types, serialization, and fragmentation.

All MeshNet packets start with a 1-byte type discriminator.  Four message
types are defined:

=====  ==================  ==============================================
Type   Name                Layout (after type byte)
=====  ==================  ==============================================
0x01   HandshakeInit       session(4) + eph_pub(32) + mac(16)  = 52 bytes
0x02   HandshakeResponse   sender(4) + recv(4) + eph_pub(32) + mac(16) = 56 bytes
0x03   TransportData       counter(8) + ciphertext(N)
0x04   TransportFragment   msg_id(2) + frag_idx(1) + frag_total(1) + chunk(N)
=====  ==================  ==============================================
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum

# Max payload the meshtastic radio can carry in one packet.
MAX_MESHTASTIC_PAYLOAD = 233


class MessageType(IntEnum):
    """One-byte discriminator at the start of every MeshNet packet."""

    HANDSHAKE_INIT = 0x01
    HANDSHAKE_RESPONSE = 0x02
    TRANSPORT_DATA = 0x03
    TRANSPORT_FRAGMENT = 0x04


# ---------------------------------------------------------------------------
# Packet dataclasses
# ---------------------------------------------------------------------------

# -- Handshake Init (0x01) --------------------------------------------------

_INIT_FMT = "<I32s16s"  # session_u32, eph_pub_32, mac_16
_INIT_SIZE = struct.calcsize(_INIT_FMT)  # 52


@dataclass(frozen=True, slots=True)
class HandshakeInit:
    """Initiator → responder: ephemeral public key + authentication MAC."""

    sender_session: int  # uint32
    ephemeral_pubkey: bytes  # 32 bytes
    mac: bytes  # 16 bytes

    def serialize(self) -> bytes:
        """Serialize to wire format (type byte + payload)."""
        return bytes([MessageType.HANDSHAKE_INIT]) + struct.pack(
            _INIT_FMT, self.sender_session, self.ephemeral_pubkey, self.mac
        )

    @classmethod
    def deserialize(cls, data: bytes) -> HandshakeInit:
        """Deserialize from payload bytes (type byte already stripped)."""
        if len(data) != _INIT_SIZE:
            raise ValueError(f"HandshakeInit: expected {_INIT_SIZE} bytes, got {len(data)}")
        session, eph, mac = struct.unpack(_INIT_FMT, data)
        return cls(sender_session=session, ephemeral_pubkey=bytes(eph), mac=bytes(mac))


# -- Handshake Response (0x02) ----------------------------------------------

_RESP_FMT = "<II32s16s"  # sender_u32, receiver_u32, eph_pub_32, mac_16
_RESP_SIZE = struct.calcsize(_RESP_FMT)  # 56


@dataclass(frozen=True, slots=True)
class HandshakeResponse:
    """Responder → initiator: ephemeral public key + authentication MAC."""

    sender_session: int  # uint32
    receiver_session: int  # uint32  (echo of initiator's sender_session)
    ephemeral_pubkey: bytes  # 32 bytes
    mac: bytes  # 16 bytes

    def serialize(self) -> bytes:
        return bytes([MessageType.HANDSHAKE_RESPONSE]) + struct.pack(
            _RESP_FMT,
            self.sender_session,
            self.receiver_session,
            self.ephemeral_pubkey,
            self.mac,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> HandshakeResponse:
        if len(data) != _RESP_SIZE:
            raise ValueError(f"HandshakeResponse: expected {_RESP_SIZE} bytes, got {len(data)}")
        sender, receiver, eph, mac = struct.unpack(_RESP_FMT, data)
        return cls(
            sender_session=sender,
            receiver_session=receiver,
            ephemeral_pubkey=bytes(eph),
            mac=bytes(mac),
        )


# -- Transport Data (0x03) --------------------------------------------------

_TRANSPORT_COUNTER_FMT = "<Q"  # counter_u64
_TRANSPORT_HEADER_SIZE = struct.calcsize(_TRANSPORT_COUNTER_FMT)  # 8


@dataclass(frozen=True, slots=True)
class TransportData:
    """Encrypted Ethernet frame payload."""

    counter: int  # uint64
    ciphertext: bytes  # variable length (includes 16-byte Poly1305 tag)

    def serialize(self) -> bytes:
        return (
            bytes([MessageType.TRANSPORT_DATA])
            + struct.pack(_TRANSPORT_COUNTER_FMT, self.counter)
            + self.ciphertext
        )

    @classmethod
    def deserialize(cls, data: bytes) -> TransportData:
        if len(data) < _TRANSPORT_HEADER_SIZE + 1:
            raise ValueError("TransportData: payload too short")
        (counter,) = struct.unpack_from(_TRANSPORT_COUNTER_FMT, data)
        ciphertext = data[_TRANSPORT_HEADER_SIZE:]
        return cls(counter=counter, ciphertext=ciphertext)

    def payload_bytes(self) -> bytes:
        """Serialized payload without the type byte (for fragmentation)."""
        return struct.pack(_TRANSPORT_COUNTER_FMT, self.counter) + self.ciphertext


# -- Transport Fragment (0x04) ----------------------------------------------

_FRAG_HEADER_FMT = "<HBB"  # msg_id_u16, frag_index_u8, frag_total_u8
_FRAG_HEADER_SIZE = struct.calcsize(_FRAG_HEADER_FMT)  # 4


@dataclass(frozen=True, slots=True)
class TransportFragment:
    """One fragment of a larger :class:`TransportData` packet."""

    msg_id: int  # uint16 — correlates fragments of the same message
    frag_index: int  # uint8 — 0-indexed
    frag_total: int  # uint8 — total count (1-indexed)
    chunk: bytes  # variable length

    def serialize(self) -> bytes:
        return (
            bytes([MessageType.TRANSPORT_FRAGMENT])
            + struct.pack(_FRAG_HEADER_FMT, self.msg_id, self.frag_index, self.frag_total)
            + self.chunk
        )

    @classmethod
    def deserialize(cls, data: bytes) -> TransportFragment:
        if len(data) < _FRAG_HEADER_SIZE:
            raise ValueError("TransportFragment: payload too short")
        msg_id, idx, total = struct.unpack_from(_FRAG_HEADER_FMT, data)
        chunk = data[_FRAG_HEADER_SIZE:]
        return cls(msg_id=msg_id, frag_index=idx, frag_total=total, chunk=chunk)


# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------

Packet = HandshakeInit | HandshakeResponse | TransportData | TransportFragment


def parse_packet(data: bytes) -> Packet:
    """Dispatch on the first byte to deserialize the correct packet type."""
    if not data:
        raise ValueError("Empty packet")
    msg_type = data[0]
    payload = data[1:]
    match msg_type:
        case MessageType.HANDSHAKE_INIT:
            return HandshakeInit.deserialize(payload)
        case MessageType.HANDSHAKE_RESPONSE:
            return HandshakeResponse.deserialize(payload)
        case MessageType.TRANSPORT_DATA:
            return TransportData.deserialize(payload)
        case MessageType.TRANSPORT_FRAGMENT:
            return TransportFragment.deserialize(payload)
        case _:
            raise ValueError(f"Unknown message type: 0x{msg_type:02x}")


# ---------------------------------------------------------------------------
# Fragmentation / reassembly
# ---------------------------------------------------------------------------

# Maximum chunk size per fragment (meshtastic payload minus fragment header and type byte).
MAX_FRAGMENT_CHUNK = MAX_MESHTASTIC_PAYLOAD - 1 - _FRAG_HEADER_SIZE  # 228


@dataclass
class _ReassemblyBuffer:
    total: int
    chunks: dict[int, bytes] = field(default_factory=dict)
    created_at: float = field(default_factory=time.monotonic)


class Fragmenter:
    """Fragment outgoing transport payloads and reassemble incoming fragments."""

    # Hard cap on concurrent reassembly buffers to prevent memory exhaustion.
    MAX_REASSEMBLY_BUFFERS: int = 256

    def __init__(self, timeout: float = 30.0) -> None:
        self._next_msg_id: int = 0
        self._buffers: dict[tuple[str, int], _ReassemblyBuffer] = {}
        self._timeout: float = timeout

    # -- outgoing -----------------------------------------------------------

    def fragment(self, transport_packet: TransportData) -> list[bytes]:
        """Fragment a :class:`TransportData` into ready-to-send wire bytes.

        If the packet fits within a single meshtastic payload, returns
        ``[transport_packet.serialize()]`` (no fragmentation).  Otherwise
        returns a list of serialized :class:`TransportFragment` packets.
        """
        serialized = transport_packet.serialize()
        if len(serialized) <= MAX_MESHTASTIC_PAYLOAD:
            return [serialized]

        # Fragment the payload (everything after type byte).
        payload = transport_packet.payload_bytes()
        msg_id = self._next_msg_id & 0xFFFF
        self._next_msg_id = (self._next_msg_id + 1) & 0xFFFF

        chunks: list[bytes] = []
        for offset in range(0, len(payload), MAX_FRAGMENT_CHUNK):
            chunks.append(payload[offset : offset + MAX_FRAGMENT_CHUNK])

        if len(chunks) > 255:
            raise ValueError(f"Payload too large to fragment: {len(payload)} bytes, {len(chunks)} fragments")

        fragments: list[bytes] = []
        for idx, chunk in enumerate(chunks):
            frag = TransportFragment(
                msg_id=msg_id,
                frag_index=idx,
                frag_total=len(chunks),
                chunk=chunk,
            )
            fragments.append(frag.serialize())
        return fragments

    # -- incoming -----------------------------------------------------------

    def reassemble(self, sender: str, fragment: TransportFragment) -> TransportData | None:
        """Feed a fragment. Returns the reassembled :class:`TransportData`
        when all fragments have arrived, or ``None`` if still incomplete.

        Enforces a maximum number of concurrent reassembly buffers.  When
        the limit is reached, the oldest buffer is evicted to make room.
        """
        # Validate fragment metadata.
        if fragment.frag_total == 0 or fragment.frag_index >= fragment.frag_total:
            return None  # malformed fragment — silently drop

        key = (sender, fragment.msg_id)
        buf = self._buffers.get(key)
        if buf is None:
            # Evict oldest buffer if at capacity.
            if len(self._buffers) >= self.MAX_REASSEMBLY_BUFFERS:
                oldest_key = min(self._buffers, key=lambda k: self._buffers[k].created_at)
                del self._buffers[oldest_key]
            buf = _ReassemblyBuffer(total=fragment.frag_total)
            self._buffers[key] = buf

        buf.chunks[fragment.frag_index] = fragment.chunk

        if len(buf.chunks) < buf.total:
            return None

        # All fragments received — reassemble.
        del self._buffers[key]
        payload = b"".join(buf.chunks[i] for i in range(buf.total))
        # payload = counter(8) + ciphertext(N)
        return TransportData.deserialize(payload)

    def gc_stale(self) -> int:
        """Remove reassembly buffers older than *timeout* seconds.

        Returns the number of evicted buffers.
        """
        now = time.monotonic()
        stale = [k for k, v in self._buffers.items() if now - v.created_at > self._timeout]
        for k in stale:
            del self._buffers[k]
        return len(stale)
