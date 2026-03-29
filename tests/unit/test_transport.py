"""Unit tests for meshnet.vpn.transport — packet types, parsing, fragmentation."""

from __future__ import annotations

import os
import struct
import time
from unittest.mock import patch

import pytest

from meshnet.vpn.transport import (
    MAX_FRAGMENT_CHUNK,
    MAX_MESHTASTIC_PAYLOAD,
    Fragmenter,
    HandshakeInit,
    HandshakeResponse,
    MessageType,
    TransportData,
    TransportFragment,
    parse_packet,
)


# ---------------------------------------------------------------------------
# HandshakeInit
# ---------------------------------------------------------------------------


class TestHandshakeInit:
    def test_serialize_deserialize_roundtrip(self):
        pkt = HandshakeInit(
            sender_session=0xDEADBEEF,
            ephemeral_pubkey=os.urandom(32),
            mac=os.urandom(16),
        )
        wire = pkt.serialize()
        assert wire[0] == MessageType.HANDSHAKE_INIT
        pkt2 = HandshakeInit.deserialize(wire[1:])
        assert pkt2.sender_session == pkt.sender_session
        assert pkt2.ephemeral_pubkey == pkt.ephemeral_pubkey
        assert pkt2.mac == pkt.mac

    def test_serialize_length(self):
        pkt = HandshakeInit(
            sender_session=1,
            ephemeral_pubkey=b"\x00" * 32,
            mac=b"\x00" * 16,
        )
        wire = pkt.serialize()
        # 1 (type) + 4 + 32 + 16 = 53
        assert len(wire) == 53

    def test_deserialize_wrong_length(self):
        with pytest.raises(ValueError, match="expected"):
            HandshakeInit.deserialize(b"\x00" * 10)

    def test_type_byte(self):
        pkt = HandshakeInit(
            sender_session=1,
            ephemeral_pubkey=b"\x00" * 32,
            mac=b"\x00" * 16,
        )
        assert pkt.serialize()[0] == 0x01


# ---------------------------------------------------------------------------
# HandshakeResponse
# ---------------------------------------------------------------------------


class TestHandshakeResponse:
    def test_serialize_deserialize_roundtrip(self):
        pkt = HandshakeResponse(
            sender_session=0x11111111,
            receiver_session=0x22222222,
            ephemeral_pubkey=os.urandom(32),
            mac=os.urandom(16),
        )
        wire = pkt.serialize()
        assert wire[0] == MessageType.HANDSHAKE_RESPONSE
        pkt2 = HandshakeResponse.deserialize(wire[1:])
        assert pkt2.sender_session == pkt.sender_session
        assert pkt2.receiver_session == pkt.receiver_session
        assert pkt2.ephemeral_pubkey == pkt.ephemeral_pubkey
        assert pkt2.mac == pkt.mac

    def test_serialize_length(self):
        pkt = HandshakeResponse(
            sender_session=1,
            receiver_session=2,
            ephemeral_pubkey=b"\x00" * 32,
            mac=b"\x00" * 16,
        )
        wire = pkt.serialize()
        # 1 + 4 + 4 + 32 + 16 = 57
        assert len(wire) == 57

    def test_deserialize_wrong_length(self):
        with pytest.raises(ValueError, match="expected"):
            HandshakeResponse.deserialize(b"\x00" * 10)


# ---------------------------------------------------------------------------
# TransportData
# ---------------------------------------------------------------------------


class TestTransportData:
    def test_serialize_deserialize_roundtrip(self):
        ct = os.urandom(64)
        pkt = TransportData(counter=42, ciphertext=ct)
        wire = pkt.serialize()
        assert wire[0] == MessageType.TRANSPORT_DATA
        pkt2 = TransportData.deserialize(wire[1:])
        assert pkt2.counter == 42
        assert pkt2.ciphertext == ct

    def test_serialize_length(self):
        ct = b"\xAA" * 50
        pkt = TransportData(counter=0, ciphertext=ct)
        wire = pkt.serialize()
        # 1 (type) + 8 (counter) + 50 (ct) = 59
        assert len(wire) == 59

    def test_payload_bytes(self):
        ct = b"\xBB" * 20
        pkt = TransportData(counter=7, ciphertext=ct)
        payload = pkt.payload_bytes()
        # 8 (counter) + 20 (ct) = 28
        assert len(payload) == 28
        assert payload[8:] == ct

    def test_deserialize_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            TransportData.deserialize(b"\x00" * 5)

    def test_counter_zero(self):
        pkt = TransportData(counter=0, ciphertext=b"data")
        wire = pkt.serialize()
        pkt2 = TransportData.deserialize(wire[1:])
        assert pkt2.counter == 0

    def test_counter_max_u64(self):
        pkt = TransportData(counter=2**64 - 1, ciphertext=b"data")
        wire = pkt.serialize()
        pkt2 = TransportData.deserialize(wire[1:])
        assert pkt2.counter == 2**64 - 1


# ---------------------------------------------------------------------------
# TransportFragment
# ---------------------------------------------------------------------------


class TestTransportFragment:
    def test_serialize_deserialize_roundtrip(self):
        chunk = os.urandom(100)
        pkt = TransportFragment(msg_id=5, frag_index=2, frag_total=4, chunk=chunk)
        wire = pkt.serialize()
        assert wire[0] == MessageType.TRANSPORT_FRAGMENT
        pkt2 = TransportFragment.deserialize(wire[1:])
        assert pkt2.msg_id == 5
        assert pkt2.frag_index == 2
        assert pkt2.frag_total == 4
        assert pkt2.chunk == chunk

    def test_deserialize_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            TransportFragment.deserialize(b"\x00" * 2)

    def test_empty_chunk(self):
        pkt = TransportFragment(msg_id=0, frag_index=0, frag_total=1, chunk=b"")
        wire = pkt.serialize()
        pkt2 = TransportFragment.deserialize(wire[1:])
        assert pkt2.chunk == b""


# ---------------------------------------------------------------------------
# parse_packet
# ---------------------------------------------------------------------------


class TestParsePacket:
    def test_handshake_init(self):
        orig = HandshakeInit(
            sender_session=1, ephemeral_pubkey=os.urandom(32), mac=os.urandom(16)
        )
        pkt = parse_packet(orig.serialize())
        assert isinstance(pkt, HandshakeInit)
        assert pkt.sender_session == 1

    def test_handshake_response(self):
        orig = HandshakeResponse(
            sender_session=1,
            receiver_session=2,
            ephemeral_pubkey=os.urandom(32),
            mac=os.urandom(16),
        )
        pkt = parse_packet(orig.serialize())
        assert isinstance(pkt, HandshakeResponse)

    def test_transport_data(self):
        orig = TransportData(counter=99, ciphertext=os.urandom(32))
        pkt = parse_packet(orig.serialize())
        assert isinstance(pkt, TransportData)
        assert pkt.counter == 99

    def test_transport_fragment(self):
        orig = TransportFragment(msg_id=1, frag_index=0, frag_total=2, chunk=b"abc")
        pkt = parse_packet(orig.serialize())
        assert isinstance(pkt, TransportFragment)

    def test_empty_packet_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            parse_packet(b"")

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown"):
            parse_packet(b"\xFF" + b"\x00" * 60)


# ---------------------------------------------------------------------------
# Fragmenter — outgoing
# ---------------------------------------------------------------------------


class TestFragmenterOutgoing:
    def test_small_packet_no_fragmentation(self):
        """A packet that fits in one meshtastic payload should not be fragmented."""
        frag = Fragmenter()
        pkt = TransportData(counter=0, ciphertext=os.urandom(50))
        result = frag.fragment(pkt)
        assert len(result) == 1
        # The single result should be the full serialized TransportData
        assert result[0][0] == MessageType.TRANSPORT_DATA

    def test_large_packet_fragmented(self):
        """A packet too big for one payload should be split into fragments."""
        frag = Fragmenter()
        # Create a payload that definitely exceeds MAX_MESHTASTIC_PAYLOAD
        pkt = TransportData(counter=0, ciphertext=os.urandom(500))
        result = frag.fragment(pkt)
        assert len(result) > 1
        for wire in result:
            assert wire[0] == MessageType.TRANSPORT_FRAGMENT
            assert len(wire) <= MAX_MESHTASTIC_PAYLOAD

    def test_msg_id_increments(self):
        frag = Fragmenter()
        pkt = TransportData(counter=0, ciphertext=os.urandom(500))
        frags1 = frag.fragment(pkt)
        frags2 = frag.fragment(pkt)
        # Different msg_ids
        f1 = TransportFragment.deserialize(frags1[0][1:])
        f2 = TransportFragment.deserialize(frags2[0][1:])
        assert f1.msg_id != f2.msg_id

    def test_msg_id_wraps_at_u16(self):
        frag = Fragmenter()
        frag._next_msg_id = 0xFFFF
        pkt = TransportData(counter=0, ciphertext=os.urandom(500))
        frags = frag.fragment(pkt)
        f = TransportFragment.deserialize(frags[0][1:])
        assert f.msg_id == 0xFFFF
        # Next should wrap
        frags2 = frag.fragment(pkt)
        f2 = TransportFragment.deserialize(frags2[0][1:])
        assert f2.msg_id == 0

    def test_fragment_indices(self):
        frag = Fragmenter()
        pkt = TransportData(counter=0, ciphertext=os.urandom(500))
        result = frag.fragment(pkt)
        for i, wire in enumerate(result):
            f = TransportFragment.deserialize(wire[1:])
            assert f.frag_index == i
            assert f.frag_total == len(result)


# ---------------------------------------------------------------------------
# Fragmenter — incoming reassembly
# ---------------------------------------------------------------------------


class TestFragmenterReassembly:
    def test_reassemble_in_order(self):
        frag = Fragmenter()
        pkt = TransportData(counter=42, ciphertext=os.urandom(500))
        wire_fragments = frag.fragment(pkt)

        frag2 = Fragmenter()
        result = None
        for wire in wire_fragments:
            f = TransportFragment.deserialize(wire[1:])
            result = frag2.reassemble("sender1", f)
        assert result is not None
        assert result.counter == 42
        assert result.ciphertext == pkt.ciphertext

    def test_reassemble_out_of_order(self):
        frag = Fragmenter()
        pkt = TransportData(counter=7, ciphertext=os.urandom(500))
        wire_fragments = frag.fragment(pkt)

        # Reverse the order
        frag2 = Fragmenter()
        result = None
        for wire in reversed(wire_fragments):
            f = TransportFragment.deserialize(wire[1:])
            result = frag2.reassemble("sender1", f)
        assert result is not None
        assert result.counter == 7

    def test_incomplete_reassembly(self):
        frag = Fragmenter()
        pkt = TransportData(counter=0, ciphertext=os.urandom(500))
        wire_fragments = frag.fragment(pkt)

        frag2 = Fragmenter()
        # Only send the first fragment
        f = TransportFragment.deserialize(wire_fragments[0][1:])
        result = frag2.reassemble("sender1", f)
        assert result is None

    def test_different_senders_separate_buffers(self):
        frag = Fragmenter()
        pkt = TransportData(counter=0, ciphertext=os.urandom(500))
        wire_fragments = frag.fragment(pkt)

        frag2 = Fragmenter()
        # Same msg_id but different senders — should not interfere
        for wire in wire_fragments[:-1]:
            f = TransportFragment.deserialize(wire[1:])
            frag2.reassemble("sender1", f)
            frag2.reassemble("sender2", f)

        # Complete for sender1 only
        last_f = TransportFragment.deserialize(wire_fragments[-1][1:])
        r1 = frag2.reassemble("sender1", last_f)
        assert r1 is not None

    def test_gc_stale(self):
        frag = Fragmenter(timeout=0.0)
        f = TransportFragment(msg_id=0, frag_index=0, frag_total=2, chunk=b"x")
        frag.reassemble("s", f)
        assert len(frag._buffers) == 1
        # Everything should be stale immediately
        evicted = frag.gc_stale()
        assert evicted == 1
        assert len(frag._buffers) == 0

    def test_gc_keeps_fresh(self):
        frag = Fragmenter(timeout=60.0)
        f = TransportFragment(msg_id=0, frag_index=0, frag_total=2, chunk=b"x")
        frag.reassemble("s", f)
        evicted = frag.gc_stale()
        assert evicted == 0
        assert len(frag._buffers) == 1
