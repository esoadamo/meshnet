"""Integration tests — full handshake + transport between two simulated peers."""

from __future__ import annotations

import os

import pytest

from meshnet.vpn.crypto import KeyPair, generate_psk
from meshnet.vpn.session import PeerSession, SessionState
from meshnet.vpn.transport import (
    Fragmenter,
    TransportData,
    TransportFragment,
    parse_packet,
)


def _establish_pair(
    psk: bytes | None = None,
) -> tuple[PeerSession, PeerSession]:
    """Run a full handshake between two sessions and return them established."""
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()

    a = PeerSession("!b", kp_b.public_bytes(), kp_a, preshared_key=psk)
    b = PeerSession("!a", kp_a.public_bytes(), kp_b, preshared_key=psk)

    init_bytes = a.initiate_handshake()
    init_pkt = parse_packet(init_bytes)
    resp_bytes = b.respond_to_handshake(init_pkt)
    resp_pkt = parse_packet(resp_bytes)
    a.complete_handshake(resp_pkt)
    return a, b


class TestEndToEndHandshakeAndTransport:
    """Integration: handshake → encrypt → fragment → reassemble → decrypt."""

    def test_small_frame_no_fragmentation(self):
        a, b = _establish_pair()
        frame = os.urandom(50)

        # A encrypts
        transport = a.encrypt_frame(frame)
        wire = transport.serialize()

        # B receives the wire bytes, parses, decrypts
        pkt = parse_packet(wire)
        assert isinstance(pkt, TransportData)
        decrypted = b.decrypt_frame(pkt)
        assert decrypted == frame

    def test_large_frame_with_fragmentation(self):
        """A large frame is fragmented, transmitted, reassembled, and decrypted."""
        a, b = _establish_pair()
        frame = os.urandom(500)

        transport = a.encrypt_frame(frame)
        frag_a = Fragmenter()
        fragments = frag_a.fragment(transport)
        assert len(fragments) > 1  # should be fragmented

        frag_b = Fragmenter()
        reassembled = None
        for wire in fragments:
            pkt = parse_packet(wire)
            assert isinstance(pkt, TransportFragment)
            reassembled = frag_b.reassemble("!a", pkt)

        assert reassembled is not None
        decrypted = b.decrypt_frame(reassembled)
        assert decrypted == frame

    def test_bidirectional_traffic(self):
        a, b = _establish_pair()

        for i in range(20):
            frame_ab = os.urandom(30 + i)
            frame_ba = os.urandom(30 + i)

            # A → B
            t = a.encrypt_frame(frame_ab)
            assert b.decrypt_frame(t) == frame_ab

            # B → A
            t = b.encrypt_frame(frame_ba)
            assert a.decrypt_frame(t) == frame_ba

    def test_with_preshared_key(self):
        psk = generate_psk()
        a, b = _establish_pair(psk=psk)

        frame = b"psk protected data"
        transport = a.encrypt_frame(frame)
        assert b.decrypt_frame(transport) == frame

    def test_rehandshake_after_established(self):
        """A second handshake should produce new keys."""
        a, b = _establish_pair()

        old_send_key = a.send_key

        # Second handshake
        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)
        a.complete_handshake(resp_pkt)

        assert a.is_established
        assert b.is_established
        assert a.send_key != old_send_key
        assert a.send_counter == 0

    def test_multiple_fragment_messages_interleaved(self):
        """Two large messages from the same sender, interleaved fragments."""
        a, b = _establish_pair()

        frame1 = os.urandom(500)
        frame2 = os.urandom(500)

        frag_out = Fragmenter()
        t1 = a.encrypt_frame(frame1)
        t2 = a.encrypt_frame(frame2)
        frags1 = frag_out.fragment(t1)
        frags2 = frag_out.fragment(t2)

        # Interleave: f1[0], f2[0], f1[1], f2[1], ...
        frag_in = Fragmenter()
        results = []
        max_len = max(len(frags1), len(frags2))
        for i in range(max_len):
            if i < len(frags1):
                pkt = parse_packet(frags1[i])
                r = frag_in.reassemble("!a", pkt)
                if r is not None:
                    results.append(b.decrypt_frame(r))
            if i < len(frags2):
                pkt = parse_packet(frags2[i])
                r = frag_in.reassemble("!a", pkt)
                if r is not None:
                    results.append(b.decrypt_frame(r))

        assert len(results) == 2
        assert frame1 in results
        assert frame2 in results


class TestEndToEndFragmentEdgeCases:
    """Edge cases in the fragment→reassemble pipeline."""

    def test_fragment_out_of_order(self):
        a, b = _establish_pair()
        frame = os.urandom(500)

        frag_out = Fragmenter()
        transport = a.encrypt_frame(frame)
        fragments = frag_out.fragment(transport)

        # Reverse order
        frag_in = Fragmenter()
        reassembled = None
        for wire in reversed(fragments):
            pkt = parse_packet(wire)
            reassembled = frag_in.reassemble("!a", pkt)

        assert reassembled is not None
        assert b.decrypt_frame(reassembled) == frame

    def test_duplicate_fragment(self):
        a, b = _establish_pair()
        frame = os.urandom(500)

        frag_out = Fragmenter()
        transport = a.encrypt_frame(frame)
        fragments = frag_out.fragment(transport)

        # Send first fragment twice, then rest
        frag_in = Fragmenter()
        reassembled = None
        pkt0 = parse_packet(fragments[0])
        frag_in.reassemble("!a", pkt0)
        frag_in.reassemble("!a", pkt0)  # duplicate

        for wire in fragments[1:]:
            pkt = parse_packet(wire)
            r = frag_in.reassemble("!a", pkt)
            if r is not None:
                reassembled = r

        assert reassembled is not None
        assert b.decrypt_frame(reassembled) == frame
