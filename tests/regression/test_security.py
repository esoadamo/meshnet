"""Regression tests — replay protection, counter exhaustion, tampered packets, malformed input."""

from __future__ import annotations

import os
import struct

import pytest
from cryptography.exceptions import InvalidTag

from meshnet.vpn.crypto import KeyPair, decrypt, encrypt, generate_psk, mac_blake2s
from meshnet.vpn.session import (
    REJECT_AFTER_MESSAGES,
    PeerSession,
    SessionState,
)
from meshnet.vpn.transport import (
    Fragmenter,
    HandshakeInit,
    HandshakeResponse,
    TransportData,
    TransportFragment,
    parse_packet,
)


def _establish_pair(
    psk: bytes | None = None,
) -> tuple[PeerSession, PeerSession]:
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    a = PeerSession("!b", kp_b.public_bytes(), kp_a, preshared_key=psk)
    b = PeerSession("!a", kp_a.public_bytes(), kp_b, preshared_key=psk)
    init = a.initiate_handshake()
    resp = b.respond_to_handshake(parse_packet(init))
    a.complete_handshake(parse_packet(resp))
    return a, b


class TestReplayProtection:
    """Verify that replayed or out-of-order packets are rejected."""

    def test_replayed_packet_rejected(self):
        a, b = _establish_pair()
        frame = b"sensitive data"
        transport = a.encrypt_frame(frame)

        # Send a second frame first so recv_counter_max > 0
        transport2 = a.encrypt_frame(b"second frame")
        b.decrypt_frame(transport2)

        # Now the first frame (counter 0) should be rejected as replay
        with pytest.raises(ValueError, match="Replay detected"):
            b.decrypt_frame(transport)

    def test_old_counter_rejected(self):
        a, b = _establish_pair()
        # Send two frames
        t1 = a.encrypt_frame(b"frame 1")
        t2 = a.encrypt_frame(b"frame 2")

        # Decrypt in order
        b.decrypt_frame(t1)
        b.decrypt_frame(t2)

        # Replaying t1 should fail
        with pytest.raises(ValueError, match="Replay detected"):
            b.decrypt_frame(t1)

    def test_counter_zero_accepted_then_rejected(self):
        a, b = _establish_pair()
        t0 = a.encrypt_frame(b"first")
        b.decrypt_frame(t0)
        assert b.recv_counter_max == 0

        # Counter 1
        t1 = a.encrypt_frame(b"second")
        b.decrypt_frame(t1)
        assert b.recv_counter_max == 1

        # Replay counter 0
        with pytest.raises(ValueError, match="Replay detected"):
            b.decrypt_frame(t0)


class TestCounterExhaustion:
    """Verify that the session rejects messages when the counter is exhausted."""

    def test_send_counter_exhausted(self):
        a, b = _establish_pair()
        a.send_counter = REJECT_AFTER_MESSAGES
        with pytest.raises(RuntimeError, match="counter exhausted"):
            a.encrypt_frame(b"too many")


class TestTamperedPackets:
    """Verify that tampered packets are detected and rejected."""

    def test_tampered_ciphertext(self):
        a, b = _establish_pair()
        transport = a.encrypt_frame(b"clean data")
        tampered_ct = bytearray(transport.ciphertext)
        tampered_ct[0] ^= 0xFF
        tampered = TransportData(counter=transport.counter, ciphertext=bytes(tampered_ct))
        with pytest.raises(InvalidTag):
            b.decrypt_frame(tampered)

    def test_tampered_counter(self):
        a, b = _establish_pair()
        transport = a.encrypt_frame(b"clean data")
        # Same ciphertext but wrong counter → decryption should fail
        tampered = TransportData(counter=transport.counter + 1, ciphertext=transport.ciphertext)
        with pytest.raises(InvalidTag):
            b.decrypt_frame(tampered)

    def test_tampered_handshake_init_mac(self):
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        a = PeerSession("!b", kp_b.public_bytes(), kp_a)
        b = PeerSession("!a", kp_a.public_bytes(), kp_b)

        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        # Tamper with the MAC
        tampered_mac = bytearray(init_pkt.mac)
        tampered_mac[0] ^= 0xFF
        tampered_init = HandshakeInit(
            sender_session=init_pkt.sender_session,
            ephemeral_pubkey=init_pkt.ephemeral_pubkey,
            mac=bytes(tampered_mac),
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(tampered_init)

    def test_tampered_handshake_response_mac(self):
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        a = PeerSession("!b", kp_b.public_bytes(), kp_a)
        b = PeerSession("!a", kp_a.public_bytes(), kp_b)

        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)
        resp_bytes = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp_bytes)

        tampered_mac = bytearray(resp_pkt.mac)
        tampered_mac[0] ^= 0xFF
        tampered_resp = HandshakeResponse(
            sender_session=resp_pkt.sender_session,
            receiver_session=resp_pkt.receiver_session,
            ephemeral_pubkey=resp_pkt.ephemeral_pubkey,
            mac=bytes(tampered_mac),
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            a.complete_handshake(tampered_resp)

    def test_tampered_ephemeral_key_in_init(self):
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        a = PeerSession("!b", kp_b.public_bytes(), kp_a)
        b = PeerSession("!a", kp_a.public_bytes(), kp_b)

        init_bytes = a.initiate_handshake()
        init_pkt = parse_packet(init_bytes)

        # Replace ephemeral key with random bytes — MAC will fail
        tampered_init = HandshakeInit(
            sender_session=init_pkt.sender_session,
            ephemeral_pubkey=os.urandom(32),
            mac=init_pkt.mac,
        )
        with pytest.raises(ValueError, match="MAC verification failed"):
            b.respond_to_handshake(tampered_init)


class TestMalformedInput:
    """Verify handling of malformed/garbage input."""

    def test_empty_packet(self):
        with pytest.raises(ValueError, match="Empty"):
            parse_packet(b"")

    def test_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown"):
            parse_packet(b"\xFF" + b"\x00" * 100)

    def test_truncated_handshake_init(self):
        with pytest.raises(ValueError, match="expected"):
            parse_packet(b"\x01" + b"\x00" * 10)

    def test_truncated_handshake_response(self):
        with pytest.raises(ValueError, match="expected"):
            parse_packet(b"\x02" + b"\x00" * 10)

    def test_truncated_transport_data(self):
        with pytest.raises(ValueError, match="too short"):
            parse_packet(b"\x03" + b"\x00" * 5)

    def test_truncated_transport_fragment(self):
        with pytest.raises(ValueError, match="too short"):
            parse_packet(b"\x04" + b"\x00" * 2)

    def test_single_byte_packet(self):
        """A single type byte with no payload."""
        # Type 0x01 with no payload → HandshakeInit deserialize will fail
        with pytest.raises(ValueError):
            parse_packet(b"\x01")


class TestCrossSessionIsolation:
    """Verify that keys from one session cannot decrypt another session's traffic."""

    def test_different_sessions_cannot_decrypt(self):
        a1, b1 = _establish_pair()
        a2, b2 = _establish_pair()

        frame = b"session 1 data"
        transport = a1.encrypt_frame(frame)

        # b2 should not be able to decrypt a1's traffic
        with pytest.raises(InvalidTag):
            b2.decrypt_frame(transport)

    def test_psk_mismatch_produces_different_keys(self):
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()
        psk1 = generate_psk()
        psk2 = generate_psk()

        a = PeerSession("!b", kp_b.public_bytes(), kp_a, preshared_key=psk1)
        b = PeerSession("!a", kp_a.public_bytes(), kp_b, preshared_key=psk2)

        init = a.initiate_handshake()
        init_pkt = parse_packet(init)
        resp = b.respond_to_handshake(init_pkt)
        resp_pkt = parse_packet(resp)
        a.complete_handshake(resp_pkt)

        # Both are "established" but keys won't match
        frame = b"test"
        transport = a.encrypt_frame(frame)
        with pytest.raises(InvalidTag):
            b.decrypt_frame(transport)


class TestFragmentationEdgeCases:
    """Regression tests for fragmentation boundary conditions."""

    def test_payload_exactly_max_meshtastic_payload(self):
        """A TransportData whose serialized form is exactly MAX_MESHTASTIC_PAYLOAD should NOT be fragmented."""
        from meshnet.vpn.transport import MAX_MESHTASTIC_PAYLOAD

        # Type byte (1) + counter (8) + ciphertext = 233
        # → ciphertext must be 233 - 9 = 224 bytes
        ct_len = MAX_MESHTASTIC_PAYLOAD - 9
        pkt = TransportData(counter=0, ciphertext=os.urandom(ct_len))
        assert len(pkt.serialize()) == MAX_MESHTASTIC_PAYLOAD

        frag = Fragmenter()
        result = frag.fragment(pkt)
        assert len(result) == 1
        assert result[0][0] == 0x03  # TransportData type

    def test_payload_one_byte_over(self):
        """One byte over the limit should trigger fragmentation."""
        from meshnet.vpn.transport import MAX_MESHTASTIC_PAYLOAD

        ct_len = MAX_MESHTASTIC_PAYLOAD - 9 + 1
        pkt = TransportData(counter=0, ciphertext=os.urandom(ct_len))
        assert len(pkt.serialize()) == MAX_MESHTASTIC_PAYLOAD + 1

        frag = Fragmenter()
        result = frag.fragment(pkt)
        assert len(result) > 1

    def test_missing_middle_fragment_leaves_incomplete(self):
        """If the middle fragment is lost, reassembly should never complete."""
        a, b = _establish_pair()
        frame = os.urandom(500)
        transport = a.encrypt_frame(frame)

        frag_out = Fragmenter()
        fragments = frag_out.fragment(transport)
        assert len(fragments) >= 3  # need at least 3 for a "middle"

        frag_in = Fragmenter()
        # Skip fragment index 1
        for i, wire in enumerate(fragments):
            if i == 1:
                continue
            pkt = parse_packet(wire)
            result = frag_in.reassemble("!a", pkt)

        # Should still be incomplete
        assert result is None
