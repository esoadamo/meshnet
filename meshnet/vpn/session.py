"""Per-peer session state machine: handshake, key derivation, encrypt/decrypt.

Implements a simplified WireGuard-style handshake:

1. Initiator generates ephemeral X25519 key, sends :class:`HandshakeInit`
   authenticated with ``MAC(DH(static_I, static_R), message)``.
2. Responder verifies MAC, generates its own ephemeral key, derives
   transport keys from three DH computations + optional PSK, and sends
   :class:`HandshakeResponse`.
3. Initiator completes the handshake by deriving the same transport keys.

After the handshake both sides have directional ``send_key`` / ``recv_key``
and use :func:`~meshnet.crypto.encrypt` / :func:`~meshnet.crypto.decrypt`
with monotonic counters for replay protection.
"""

from __future__ import annotations

import logging
import os
import time
from enum import Enum

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from meshnet.vpn.crypto import (
    KeyPair,
    decrypt,
    derive_transport_keys,
    dh,
    encrypt,
    kdf,
    mac_blake2s,
    verify_mac,
)
from meshnet.vpn.transport import (
    HandshakeInit,
    HandshakeResponse,
    TransportData,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REKEY_AFTER_SECONDS: int = 300  # 5 minutes
REKEY_AFTER_MESSAGES: int = 2**16
REJECT_AFTER_MESSAGES: int = 2**64 - 1


class SessionState(Enum):
    IDLE = "idle"
    INIT_SENT = "init_sent"
    ESTABLISHED = "established"


class PeerSession:
    """Manages handshake state and transport encryption for one peer."""

    def __init__(
        self,
        peer_node_id: str,
        peer_static_public: bytes,
        local_keypair: KeyPair,
        preshared_key: bytes | None = None,
    ) -> None:
        self.peer_node_id: str = peer_node_id
        self.peer_static_public: X25519PublicKey = X25519PublicKey.from_public_bytes(
            peer_static_public
        )
        self.local_keypair: KeyPair = local_keypair
        self.psk: bytes | None = preshared_key

        self.state: SessionState = SessionState.IDLE
        self.send_key: bytes | None = None
        self.recv_key: bytes | None = None
        self.send_counter: int = 0
        self.recv_counter_max: int = 0

        # Handshake temporaries
        self._local_session_id: int = 0
        self._remote_session_id: int = 0
        self._ephemeral_keypair: KeyPair | None = None
        self._peer_ephemeral_public: X25519PublicKey | None = None
        self._established_at: float = 0.0

    # -- initiator side -----------------------------------------------------

    def initiate_handshake(self) -> bytes:
        """Generate a :class:`HandshakeInit` message (53 wire bytes).

        Transitions state to ``INIT_SENT``.
        """
        self._ephemeral_keypair = KeyPair.generate()
        self._local_session_id = int.from_bytes(os.urandom(4), "little")

        # MAC key = first 32 bytes of DH(static_local, static_peer)
        mac_key = dh(self.local_keypair.private, self.peer_static_public)

        eph_pub = self._ephemeral_keypair.public_bytes()
        # MAC covers session_id (4 LE bytes) + ephemeral public key (32 bytes).
        mac_data = self._local_session_id.to_bytes(4, "little") + eph_pub
        tag = mac_blake2s(mac_key, mac_data)

        pkt = HandshakeInit(
            sender_session=self._local_session_id,
            ephemeral_pubkey=eph_pub,
            mac=tag,
        )
        self.state = SessionState.INIT_SENT
        log.info("Handshake INIT → %s (session=%08x)", self.peer_node_id, self._local_session_id)
        return pkt.serialize()

    def complete_handshake(self, response: HandshakeResponse) -> None:
        """Process a :class:`HandshakeResponse` (initiator side).

        Transitions state to ``ESTABLISHED``.

        :raises ValueError: on session mismatch or MAC verification failure.
        """
        if response.receiver_session != self._local_session_id:
            raise ValueError(
                f"Session mismatch: expected {self._local_session_id:#010x}, "
                f"got {response.receiver_session:#010x}"
            )

        if self._ephemeral_keypair is None:
            raise ValueError("No ephemeral keypair — initiate_handshake not called?")

        peer_eph = X25519PublicKey.from_public_bytes(response.ephemeral_pubkey)

        # Three DH computations (initiator perspective).
        dh_ee = dh(self._ephemeral_keypair.private, peer_eph)
        dh_se = dh(self.local_keypair.private, peer_eph)
        dh_es = dh(self._ephemeral_keypair.private, self.peer_static_public)

        # Verify response MAC using a key derived from the DH mix.
        resp_mac_key = kdf(dh_ee + dh_se + dh_es, b"meshnet-hs-mac", b"response-mac")
        mac_data = (
            response.sender_session.to_bytes(4, "little")
            + response.receiver_session.to_bytes(4, "little")
            + response.ephemeral_pubkey
        )
        if not verify_mac(resp_mac_key, mac_data, response.mac):
            raise ValueError("HandshakeResponse MAC verification failed")

        send_key, recv_key = derive_transport_keys(
            dh_ee, dh_se, dh_es, self.psk, is_initiator=True
        )

        self._remote_session_id = response.sender_session
        self._peer_ephemeral_public = peer_eph
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_counter = 0
        self.recv_counter_max = 0
        self._established_at = time.monotonic()
        self.state = SessionState.ESTABLISHED

        # Clear ephemeral material.
        self._ephemeral_keypair = None
        log.info(
            "Handshake COMPLETE with %s (local=%08x, remote=%08x)",
            self.peer_node_id,
            self._local_session_id,
            self._remote_session_id,
        )

    # -- responder side -----------------------------------------------------

    def respond_to_handshake(self, init: HandshakeInit) -> bytes:
        """Process a :class:`HandshakeInit` and return a :class:`HandshakeResponse`.

        Transitions state to ``ESTABLISHED``.

        :raises ValueError: on MAC verification failure.
        """
        # Verify init MAC using DH(static_local, static_peer).
        # The initiator used DH(static_I, static_R); the responder computes
        # DH(static_R, static_I) — the same shared secret (X25519 is commutative).
        mac_key = dh(self.local_keypair.private, self.peer_static_public)
        mac_data = init.sender_session.to_bytes(4, "little") + init.ephemeral_pubkey
        if not verify_mac(mac_key, mac_data, init.mac):
            raise ValueError("HandshakeInit MAC verification failed")

        peer_eph = X25519PublicKey.from_public_bytes(init.ephemeral_pubkey)
        eph_kp = KeyPair.generate()
        self._local_session_id = int.from_bytes(os.urandom(4), "little")

        # Three DH computations (responder perspective).
        # dh_ee = DH(eph_R, eph_I)  — same as DH(eph_I, eph_R)
        # dh_se = DH(eph_R, static_I) — same as DH(static_I, eph_R)
        # dh_es = DH(static_R, eph_I) — same as DH(eph_I, static_R)
        dh_ee = dh(eph_kp.private, peer_eph)
        dh_se = dh(eph_kp.private, self.peer_static_public)
        dh_es = dh(self.local_keypair.private, peer_eph)

        send_key, recv_key = derive_transport_keys(
            dh_ee, dh_se, dh_es, self.psk, is_initiator=False
        )

        # Build response MAC using a key derived from the DH mix.
        resp_mac_key = kdf(dh_ee + dh_se + dh_es, b"meshnet-hs-mac", b"response-mac")
        eph_pub = eph_kp.public_bytes()
        mac_data = (
            self._local_session_id.to_bytes(4, "little")
            + init.sender_session.to_bytes(4, "little")
            + eph_pub
        )
        tag = mac_blake2s(resp_mac_key, mac_data)

        pkt = HandshakeResponse(
            sender_session=self._local_session_id,
            receiver_session=init.sender_session,
            ephemeral_pubkey=eph_pub,
            mac=tag,
        )

        self._remote_session_id = init.sender_session
        self._peer_ephemeral_public = peer_eph
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_counter = 0
        self.recv_counter_max = 0
        self._established_at = time.monotonic()
        self.state = SessionState.ESTABLISHED
        log.info(
            "Handshake RESPOND → %s (local=%08x, remote=%08x)",
            self.peer_node_id,
            self._local_session_id,
            self._remote_session_id,
        )
        return pkt.serialize()

    # -- transport ----------------------------------------------------------

    def encrypt_frame(self, frame: bytes) -> TransportData:
        """Encrypt an Ethernet frame into a :class:`TransportData` packet.

        :raises RuntimeError: if the session is not established.
        """
        if self.state != SessionState.ESTABLISHED or self.send_key is None:
            raise RuntimeError(f"Session with {self.peer_node_id} not established")
        if self.send_counter >= REJECT_AFTER_MESSAGES:
            raise RuntimeError("Send counter exhausted — rekey required")

        ct = encrypt(self.send_key, self.send_counter, frame)
        pkt = TransportData(counter=self.send_counter, ciphertext=ct)
        self.send_counter += 1
        return pkt

    def decrypt_frame(self, data: TransportData) -> bytes:
        """Decrypt a :class:`TransportData` packet back to an Ethernet frame.

        :raises RuntimeError: if the session is not established.
        :raises ValueError: on replay (counter already seen).
        :raises cryptography.exceptions.InvalidTag: on authentication failure.
        """
        if self.state != SessionState.ESTABLISHED or self.recv_key is None:
            raise RuntimeError(f"Session with {self.peer_node_id} not established")
        if data.counter <= self.recv_counter_max and self.recv_counter_max > 0:
            raise ValueError(
                f"Replay detected: counter {data.counter} <= {self.recv_counter_max}"
            )

        frame = decrypt(self.recv_key, data.counter, data.ciphertext)
        self.recv_counter_max = max(self.recv_counter_max, data.counter)
        return frame

    # -- rekey check --------------------------------------------------------

    def needs_rekey(self) -> bool:
        """``True`` when the session should be rekeyed."""
        if self.state != SessionState.ESTABLISHED:
            return False
        if self.send_counter >= REKEY_AFTER_MESSAGES:
            return True
        if time.monotonic() - self._established_at >= REKEY_AFTER_SECONDS:
            return True
        return False

    @property
    def is_established(self) -> bool:
        return self.state == SessionState.ESTABLISHED
