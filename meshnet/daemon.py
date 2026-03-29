"""MeshVPN async daemon — bridges the TAP interface with the Meshtastic radio.

Three concurrent tasks:

1. **tap → mesh**: read Ethernet frames from TAP, route, encrypt, fragment,
   send over meshtastic.
2. **mesh → tap**: receive meshtastic packets, reassemble, decrypt, write
   to TAP.
3. **handshake manager**: periodically initiate handshakes for idle peers
   and trigger rekeying for established sessions that have exceeded their
   lifetime.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

from meshtastic import portnums_pb2

from meshnet.config import MeshnetConfig, parse_config
from meshnet.crypto import KeyPair
from meshnet.routing import RoutingTable
from meshnet.session import PeerSession, SessionState
from meshnet.tap import TapDevice
from meshnet.transport import (
    Fragmenter,
    HandshakeInit,
    HandshakeResponse,
    TransportData,
    TransportFragment,
    parse_packet,
)

# Avoid circular import at module level — import at runtime.
# meshtastic_socket lives in the project root, not inside the meshnet package.
sys.path.insert(0, ".")

log = logging.getLogger(__name__)

IP_TUNNEL_APP: int = portnums_pb2.PortNum.IP_TUNNEL_APP
PRIVATE_APP: int = portnums_pb2.PortNum.PRIVATE_APP

# Inter-fragment send delay (seconds).  Meshtastic can handle roughly one
# packet every 2-3 seconds; this keeps us below the radio's duty-cycle limit.
INTER_FRAGMENT_DELAY: float = 2.0

# How often the handshake manager polls (seconds).
HANDSHAKE_POLL_INTERVAL: float = 5.0

# How often to garbage-collect stale reassembly buffers (seconds).
FRAGMENT_GC_INTERVAL: float = 10.0


class MeshVPN:
    """Async VPN daemon bridging a TAP device to a Meshtastic mesh radio."""

    def __init__(self, config_path: str) -> None:
        self.config_path: str = config_path
        self.config: MeshnetConfig | None = None

        # Set during start().
        self._mesh: Any = None  # meshtastic_socket.Meshtastic
        self._tap: TapDevice | None = None
        self._routing: RoutingTable = RoutingTable()
        self._sessions: dict[str, PeerSession] = {}
        self._fragmenter: Fragmenter = Fragmenter()
        self._vpn_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._unregister_listener: Any = None
        self._tasks: list[asyncio.Task[None]] = []

    # -- public interface ---------------------------------------------------

    async def start(self) -> None:
        """Parse config, connect to radio, open TAP, launch event loops."""
        self.config = parse_config(self.config_path)
        cfg = self.config

        # Build local keypair.
        local_kp = KeyPair.from_private_bytes(cfg.interface.private_key)
        log.info(
            "Local public key: %s",
            local_kp.public_base64(),
        )

        # Connect to the meshtastic radio.
        from meshtastic_socket import Meshtastic

        self._mesh = Meshtastic(
            ip=cfg.interface.meshtastic_host,
            port=cfg.interface.meshtastic_port,
        )
        await self._mesh.connect()
        log.info("Meshtastic connected")

        # Register a listener for IP_TUNNEL_APP packets (or PRIVATE_APP as fallback).
        def vpn_filter(packet: dict[str, Any]) -> bool:
            portnum = packet.get("decoded", {}).get("portnum", "")
            return portnum in ("IP_TUNNEL_APP", "PRIVATE_APP")

        self._unregister_listener = self._mesh._register_listener(
            vpn_filter, self._vpn_queue
        )

        # Open TAP device.
        self._tap = TapDevice(
            name=cfg.interface.tap_name,
            mtu=cfg.interface.mtu,
        )
        address_str = str(cfg.interface.address)
        await self._tap.open(address_str)

        # Build routing table and sessions.
        for peer in cfg.peers:
            for network in peer.allowed_ips:
                self._routing.add_route(network, peer.endpoint)
            self._sessions[peer.endpoint] = PeerSession(
                peer_node_id=peer.endpoint,
                peer_static_public=peer.public_key,
                local_keypair=local_kp,
                preshared_key=peer.preshared_key,
            )

        # Launch the three concurrent loops.
        self._tasks = [
            asyncio.create_task(self._tap_to_mesh_loop(), name="tap→mesh"),
            asyncio.create_task(self._mesh_to_tap_loop(), name="mesh→tap"),
            asyncio.create_task(self._handshake_manager(), name="handshake"),
        ]
        log.info("MeshVPN running — %d peer(s) configured", len(cfg.peers))

        # Wait for all tasks (they run forever until cancelled).
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """Cancel all tasks and release resources."""
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        if self._unregister_listener:
            self._unregister_listener()
        if self._tap:
            self._tap.close()
        if self._mesh:
            self._mesh.close()
        log.info("MeshVPN stopped")

    # -- TAP → mesh ---------------------------------------------------------

    async def _tap_to_mesh_loop(self) -> None:
        """Read frames from the TAP device, encrypt, and send over mesh."""
        assert self._tap is not None
        while True:
            try:
                frame = await self._tap.read_frame()
            except OSError as exc:
                log.error("TAP read error: %s", exc)
                await asyncio.sleep(1.0)
                continue

            peer_id = self._routing.lookup_from_frame(frame)
            if peer_id is None:
                continue  # no route — silently drop

            session = self._sessions.get(peer_id)
            if session is None or not session.is_established:
                log.debug("Dropping frame — no session for %s", peer_id)
                continue

            try:
                transport = session.encrypt_frame(frame)
            except RuntimeError as exc:
                log.warning("Encrypt failed for %s: %s", peer_id, exc)
                continue

            fragments = self._fragmenter.fragment(transport)
            for i, frag_bytes in enumerate(fragments):
                await self._send_raw(peer_id, frag_bytes)
                if i < len(fragments) - 1:
                    await asyncio.sleep(INTER_FRAGMENT_DELAY)

    # -- mesh → TAP ---------------------------------------------------------

    async def _mesh_to_tap_loop(self) -> None:
        """Receive mesh packets, decrypt, and write to the TAP device."""
        assert self._tap is not None
        gc_counter = 0
        while True:
            msg = await self._vpn_queue.get()
            gc_counter += 1
            if gc_counter % 50 == 0:
                self._fragmenter.gc_stale()

            sender: str = msg.get("sender", "")
            data: bytes = msg.get("data", b"")
            if not data or not sender:
                continue

            try:
                await self._process_incoming(sender, data)
            except Exception as exc:
                log.warning("Error processing packet from %s: %s", sender, exc)

    async def _process_incoming(self, sender: str, data: bytes) -> None:
        """Parse an incoming mesh packet and dispatch by type."""
        pkt = parse_packet(data)

        if isinstance(pkt, HandshakeInit):
            session = self._sessions.get(sender)
            if session is None:
                log.warning("HandshakeInit from unknown peer %s", sender)
                return
            response_bytes = session.respond_to_handshake(pkt)
            await self._send_raw(sender, response_bytes, want_ack=True)

        elif isinstance(pkt, HandshakeResponse):
            session = self._sessions.get(sender)
            if session is None:
                log.warning("HandshakeResponse from unknown peer %s", sender)
                return
            session.complete_handshake(pkt)

        elif isinstance(pkt, TransportData):
            session = self._sessions.get(sender)
            if session is None or not session.is_established:
                log.debug("Transport data from non-established peer %s", sender)
                return
            frame = session.decrypt_frame(pkt)
            assert self._tap is not None
            await self._tap.write_frame(frame)

        elif isinstance(pkt, TransportFragment):
            reassembled = self._fragmenter.reassemble(sender, pkt)
            if reassembled is not None:
                session = self._sessions.get(sender)
                if session is None or not session.is_established:
                    return
                frame = session.decrypt_frame(reassembled)
                assert self._tap is not None
                await self._tap.write_frame(frame)

    # -- handshake manager --------------------------------------------------

    async def _handshake_manager(self) -> None:
        """Periodically initiate handshakes for idle or expired sessions."""
        while True:
            for session in self._sessions.values():
                if session.state == SessionState.IDLE or session.needs_rekey():
                    try:
                        init_bytes = session.initiate_handshake()
                        await self._send_raw(
                            session.peer_node_id, init_bytes, want_ack=True
                        )
                    except Exception as exc:
                        log.warning(
                            "Handshake initiation failed for %s: %s",
                            session.peer_node_id,
                            exc,
                        )
            await asyncio.sleep(HANDSHAKE_POLL_INTERVAL)

    # -- low-level send -----------------------------------------------------

    async def _send_raw(
        self, node_id: str, data: bytes, want_ack: bool = False
    ) -> None:
        """Send raw bytes to a mesh node on the IP_TUNNEL_APP port."""
        retry_count = 2 if want_ack else None
        try:
            await self._mesh._send_data_with_ack(
                payload=data,
                port_num=PRIVATE_APP,
                destination_id=node_id,
                channel_index=0,
                retry_count=retry_count,
                ack_timeout=15.0,
                pki_encrypted=False,  # MeshNet handles its own encryption
            )
        except ConnectionError as exc:
            log.warning("Send to %s failed: %s", node_id, exc)
