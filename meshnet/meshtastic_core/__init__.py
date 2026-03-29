"""
Meshtastic TCP client with channel-based and peer-to-peer communication.

Usage::

    mesh = Meshtastic(ip="10.1.5.3")
    await mesh.connect()

    ch   = mesh.channel("jacomms")          # broadcast on a named channel
    peer = mesh.peer("!d45b9db8")           # direct message to a node ID
    peer = mesh.peer("postar")              # …or resolve by long/short name

    await ch.send_text("hello")
    await peer.send_text("hi", retry_count=2, ack_timeout=10.0)

    msg = await ch.recv(timeout=10.0)
    msg = await peer.recv(timeout=30.0)

    mesh.close()
"""
import asyncio
import logging
from typing import Any, Callable

from pubsub import pub
from meshtastic import tcp_interface, portnums_pb2


class Meshtastic:
    """
    Entry point for Meshtastic communication over TCP.

    Manages the connection, ACK tracking and dispatches incoming text
    packets to registered :class:`ChannelSocket` / :class:`PeerSocket`
    listeners.
    """

    def __init__(self, ip: str, port: int = 4403) -> None:
        """Initialize the Meshtastic client.

        :param ip: The IP address of the Meshtastic device.
        :param port: The TCP port of the Meshtastic device.
        """
        self.hostname: str = ip
        self.port: int = port
        self.interface: tcp_interface.TCPInterface | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected: bool = False
        self._ack_futures: dict[int, asyncio.Future[bool]] = {}
        self._early_acks: dict[int, str] = {}
        self._listeners: list[tuple[Callable[[dict[str, Any]], bool], asyncio.Queue[dict[str, Any]]]] = []

    # ------------------------------------------------------------------
    # Public: lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish a TCP connection to the Meshtastic device."""
        self._loop = asyncio.get_running_loop()
        logging.info("Connecting to %s:%s", self.hostname, self.port)
        self.interface = await self._loop.run_in_executor(
            None,
            lambda: tcp_interface.TCPInterface(
                hostname=self.hostname, portNumber=self.port
            ),
        )
        self._connected = True
        # TEXT_MESSAGE_APP is published to receive.text in most library versions;
        # receive.data is kept as a catch-all for older builds.
        pub.subscribe(self._on_receive_text, "meshtastic.receive.text")
        pub.subscribe(self._on_receive_data, "meshtastic.receive.data")
        pub.subscribe(self._on_receive_routing, "meshtastic.receive.routing")
        logging.info("Connected and subscribed.")

    def close(self) -> None:
        """Disconnect from the device and release resources."""
        if self.interface:
            self.interface.close()
            self.interface = None
        self._connected = False

    # ------------------------------------------------------------------
    # Public: socket factories
    # ------------------------------------------------------------------

    def channel(self, name: str) -> "ChannelSocket":
        """Return a :class:`ChannelSocket` for broadcast comms on *name*."""
        self._require_connected()
        return ChannelSocket(self, name)

    def peer(self, node: str) -> "PeerSocket":
        """Return a :class:`PeerSocket` for direct comms with *node*.

        *node* may be a node ID (``!d45b9db8``) or a long/short name.
        """
        self._require_connected()
        return PeerSocket(self, node)

    # ------------------------------------------------------------------
    # Internal: listener registry
    # ------------------------------------------------------------------

    def _register_listener(
        self, filter_fn: Callable[[dict[str, Any]], bool], queue: asyncio.Queue[dict[str, Any]]
    ) -> Callable[[], None]:
        """Register a (filter, queue) pair. Returns an unregister callable.

        :param filter_fn: A function that returns True if the listener wants this packet.
        :param queue: The asyncio Queue to push matching messages into.
        :return: A callable to unregister the listener.
        """
        entry = (filter_fn, queue)
        self._listeners.append(entry)

        def unregister() -> None:
            """Unregister the listener."""
            try:
                self._listeners.remove(entry)
            except ValueError:
                pass

        return unregister

    def _dispatch(self, packet: dict[str, Any]) -> None:
        """Push *packet* into every listener queue whose filter matches.

        :param packet: The received packet dictionary.
        """
        decoded = packet.get("decoded", {})
        msg = {
            "sender": packet.get("fromId", "unknown"),
            "text": decoded.get("text", ""),
            "data": decoded.get("payload", b""),
            "portnum": decoded.get("portnum", ""),
            "packet": packet,
            "channel": packet.get("channel", 0),
        }
        for filter_fn, queue in self._listeners:
            if filter_fn(packet):
                if self._loop:
                    self._loop.call_soon_threadsafe(queue.put_nowait, msg)

    # ------------------------------------------------------------------
    # Internal: pubsub callbacks
    # ------------------------------------------------------------------

    def _on_receive_text(self, packet: dict[str, Any], interface: Any) -> None:  # noqa: ARG002
        """Handles TEXT_MESSAGE_APP packets from ``meshtastic.receive.text``.

        :param packet: The incoming packet dictionary.
        :param interface: The meshtastic interface (ignored).
        """
        self._dispatch(packet)

    def _on_receive_data(self, packet: dict[str, Any], interface: Any) -> None:  # noqa: ARG002
        """Handles undefined or raw data packets from ``meshtastic.receive.data`` subtopics.

        :param packet: The incoming packet dictionary.
        :param interface: The meshtastic interface (ignored).
        """
        self._dispatch(packet)

    def _on_receive_routing(self, packet: dict[str, Any], interface: Any) -> None:  # noqa: ARG002
        """Handles ROUTING_APP ACK/NAK packets from ``meshtastic.receive.routing``.

        :param packet: The incoming routing packet dictionary.
        :param interface: The meshtastic interface (ignored).
        """
        decoded = packet.get("decoded", {})
        routing = decoded.get("routing", {})
        request_id = decoded.get("requestId")

        if request_id is None:
            return

        error_reason = routing.get("errorReason", "NONE")
        fut = self._ack_futures.get(request_id)
        if fut and not fut.done():
            if error_reason == "NONE":
                self._loop.call_soon_threadsafe(fut.set_result, True)
            else:
                self._loop.call_soon_threadsafe(
                    fut.set_exception,
                    ConnectionError(f"NAK received: {error_reason}"),
                )
        else:
            # ACK arrived before the future was registered — park it.
            self._early_acks[request_id] = error_reason
            if len(self._early_acks) > 100:
                self._early_acks.pop(next(iter(self._early_acks)))

    # ------------------------------------------------------------------
    # Internal: shared send engine
    # ------------------------------------------------------------------

    async def _send_data_with_ack(
        self,
        payload: bytes | str,
        port_num: int,
        destination_id: str = "^all",
        channel_index: int = 0,
        retry_count: int | None = None,
        ack_timeout: float = 15.0,
        pki_encrypted: bool = False,
    ) -> Any:
        """Core send loop shared by :class:`ChannelSocket` and :class:`PeerSocket`.

        :param payload: Data to send (string or bytes).
        :param port_num: The port number logic app.
        :param destination_id: The destination node ID or broadcast address.
        :param channel_index: The channel index to send on.
        :param retry_count: Number of retries on timeout.
        :param ack_timeout: Wait time for an ACK.
        :param pki_encrypted: Whether to use PKI encryption.
        :return: The sent packet object from the radio.
        :raises ConnectionError: If not connected, or if an ACK is not received.
        """
        self._require_connected()
        want_ack = retry_count is not None
        max_attempts = (retry_count + 1) if want_ack else 1

        encoded_payload = payload.encode("utf-8") if isinstance(payload, str) else payload

        for attempt in range(1, max_attempts + 1):
            logging.info(
                "Sending payload (%s bytes) → dest=%s channel=%s port=%s (attempt %s/%s)",
                len(encoded_payload), destination_id, channel_index, port_num, attempt, max_attempts,
            )

            dest = destination_id  # local ref avoids late-binding in lambda
            ch = channel_index
            packet = await self._loop.run_in_executor(
                None,
                lambda: self.interface.sendData(
                    encoded_payload,
                    destinationId=dest,
                    portNum=port_num,
                    channelIndex=ch,
                    wantAck=want_ack,
                    pkiEncrypted=pki_encrypted,
                ),
            )

            if not want_ack:
                return packet

            packet_id = packet.id

            # Handle early ACK (arrived before we registered the future)
            if packet_id in self._early_acks:
                error_reason = self._early_acks.pop(packet_id)
                if error_reason == "NONE":
                    logging.info("Message acknowledged (early): %s", packet_id)
                    return packet
                raise ConnectionError(f"NAK received: {error_reason}")

            fut = self._loop.create_future()
            self._ack_futures[packet_id] = fut

            try:
                await asyncio.wait_for(fut, timeout=ack_timeout)
                logging.info("Message acknowledged: %s", packet_id)
                return packet
            except asyncio.TimeoutError:
                logging.warning(
                    "ACK timeout for packet %s after %ss (attempt %s/%s)",
                    packet_id, ack_timeout, attempt, max_attempts,
                )
            except ConnectionError:
                raise  # NAK is always fatal
            finally:
                self._ack_futures.pop(packet_id, None)

        raise ConnectionError(
            f"No ACK received after {max_attempts} attempt(s)."
        )

    # ------------------------------------------------------------------
    # Internal: helpers
    # ------------------------------------------------------------------

    def _require_connected(self) -> None:
        """Ensures the client is connected before sending data.

        :raises ConnectionError: If the client is disconnected.
        """
        if not self._connected or not self.interface:
            raise ConnectionError("Not connected. Call `await mesh.connect()` first.")

    def _find_channel_index(self, name: str) -> int:
        """Resolve a channel name to its index number."""
        available = []
        if hasattr(self.interface.localNode, "channels"):
            for ch in self.interface.localNode.channels:
                if ch.settings:
                    ch_name = ch.settings.name
                    if ch_name:
                        available.append(ch_name)
                        if ch_name == name:
                            return ch.index
        raise ValueError(
            f"Channel '{name}' not found. Available named channels: {available}"
        )

    def _resolve_node_id(self, node: str) -> str:
        """Resolve a node ID or display name to the canonical ``!xxxxxxxx`` form."""
        if node.startswith("!"):
            return node  # already a node ID
        nodes = self.interface.nodes or {}
        for node_id, info in nodes.items():
            user = info.get("user", {})
            if user.get("longName") == node or user.get("shortName") == node:
                return node_id
        raise ValueError(
            f"Node '{node}' not found. "
            f"Known nodes: {[n.get('user', {}).get('longName') for n in nodes.values()]}"
        )


# ---------------------------------------------------------------------------
# ChannelSocket
# ---------------------------------------------------------------------------

class ChannelSocket:
    """
    Broadcast text messaging on a named Meshtastic channel.

    Obtain via :meth:`Meshtastic.channel`::

        ch = mesh.channel("jacomms")
        await ch.send_text("hello")
        msg = await ch.recv(timeout=10.0)
    """

    def __init__(self, client: Meshtastic, channel_name: str) -> None:
        """Initialize the ChannelSocket.

        :param client: The Meshtastic client instance.
        :param channel_name: The named channel to bind to.
        """
        self._client: Meshtastic = client
        self.channel_name: str = channel_name
        self.channel_index: int = client._find_channel_index(channel_name)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._unregister: Callable[[], None] = client._register_listener(self._filter, self._queue)
        logging.info(
            "ChannelSocket ready: '%s' (index %s)", channel_name, self.channel_index
        )

    # ------------------------------------------------------------------

    def _filter(self, packet: dict[str, Any]) -> bool:
        """Filter incoming packets to match our channel instance.

        :param packet: Packet info dict to check.
        :return: True if the packet matches our channel index.
        """
        return packet.get("channel", 0) == self.channel_index

    async def send_text(
        self,
        text: str,
        retry_count: int | None = None,
        ack_timeout: float = 15.0,
    ) -> Any:
        """Broadcast *text* to all nodes on this channel.

        :param text: The string to send.
        :param retry_count: Number of retries if ACK not received (``None`` = fire & forget).
        :param ack_timeout: Per-attempt ACK wait in seconds.
        :return: The packet sent object.
        """
        return await self._client._send_data_with_ack(
            payload=text,
            port_num=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
            destination_id="^all",
            channel_index=self.channel_index,
            retry_count=retry_count,
            ack_timeout=ack_timeout,
        )

    async def send_bytes(
        self,
        data: bytes,
        port_num: int = portnums_pb2.PortNum.UNKNOWN_APP,
        retry_count: int | None = None,
        ack_timeout: float = 15.0,
    ) -> Any:
        """Broadcast raw *data* to all nodes on this channel over *port_num*.

        :param data: The raw byte payload.
        :param port_num: The PortNum logic app to route to (default ``UNKNOWN_APP``).
        :param retry_count: Number of retries if ACK not received (``None`` = fire & forget).
        :param ack_timeout: Per-attempt ACK wait in seconds.
        :return: The packet sent object.
        """
        return await self._client._send_data_with_ack(
            payload=data,
            port_num=port_num,
            destination_id="^all",
            channel_index=self.channel_index,
            retry_count=retry_count,
            ack_timeout=ack_timeout,
        )

    async def recv(self, timeout: float | None = None) -> dict[str, Any] | None:
        """Wait for the next message on this channel.

        :param timeout: Time in seconds to wait, or None to block indefinitely.
        :return: Message dict with keys ``sender``, ``text``, ``data``, ``portnum``, ``packet``, ``channel``,
                 or ``None`` on timeout.
        """
        try:
            if timeout is None:
                return await self._queue.get()
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def has_data(self) -> bool:
        """``True`` if a message is immediately available (non-blocking check).

        :return: True if a packet is queued up to read.
        """
        return not self._queue.empty()

    def close(self) -> None:
        """Unregister this socket's listener from the client dispatcher."""
        self._unregister()


# ---------------------------------------------------------------------------
# PeerSocket
# ---------------------------------------------------------------------------

class PeerSocket:
    """
    Direct (peer-to-peer) text messaging with a specific Meshtastic node.

    Obtain via :meth:`Meshtastic.peer`::

        peer = mesh.peer("!d45b9db8")   # node ID
        peer = mesh.peer("postar")      # long name or short name

        await peer.send_text("hey", retry_count=2)
        msg = await peer.recv(timeout=30.0)
    """

    def __init__(self, client: Meshtastic, node: str) -> None:
        """Initialize the PeerSocket.

        :param client: The Meshtastic client instance.
        :param node: The node ID string or name string to connect to.
        """
        self._client: Meshtastic = client
        self.node_id: str = client._resolve_node_id(node)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._unregister: Callable[[], None] = client._register_listener(self._filter, self._queue)
        logging.info("PeerSocket ready: peer=%s", self.node_id)

    # ------------------------------------------------------------------

    def _filter(self, packet: dict[str, Any]) -> bool:
        """Filter incoming packets to match our peer source id.

        :param packet: Packet info dict to check.
        :return: True if the packet's fromId matches our target node.
        """
        # Receive messages that originated from this peer
        return packet.get("fromId") == self.node_id

    async def send_text(
        self,
        text: str,
        retry_count: int | None = None,
        ack_timeout: float = 15.0,
        pki: bool = True,
    ) -> Any:
        """Send *text* directly to the peer.

        :param text: The text payload to transmit.
        :param retry_count: Number of retries on ACK timeout (``None`` = fire & forget).
        :param ack_timeout: Per-attempt ACK wait in seconds.
        :param pki: If ``True``, use true end-to-end PKI encryption. Else fallback to channel PSK.
        :return: The sent packet object.
        """
        return await self._client._send_data_with_ack(
            payload=text,
            port_num=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
            destination_id=self.node_id,
            channel_index=0,  # DMs travel on the primary channel
            retry_count=retry_count,
            ack_timeout=ack_timeout,
            pki_encrypted=pki,
        )

    async def send_bytes(
        self,
        data: bytes,
        port_num: int = portnums_pb2.PortNum.UNKNOWN_APP,
        retry_count: int | None = None,
        ack_timeout: float = 15.0,
        pki: bool = True,
    ) -> Any:
        """Send raw *data* directly to the peer over *port_num*.

        :param data: The raw byte array to send.
        :param port_num: The PortNum logic app to route to (default ``UNKNOWN_APP``).
        :param retry_count: Number of retries on ACK timeout (``None`` = fire & forget).
        :param ack_timeout: Per-attempt ACK wait in seconds.
        :param pki: If ``True``, use PKI encryption.
        :return: The sent packet object.
        """
        return await self._client._send_data_with_ack(
            payload=data,
            port_num=port_num,
            destination_id=self.node_id,
            channel_index=0,
            retry_count=retry_count,
            ack_timeout=ack_timeout,
            pki_encrypted=pki,
        )

    async def recv(self, timeout: float | None = None) -> dict[str, Any] | None:
        """Wait for the next direct message from this peer.

        :param timeout: Seconds until TimeoutException is captured and converted to None.
        :return: Message dict with keys ``sender``, ``text``, ``data``, ``portnum``, ``packet``, ``channel``,
                 or ``None`` on timeout.
        """
        try:
            if timeout is None:
                return await self._queue.get()
            return await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def has_data(self) -> bool:
        """``True`` if a direct message is immediately available.

        :return: True if the receiving queue contains an element.
        """
        return not self._queue.empty()

    def close(self) -> None:
        """Unregister this socket's listener from the client dispatcher."""
        self._unregister()
