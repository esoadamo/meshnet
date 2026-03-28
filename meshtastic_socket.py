"""
Provides the MeshtasticSocket class for communicating with a Meshtastic device over TCP.
"""
import asyncio
import logging
from pubsub import pub
from meshtastic import tcp_interface

class MeshtasticSocket:
    def __init__(self, hostname: str, channel_name: str, port=4403):
        self.hostname = hostname
        self.port = port
        self.channel_name = channel_name
        self.channel_index = None
        self.interface = None
        self._message_queue = None
        self._connected = False
        self._loop = None
        self._ack_futures = {}
        self._early_acks = {}
        
    async def connect(self):
        """Connect to the Meshtastic device over TCP asynchronously."""
        self._loop = asyncio.get_running_loop()
        self._message_queue = asyncio.Queue()
        
        logging.info("Connecting to %s:%s", self.hostname, self.port)
        # tcp_interface.TCPInterface runs its own background thread
        # We run it in a thread executor since its init blocks until connected
        self.interface = await self._loop.run_in_executor(
            None, 
            lambda: tcp_interface.TCPInterface(hostname=self.hostname, portNumber=self.port)
        )
        self._connected = True
        
        # Subscribe to text/data messages and ACK/routing packets (different topics!)
        pub.subscribe(self._on_receive_data, "meshtastic.receive.data")
        pub.subscribe(self._on_receive_routing, "meshtastic.receive.routing")
        logging.info("Connected and subscribed to receive.data and receive.routing")
        
        # Resolve channel index if a name was provided
        self.channel_index = self._find_channel_index(self.channel_name)
        logging.info("Resolved channel '%s' to index %s", self.channel_name, self.channel_index)

    def _find_channel_index(self, name):
        """Helper to find the channel index by its string name."""
        available_channels = []
        if hasattr(self.interface.localNode, 'channels'):
            for ch in self.interface.localNode.channels:
                if ch.settings:
                    ch_name = ch.settings.name
                    if ch_name:
                        available_channels.append(ch_name)
                        if ch_name == name:
                            return ch.index
        raise ValueError(f"Channel '{name}' not found. Available named channels: {available_channels}")

    def _on_receive_routing(self, packet, interface):  # noqa: ARG002
        """Callback for ROUTING_APP packets (ACKs/NAKs) from meshtastic pubSub."""
        decoded = packet.get("decoded", {})
        routing = decoded.get("routing", {})
        request_id = decoded.get("requestId")

        logging.debug("[ACK] ROUTING_APP received — requestId=%s, pending_futures=%s, early_acks=%s",
                      request_id, list(self._ack_futures.keys()), list(self._early_acks.keys()))

        if request_id is None:
            logging.debug("[ACK] ROUTING_APP packet has no requestId — ignoring")
            return

        error_reason = routing.get("errorReason", "NONE")
        fut = self._ack_futures.get(request_id)
        if fut and not fut.done():
            logging.debug("[ACK] Resolving future for request_id=%s, error_reason=%s", request_id, error_reason)
            if error_reason == "NONE":
                self._loop.call_soon_threadsafe(fut.set_result, True)
            else:
                self._loop.call_soon_threadsafe(
                    fut.set_exception,
                    ConnectionError(f"NAK received: {error_reason}")
                )
        else:
            logging.debug("[ACK] No matching future for request_id=%s — storing as early ACK", request_id)
            self._early_acks[request_id] = error_reason
            if len(self._early_acks) > 100:
                self._early_acks.pop(next(iter(self._early_acks)))

    def _on_receive_data(self, packet, interface):  # noqa: ARG002
        """Callback for incoming data/text packets from meshtastic pubSub."""
        decoded = packet.get("decoded", {})
        portnum = decoded.get("portnum", "UNKNOWN_APP")

        # Handle text messages
        if portnum == "TEXT_MESSAGE_APP":
            # Filter by channel if one was explicitly requested
            packet_channel = packet.get("channel", 0)
            if self.channel_index is not None and packet_channel != self.channel_index:
                return
                
            text = decoded.get("text", "")
            sender = packet.get("fromId", "unknown")
            msg_data = {"sender": sender, "text": text, "packet": packet, "channel": packet_channel}
            
            # Put to async queue safely
            if self._message_queue and self._loop:
                self._loop.call_soon_threadsafe(self._message_queue.put_nowait, msg_data)
        
    async def send_text(self, text, retry_count=None, ack_timeout=15.0):
        """
        Send a text message to the mesh on the targeted channel.
        :param text: Text to send.
        :param retry_count: Number of times to retry if ACK is not received. 
                            If None, it does not wait for ACK.
        :param ack_timeout: Timeout in seconds for each ACK wait.
        """
        if not self._connected or not self.interface:
            raise ConnectionError("Not connected to a Meshtastic device.")
            
        want_ack = retry_count is not None
        attempts = 0
        max_attempts = (retry_count + 1) if want_ack else 1
        
        while attempts < max_attempts:
            attempts += 1
            logging.info("Sending message: '%s' on channel index %s (Attempt %s/%s)", 
                         text, self.channel_index, attempts, max_attempts)
                         
            packet = await self._loop.run_in_executor(
                None,
                lambda: self.interface.sendText(text, channelIndex=self.channel_index, wantAck=want_ack)
            )
            
            if not want_ack:
                return packet
                
            packet_id = packet.id
            logging.debug("[SEND] sendText returned packet.id=%s (type=%s)", packet_id, type(packet_id).__name__)
            
            # Check if the ACK arrived before we could register the future (race condition)
            if packet_id in self._early_acks:
                error_reason = self._early_acks.pop(packet_id)
                logging.debug("[SEND] Early ACK hit for packet_id=%s, error_reason=%s", packet_id, error_reason)
                if error_reason == "NONE":
                    logging.info("Message acknowledged (early): %s", packet_id)
                    return packet
                else:
                    # NAK is fatal — no point retrying
                    raise ConnectionError(f"NAK received: {error_reason}")
            
            fut = self._loop.create_future()
            self._ack_futures[packet_id] = fut
            logging.debug("[SEND] Registered future for packet_id=%s, now waiting up to %ss", packet_id, ack_timeout)
            
            try:
                # Wait for acknowledgment
                await asyncio.wait_for(fut, timeout=ack_timeout)
                logging.info("Message acknowledged: %s", packet_id)
                return packet
            except asyncio.TimeoutError:
                logging.warning("[SEND] ACK timeout for packet_id=%s after %ss — pending_futures=%s, early_acks=%s",
                                packet_id, ack_timeout, list(self._ack_futures.keys()), list(self._early_acks.keys()))
            except ConnectionError:
                # NAK received via future — fatal, do not retry
                raise
            finally:
                self._ack_futures.pop(packet_id, None)
                
        # If we exited the loop and wanted an ack, it means all retries timed out
        raise ConnectionError(f"Failed to receive ACK after {max_attempts} attempts.")

    async def recv(self, timeout=None):
        """
        Asynchronously block and wait for an incoming message.
        :param timeout: Time in seconds to wait. None means await indefinitely.
        :return: message dictionary or None if timeout.
        """
        if not self._message_queue:
            return None
            
        try:
            if timeout is None:
                return await self._message_queue.get()
            else:
                return await asyncio.wait_for(self._message_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def has_data(self):
        """Check if there is data available to read without blocking."""
        if not self._message_queue:
            return False
        return not self._message_queue.empty()

    def close(self):
        """Close the interface."""
        if self.interface:
            self.interface.close()
            self.interface = None
        self._connected = False
