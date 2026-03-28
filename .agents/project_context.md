# meshtastic-net Project Context

## Project Purpose
To provide a traditional, socket-like wrapper around the `meshtastic` python package for IP-based TCP devices.
Allows simple `connect()`, `send_text()`, `recv(timeout)`, and `has_data()` operations.

## Dependencies
- Package manager: `uv`
- Core library dependencies: `meshtastic`

## Usage Instructions
- For IP nodes, we connect using `meshtastic.tcp_interface.TCPInterface`.
- **Channel Routing**: The constructor accepts `channel_name`. If provided, it maps the name to a channel index.
- Default Python pubSub listens to `meshtastic.receive.data`. Incoming packets are filtered by the resolved `channel_index` before queuing.
- Messages are pushed to an internal thread-safe `queue.Queue`.
- The user can block on `.recv()` like a traditional socket.

## Future Plans
- Expanding to handle specific message IDs.
- Acknowledgments structure if required.
