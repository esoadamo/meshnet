# MeshNet

**WireGuard-style VPN over Meshtastic mesh radio**

MeshNet creates encrypted, peer-to-peer IP tunnels that run over
[Meshtastic](https://meshtastic.org/) LoRa mesh radios.  It bridges a Linux
TAP virtual Ethernet interface to the mesh network, giving every node a
routable IP address — even when there is no Internet infrastructure.

## Features

| Feature | Description |
|---|---|
| **WireGuard-inspired cryptography** | X25519 key exchange, ChaCha20-Poly1305 AEAD, HKDF-SHA256 KDF, BLAKE2s MACs |
| **Simplified handshake** | 1-RTT handshake with mutual static-key authentication and ephemeral forward secrecy |
| **Optional preshared key (PSK)** | Extra symmetric key mixed into key derivation for post-quantum defence-in-depth |
| **Automatic rekeying** | Sessions rekey after 5 minutes or 2¹⁶ messages |
| **Sliding-window replay protection** | 256-packet window rejects duplicates while tolerating reordering |
| **Fragmentation / reassembly** | Transparently splits payloads exceeding the 233-byte Meshtastic radio MTU |
| **Familiar CLI** | `meshnet genkey`, `pubkey`, `genpsk`, `up`, `down`, `show` — just like `wg` |

## Architecture

```
┌──────────────┐      TAP       ┌─────────────────┐    TCP/IP    ┌────────────────┐
│  Linux apps  │  ◄─────────►   │  MeshVPN Daemon  │  ◄────────► │  Meshtastic    │
│  (10.0.0.x)  │   Ethernet     │  encrypt/decrypt │    4403     │  LoRa Radio    │
└──────────────┘   frames       │  fragment/reasm  │             └────────────────┘
                                └─────────────────┘
```

### Package layout

```
meshnet/
├── __init__.py            # version
├── cli/                   # CLI entry point ("meshnet" command)
│   └── __init__.py
├── meshtastic_core/       # Meshtastic TCP client abstraction
│   └── __init__.py
└── vpn/
    ├── config.py          # WireGuard-style config parser
    ├── crypto.py          # X25519, ChaCha20-Poly1305, HKDF, BLAKE2s
    ├── daemon.py          # Async VPN daemon (TAP ↔ mesh bridge)
    ├── routing.py         # AllowedIPs routing table + Ethernet frame parsing
    ├── session.py         # Per-peer handshake state machine + encrypt/decrypt
    ├── tap.py             # Linux TAP device via ioctl
    └── transport.py       # Wire protocol: packets, serialisation, fragmentation
```

## Quick start

### Prerequisites

* Python ≥ 3.13
* Linux (for TAP device)
* A Meshtastic device reachable over TCP (default port 4403)
* [uv](https://docs.astral.sh/uv/) package manager (recommended)

### Installation

```bash
git clone https://github.com/esoadamo/meshnet.git
cd meshnet
uv sync          # installs into .venv
```

Or install as a package:

```bash
pip install .
```

### Generate keys

```bash
# Generate a private key
meshnet genkey > privatekey

# Derive the public key
meshnet pubkey < privatekey > publickey

# Generate an optional preshared key (one per peer pair)
meshnet genpsk > presharedkey
```

### Create a configuration file

Create `mesh0.conf`:

```ini
[Interface]
PrivateKey = <base64 private key>
Address = 10.0.0.1/24
MTU = 180
TapName = mesh0
MeshtasticConnect = tcp://10.1.5.3:4403

[Peer]
PublicKey = <peer's base64 public key>
PresharedKey = <optional base64 PSK>
AllowedIPs = 10.0.0.2/32
Endpoint = !d45b9db8
```

> **Security:** Set `chmod 600 mesh0.conf` — the file contains your private key.

### Start the tunnel

```bash
sudo meshnet up -c mesh0.conf
```

### Show status

```bash
meshnet show -c mesh0.conf
```

### Stop the tunnel

```bash
meshnet down
```

## Configuration reference

### `[Interface]` section

| Key | Required | Default | Description |
|---|---|---|---|
| `PrivateKey` | ✅ | — | Base64-encoded X25519 private key (32 bytes) |
| `Address` | ✅ | — | Local IP address with CIDR prefix (e.g. `10.0.0.1/24`) |
| `MTU` | ❌ | `180` | TAP device MTU (constrained by Meshtastic payload size) |
| `TapName` | ❌ | `mesh0` | Linux TAP interface name |
| `MeshtasticConnect` | ✅ | — | Connection URI for the Meshtastic device (see below) |

**`MeshtasticConnect` URI schemes:**

| Scheme | Example | Description |
|---|---|---|
| `tcp://` | `tcp://10.1.5.3:4403` | TCP connection (port defaults to `4403`) |
| `serial://` | `serial:///dev/ttyUSB0` | Linux serial port |
| `serial://` | `serial://COM3` | Windows COM port |

### `[Peer]` section (one or more)

| Key | Required | Description |
|---|---|---|
| `PublicKey` | ✅ | Peer's base64-encoded X25519 public key |
| `PresharedKey` | ❌ | Optional base64-encoded 32-byte PSK for extra security |
| `AllowedIPs` | ✅ | Comma-separated CIDR ranges routed to this peer |
| `Endpoint` | ✅ | Meshtastic node ID (e.g. `!d45b9db8`) |

## Wire protocol

All packets start with a 1-byte type discriminator:

| Type | Name | Layout (after type byte) |
|---|---|---|
| `0x01` | HandshakeInit | `session(4) + eph_pub(32) + mac(16)` = 52 B |
| `0x02` | HandshakeResponse | `sender(4) + recv(4) + eph_pub(32) + mac(16)` = 56 B |
| `0x03` | TransportData | `counter(8) + ciphertext(N)` |
| `0x04` | TransportFragment | `msg_id(2) + frag_idx(1) + frag_total(1) + chunk(N)` |

### Handshake flow

```
    Initiator                       Responder
       │                                │
       │  HandshakeInit (0x01)          │
       │  session_I + eph_I + MAC       │
       │ ─────────────────────────────► │
       │                                │
       │  HandshakeResponse (0x02)      │
       │  session_R + session_I +       │
       │  eph_R + MAC                   │
       │ ◄───────────────────────────── │
       │                                │
       │  [session established]         │
       │  TransportData (0x03)          │
       │ ◄─────────────────────────────►│
```

Three Diffie-Hellman computations derive transport keys:

1. **DH(eph_I, eph_R)** — ephemeral-ephemeral (forward secrecy)
2. **DH(static_I, eph_R)** — static-ephemeral (identity binding)
3. **DH(eph_I, static_R)** — ephemeral-static (identity binding)

If a PSK is configured, it is mixed into the HKDF salt for additional
post-quantum protection.

## Testing

```bash
uv run pytest tests/ -v --tb=short
```

The test suite includes **186 tests** across three categories:

* **Unit tests** — crypto, transport, config, routing, session, TAP, CLI, meshtastic core
* **Integration tests** — full handshake→encrypt→fragment→reassemble→decrypt pipelines
* **Regression tests** — replay protection, tampering, malformed input, cross-session isolation

All external dependencies (Meshtastic library, TAP device, OS calls) are mocked.

## Security

See [THREAT_MODEL.md](THREAT_MODEL.md) for a detailed threat model and
security analysis.

### Security hardening summary

* **Replay protection**: Sliding-window (256 packets) rejects duplicates while tolerating mesh reordering
* **Nonce safety**: Counter overflow guard prevents nonce reuse
* **Input validation**: TAP name regex, MTU bounds, fragment metadata checks
* **PID file**: Atomic creation with `O_EXCL` prevents TOCTOU race conditions
* **Config permissions**: Warning emitted if config file (containing private key) is world-readable
* **Reassembly limits**: Hard cap on concurrent reassembly buffers prevents memory exhaustion

## License

See repository for license details.