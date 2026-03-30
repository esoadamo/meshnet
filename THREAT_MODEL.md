# MeshNet Threat Model

This document describes the security architecture, trust boundaries, attack
surfaces, identified threats, and mitigations for MeshNet — a WireGuard-style
VPN that runs over Meshtastic LoRa mesh radios.

---

## 1. System overview

MeshNet consists of:

| Component | Trust level | Description |
|---|---|---|
| **meshnet daemon** | Trusted (root) | Runs with `CAP_NET_ADMIN`, manages TAP device, holds private key in memory |
| **Configuration file** | Sensitive | Contains the X25519 private key and PSK in base64 |
| **Meshtastic radio** | Untrusted transport | LoRa mesh radio accessed via TCP; all data on the radio link is considered public |
| **Peer nodes** | Authenticated | Peers are identified by their static X25519 public key; unauthenticated nodes are rejected |
| **Linux TAP device** | Trusted local | Virtual Ethernet interface in kernel space; only root can create it |
| **Local applications** | Trusted local | Any process can send IP traffic through the TAP device |

### Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    Trusted (local host)                      │
│                                                             │
│  ┌──────────┐     TAP      ┌────────────┐                  │
│  │ Local    │◄────────────►│  meshnet   │                   │
│  │ Apps     │  plaintext    │  daemon    │                   │
│  └──────────┘  Ethernet     └─────┬──────┘                  │
│                                   │ TCP :4403               │
│                              ┌────▼──────┐                  │
│                              │ Meshtastic│                  │
│                              │ device    │                  │
└──────────────────────────────┴───────────┴──────────────────┘
                                    │
                        ════════════╪═══════════  ← Trust boundary
                                    │
                            ┌───────▼───────┐
                            │  LoRa radio   │
                            │  (broadcast)  │  ← Untrusted, public
                            └───────────────┘
```

---

## 2. Cryptographic design

### Primitives

| Primitive | Usage | Library |
|---|---|---|
| X25519 | Static + ephemeral key exchange (PKI mode) | `cryptography` (OpenSSL) |
| ChaCha20-Poly1305 | AEAD encryption of transport data (both modes) | `cryptography` |
| HKDF-SHA256 | Transport key derivation from DH outputs (PKI) or PSK (Symmetric) | `cryptography` |
| BLAKE2s (keyed, 128-bit) | Handshake message authentication (PKI mode) | Python `hashlib` |

### Peer modes

MeshNet supports two peer modes:

**PKI mode** (default, `PeerMode = PKI`) — a 1-RTT X25519 handshake with
mutual static-key authentication.  An optional PSK is mixed into the KDF
for post-quantum defence-in-depth.  Sessions rekey automatically.

**Symmetric mode** (`PeerMode = SYMMETRIC`) — the transport key is derived
from the config PSK via `HKDF-SHA256(ikm=PSK, salt="symmetric",
info="meshnet-symmetric-key")`.  No handshake is performed; the session is
immediately established.  Both peers must configure the same PSK.

### Handshake (PKI mode)

The handshake is a simplified WireGuard IKpsk2-like pattern:

```
Initiator (I)                               Responder (R)
─────────────                               ─────────────
e_I ← X25519.generate()
MAC ← BLAKE2s(DH(s_I, s_R),
              session_I ‖ e_I.pub)
                                    ──►
                                            Verify MAC using DH(s_R, s_I)
                                            e_R ← X25519.generate()
                                            Compute:
                                              dh_ee = DH(e_R, e_I)
                                              dh_se = DH(e_R, s_I)
                                              dh_es = DH(s_R, e_I)
                                            keys = HKDF(dh_ee‖dh_se‖dh_es,
                                                        salt=PSK∨0, "meshnet-…")
                                            MAC_R ← BLAKE2s(HKDF(…,"response-mac"),
                                                            session_R ‖ session_I ‖ e_R.pub)
                                    ◄──
Verify MAC_R
Compute same DH and derive keys
```

**Key properties:**

* **Forward secrecy** (PKI only): Compromising a static key does not reveal past session keys (ephemeral DH).
* **Mutual authentication** (PKI only): Both sides prove possession of their static private key through DH.
* **Optional PSK** (PKI): Adds a symmetric secret to the KDF, providing defence-in-depth against future quantum attacks on X25519.

### Nonce / counter strategy

**PKI mode**: Send counter starts at 0 after each handshake.  This is safe
because every handshake derives fresh transport keys from ephemeral DH.

**Symmetric mode**: The derived key is static (same PSK → same key), so
the send counter starts at a random 64-bit value
(`int.from_bytes(os.urandom(8), "little")`) to prevent nonce reuse across
daemon restarts.  With a 64-bit counter space and random starting point,
the birthday-bound risk of two sessions overlapping is approximately
2⁻³² after ~2³² daemon restarts — acceptable for the threat model.

---

## 3. Threat catalogue

### 3.1 Network-layer threats (LoRa radio link)

| ID | Threat | Severity | Mitigation | Status |
|---|---|---|---|---|
| **N-1** | **Eavesdropping** — attacker captures LoRa packets | High | All transport data is ChaCha20-Poly1305 encrypted; handshake exposes only ephemeral public keys | ✅ Mitigated |
| **N-2** | **Replay attack** — attacker re-transmits captured packets | High | Sliding-window replay protection (256-packet window); counter tracked per session with set-based deduplication | ✅ Mitigated |
| **N-3** | **Packet tampering** — attacker modifies ciphertext in transit | High | Poly1305 authentication tag detects any modification | ✅ Mitigated |
| **N-4** | **Handshake replay** — attacker replays a `HandshakeInit` | Medium | MAC is bound to the initiator's static key; responder generates fresh ephemeral key each time; replayed inits produce new (useless-to-attacker) sessions | ✅ Mitigated |
| **N-5** | **Handshake flood** — attacker sends many `HandshakeInit` packets | Medium | Each init requires a DH computation on the responder. No rate limiting currently exists. | ⚠️ Residual risk |
| **N-6** | **Fragment injection** — attacker injects crafted fragments | Medium | Fragments are reassembled then decrypted; injected data fails AEAD authentication | ✅ Mitigated |
| **N-7** | **Fragment memory exhaustion** — attacker floods incomplete fragments | Medium | Hard cap of 256 concurrent reassembly buffers + 30s timeout GC; oldest buffer evicted at capacity | ✅ Mitigated |

### 3.1 Protocol-level threats

| ID | Threat | Severity | Mitigation | Status |
|---|---|---|---|---|
| **P-1** | **Identity misbinding** — peer impersonation | High | Handshake MAC uses `DH(static_I, static_R)`; only the holder of the correct static key can produce a valid MAC | ✅ Mitigated |
| **P-2** | **Session ID collision** — two sessions with same 32-bit ID | Low | Session IDs are random (`os.urandom(4)`); collision probability is ~1/2³² per handshake | ✅ Acceptable |
| **P-3** | **Cross-session key reuse** — same transport keys in different sessions | Critical | **PKI**: Each handshake generates fresh ephemeral keys; three independent DH computations ensure unique key material. **Symmetric**: Key is static but nonce collision is mitigated by random 64-bit counter start | ✅ Mitigated |
| **P-4** | **Denial of service via rekeying** — forcing constant rekeys | Medium | Rekey only triggered by time (5 h) or message count (2¹⁶); idle links defer rekey until next traffic; handshake flood rate limiting not implemented; **Symmetric** mode is immune (no rekeying) | ⚠️ Residual risk (PKI only) |

---

## 4. Residual risks and recommendations

### Current residual risks

| Risk | Recommendation |
|---|---|
| **No handshake rate limiting (N-5, P-4)** | Implement per-peer rate limiting on handshake initiation and response (e.g. 1 handshake per 5 seconds per peer) |
| **Symmetric mode: no forward secrecy** | PSK compromise exposes all traffic; rotate PSKs periodically; prefer PKI mode when latency permits |
| **Symmetric mode: nonce collision risk** | Random 64-bit counter start has ~2⁻³² collision probability after ~2³² restarts; acceptable but consider persisting last counter value for long-lived deployments |
| **Daemon runs as root (H-5)** | Configure `RunAsUser`/`RunAsGroup` in `[Interface]` to drop privileges after TAP creation; without these options the daemon stays root |

---

## 5. STRIDE analysis summary

| STRIDE Category | Applicable threats | Primary mitigations |
|---|---|---|
| **Spoofing** | P-1 (impersonation) | PKI: static key mutual authentication via DH+MAC; Symmetric: PSK knowledge required |
| **Tampering** | N-3 (packet modification) | Poly1305 AEAD authentication tag (both modes) |
| **Repudiation** | — | Not addressed (no audit logging yet) |
| **Information disclosure** | N-1 (eavesdropping), C-2 (key theft), H-1 (config exposure) | ChaCha20 encryption, permission warnings |
| **Denial of service** | N-5 (handshake flood), N-7 (fragment exhaustion) | Buffer limits, GC timeouts |
| **Elevation of privilege** | H-5 (root daemon) | Root required for TAP; optional `RunAsUser`/`RunAsGroup` drops privileges after setup |

---

## 6. Security contact

If you discover a security vulnerability, please report it privately through
GitHub's security advisory feature rather than opening a public issue.
