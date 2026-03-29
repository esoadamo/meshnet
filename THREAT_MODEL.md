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
| X25519 | Static + ephemeral key exchange | `cryptography` (OpenSSL) |
| ChaCha20-Poly1305 | AEAD encryption of transport data | `cryptography` |
| HKDF-SHA256 | Transport key derivation from DH outputs | `cryptography` |
| BLAKE2s (keyed, 128-bit) | Handshake message authentication | Python `hashlib` |

### Handshake

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

* **Forward secrecy**: Compromising a static key does not reveal past session keys (ephemeral DH).
* **Mutual authentication**: Both sides prove possession of their static private key through DH.
* **Optional PSK**: Adds a symmetric secret to the KDF, providing defence-in-depth against future quantum attacks on X25519.

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

### 3.2 Cryptographic threats

| ID | Threat | Severity | Mitigation | Status |
|---|---|---|---|---|
| **C-1** | **Nonce reuse** — same (key, nonce) pair used twice | Critical | Monotonic counter per session; counter overflow guard raises `OverflowError`; sessions rekey after 2¹⁶ messages or 5 minutes | ✅ Mitigated |
| **C-2** | **Key compromise** — static private key stolen | Critical | Config file permission warning (should be `0600`); private key never logged; ephemeral keys provide forward secrecy for past sessions | ⚠️ Partially mitigated |
| **C-3** | **Weak randomness** — predictable key generation | High | Uses `os.urandom()` and `X25519PrivateKey.generate()` from the `cryptography` library (backed by OpenSSL CSPRNG) | ✅ Mitigated |
| **C-4** | **Quantum attack on X25519** — future quantum computer breaks ECDH | Low (future) | Optional PSK provides a symmetric fallback; full post-quantum key exchange not yet implemented | ⚠️ Partial (PSK-only) |
| **C-5** | **Side-channel timing** — MAC verification leaks information | Medium | BLAKE2s MAC verified via `hmac.compare_digest()` (constant-time comparison) | ✅ Mitigated |

### 3.3 Host-level threats

| ID | Threat | Severity | Mitigation | Status |
|---|---|---|---|---|
| **H-1** | **Config file exposure** — private key readable by other users | High | CLI warns on insecure permissions; documentation recommends `chmod 600` | ⚠️ Warning only |
| **H-2** | **PID file race condition** — TOCTOU between check and write | Low | PID file created atomically with `O_CREAT \| O_EXCL` | ✅ Mitigated |
| **H-3** | **PID file poisoning** — attacker writes arbitrary PID | Low | PID content validated: must be numeric and positive before `kill()` | ✅ Mitigated |
| **H-4** | **TAP name injection** — malicious interface name | Medium | TAP name validated against `^[a-zA-Z0-9][-a-zA-Z0-9]{0,14}$`; MTU bounds-checked | ✅ Mitigated |
| **H-5** | **Privilege escalation** — daemon runs as root | Medium | Necessary for TAP device creation (`CAP_NET_ADMIN`); no privilege dropping after setup | ⚠️ Residual risk |
| **H-6** | **Memory exposure** — key material in process memory | Low | Python does not offer secure memory zeroing; keys remain in heap until GC'd | ⚠️ Inherent limitation |

### 3.4 Protocol-level threats

| ID | Threat | Severity | Mitigation | Status |
|---|---|---|---|---|
| **P-1** | **Identity misbinding** — peer impersonation | High | Handshake MAC uses `DH(static_I, static_R)`; only the holder of the correct static key can produce a valid MAC | ✅ Mitigated |
| **P-2** | **Session ID collision** — two sessions with same 32-bit ID | Low | Session IDs are random (`os.urandom(4)`); collision probability is ~1/2³² per handshake | ✅ Acceptable |
| **P-3** | **Cross-session key reuse** — same transport keys in different sessions | Critical | Each handshake generates fresh ephemeral keys; three independent DH computations ensure unique key material | ✅ Mitigated |
| **P-4** | **Denial of service via rekeying** — forcing constant rekeys | Medium | Rekey only triggered by time (5 min) or message count (2¹⁶); handshake flood rate limiting not implemented | ⚠️ Residual risk |

---

## 4. Residual risks and recommendations

### Current residual risks

| Risk | Recommendation |
|---|---|
| **No handshake rate limiting (N-5, P-4)** | Implement per-peer rate limiting on handshake initiation and response (e.g. 1 handshake per 5 seconds per peer) |
| **Daemon runs as root (H-5)** | After TAP device creation, drop to an unprivileged user/group using `setuid()`/`setgid()` |
| **No secure memory zeroing (H-6)** | Inherent Python limitation; for highest-security deployments, consider a C/Rust core for key management |
| **Config file not enforced 0600 (H-1)** | Optionally refuse to start if permissions are too open (like SSH does with `~/.ssh/id_rsa`) |
| **No certificate/PKI-based identity (P-1)** | Consider adding an optional certificate chain for identity verification in larger mesh networks |
| **Meshtastic TCP unencrypted (N-1)** | The TCP link to the local Meshtastic device is plaintext; if the radio is remote, tunnel it through SSH or TLS |

### Future enhancements

1. **Post-quantum key exchange** — Replace or augment X25519 with a hybrid KEM (e.g. ML-KEM/Kyber + X25519)
2. **Privilege separation** — Fork a privileged TAP helper and run crypto/routing as unprivileged
3. **Cookie-based DoS protection** — Add a cookie mechanism (like WireGuard's `mac2`) to validate handshake initiators under load
4. **Audit logging** — Log handshake events, auth failures, and rekey events to syslog for SIEM integration
5. **Key rotation** — Support hot-reloading of config files for key rotation without daemon restart

---

## 5. STRIDE analysis summary

| STRIDE Category | Applicable threats | Primary mitigations |
|---|---|---|
| **Spoofing** | P-1 (impersonation) | Static key mutual authentication via DH+MAC |
| **Tampering** | N-3 (packet modification) | Poly1305 AEAD authentication tag |
| **Repudiation** | — | Not addressed (no audit logging yet) |
| **Information disclosure** | N-1 (eavesdropping), C-2 (key theft), H-1 (config exposure) | ChaCha20 encryption, permission warnings |
| **Denial of service** | N-5 (handshake flood), N-7 (fragment exhaustion) | Buffer limits, GC timeouts |
| **Elevation of privilege** | H-5 (root daemon) | Root required for TAP; no privilege drop yet |

---

## 6. Security contact

If you discover a security vulnerability, please report it privately through
GitHub's security advisory feature rather than opening a public issue.
