"""Integration tests: two-device session recovery with mocked time and lossy channels.

Tests cover four main scenarios for PKI session mode:

1. **Good connection** — handshake completes and a "hello world" frame
   flows from one device to the other without loss.

2. **Bad connection / init lost** — the HandshakeInit is dropped; after the
   INIT_SENT timeout the session resets to IDLE and the next attempt succeeds.

3. **Bad connection / response lost** — the HandshakeResponse is dropped;
   B is established but A times out, resets, and the retry succeeds.

4. **Data-packet loss** — individual transport frames are lost but the session
   remains usable; subsequent frames including a final "hello world" decrypt
   correctly.

Time is controlled via a ``MockClock`` that patches ``time.monotonic`` and
``time.time`` globally so timeouts can be triggered without waiting.
"""

from __future__ import annotations

import asyncio
import random
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import patch

import pytest

from meshnet.vpn.crypto import KeyPair, generate_psk
from meshnet.vpn.session import (
    INIT_TIMEOUT_SECONDS,
    REKEY_AFTER_SECONDS,
    REKEY_DEFER_IDLE_SECONDS,
    PeerSession,
    SessionState,
)
from meshnet.vpn.transport import TransportData, parse_packet


# ---------------------------------------------------------------------------
# Mock clock
# ---------------------------------------------------------------------------


class MockClock:
    """Controllable monotonic + wall clock for session timeout testing.

    Both clocks advance together.  ``wall_offset`` separates them so that
    code comparing ``time.monotonic()`` with ``time.time()`` still works.
    """

    def __init__(
        self,
        monotonic_start: float = 0.0,
        wall_offset: float = 1_000_000.0,
    ) -> None:
        self._monotonic: float = monotonic_start
        self._wall: float = monotonic_start + wall_offset

    def advance(self, seconds: float) -> None:
        """Advance both clocks by *seconds*."""
        self._monotonic += seconds
        self._wall += seconds

    def monotonic(self) -> float:
        """Return the current mocked monotonic time."""
        return self._monotonic

    def time(self) -> float:
        """Return the current mocked wall-clock time."""
        return self._wall


@contextmanager
def frozen_session_time(clock: MockClock) -> Iterator[MockClock]:
    """Patch ``time.monotonic`` and ``time.time`` globally for this block.

    All code that imports ``time`` (session, transport, …) will observe the
    mock clock.  The patches are restored on exit.
    """
    import time as _time_mod

    with patch.object(_time_mod, "monotonic", side_effect=clock.monotonic):
        with patch.object(_time_mod, "time", side_effect=clock.time):
            yield clock


# ---------------------------------------------------------------------------
# Lossy channel simulation
# ---------------------------------------------------------------------------


class LossyChannel:
    """Simulates a radio link with optional deterministic or random packet loss.

    Parameters
    ----------
    drop_indices:
        Set of zero-based packet indices to drop deterministically.
    drop_probability:
        Independent per-packet drop probability (0.0 = no loss, 1.0 = all).
    seed:
        RNG seed for reproducible probabilistic tests.
    """

    def __init__(
        self,
        drop_indices: set[int] | None = None,
        drop_probability: float = 0.0,
        seed: int = 42,
    ) -> None:
        self._drop_indices: set[int] = drop_indices or set()
        self._drop_probability: float = drop_probability
        self._rng: random.Random = random.Random(seed)
        self._counter: int = 0
        self.dropped_count: int = 0
        self.delivered_count: int = 0

    def transmit(self, data: bytes) -> bytes | None:
        """Simulate transmission.

        Returns the data unchanged if it is delivered, or ``None`` if it
        is dropped.
        """
        idx = self._counter
        self._counter += 1
        dropped = idx in self._drop_indices or (
            self._drop_probability > 0
            and self._rng.random() < self._drop_probability
        )
        if dropped:
            self.dropped_count += 1
            return None
        self.delivered_count += 1
        return data


# ---------------------------------------------------------------------------
# PKI session helpers
# ---------------------------------------------------------------------------


def _make_pki_pair(
    psk: bytes | None = None,
) -> tuple[PeerSession, PeerSession]:
    """Create two unconnected :class:`PeerSession` objects (A↔B)."""
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    session_a = PeerSession("!b", kp_b.public_bytes(), kp_a, preshared_key=psk)
    session_b = PeerSession("!a", kp_a.public_bytes(), kp_b, preshared_key=psk)
    return session_a, session_b


def _attempt_handshake(
    session_a: PeerSession,
    session_b: PeerSession,
    channel_a_to_b: LossyChannel | None = None,
    channel_b_to_a: LossyChannel | None = None,
) -> bool:
    """Run one handshake exchange through optional lossy channels.

    Returns ``True`` when both sides reach ``ESTABLISHED``.
    Returns ``False`` (and leaves the sessions in their intermediate
    states) if any message is dropped.
    """
    ch_ab = channel_a_to_b or LossyChannel()
    ch_ba = channel_b_to_a or LossyChannel()

    init_bytes = session_a.initiate_handshake()
    delivered_init = ch_ab.transmit(init_bytes)
    if delivered_init is None:
        return False  # HandshakeInit lost

    init_pkt = parse_packet(delivered_init)
    resp_bytes = session_b.respond_to_handshake(init_pkt)

    delivered_resp = ch_ba.transmit(resp_bytes)
    if delivered_resp is None:
        return False  # HandshakeResponse lost — B is established, A is not

    resp_pkt = parse_packet(delivered_resp)
    session_a.complete_handshake(resp_pkt)
    return session_a.is_established and session_b.is_established


def _tick_handshake_manager(session: PeerSession) -> None:
    """Simulate one poll cycle of the daemon's handshake manager.

    Resets the session to IDLE if the INIT_SENT timeout has expired.
    """
    if session.init_timed_out():
        session.reset_to_idle()


# ---------------------------------------------------------------------------
# Tests: PKI mode — perfect channel
# ---------------------------------------------------------------------------


class TestPKIGoodConnection:
    """PKI handshake and frame transport over a lossless channel."""

    def test_hello_world_a_to_b(self) -> None:
        """A initiates, handshake succeeds, hello-world frame reaches B."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert _attempt_handshake(session_a, session_b)

            frame = b"hello world"
            transport = session_a.encrypt_frame(frame)
            assert session_b.decrypt_frame(transport) == frame

    def test_hello_world_b_to_a(self) -> None:
        """After the same handshake, B can also send to A."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert _attempt_handshake(session_a, session_b)

            frame = b"hello world"
            transport = session_b.encrypt_frame(frame)
            assert session_a.decrypt_frame(transport) == frame

    def test_hello_world_with_preshared_key(self) -> None:
        """PKI + PSK mode: handshake completes and frame is delivered."""
        clock = MockClock()
        with frozen_session_time(clock):
            psk = generate_psk()
            session_a, session_b = _make_pki_pair(psk=psk)
            assert _attempt_handshake(session_a, session_b)

            frame = b"hello world"
            assert session_b.decrypt_frame(session_a.encrypt_frame(frame)) == frame

    def test_bidirectional_multiple_frames(self) -> None:
        """Ten frames flow correctly in each direction after one handshake."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert _attempt_handshake(session_a, session_b)

            for i in range(10):
                msg = f"message {i}".encode()
                assert session_b.decrypt_frame(session_a.encrypt_frame(msg)) == msg
                assert session_a.decrypt_frame(session_b.encrypt_frame(msg)) == msg

    def test_both_sides_established_after_handshake(self) -> None:
        """Both sessions reach ESTABLISHED state after a successful handshake."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert session_a.state == SessionState.IDLE
            assert session_b.state == SessionState.IDLE

            assert _attempt_handshake(session_a, session_b)

            assert session_a.state == SessionState.ESTABLISHED
            assert session_b.state == SessionState.ESTABLISHED


# ---------------------------------------------------------------------------
# Tests: PKI mode — lossy channel recovery
# ---------------------------------------------------------------------------


class TestPKIBadConnection:
    """PKI session recovery when handshake or data packets are lost."""

    def test_recovery_when_init_lost(self) -> None:
        """HandshakeInit dropped → A times out → A resets → retry succeeds.

        Production equivalent: A sends an init, it never reaches B over the
        radio.  After INIT_TIMEOUT_SECONDS the handshake manager resets A
        to IDLE.  The next frame (or next manager poll) triggers a fresh
        handshake that succeeds, and the hello-world message is delivered.
        """
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()

            # First attempt: init is dropped before it reaches B.
            drop_first = LossyChannel(drop_indices={0})
            result = _attempt_handshake(session_a, session_b, channel_a_to_b=drop_first)
            assert not result
            assert session_a.state == SessionState.INIT_SENT
            assert session_b.state == SessionState.IDLE  # B never saw anything

            # Advance past the INIT_SENT timeout.
            clock.advance(INIT_TIMEOUT_SECONDS + 1)
            _tick_handshake_manager(session_a)
            assert session_a.state == SessionState.IDLE

            # Retry over a perfect channel — must succeed.
            assert _attempt_handshake(session_a, session_b)
            assert session_a.is_established
            assert session_b.is_established

            # Hello-world message flows.
            frame = b"hello world"
            assert session_b.decrypt_frame(session_a.encrypt_frame(frame)) == frame

    def test_recovery_when_response_lost(self) -> None:
        """HandshakeResponse dropped → A times out → A resets → retry succeeds.

        B responds and becomes ESTABLISHED; A never sees the response so it
        stays INIT_SENT.  After timeout A retries.  B (already ESTABLISHED)
        processes the new init and re-establishes with fresh keys.
        """
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()

            perfect_ab = LossyChannel()
            drop_resp = LossyChannel(drop_indices={0})
            result = _attempt_handshake(
                session_a,
                session_b,
                channel_a_to_b=perfect_ab,
                channel_b_to_a=drop_resp,
            )
            assert not result
            # B responded → B is ESTABLISHED with old keys.
            assert session_b.state == SessionState.ESTABLISHED
            # A never got the response → A is still waiting.
            assert session_a.state == SessionState.INIT_SENT

            # Advance past the timeout and let the manager reset A.
            clock.advance(INIT_TIMEOUT_SECONDS + 1)
            _tick_handshake_manager(session_a)
            assert session_a.state == SessionState.IDLE

            # Retry.  B (ESTABLISHED) re-handshakes when it sees a new init
            # with a different sender_session.
            assert _attempt_handshake(session_a, session_b)
            assert session_a.is_established
            assert session_b.is_established

            # Hello world flows after recovery.
            frame = b"hello world"
            assert session_b.decrypt_frame(session_a.encrypt_frame(frame)) == frame

    def test_recovery_after_multiple_consecutive_failures(self) -> None:
        """Three consecutive dropped inits; session recovers on the fourth try."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()

            for _ in range(3):
                drop_all = LossyChannel(drop_indices={0})
                _attempt_handshake(session_a, session_b, channel_a_to_b=drop_all)
                assert session_a.state == SessionState.INIT_SENT
                assert not session_a.init_timed_out()  # not yet

                clock.advance(INIT_TIMEOUT_SECONDS + 1)
                assert session_a.init_timed_out()
                _tick_handshake_manager(session_a)
                assert session_a.state == SessionState.IDLE

            # Fourth attempt is clean.
            assert _attempt_handshake(session_a, session_b)
            frame = b"hello world"
            assert session_b.decrypt_frame(session_a.encrypt_frame(frame)) == frame

    def test_data_packets_survive_partial_loss(self) -> None:
        """Even-indexed frames are dropped; odd-indexed ones are received intact."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert _attempt_handshake(session_a, session_b)

            received: list[bytes] = []
            for i in range(10):
                frame = f"message {i}".encode()
                transport = session_a.encrypt_frame(frame)
                wire = transport.serialize()
                # Drop even-indexed packets (0, 2, 4, …).
                ch = LossyChannel(drop_indices={0} if i % 2 == 0 else set())
                delivered = ch.transmit(wire)
                if delivered is not None:
                    pkt = parse_packet(delivered)
                    assert isinstance(pkt, TransportData)
                    received.append(session_b.decrypt_frame(pkt))

            assert len(received) == 5  # only odd-indexed messages survived
            expected = [f"message {i}".encode() for i in range(1, 10, 2)]
            assert received == expected

    def test_session_usable_after_lost_data_frames(self) -> None:
        """A encrypts several frames that are never delivered; session remains alive.

        The send counter advances on A's side but B's replay window is unaffected.
        A final hello-world message must still decrypt correctly on B.
        """
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert _attempt_handshake(session_a, session_b)

            # Encrypt several frames but never deliver them to B.
            for i in range(20):
                session_a.encrypt_frame(f"silently lost {i}".encode())

            # A final frame must still reach B.
            frame = b"hello world"
            transport = session_a.encrypt_frame(frame)
            assert session_b.decrypt_frame(transport) == frame

    def test_init_not_timed_out_before_deadline(self) -> None:
        """A session in INIT_SENT does NOT time out before INIT_TIMEOUT_SECONDS."""
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            drop_ch = LossyChannel(drop_indices={0})
            _attempt_handshake(session_a, session_b, channel_a_to_b=drop_ch)
            assert session_a.state == SessionState.INIT_SENT

            # Advance to just before the timeout — must NOT reset.
            clock.advance(INIT_TIMEOUT_SECONDS - 1)
            assert not session_a.init_timed_out()
            _tick_handshake_manager(session_a)
            assert session_a.state == SessionState.INIT_SENT

    def test_rekey_triggers_after_session_age(self) -> None:
        """An established session needs rekeying once it is old enough.

        The idle-deferral check defers rekeying when ``last_rx`` is stale.
        To trigger the rekey path we must simulate recent traffic — a frame
        is received just before the rekey deadline so ``last_rx`` is fresh.
        """
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()
            assert _attempt_handshake(session_a, session_b)

            # Session is fresh — no rekey needed.
            assert not session_a.needs_rekey()

            # Advance to just before the rekey threshold.
            clock.advance(REKEY_AFTER_SECONDS - 1)
            assert not session_a.needs_rekey()

            # Simulate receiving a frame just before the deadline so last_rx
            # stays within REKEY_DEFER_IDLE_SECONDS of "now".
            transport = session_b.encrypt_frame(b"ping")
            session_a.decrypt_frame(transport)

            # Advance past the rekey threshold; last_rx is still recent.
            clock.advance(2)
            assert session_a.needs_rekey()

    def test_hello_world_recovery_full_cycle(self) -> None:
        """Full production cycle: init lost, timeout, reset, retry, delivery.

        Mirrors exactly what the daemon does:
        1. TAP frame arrives → IDLE session → initiate_handshake().
        2. Radio drops the init.
        3. HANDSHAKE_POLL_INTERVAL fires → init_timed_out() → reset_to_idle().
        4. TAP frame arrives again → initiate_handshake().
        5. This time the handshake completes → frame delivered.
        """
        clock = MockClock()
        with frozen_session_time(clock):
            session_a, session_b = _make_pki_pair()

            # Step 1–2: A initiates, init is lost.
            init_bytes = session_a.initiate_handshake()
            assert session_a.state == SessionState.INIT_SENT
            # (init_bytes not delivered to B)

            # Step 3: timeout fires.
            clock.advance(INIT_TIMEOUT_SECONDS + 1)
            _tick_handshake_manager(session_a)
            assert session_a.state == SessionState.IDLE

            # Step 4–5: A retries over a perfect channel.
            init_bytes2 = session_a.initiate_handshake()
            init_pkt2 = parse_packet(init_bytes2)
            resp_bytes2 = session_b.respond_to_handshake(init_pkt2)
            resp_pkt2 = parse_packet(resp_bytes2)
            session_a.complete_handshake(resp_pkt2)

            assert session_a.is_established
            assert session_b.is_established

            frame = b"hello world"
            assert session_b.decrypt_frame(session_a.encrypt_frame(frame)) == frame


# ---------------------------------------------------------------------------
# Daemon-level integration: two VPN instances wired together
# ---------------------------------------------------------------------------


def _build_minimal_vpn(
    local_kp: KeyPair,
    peer_kp: KeyPair,
    peer_node_id: str,
    psk: bytes | None = None,
) -> "MeshVPN":  # type: ignore[name-defined]
    """Construct a :class:`MeshVPN` with pre-populated sessions (no radio needed).

    Bypasses ``start()`` to avoid needing a real TAP device or radio.
    """
    from meshnet.vpn.daemon import MeshVPN
    from meshnet.vpn.routing import RoutingTable
    from meshnet.vpn.transport import Fragmenter

    vpn: MeshVPN = object.__new__(MeshVPN)
    vpn.config = None
    vpn._mesh = _FakeMesh()
    vpn._tap = _FakeTap()
    vpn._routing = RoutingTable()
    vpn._fragmenter = Fragmenter()
    vpn._vpn_queue = asyncio.Queue()
    vpn._tasks = []
    vpn._unregister_listener = None

    vpn._sessions = {
        peer_node_id: PeerSession(
            peer_node_id,
            peer_kp.public_bytes(),
            local_kp,
            preshared_key=psk,
        )
    }
    return vpn


class _FakeMesh:
    """Minimal mesh stub that records sent packets."""

    def __init__(self) -> None:
        self.sent_packets: list[tuple[str, bytes]] = []

    async def _send_data_with_ack(
        self, payload: bytes, port_num: int, destination_id: str, **kwargs
    ) -> None:
        self.sent_packets.append((destination_id, payload))

    def _register_listener(self, filter_fn, queue):  # noqa: ANN001
        return lambda: None

    async def connect(self) -> None:
        pass

    def close(self) -> None:
        pass


class _FakeTap:
    """Minimal TAP stub that captures written frames."""

    def __init__(self) -> None:
        self.written_frames: list[bytes] = []
        self._read_queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def open(self, address: str) -> None:
        pass

    async def read_frame(self) -> bytes:
        return await self._read_queue.get()

    async def write_frame(self, frame: bytes) -> None:
        self.written_frames.append(frame)

    def close(self) -> None:
        pass


class TestDaemonTwoDevicePKI:
    """Two MeshVPN instances exchange handshake + data via _process_incoming."""

    @pytest.mark.asyncio
    async def test_good_connection_hello_world(self) -> None:
        """Full PKI handshake via daemon dispatch; hello world written to TAP."""
        kp_a = KeyPair.generate()
        kp_b = KeyPair.generate()

        vpn_a = _build_minimal_vpn(kp_a, kp_b, "!node_b")
        vpn_b = _build_minimal_vpn(kp_b, kp_a, "!node_a")

        session_a: PeerSession = vpn_a._sessions["!node_b"]  # type: ignore[assignment]

        # A initiates the handshake.
        init_bytes = session_a.initiate_handshake()

        # Deliver init to B's daemon.
        await vpn_b._process_incoming("!node_a", init_bytes)
        assert vpn_b._sessions["!node_a"].state == SessionState.ESTABLISHED

        # B's daemon sent a response — deliver it to A.
        assert len(vpn_b._mesh.sent_packets) == 1
        _, resp_bytes = vpn_b._mesh.sent_packets[0]
        await vpn_a._process_incoming("!node_b", resp_bytes)
        assert vpn_a._sessions["!node_b"].state == SessionState.ESTABLISHED

        # A sends "hello world" as a transport packet to B's daemon.
        frame = b"hello world" + b"\x00" * 20  # minimal frame padding
        transport_pkt = session_a.encrypt_frame(frame)
        await vpn_b._process_incoming("!node_a", transport_pkt.serialize())

        # B's TAP device should have received the decrypted frame.
        assert len(vpn_b._tap.written_frames) == 1  # type: ignore[union-attr]
        assert vpn_b._tap.written_frames[0] == frame  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_bad_connection_response_lost_then_recovery(self) -> None:
        """Response is lost; after timeout+reset A retries and hello world arrives."""
        clock = MockClock()
        with frozen_session_time(clock):
            kp_a = KeyPair.generate()
            kp_b = KeyPair.generate()

            vpn_a = _build_minimal_vpn(kp_a, kp_b, "!node_b")
            vpn_b = _build_minimal_vpn(kp_b, kp_a, "!node_a")

            session_a: PeerSession = vpn_a._sessions["!node_b"]  # type: ignore[assignment]

            # A sends init; B responds but the response is lost.
            init_bytes = session_a.initiate_handshake()
            await vpn_b._process_incoming("!node_a", init_bytes)
            assert vpn_b._sessions["!node_a"].state == SessionState.ESTABLISHED
            # (Don't deliver B's response to A.)

            assert session_a.state == SessionState.INIT_SENT

            # Advance past the timeout; daemon manager resets A.
            clock.advance(INIT_TIMEOUT_SECONDS + 1)
            assert session_a.init_timed_out()
            session_a.reset_to_idle()
            assert session_a.state == SessionState.IDLE

            # A retries.  B (ESTABLISHED) re-handshakes with the new init.
            init_bytes2 = session_a.initiate_handshake()
            await vpn_b._process_incoming("!node_a", init_bytes2)
            # B sent a new response (index 1 in sent_packets list).
            assert len(vpn_b._mesh.sent_packets) == 2
            _, resp_bytes2 = vpn_b._mesh.sent_packets[1]

            await vpn_a._process_incoming("!node_b", resp_bytes2)
            assert session_a.state == SessionState.ESTABLISHED

            # Hello world must now reach B's TAP.
            frame = b"hello world" + b"\x00" * 20
            transport_pkt = session_a.encrypt_frame(frame)
            await vpn_b._process_incoming("!node_a", transport_pkt.serialize())
            assert vpn_b._tap.written_frames[-1] == frame  # type: ignore[union-attr]


