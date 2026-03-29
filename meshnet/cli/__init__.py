"""MeshNet CLI — ``meshnet`` command.

Subcommands mirror WireGuard's ``wg`` tool::

    meshnet genkey          # print base64 X25519 private key
    meshnet pubkey          # stdin private key → stdout public key
    meshnet genpsk          # print base64 32-byte preshared key
    meshnet up -c mesh0.conf   # start the VPN daemon
    meshnet down            # stop the daemon (sends SIGTERM to PID file)
    meshnet show            # show interface & peer status
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import os
import signal
import sys
from pathlib import Path

from meshnet.vpn.crypto import KeyPair, generate_psk

PID_DIR = Path("/run/meshnet")


def _cmd_genkey(_args: argparse.Namespace) -> None:
    """Generate and print a base64-encoded X25519 private key."""
    kp = KeyPair.generate()
    print(kp.private_base64())


def _cmd_pubkey(_args: argparse.Namespace) -> None:
    """Read a base64 private key from stdin, print the matching public key."""
    raw = sys.stdin.readline().strip()
    if not raw:
        print("Error: no key provided on stdin", file=sys.stderr)
        sys.exit(1)
    kp = KeyPair.from_base64(raw)
    print(kp.public_base64())


def _cmd_genpsk(_args: argparse.Namespace) -> None:
    """Generate and print a base64-encoded 32-byte preshared key."""
    print(base64.b64encode(generate_psk()).decode())


def _cmd_up(args: argparse.Namespace) -> None:
    """Start the MeshVPN daemon."""
    if os.geteuid() != 0:
        print("Error: meshnet up requires root (for TAP device creation)", file=sys.stderr)
        sys.exit(1)

    from meshnet.vpn.daemon import MeshVPN

    config_path: str = args.config
    vpn = MeshVPN(config_path)
    loop = asyncio.new_event_loop()

    def _shutdown(sig: int, _frame: object) -> None:
        log = logging.getLogger(__name__)
        log.info("Received signal %s — shutting down", sig)
        loop.call_soon_threadsafe(loop.create_task, vpn.stop())

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Write PID file.
    PID_DIR.mkdir(parents=True, exist_ok=True)
    pid_file = PID_DIR / "meshnet.pid"
    pid_file.write_text(str(os.getpid()))

    try:
        loop.run_until_complete(vpn.start())
    except KeyboardInterrupt:
        loop.run_until_complete(vpn.stop())
    finally:
        pid_file.unlink(missing_ok=True)
        loop.close()


def _cmd_down(_args: argparse.Namespace) -> None:
    """Stop a running MeshVPN daemon by sending SIGTERM to its PID."""
    pid_file = PID_DIR / "meshnet.pid"
    if not pid_file.exists():
        print("No running meshnet daemon found", file=sys.stderr)
        sys.exit(1)
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to meshnet daemon (PID {pid})")
    except ProcessLookupError:
        print(f"PID {pid} not running — removing stale PID file", file=sys.stderr)
        pid_file.unlink(missing_ok=True)


def _cmd_show(_args: argparse.Namespace) -> None:
    """Show VPN configuration and status (offline — reads config only)."""
    config_path = _args.config
    if not config_path:
        print("Error: --config is required for show", file=sys.stderr)
        sys.exit(1)

    from meshnet.vpn.config import parse_config
    from meshnet.vpn.crypto import KeyPair

    cfg = parse_config(config_path)
    iface = cfg.interface
    local_kp = KeyPair.from_private_bytes(iface.private_key)

    print(f"interface: {iface.tap_name}")
    print(f"  public key: {local_kp.public_base64()}")
    print(f"  address: {iface.address}")
    print(f"  mtu: {iface.mtu}")
    print(f"  meshtastic: {iface.meshtastic_host}:{iface.meshtastic_port}")
    print()

    for peer in cfg.peers:
        pub_b64 = base64.b64encode(peer.public_key).decode()
        print(f"peer: {pub_b64}")
        print(f"  endpoint: {peer.endpoint}")
        allowed = ", ".join(str(n) for n in peer.allowed_ips)
        print(f"  allowed ips: {allowed}")
        if peer.preshared_key:
            print("  preshared key: (set)")
        print()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point registered as ``meshnet`` in pyproject.toml."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="meshnet",
        description="MeshNet: WireGuard-like VPN over Meshtastic mesh radio",
    )
    sub = parser.add_subparsers(dest="command")

    # meshnet genkey
    sub.add_parser("genkey", help="Generate a private key (base64)")

    # meshnet pubkey
    sub.add_parser("pubkey", help="Derive public key from private key on stdin")

    # meshnet genpsk
    sub.add_parser("genpsk", help="Generate a preshared key (base64)")

    # meshnet up -c <config>
    p_up = sub.add_parser("up", help="Start the VPN tunnel")
    p_up.add_argument("--config", "-c", required=True, help="Path to config file")

    # meshnet down
    sub.add_parser("down", help="Stop the VPN tunnel")

    # meshnet show -c <config>
    p_show = sub.add_parser("show", help="Show interface and peer info")
    p_show.add_argument("--config", "-c", required=True, help="Path to config file")

    args = parser.parse_args()

    dispatch = {
        "genkey": _cmd_genkey,
        "pubkey": _cmd_pubkey,
        "genpsk": _cmd_genpsk,
        "up": _cmd_up,
        "down": _cmd_down,
        "show": _cmd_show,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)
    handler(args)


if __name__ == "__main__":
    main()
