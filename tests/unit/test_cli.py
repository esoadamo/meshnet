"""Unit tests for meshnet.cli — CLI dispatch, genkey, pubkey, genpsk, show, down."""

from __future__ import annotations

import argparse
import base64
import os
import signal
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from meshnet.vpn.crypto import KeyPair


class TestCLIGenkey:
    def test_genkey_outputs_valid_base64_key(self, capsys):
        from meshnet.cli import _cmd_genkey

        _cmd_genkey(argparse.Namespace())
        output = capsys.readouterr().out.strip()
        raw = base64.b64decode(output)
        assert len(raw) == 32

    def test_genkey_produces_unique_keys(self, capsys):
        from meshnet.cli import _cmd_genkey

        _cmd_genkey(argparse.Namespace())
        k1 = capsys.readouterr().out.strip()
        _cmd_genkey(argparse.Namespace())
        k2 = capsys.readouterr().out.strip()
        assert k1 != k2


class TestCLIPubkey:
    def test_pubkey_from_stdin(self, capsys):
        from meshnet.cli import _cmd_pubkey

        kp = KeyPair.generate()
        with patch("sys.stdin", StringIO(kp.private_base64() + "\n")):
            _cmd_pubkey(argparse.Namespace())
        output = capsys.readouterr().out.strip()
        assert output == kp.public_base64()

    def test_pubkey_empty_stdin(self):
        from meshnet.cli import _cmd_pubkey

        with patch("sys.stdin", StringIO("")):
            with pytest.raises(SystemExit):
                _cmd_pubkey(argparse.Namespace())


class TestCLIGenpsk:
    def test_genpsk_outputs_valid_base64(self, capsys):
        from meshnet.cli import _cmd_genpsk

        _cmd_genpsk(argparse.Namespace())
        output = capsys.readouterr().out.strip()
        raw = base64.b64decode(output)
        assert len(raw) == 32


class TestCLIShow:
    def test_show_displays_interface_and_peers(self, capsys, config_file: Path):
        from meshnet.cli import _cmd_show

        args = argparse.Namespace(config=str(config_file))
        _cmd_show(args)
        output = capsys.readouterr().out
        assert "interface:" in output
        assert "public key:" in output
        assert "peer:" in output
        assert "allowed ips:" in output

    def test_show_missing_config(self):
        from meshnet.cli import _cmd_show

        args = argparse.Namespace(config=None)
        with pytest.raises(SystemExit):
            _cmd_show(args)


class TestCLIDown:
    def test_down_no_pid_file(self, tmp_path):
        from meshnet.cli import _cmd_down

        with patch("meshnet.cli.PID_DIR", tmp_path):
            with pytest.raises(SystemExit):
                _cmd_down(argparse.Namespace())

    def test_down_sends_sigterm(self, tmp_path):
        from meshnet.cli import _cmd_down

        pid_file = tmp_path / "meshnet.pid"
        pid_file.write_text(str(os.getpid()))
        with (
            patch("meshnet.cli.PID_DIR", tmp_path),
            patch("os.kill") as mock_kill,
        ):
            _cmd_down(argparse.Namespace())
        mock_kill.assert_called_once_with(os.getpid(), signal.SIGTERM)

    def test_down_stale_pid(self, tmp_path):
        from meshnet.cli import _cmd_down

        pid_file = tmp_path / "meshnet.pid"
        pid_file.write_text("999999999")
        with (
            patch("meshnet.cli.PID_DIR", tmp_path),
            patch("os.kill", side_effect=ProcessLookupError),
        ):
            _cmd_down(argparse.Namespace())
        # PID file should be cleaned up
        assert not pid_file.exists()


class TestCLIMain:
    def test_no_command_exits(self):
        from meshnet.cli import main

        with patch("sys.argv", ["meshnet"]):
            with pytest.raises(SystemExit):
                main()

    def test_genkey_via_main(self, capsys):
        from meshnet.cli import main

        with patch("sys.argv", ["meshnet", "genkey"]):
            main()
        output = capsys.readouterr().out.strip()
        raw = base64.b64decode(output)
        assert len(raw) == 32

    def test_genpsk_via_main(self, capsys):
        from meshnet.cli import main

        with patch("sys.argv", ["meshnet", "genpsk"]):
            main()
        output = capsys.readouterr().out.strip()
        raw = base64.b64decode(output)
        assert len(raw) == 32
