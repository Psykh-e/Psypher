import io
import json
import os
import secrets
import subprocess
import sys

import pytest
from conftest import PASSWORD

from psypher import cli
from psypher.errors import AccessError
from psypher.vault import Vault


def run_cli(*arguments, data=None, timeout=30):
    result = subprocess.run(
        [sys.executable, "-m", "psypher", *map(str, arguments)],
        input=(json.dumps(data) + "\n").encode() if data is not None else b"",
        capture_output=True,
        timeout=timeout,
    )
    output = json.loads(result.stdout) if result.stdout.strip().startswith(b"{") else None
    return result, output


def test_end_to_end_cli_json(tmp_path):
    root, recovery_file = tmp_path / "vault", tmp_path / "separate" / "recovery"
    recovery = secrets.token_bytes(32).hex()
    result, output = run_cli(
        "init",
        "--vault",
        root,
        "--recovery-out",
        recovery_file,
        "--secrets-fd",
        0,
        "--json",
        data={"password": PASSWORD, "recovery_key": recovery, "recovery_confirmation": recovery},
    )
    assert result.returncode == 0, result.stdout
    assert output["result"]["recovery_confirmed"]
    assert PASSWORD.encode() not in result.stdout + result.stderr
    assert recovery.encode() not in result.stdout + result.stderr
    source = tmp_path / "özel.txt"
    source.write_bytes(b"private content")
    common = ["--vault", root, "--secrets-fd", 0, "--json"]
    auth = {"password": PASSWORD}
    result, output = run_cli(*common, "add", source, "--dry-run", data=auth)
    assert result.returncode == 0
    assert output["result"]["count"] == 1
    result, output = run_cli("add", source, *common, "--yes", data=auth)
    assert result.returncode == 0
    assert output["result"]["added"] == 1
    result, output = run_cli("list", *common, data=auth)
    assert output["result"]["files"] == [{"name": source.name, "size": len(b"private content")}]
    result, output = run_cli("verify", *common, data=auth)
    assert output["result"]["verified"] == 1
    destination = tmp_path / "export"
    result, output = run_cli("export", *common, "--destination", destination, "--yes", data=auth)
    assert result.returncode == 0
    assert (destination / source.name).read_bytes() == source.read_bytes()
    backup = tmp_path / "backup"
    result, output = run_cli("backup", *common, "--destination", backup, data=auth)
    assert output["result"]["verified"] is True
    result, output = run_cli(
        "restore",
        "--vault",
        backup,
        "--destination",
        tmp_path / "restored",
        "--secrets-fd",
        0,
        "--json",
        "--yes",
        data=auth,
    )
    assert result.returncode == 0
    assert output["result"]["restored"] == 1
    result, output = run_cli("remove", source.name, *common, "--yes", data=auth)
    assert output["result"]["removed"] == 1
    assert source.read_bytes() == b"private content"


def test_cli_recovery_and_keyfile(vault_data, tmp_path):
    root, recovery = vault_data
    key_path = tmp_path / "factor"
    result, output = run_cli("keyfile", "generate", "--out", key_path, "--json")
    assert result.returncode == 0
    assert len(key_path.read_bytes()) == 32
    result, output = run_cli(
        "keyfile",
        "enable",
        "--vault",
        root,
        "--new-keyfile",
        key_path,
        "--secrets-fd",
        0,
        "--json",
        "--yes",
        data={"password": PASSWORD},
    )
    assert result.returncode == 0
    assert output["result"]["keyfile_required"]
    result, output = run_cli(
        "doctor", "--vault", root, "--secrets-fd", 0, "--json", data={"password": PASSWORD}
    )
    assert result.returncode == 3
    new_recovery = secrets.token_bytes(32).hex()
    result, output = run_cli(
        "recover",
        "--vault",
        root,
        "--recovery-out",
        tmp_path / "new-recovery",
        "--secrets-fd",
        0,
        "--json",
        "--yes",
        data={
            "recovery_key": recovery.hex(),
            "new_password": "new-recovered-passphrase",
            "new_recovery_key": new_recovery,
            "new_recovery_confirmation": new_recovery,
        },
    )
    assert result.returncode == 0, result.stdout
    assert output["result"]["recovery_rotated"]
    with pytest.raises(AccessError):
        Vault.open(root, recovery=recovery)
    with Vault.open(root, "new-recovered-passphrase"):
        pass


def test_cli_password_preserves_keyfile(tmp_path):
    key = secrets.token_bytes(32)
    recovery = secrets.token_bytes(32)
    keyfile, root = tmp_path / "key", tmp_path / "vault"
    keyfile.write_bytes(key)
    Vault.create(root, PASSWORD, recovery, recovery, key)
    result, output = run_cli(
        "passwd",
        "--vault",
        root,
        "--keyfile",
        keyfile,
        "--json",
        "--secrets-fd",
        0,
        data={"password": PASSWORD, "new_password": "changed-long-passphrase"},
    )
    assert result.returncode == 0
    assert output["result"]["keyfile_required"]
    with Vault.open(root, "changed-long-passphrase", key):
        pass


@pytest.mark.parametrize(
    "arguments", [[], ["doctor", "--json"], ["--json"], ["init", "--json"], ["unknown", "--json"]]
)
def test_noninteractive_usage_errors_are_fast(arguments):
    result, output = run_cli(*arguments, timeout=5)
    assert result.returncode == 2
    if "--json" in arguments:
        assert output["error"]["code"] == 2
    assert b"Traceback" not in result.stderr


def test_no_argv_secret_or_error_reflection():
    marker = "NEVER-REFLECT-THIS-SECRET"
    result, output = run_cli("doctor", "--password", marker, "--json")
    assert result.returncode == 2
    assert marker.encode() not in result.stdout + result.stderr


def test_missing_auth_and_confirmation(vault_data, tmp_path):
    root, _ = vault_data
    result, output = run_cli("doctor", "--vault", root, "--json", "--secrets-fd", 0, data={})
    assert result.returncode == 2
    source = tmp_path / "source"
    source.write_bytes(b"data")
    result, output = run_cli(
        "add", source, "--vault", root, "--json", "--secrets-fd", 0, data={"password": PASSWORD}
    )
    assert result.returncode == 2
    with Vault.open(root, PASSWORD) as vault:
        assert vault.list()["files"] == []


def test_json_integrity_error(vault_data, tmp_path):
    root, _ = vault_data
    source = tmp_path / "source"
    source.write_bytes(b"data")
    with Vault.open(root, PASSWORD) as vault:
        vault.add([source])
        obj = root / "objects" / vault.catalog["files"][source.name]["id"]
        obj.write_bytes(b"broken")
    result, output = run_cli(
        "verify", "--vault", root, "--json", "--secrets-fd", 0, data={"password": PASSWORD}
    )
    assert result.returncode == 4
    assert output["ok"] is False
    assert b"Traceback" not in result.stderr


def test_global_flags_before_and_after_command():
    for arguments in (
        ["--vault", "example", "--json", "doctor"],
        ["doctor", "--vault", "example", "--json"],
    ):
        result = cli.parser().parse_args(arguments)
        assert result.vault.name == "example"
        assert result.json


def test_timeout_closes_session_and_releases_lock(vault_data, monkeypatch):
    root, _ = vault_data

    class Terminal(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", Terminal())
    responses = iter(["1", "h", PASSWORD, cli.SessionTimeout(), "0"])

    def respond(*args, **kwargs):
        value = next(responses)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(cli, "timed_input", respond)
    assert cli.menu(root) == 0
    with Vault.open(root, PASSWORD):
        pass


def test_import_is_side_effect_free(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import psypher; import psypher.crypto; "
            "import psypher.filesystem; import psypher.vault; import psypher.cli",
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout == b""
    assert result.stderr == b""
    assert list(tmp_path.iterdir()) == []


def test_invalid_secret_unicode_is_usage_error():
    result, output = run_cli(
        "doctor", "--vault", "example", "--json", "--secrets-fd", 0, data={"password": "\ud800"}
    )
    assert result.returncode == 2
    assert output["error"]["code"] == 2
    assert b"Traceback" not in result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows terminal timer")
def test_real_input_timeout_does_not_leave_input_thread(monkeypatch):
    import msvcrt
    import threading

    before = set(threading.enumerate())
    monkeypatch.setattr(msvcrt, "kbhit", lambda: False)
    with pytest.raises(cli.SessionTimeout):
        cli.timed_input("", timeout=0.001)
    assert set(threading.enumerate()) == before


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL")
def test_private_file_has_protected_windows_dacl(tmp_path):
    import ctypes
    from ctypes import wintypes

    from psypher.filesystem import write_private

    path = tmp_path / "restricted-secret"
    write_private(path, b"secret")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    required = wintypes.DWORD()
    advapi.GetFileSecurityW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(required))
    buffer = ctypes.create_string_buffer(required.value)
    assert advapi.GetFileSecurityW(str(path), 4, buffer, required, ctypes.byref(required))
    control, revision = wintypes.WORD(), wintypes.DWORD()
    advapi.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    assert advapi.GetSecurityDescriptorControl(
        buffer, ctypes.byref(control), ctypes.byref(revision)
    )
    assert control.value & 0x1000  # SE_DACL_PROTECTED
    text = wintypes.LPWSTR()
    advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.c_void_p,
    ]
    assert advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
        buffer, 1, 4, ctypes.byref(text), None
    )
    try:
        assert text.value.count("(A;") == 2
        assert ";;;SY)" in text.value
        assert ";;;WD)" not in text.value
        assert ";;;BU)" not in text.value
    finally:
        kernel = ctypes.WinDLL("kernel32")
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
