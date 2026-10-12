"""Run installed-wheel or portable-executable flows outside the repository.

This is a local distribution check, not a substitute for a clean Windows VM.
All input data and credentials are generated, isolated, and removed at the end.
"""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--exe", type=Path)
    mode.add_argument("--python", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix="psypher-distribution-") as directory:
        temporary = Path(directory)
        environment = dict(os.environ)
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            environment.pop(name, None)
        if args.exe:
            original = args.exe.resolve()
            portable = temporary / "portable bundle"
            shutil.copytree(original.parent, portable)
            prefix = [str(portable / original.name)]
            if os.name == "nt":
                environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        else:
            prefix = [str(args.python.resolve()), "-m", "psypher"]
        root = temporary / "vault.psyvault"
        password = secrets.token_urlsafe(24)
        recovery = secrets.token_bytes(32).hex()
        recovery_path = temporary / "separate" / "recovery.recovery"
        key_path = temporary / "separate" / "factor.key"

        def call(command, *parameters, data=None, expected=0, vault=None, key=None):
            arguments = [
                *prefix,
                command,
                "--vault",
                str(vault or root),
                "--json",
                "--yes",
                "--secrets-fd",
                "0",
                *map(str, parameters),
            ]
            if key:
                arguments.extend(["--keyfile", str(key)])
            result = subprocess.run(
                arguments,
                input=(json.dumps(data or {"password": password}) + "\n").encode(),
                cwd=temporary,
                env=environment,
                capture_output=True,
                timeout=45,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            assert result.returncode == expected, (command, result.stdout, result.stderr)
            value = json.loads(result.stdout)
            assert value["ok"] == (expected == 0)
            for field in (data or {}).values():
                assert field.encode() not in result.stdout + result.stderr
            results.append({"command": command, "exit_code": result.returncode})
            return value.get("result", value.get("error"))

        call(
            "init",
            "--recovery-out",
            recovery_path,
            data={
                "password": password,
                "recovery_key": recovery,
                "recovery_confirmation": recovery,
            },
        )
        call("keyfile", "generate", "--out", key_path)
        call("keyfile", "enable", "--new-keyfile", key_path)
        source = temporary / "özel belgeler"
        source.mkdir()
        (source / "boş klasör").mkdir()
        payload = secrets.token_bytes(2 * 1024 * 1024 + 31)
        (source / "dosya.txt").write_bytes(payload)
        (source / "boş").write_bytes(b"")
        assert call("add", source, "--dry-run", key=key_path)["count"] == 2
        call("add", source, key=key_path)
        assert len(call("list", key=key_path)["files"]) == 2
        assert call("verify", key=key_path)["verified"] == 2
        assert call("doctor", key=key_path)["independently_audited"] is False
        exported = temporary / "export"
        call("export", "--destination", exported, key=key_path)
        assert (
            hashlib.sha256((exported / source.name / "dosya.txt").read_bytes()).digest()
            == hashlib.sha256(payload).digest()
        )
        backup = temporary / "backup.psybackup"
        assert call("backup", "--destination", backup, key=key_path)["verified"]
        restored = temporary / "restore.psyvault"
        call("restore", "--destination", restored, vault=backup, key=key_path)
        legacy_key = Fernet.generate_key()
        legacy_key_path = temporary / "legacy.key"
        legacy_key_path.write_bytes(legacy_key)
        legacy_path = temporary / "legacy.txt_psykhenc"
        legacy_token = Fernet(legacy_key).encrypt(b"synthetic legacy data")
        legacy_path.write_bytes(legacy_token)
        call("migrate", "--legacy-key", legacy_key_path, legacy_path, key=key_path)
        assert legacy_path.read_bytes() == legacy_token
        new_password = secrets.token_urlsafe(24)
        call("passwd", data={"password": password, "new_password": new_password}, key=key_path)
        call("list", data={"password": password}, expected=3, key=key_path)
        password = new_password
        call("keyfile", "disable", key=key_path)
        call("doctor")
        new_recovery = secrets.token_bytes(32).hex()
        final_password = secrets.token_urlsafe(24)
        call(
            "recover",
            "--recovery-in",
            recovery_path,
            "--recovery-out",
            temporary / "new.recovery",
            data={
                "new_password": final_password,
                "new_recovery_key": new_recovery,
                "new_recovery_confirmation": new_recovery,
            },
        )
        password = final_password
        call("remove", source.name + "/dosya.txt")
        assert call("verify")["verified"] == 2
        assert (source / "dosya.txt").read_bytes() == payload
    report = {
        "mode": "portable-executable" if args.exe else "clean-venv-wheel",
        "repository_not_in_cwd": True,
        "cases": results,
        "case_count": len(results),
        "generated_sources_preserved": True,
        "temporary_files_removed": True,
        "clean_windows_vm": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"mode": report["mode"], "passed": len(results)}))


if __name__ == "__main__":
    main()
