import json
import os
import subprocess
import sys

import pytest
from conftest import PASSWORD

from psypher.vault import Vault

CHILD = """
import json, os, sys
from pathlib import Path
from psypher.vault import Vault
secret = json.loads(sys.stdin.readline())
with Vault.open(Path(sys.argv[1]), secret['password']) as vault:
    def kill(name):
        if name == sys.argv[3]:
            os._exit(77)  # intentionally bypass every Python cleanup/finally
    vault._checkpoint = kill
    vault.add([Path(sys.argv[2])])
"""


@pytest.mark.parametrize(
    "checkpoint",
    [
        "object-written",
        "object-published",
        "header-written",
        "catalog-written",
        "before-current",
        "after-current",
    ],
)
def test_actual_process_death_preserves_valid_generation(vault_data, tmp_path, checkpoint):
    root, _ = vault_data
    source = tmp_path / "original"
    content = os.urandom(2 * 1024 * 1024)
    source.write_bytes(content)
    result = subprocess.run(
        [sys.executable, "-c", CHILD, str(root), str(source), checkpoint],
        input=(json.dumps({"password": PASSWORD}) + "\n").encode(),
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 77, result.stderr
    assert source.read_bytes() == content
    with Vault.open(root, PASSWORD) as vault:
        count = 1 if checkpoint == "after-current" else 0
        assert vault.verify(persist=False)["verified"] == count
        assert len(vault.list()["files"]) == count
        if count:
            vault.export(tmp_path / "export")
            assert (tmp_path / "export" / source.name).read_bytes() == content
        else:
            assert vault.doctor()["unreferenced_ciphertext_files"] >= 1
