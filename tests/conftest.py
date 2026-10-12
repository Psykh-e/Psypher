import secrets

import pytest

from psypher.vault import Vault

PASSWORD = "test-only-long-passphrase-123"


@pytest.fixture
def vault_data(tmp_path):
    root = tmp_path / "vault"
    recovery = secrets.token_bytes(32)
    Vault.create(root, PASSWORD, recovery, recovery)
    return root, recovery


@pytest.fixture
def vault(vault_data):
    with Vault.open(vault_data[0], PASSWORD) as value:
        yield value
