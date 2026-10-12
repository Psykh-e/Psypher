import copy
import errno
import hashlib
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import PASSWORD
from cryptography.fernet import Fernet

from psypher import crypto
from psypher.errors import AccessError, IntegrityError, LockedError, StorageError, UsageError
from psypher.filesystem import no_links, read_bounded, safe_name
from psypher.vault import Vault, _validate_catalog


def test_file_tree_empty_unicode_and_no_extension(vault, tmp_path):
    source = tmp_path / "özel"
    (source / "alt" / "boş").mkdir(parents=True)
    examples = {
        "a.txt": b"hello",
        "uzantısız": b"\x00\xff",
        "alt/boş.txt": b"",
        "alt/multi.part.txt": b"some data",
    }
    for name, data in examples.items():
        (source / name).write_bytes(data)
    assert vault.add([source])["added"] == 4
    assert vault.verify()["verified"] == 4
    destination = tmp_path / "export"
    vault.export(destination)
    for name, data in examples.items():
        assert (source / name).read_bytes() == data
        assert (destination / source.name / name).read_bytes() == data
    assert (destination / source.name / "alt" / "boş").is_dir()


def test_init_confirmation_and_no_clobber(tmp_path):
    root = tmp_path / "vault"
    recovery = secrets.token_bytes(32)
    with pytest.raises(UsageError):
        Vault.create(root, PASSWORD, recovery, secrets.token_bytes(32))
    assert not root.exists()
    root.mkdir()
    sentinel = root / "existing"
    sentinel.write_bytes(b"preserved")
    with pytest.raises(StorageError):
        Vault.create(root, PASSWORD, recovery, recovery)
    assert sentinel.read_bytes() == b"preserved"


def test_lock_and_release_after_bad_password(vault_data):
    root, _ = vault_data
    with pytest.raises(AccessError):
        Vault.open(root, "wrong")
    with Vault.open(root, PASSWORD):
        with pytest.raises(LockedError):
            Vault.open(root, PASSWORD)
    with Vault.open(root, PASSWORD) as reopened:
        assert reopened.list()["files"] == []


def test_lock_across_process(vault, tmp_path):
    command = [
        sys.executable,
        "-c",
        "from psypher.vault import Vault; "
        "from psypher.errors import LockedError; import sys; "
        "\ntry: Vault.open(sys.argv[1], 'wrong')\nexcept LockedError: sys.exit(3)",
        str(vault.root),
    ]
    result = subprocess.run(command, capture_output=True, timeout=15)
    assert result.returncode == 3


def test_header_catalog_binding(vault_data):
    root, _ = vault_data
    pointer = (root / "CURRENT").read_text()
    header_path = root / "generations" / pointer / "header.json"
    header = crypto.parse_json(header_path.read_bytes(), crypto.MAX_HEADER)
    # Valid-shaped change in recovery slot must fail when opening with the password.
    header["recovery"]["nonce"] = crypto.encode(secrets.token_bytes(24))
    header_path.write_bytes(crypto.canonical(header))
    with pytest.raises(IntegrityError):
        Vault.open(root, PASSWORD)


def test_catalog_tampering(vault_data):
    root, _ = vault_data
    path = root / "generations" / (root / "CURRENT").read_text() / "catalog.enc"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    with pytest.raises(IntegrityError):
        Vault.open(root, PASSWORD)


def test_export_corruption_does_not_publish_plaintext(vault, tmp_path):
    source = tmp_path / "sensitive.txt"
    source.write_bytes(b"secret-content" * 1000)
    vault.add([source])
    entry = vault.catalog["files"][source.name]
    object_path = vault.root / "objects" / entry["id"]
    data = bytearray(object_path.read_bytes())
    data[-1] ^= 1  # final tag corruption, after plaintext chunks have been checked
    object_path.write_bytes(data)
    destination = tmp_path / "export"
    with pytest.raises(IntegrityError):
        vault.export(destination)
    assert not (destination / source.name).exists()
    assert not list(destination.glob(".psypher-export-*"))
    assert source.read_bytes() == b"secret-content" * 1000
    assert vault.doctor()["status"]["verified"] is None


def test_export_refuses_overwrite(vault, tmp_path):
    source = tmp_path / "file.txt"
    source.write_bytes(b"source")
    vault.add([source])
    destination = tmp_path / "export"
    destination.mkdir()
    (destination / source.name).write_bytes(b"existing")
    with pytest.raises(StorageError):
        vault.export(destination)
    assert (destination / source.name).read_bytes() == b"existing"


def test_password_rotation_preserves_objects_and_old_backup_access(vault, tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"a" * 1234)
    vault.add([source])
    obj = vault.root / "objects" / vault.catalog["files"][source.name]["id"]
    before = obj.read_bytes()
    backup = tmp_path / "backup"
    vault.backup(backup)
    vault.change_access("new-test-only-passphrase")
    assert obj.read_bytes() == before
    assert len(list((vault.root / "generations").iterdir())) == 1
    root = vault.root
    vault.close()
    with pytest.raises(AccessError):
        Vault.open(root, PASSWORD)
    with Vault.open(root, "new-test-only-passphrase") as new:
        assert new.verify()["verified"] == 1
    with Vault.open(backup, PASSWORD) as old:
        assert old.verify(persist=False)["verified"] == 1


def test_keyfile_enable_disable_and_recovery_rotation(vault, vault_data):
    root, recovery = vault_data
    keyfile = secrets.token_bytes(32)
    vault.change_access(PASSWORD, keyfile)
    vault.close()
    with pytest.raises(AccessError):
        Vault.open(root, PASSWORD)
    with Vault.open(root, recovery=recovery) as recovering:
        new_recovery = secrets.token_bytes(32)
        recovering.change_access(
            "recovered-test-passphrase", recovery=new_recovery, confirmation=new_recovery
        )
    with pytest.raises(AccessError):
        Vault.open(root, recovery=recovery)
    with Vault.open(root, recovery=new_recovery) as new:
        assert new.doctor()["keyfile_required"] is False
    with Vault.open(root, "recovered-test-passphrase"):
        pass


def test_backup_restore_and_status(vault, tmp_path):
    source = tmp_path / "example"
    source.write_bytes(secrets.token_bytes(3333))
    vault.add([source])
    assert vault.doctor()["status"]["verified"] is None
    vault.verify()
    backup = tmp_path / "backup"
    vault.backup(backup)
    status = vault.doctor()["status"]
    assert status["backup"]["covers_current_catalog"]
    assert status["verified"]["covers_current_catalog"]
    restored = tmp_path / "restored"
    assert Vault.restore(backup, restored, PASSWORD)["restored"] == 1
    with Vault.open(restored, PASSWORD) as new:
        new.export(tmp_path / "export")
    assert (tmp_path / "export" / source.name).read_bytes() == source.read_bytes()
    extra = tmp_path / "extra"
    extra.write_bytes(b"new")
    vault.add([extra])
    assert not vault.doctor()["status"]["backup"]["covers_current_catalog"]
    assert not vault.doctor()["status"]["verified"]["covers_current_catalog"]


def test_corrupt_backup_not_published_or_restored(vault, tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"data")
    vault.add([source])
    identity = vault.catalog["files"][source.name]["id"]
    obj = vault.root / "objects" / identity
    original = obj.read_bytes()
    obj.write_bytes(original[:-1])
    with pytest.raises(IntegrityError):
        vault.backup(tmp_path / "bad-backup")
    assert not (tmp_path / "bad-backup").exists()
    assert not list(tmp_path.glob(".psypher-copy-*"))
    obj.write_bytes(original)
    backup = tmp_path / "backup"
    vault.backup(backup)
    (backup / "objects" / identity).write_bytes(original[:-1])
    with pytest.raises(IntegrityError):
        Vault.restore(backup, tmp_path / "restore", PASSWORD)
    assert not (tmp_path / "restore").exists()


def test_remove_and_partial_export(vault, tmp_path):
    directory = tmp_path / "tree"
    directory.mkdir()
    (directory / "a").write_bytes(b"a")
    (directory / "b").write_bytes(b"b")
    vault.add([directory])
    vault.export(tmp_path / "export", ["tree/a"])
    assert not (tmp_path / "export" / "tree/b").exists()
    assert vault.remove(["tree/a"])["removed"] == 1
    assert vault.list()["directories"] == ["tree"]
    assert vault.remove(["tree"])["removed"] == 1
    assert vault.list() == {"files": [], "directories": []}
    assert (directory / "a").read_bytes() == b"a"


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
def test_add_fault_injection(vault, tmp_path, monkeypatch, checkpoint):
    source = tmp_path / "original.txt"
    content = secrets.token_bytes(crypto.CHUNK_SIZE + 77)
    source.write_bytes(content)

    def fail(name):
        if name == checkpoint:
            raise OSError(errno.ENOSPC, "simulated disk-full")

    monkeypatch.setattr(vault, "_checkpoint", fail)
    with pytest.raises(OSError):
        vault.add([source])
    assert source.read_bytes() == content
    root = vault.root
    vault.close()
    with Vault.open(root, PASSWORD) as reopened:
        reopened.verify(persist=False)
        assert len(reopened.list()["files"]) == (1 if checkpoint == "after-current" else 0)


def test_cancel_stream_and_export(vault, tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"x" * (crypto.CHUNK_SIZE + 10))

    def cancel(*args):
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        vault.add([source], cancel)
    assert vault.list()["files"] == []
    assert list((vault.root / "objects").iterdir()) == []
    vault.add([source])
    with pytest.raises(KeyboardInterrupt):
        vault.export(tmp_path / "export", event=cancel)
    assert not list((tmp_path / "export").iterdir())


@pytest.mark.parametrize(
    "checkpoint", ["snapshot-file-copied", "snapshot-verified", "export-verified"]
)
def test_output_fault_injection(vault, tmp_path, monkeypatch, checkpoint):
    source = tmp_path / "source"
    source.write_bytes(b"original")
    vault.add([source])

    def fail(name):
        if name == checkpoint:
            raise OSError(errno.EACCES, "simulated permission failure")

    monkeypatch.setattr(vault, "_checkpoint", fail)
    with pytest.raises(OSError):
        if checkpoint.startswith("snapshot"):
            vault.backup(tmp_path / "backup")
            assert not (tmp_path / "backup").exists()
        else:
            vault.export(tmp_path / "export")
    assert not list(tmp_path.glob(".psypher-copy-*"))
    assert not list(tmp_path.rglob(".psypher-export-*"))
    assert vault.verify(persist=False)["verified"] == 1


def test_source_mutation_detected(vault, tmp_path):
    source = tmp_path / "source"
    source.write_bytes(b"a" * (crypto.CHUNK_SIZE + 1))
    touched = False

    def mutate(*args):
        nonlocal touched
        if not touched:
            touched = True
            source.write_bytes(b"changed")

    with pytest.raises(StorageError):
        vault.add([source], mutate)
    assert vault.list()["files"] == []


def test_no_secret_leak_to_vault(vault, tmp_path):
    filename = "private-filename-f9c10d.txt"
    content = b"highly-private-content-264b4577d2d0" * 20
    source = tmp_path / filename
    source.write_bytes(content)
    vault.add([source])
    root = vault.root
    master = vault.master
    vault.close()  # Windows byte-range locks intentionally prevent reading .lock from a second handle.
    for path in root.rglob("*"):
        if path.is_file():
            stored = path.read_bytes()
            for secret in (filename.encode(), content[:32], PASSWORD.encode(), master):
                assert secret not in stored


def test_legacy_read_only_migration_and_batch_rollback(vault, tmp_path):
    key = Fernet.generate_key()
    legacy = tmp_path / "file.txt_psykhenc"
    content = Fernet(key).encrypt(b"legacy example")
    legacy.write_bytes(content)
    assert vault.import_legacy([legacy], key)["migrated"] == 1
    assert legacy.read_bytes() == content
    vault.export(tmp_path / "export")
    assert (tmp_path / "export/file.txt").read_bytes() == b"legacy example"
    second = tmp_path / "other_psykhenc"
    second.write_bytes(Fernet(key).encrypt(b"other"))
    bad = tmp_path / "broken_psykhenc"
    bad.write_bytes(b"not-a-fernet-token")
    with pytest.raises(IntegrityError):
        vault.import_legacy([second, bad], key)
    assert len(vault.list()["files"]) == 1
    assert bad.read_bytes() == b"not-a-fernet-token"


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/root",
        "C:/root",
        "a\\b",
        "a//b",
        "a/../b",
        "CON",
        "nul.txt",
        "file:stream",
        "trailing.",
        "trailing ",
        "x\n",
    ],
)
def test_unsafe_names(name):
    with pytest.raises(IntegrityError):
        safe_name(name)


def test_catalog_rejects_bad_hierarchy_and_case_collision(vault):
    candidate = copy.deepcopy(vault.catalog)
    candidate["directories"] = ["missing/child"]
    with pytest.raises(IntegrityError):
        _validate_catalog(candidate)
    candidate["directories"] = ["folder", "FOLDER"]
    with pytest.raises(IntegrityError):
        _validate_catalog(candidate)


def test_windows_junction_or_posix_symlink_rejected(vault, tmp_path):
    original = tmp_path / "original"
    original.mkdir()
    (original / "data").write_bytes(b"secret")
    link = tmp_path / "link"
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(original)], capture_output=True, timeout=10
        )
        assert result.returncode == 0
    else:
        link.symlink_to(original, target_is_directory=True)
    try:
        with pytest.raises(StorageError):
            no_links(link / "data")
        with pytest.raises(StorageError):
            vault.add([link])
        with pytest.raises(StorageError):
            vault.export(link)
    finally:
        if os.name == "nt":
            os.rmdir(link)
        else:
            link.unlink()
    assert (original / "data").read_bytes() == b"secret"


def test_no_automatic_directory_scan(vault, tmp_path):
    with pytest.raises(UsageError):
        vault.add([tmp_path])
    with pytest.raises(UsageError):
        vault.add([vault.root])
    with pytest.raises(UsageError):
        vault.add([])


def test_casefold_collision_rejected(vault, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "Name.txt").write_bytes(b"a")
    (b / "name.txt").write_bytes(b"b")
    with pytest.raises(IntegrityError):
        vault.add([a / "Name.txt", b / "name.txt"])
    assert vault.list()["files"] == []


def test_unknown_current_and_bounded_read(tmp_path):
    root = tmp_path / "not-vault"
    root.mkdir()
    with pytest.raises(IntegrityError):
        Vault.open(root, PASSWORD)
    assert not (root / ".lock").exists()
    file = tmp_path / "large"
    file.write_bytes(b"a" * 100)
    with pytest.raises(IntegrityError):
        read_bounded(file, 10)


def test_closed_session_drops_master(vault):
    vault.close()
    assert vault.master is None
    assert vault.catalog == {}
    with pytest.raises(AccessError):
        vault.list()


def test_existing_repo_fixture_is_only_read(vault):
    fixture = Path(__file__).resolve().parents[1] / "Psypher" / "test.txt"
    before = hashlib.sha256(fixture.read_bytes()).digest()
    vault.add([fixture])
    assert hashlib.sha256(fixture.read_bytes()).digest() == before


def test_private_permissions_failure_never_creates_secret(tmp_path, monkeypatch):
    from psypher import filesystem

    def unsupported(_):
        raise StorageError("unsupported ACL filesystem")

    monkeypatch.setattr(filesystem, "require_private_filesystem", unsupported)
    target = tmp_path / "secret"
    with pytest.raises(StorageError):
        filesystem.write_private(target, b"private data")
    assert not target.exists()


def test_catalog_rejects_bool_version(vault):
    candidate = copy.deepcopy(vault.catalog)
    candidate["version"] = True
    with pytest.raises(IntegrityError):
        _validate_catalog(candidate)


@pytest.mark.parametrize("target", ["header", "pointer"])
def test_silent_write_corruption_does_not_commit(vault, tmp_path, monkeypatch, target):
    import psypher.vault as module

    source = tmp_path / "source"
    source.write_bytes(b"preserved original")
    before = (vault.root / "CURRENT").read_bytes()
    original_write = module.write_private

    def corrupt(path, data):
        original_write(path, data)
        if (target == "header" and path.name == "header.json") or (
            target == "pointer" and path.name.startswith(".current-")
        ):
            changed = bytearray(data)
            changed[-1] ^= 1
            path.write_bytes(changed)

    monkeypatch.setattr(module, "write_private", corrupt)
    with pytest.raises(IntegrityError):
        vault.add([source])
    assert (vault.root / "CURRENT").read_bytes() == before
    assert vault.list()["files"] == []
    assert source.read_bytes() == b"preserved original"
