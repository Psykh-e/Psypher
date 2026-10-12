"""Transactional vault API shared by the interactive console and CLI."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import io
import os
import shutil
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from .errors import AccessError, IntegrityError, StorageError, UsageError
from .filesystem import (
    VaultLock,
    delete_owned_tree,
    no_links,
    open_read,
    private_mkdir,
    private_open,
    private_parents,
    publish,
    publish_directory,
    read_bounded,
    require_private_filesystem,
    safe_name,
    sync_directory,
    sync_file,
    within,
    write_private,
)

MAX_ENTRIES = 20000
Event = Callable[[str, int, int], None] | None


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def content_digest(catalog: dict) -> str:
    return hashlib.sha256(
        crypto.canonical({"files": catalog["files"], "directories": catalog["directories"]})
    ).hexdigest()


def _validate_catalog(catalog: dict) -> None:
    try:
        if (
            set(catalog) != {"version", "files", "directories", "status"}
            or type(catalog["version"]) is not int
            or catalog["version"] != 1
        ):
            raise ValueError()
        files, directories = catalog["files"], catalog["directories"]
        if not isinstance(files, dict) or not isinstance(directories, list):
            raise ValueError()
        if len(files) + len(directories) > MAX_ENTRIES or len(set(directories)) != len(directories):
            raise ValueError()
        identities = set()
        folded = set()
        for name in [*files, *directories]:
            safe_name(name)
            if name.casefold() in folded:
                raise ValueError()
            folded.add(name.casefold())
            parent = name.rpartition("/")[0]
            if parent and parent not in directories:
                raise ValueError()
        for entry in files.values():
            if not isinstance(entry, dict) or set(entry) != {"id", "size", "sha256"}:
                raise ValueError()
            identity = crypto.identifier(entry["id"])
            if identity in identities:
                raise ValueError()
            identities.add(identity)
            if type(entry["size"]) is not int or not 0 <= entry["size"] <= 2**63 - 1:
                raise ValueError()
            digest = entry["sha256"]
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)
            ):
                raise ValueError()
        status = catalog["status"]
        if not isinstance(status, dict) or set(status) != {
            "recovery_confirmed_at",
            "verified",
            "backup",
        }:
            raise ValueError()
        if not isinstance(status["recovery_confirmed_at"], str):
            raise ValueError()
        datetime.fromisoformat(status["recovery_confirmed_at"])
        for name in ("verified", "backup"):
            record = status[name]
            if record is not None:
                if not isinstance(record, dict) or set(record) != {"at", "content_digest"}:
                    raise ValueError()
                datetime.fromisoformat(record["at"])
                if (
                    not isinstance(record["content_digest"], str)
                    or len(record["content_digest"]) != 64
                ):
                    raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise IntegrityError("Şifreli katalog biçimi geçersiz.") from exc


class Vault:
    def __init__(self, root: Path):
        self.root = no_links(root)
        require_private_filesystem(self.root)
        self.lock = VaultLock(self.root)
        self.master: bytes | None = None
        self.header: dict = {}
        self.catalog: dict = {}
        self.generation: str | None = None
        self.closed = False

    def __enter__(self):
        self._live()
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        self.master = None
        self.catalog = {}
        self.header = {}
        self.lock.release()
        self.closed = True

    def _live(self) -> None:
        if self.closed or self.master is None:
            raise AccessError("Kasa kilitli. Yeniden açın.")

    @staticmethod
    def _current(root: Path) -> str:
        try:
            text = read_bounded(root / "CURRENT", 33).decode("ascii")
        except (UnicodeError, FileNotFoundError) as exc:
            raise IntegrityError("Kasa CURRENT kaydı yok veya bozuk.") from exc
        return crypto.identifier(text)

    @classmethod
    def open(
        cls,
        root: str | Path,
        password: str | None = None,
        keyfile: bytes | None = None,
        recovery: bytes | None = None,
        *,
        _master: bytes | None = None,
    ):
        vault = cls(Path(root))
        if not vault.root.is_dir():
            raise StorageError("Kasa klasörü bulunamadı.")
        cls._current(vault.root)  # Don't create a lock in an arbitrary user directory.
        try:
            vault.lock.acquire()
            for name in ("objects", "generations"):
                if not no_links(vault.root / name).is_dir():
                    raise IntegrityError("Kasa dizin yapısı bozuk.")
            vault.generation = cls._current(vault.root)
            directory = no_links(vault.root / "generations" / vault.generation)
            vault.header = crypto.parse_json(
                read_bounded(directory / "header.json", crypto.MAX_HEADER), crypto.MAX_HEADER
            )
            crypto.validate_header(vault.header)
            if vault.header["generation"] != vault.generation:
                raise IntegrityError("Katalog nesli başlıkla eşleşmiyor.")
            vault.master = (
                _master
                if _master is not None
                else crypto.unlock(vault.header, password, keyfile, recovery)
            )
            sealed = read_bounded(directory / "catalog.enc", crypto.MAX_CATALOG + 40)
            plain = crypto.unseal(
                sealed, vault._catalog_key(vault.header), vault._catalog_aad(vault.header)
            )
            vault.catalog = crypto.parse_json(plain, crypto.MAX_CATALOG)
            _validate_catalog(vault.catalog)
            return vault
        except BaseException:
            vault.close()
            raise

    @classmethod
    def create(
        cls,
        root: str | Path,
        password: str,
        recovery: bytes,
        recovery_confirmation: bytes,
        keyfile: bytes | None = None,
    ) -> None:
        if len(recovery) != 32 or not hmac.compare_digest(recovery, recovery_confirmation):
            raise UsageError("Kurtarma anahtarı yeniden doğrulanmadan kasa oluşturulamaz.")
        root = no_links(root)
        if root.exists():
            raise StorageError("Kasa hedefi zaten mevcut; yeni bir konum seçin.")
        header, master = crypto.create_header(password, recovery, keyfile)
        private_parents(root.parent)
        staging = root.parent / (".psypher-init-" + crypto.new_id())
        private_mkdir(staging)
        vault = cls(staging)
        try:
            private_mkdir(staging / "objects")
            private_mkdir(staging / "generations")
            vault.lock.acquire()
            vault.master = master
            catalog = {
                "version": 1,
                "files": {},
                "directories": [],
                "status": {"recovery_confirmed_at": now(), "verified": None, "backup": None},
            }
            vault._commit(catalog, header)
            vault.close()
            publish_directory(staging, root)
        finally:
            vault.close()
            if staging.exists():
                delete_owned_tree(staging)

    def _catalog_key(self, header: dict) -> bytes:
        return crypto.derive(self.master, header["vault_id"], "catalog/" + header["generation"])

    @staticmethod
    def _catalog_aad(header: dict) -> bytes:
        return b"psypher/catalog/v1/" + hashlib.sha256(crypto.canonical(header)).digest()

    def _checkpoint(self, name: str) -> None:
        """Fault-injection seam. Production implementation deliberately has no hooks."""

    def _commit(self, catalog: dict, header: dict | None = None) -> None:
        self._live()
        _validate_catalog(catalog)
        plain = crypto.canonical(catalog)
        if len(plain) > crypto.MAX_CATALOG:
            raise UsageError("Katalog kapasitesi aşıldı (8 MiB / 20.000 kayıt).")
        if self.generation is not None and self._current(self.root) != self.generation:
            raise IntegrityError("Aktif kasa nesli oturum sırasında değişti.")
        new_header = copy.deepcopy(header if header is not None else self.header)
        new_header["generation"] = crypto.new_id()
        crypto.validate_header(new_header)
        directory = self.root / "generations" / new_header["generation"]
        pointer = self.root / (".current-" + crypto.new_id())
        private_mkdir(directory)
        try:
            write_private(directory / "header.json", crypto.canonical(new_header))
            self._checkpoint("header-written")
            blob = crypto.seal(plain, self._catalog_key(new_header), self._catalog_aad(new_header))
            write_private(directory / "catalog.enc", blob)
            self._checkpoint("catalog-written")
            if read_bounded(directory / "header.json", crypto.MAX_HEADER) != crypto.canonical(
                new_header
            ):
                raise IntegrityError("Yazılan kasa başlığı doğrulanamadı.")
            recovered = crypto.unseal(
                read_bounded(directory / "catalog.enc", crypto.MAX_CATALOG + 40),
                self._catalog_key(new_header),
                self._catalog_aad(new_header),
            )
            if recovered != plain:
                raise IntegrityError("Yazılan katalog doğrulanamadı.")
            sync_directory(self.root / "generations")
            write_private(pointer, new_header["generation"].encode("ascii"))
            self._checkpoint("before-current")
            if read_bounded(pointer, 33) != new_header["generation"].encode("ascii"):
                raise IntegrityError("Yazılan aktif nesil kaydı doğrulanamadı.")
            publish(pointer, self.root / "CURRENT", replace=True)
            self.generation = new_header["generation"]
            self.header = new_header
            self.catalog = copy.deepcopy(catalog)
            self._checkpoint("after-current")
        finally:
            with contextlib.suppress(OSError):
                pointer.unlink(missing_ok=True)
            # Do not delete a generation if CURRENT was switched before a crash/failure.
            active = self._current(self.root) if (self.root / "CURRENT").exists() else None
            if active != new_header["generation"]:
                delete_owned_tree(directory)
        self._prune_generations()

    def _prune_generations(self) -> None:
        # Old headers can expose the root key to old passwords; remove after commit.
        # Interrupted rotations require a later successful cleanup; see SECURITY.md.
        for directory in no_links(self.root / "generations").iterdir():
            if directory.name == self.generation:
                continue
            try:
                crypto.identifier(directory.name)
                no_links(directory)
                if set(p.name for p in directory.iterdir()) <= {"header.json", "catalog.enc"}:
                    delete_owned_tree(directory)
            except (OSError, StorageError, IntegrityError):
                continue

    def _object_key(self, identity: str) -> bytes:
        self._live()
        return crypto.derive(self.master, self.header["vault_id"], "object/" + identity)

    def _read_object(
        self, entry: dict, target=None, event: Event = None, name: str = ""
    ) -> tuple[int, str]:
        identity = entry["id"]
        callback = (lambda done: event(name, done, entry["size"])) if event else None
        with open_read(self.root / "objects" / identity) as source:
            size, digest = crypto.decrypt_stream(
                source,
                target,
                self._object_key(identity),
                crypto.object_context(self.header["vault_id"], identity),
                callback,
                entry["size"],
            )
        if not hmac.compare_digest(digest, entry["sha256"]):
            raise IntegrityError("Dosya özeti katalogla eşleşmiyor.")
        return size, digest

    def _store_stream(self, source, event: Event, name: str, expected: int) -> dict:
        identity = crypto.new_id()
        final = self.root / "objects" / identity
        temp = self.root / "objects" / (".tmp-" + identity)
        published = False
        try:
            with private_open(temp) as target:
                callback = (lambda done: event(name, done, expected)) if event else None
                size, digest = crypto.encrypt_stream(
                    source,
                    target,
                    self._object_key(identity),
                    crypto.object_context(self.header["vault_id"], identity),
                    callback,
                )
                sync_file(target)
            self._checkpoint("object-written")
            entry = {"id": identity, "size": size, "sha256": digest}
            with open_read(temp) as target:
                checked = crypto.decrypt_stream(
                    target,
                    None,
                    self._object_key(identity),
                    crypto.object_context(self.header["vault_id"], identity),
                    expected_size=size,
                )
            if checked != (size, digest):
                raise IntegrityError("Şifrelenen nesne doğrulanamadı.")
            publish(temp, final)
            published = True
            self._checkpoint("object-published")
            return entry
        except BaseException:
            if published:
                with contextlib.suppress(OSError, StorageError):
                    no_links(final).unlink(missing_ok=True)
            raise
        finally:
            with contextlib.suppress(OSError):
                no_links(temp).unlink(missing_ok=True)

    def preview_add(self, paths: Iterable[str | Path]) -> dict:
        self._live()
        files: dict[str, Path] = {}
        directories: set[str] = set()

        def collect(path: Path, name: str):
            no_links(path)
            safe_name(name)
            if len(files) + len(directories) >= MAX_ENTRIES:
                raise UsageError("İçe aktarma kayıt sınırı aşıldı.")
            if path.is_dir():
                if name in directories:
                    raise UsageError("Aynı klasör birden fazla seçildi.")
                directories.add(name)
                for child in reversed(sorted(path.iterdir())):
                    pending.append((child, name + "/" + child.name))
            elif path.is_file():
                if name in files:
                    raise UsageError("Aynı adlı dosyalar birlikte eklenemez.")
                files[name] = path
            else:
                raise StorageError("Kaynak normal bir dosya veya klasör değil.")

        for value in paths:
            path = no_links(value)
            if within(path, self.root) or within(self.root, path):
                raise UsageError("Kasa veya kasayı içeren klasör kaynak olamaz.")
            pending = [(path, path.name)]
            while pending:
                collect(*pending.pop())
        if not files and not directories:
            raise UsageError("En az bir kaynak seçin.")
        candidate = copy.deepcopy(self.catalog)
        for name in files:
            if name in candidate["files"]:
                raise UsageError("Kasada aynı adlı dosya var; kaynak adını değiştirin.")
            candidate["files"][name] = {"id": crypto.new_id(), "size": 0, "sha256": "0" * 64}
        candidate["directories"] = sorted(set(candidate["directories"]) | directories)
        _validate_catalog(candidate)
        return {
            "files": files,
            "directories": directories,
            "count": len(files),
            "bytes": sum(p.stat().st_size for p in files.values()),
        }

    def add(self, paths: Iterable[str | Path], event: Event = None) -> dict:
        preview = self.preview_add(paths)
        candidate = copy.deepcopy(self.catalog)
        added = []
        try:
            for name, path in sorted(preview["files"].items()):
                with open_read(path) as source:
                    before = os.fstat(source.fileno())
                    entry = self._store_stream(source, event, name, before.st_size)
                    added.append(entry["id"])
                    after = os.fstat(source.fileno())
                    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                    ) or entry["size"] != before.st_size:
                        raise StorageError("Kaynak dosya işlem sırasında değişti; yeniden deneyin.")
                    candidate["files"][name] = entry
            candidate["directories"] = sorted(
                set(candidate["directories"]) | preview["directories"]
            )
            self._commit(candidate)
            return {"added": len(added), "bytes": preview["bytes"]}
        finally:
            self._discard_unreferenced(added)

    def _discard_unreferenced(self, identities: Iterable[str]) -> None:
        # Read the actual committed generation, even after an injected post-commit failure.
        try:
            active = self._current(self.root)
            if active != self.generation:
                return  # Indeterminate commit: preserve data, never guess.
            referenced = {entry["id"] for entry in self.catalog["files"].values()}
            for identity in identities:
                if identity not in referenced:
                    with contextlib.suppress(OSError, StorageError):
                        no_links(self.root / "objects" / crypto.identifier(identity)).unlink(
                            missing_ok=True
                        )
        except (OSError, IntegrityError):
            pass

    def list(self) -> dict:
        self._live()
        return {
            "files": [
                {"name": name, "size": entry["size"]}
                for name, entry in sorted(self.catalog["files"].items())
            ],
            "directories": list(self.catalog["directories"]),
        }

    def _selection(self, names: Iterable[str] | None) -> tuple[dict, list[str]]:
        if names is None:
            return dict(self.catalog["files"]), list(self.catalog["directories"])
        files, directories = {}, set()
        for name in names:
            safe_name(name)
            if name not in self.catalog["files"] and name not in self.catalog["directories"]:
                raise UsageError("Seçilen dosya/klasör kasada bulunamadı.")
            files.update(
                {
                    n: e
                    for n, e in self.catalog["files"].items()
                    if n == name or n.startswith(name + "/")
                }
            )
            directories.update(
                n for n in self.catalog["directories"] if n == name or n.startswith(name + "/")
            )
        # Include parent directories when exporting a nested single file.
        for name in [*files, *directories]:
            parent = name.rpartition("/")[0]
            while parent:
                directories.add(parent)
                parent = parent.rpartition("/")[0]
        return files, sorted(directories)

    def export(
        self, destination: str | Path, names: Iterable[str] | None = None, event: Event = None
    ) -> dict:
        self._live()
        destination = no_links(destination)
        if within(destination, self.root):
            raise UsageError("Açık dosyalar kasa içine çıkarılamaz.")
        files, directories = self._selection(names)
        for name in files:
            target = no_links(destination / name)
            if not within(target, destination) or target.exists():
                raise StorageError("Dışa aktarma hedefi mevcut veya güvenli değil.")
        for name in directories:
            target = no_links(destination / name)
            if target.exists() and not target.is_dir():
                raise StorageError("Hedef klasör yolunda bir dosya var.")
        private_parents(destination)
        for name in sorted(directories, key=lambda item: item.count("/")):
            private_parents(destination / name)
        for name, entry in sorted(files.items()):
            target = no_links(destination / name)
            private_parents(target.parent)
            temp = target.parent / (".psypher-export-" + crypto.new_id())
            try:
                with private_open(temp) as output:
                    self._read_object(entry, output, event, name)
                    sync_file(output)
                self._checkpoint("export-verified")
                publish(temp, target)
            finally:
                with contextlib.suppress(OSError):
                    no_links(temp).unlink(missing_ok=True)
        return {"exported": len(files), "bytes": sum(entry["size"] for entry in files.values())}

    def remove(self, names: Iterable[str]) -> dict:
        self._live()
        names = list(names)
        if not names:
            raise UsageError("Silinecek kayıt seçin.")
        self._selection(names)  # Validate names, but don't remove their parents.
        candidate = copy.deepcopy(self.catalog)
        removed = []
        for name, entry in self.catalog["files"].items():
            if any(name == value or name.startswith(value + "/") for value in names):
                removed.append(entry["id"])
                del candidate["files"][name]
        candidate["directories"] = [
            name
            for name in candidate["directories"]
            if not any(name == value or name.startswith(value + "/") for value in names)
        ]
        self._commit(candidate)
        self._discard_unreferenced(removed)
        return {"removed": len(removed)}

    def verify(self, event: Event = None, *, persist: bool = True) -> dict:
        self._live()
        for name, entry in sorted(self.catalog["files"].items()):
            self._read_object(entry, event=event, name=name)
        result = {
            "verified": len(self.catalog["files"]),
            "at": now(),
            "content_digest": content_digest(self.catalog),
        }
        if persist:
            candidate = copy.deepcopy(self.catalog)
            candidate["status"]["verified"] = {
                "at": result["at"],
                "content_digest": result["content_digest"],
            }
            self._commit(candidate)
        return result

    def change_access(
        self,
        password: str,
        keyfile: bytes | None = None,
        recovery: bytes | None = None,
        confirmation: bytes | None = None,
    ) -> dict:
        self._live()
        if recovery is not None:
            if (
                len(recovery) != 32
                or confirmation is None
                or not hmac.compare_digest(recovery, confirmation)
            ):
                raise UsageError("Yeni kurtarma anahtarı tekrar doğrulanmalı.")
            header, _ = crypto.create_header(
                password, recovery, keyfile, self.master, self.header["vault_id"]
            )
        else:
            header = crypto.rewrap_password(self.header, self.master, password, keyfile)
        candidate = copy.deepcopy(self.catalog)
        if recovery is not None:
            candidate["status"]["recovery_confirmed_at"] = now()
        self._commit(candidate, header)
        return {
            "changed": True,
            "keyfile_required": keyfile is not None,
            "recovery_rotated": recovery is not None,
        }

    def _copy_snapshot(self, destination: Path, event: Event = None, backup: bool = True) -> dict:
        destination = no_links(destination)
        if destination.exists() or within(destination, self.root) or within(self.root, destination):
            raise StorageError("Yedek/geri yükleme için kasadan ayrı ve yeni bir konum seçin.")
        private_parents(destination.parent)
        staging = destination.parent / (".psypher-copy-" + crypto.new_id())
        private_mkdir(staging)
        try:
            private_mkdir(staging / "objects")
            private_mkdir(staging / "generations")
            generation_dir = staging / "generations" / self.generation
            private_mkdir(generation_dir)
            sources = [
                (self.root / "generations" / self.generation / name, generation_dir / name)
                for name in ("header.json", "catalog.enc")
            ]
            sources.extend(
                (self.root / "objects" / entry["id"], staging / "objects" / entry["id"])
                for entry in self.catalog["files"].values()
            )
            for source, target in sources:
                with open_read(source) as incoming, private_open(target) as outgoing:
                    shutil.copyfileobj(incoming, outgoing, crypto.CHUNK_SIZE)
                    sync_file(outgoing)
                self._checkpoint("snapshot-file-copied")
            write_private(staging / "CURRENT", self.generation.encode("ascii"))
            if backup:
                write_private(staging / "BACKUP", b"PSYBACKUP1\n")
            with Vault.open(staging, _master=self.master) as check:
                result = check.verify(event, persist=False)
            self._checkpoint("snapshot-verified")
            publish_directory(staging, destination)
            return result
        finally:
            if staging.exists():
                delete_owned_tree(staging)

    def backup(self, destination: str | Path, event: Event = None) -> dict:
        self._live()
        result = self._copy_snapshot(Path(destination), event)
        candidate = copy.deepcopy(self.catalog)
        candidate["status"]["backup"] = {
            "at": result["at"],
            "content_digest": result["content_digest"],
        }
        self._commit(candidate)
        return {"backed_up": result["verified"], "at": result["at"], "verified": True}

    @classmethod
    def restore(
        cls,
        backup: str | Path,
        destination: str | Path,
        password: str | None = None,
        keyfile: bytes | None = None,
        recovery: bytes | None = None,
        event: Event = None,
    ) -> dict:
        backup = no_links(backup)
        if read_bounded(backup / "BACKUP", 11) != b"PSYBACKUP1\n":
            raise IntegrityError("Geçersiz yedek biçimi.")
        with cls.open(backup, password, keyfile, recovery) as source:
            result = source._copy_snapshot(Path(destination), event, backup=False)
        return {"restored": result["verified"], "verified": True}

    def doctor(self) -> dict:
        self._live()
        digest = content_digest(self.catalog)
        status = copy.deepcopy(self.catalog["status"])
        for name in ("verified", "backup"):
            if status[name] is not None:
                status[name]["covers_current_catalog"] = hmac.compare_digest(
                    status[name]["content_digest"], digest
                )
        inactive = [
            p.name
            for p in no_links(self.root / "generations").iterdir()
            if p.name != self.generation
        ]
        referenced = {entry["id"] for entry in self.catalog["files"].values()}
        object_names = {no_links(path).name for path in (self.root / "objects").iterdir()}
        return {
            "version": "2.0.0b1",
            "release": "beta",
            "independently_audited": False,
            "format": 1,
            "cipher": "XChaCha20-Poly1305 secretstream",
            "kdf": {"algorithm": "Argon2id", "memory_mib": 256, "passes": 3},
            "keyfile_required": self.header["password"]["keyfile"],
            "files": len(self.catalog["files"]),
            "status": status,
            "inactive_generations": len(inactive),
            "unreferenced_ciphertext_files": len(object_names - referenced),
            "missing_objects": len(referenced - object_names),
            "limits": {"catalog_mib": 8, "entries": MAX_ENTRIES},
            "rollback_detection": False,
            "secure_memory_erasure": False,
        }

    def import_legacy(self, paths: Iterable[str | Path], key: bytes, event: Event = None) -> dict:
        from cryptography.fernet import Fernet, InvalidToken

        self._live()
        try:
            fernet = Fernet(key)
        except (ValueError, TypeError) as exc:
            raise UsageError("Eski Fernet anahtarı geçersiz.") from exc
        candidate = copy.deepcopy(self.catalog)
        added = []
        try:
            for value in paths:
                path = no_links(value)
                if not path.name.endswith("_psykhenc") or within(path, self.root):
                    raise UsageError("Eski şifreli dosyaları açıkça seçin (_psykhenc).")
                name = safe_name(path.name.removesuffix("_psykhenc"))
                if name in candidate["files"]:
                    raise UsageError("Kasada aynı isimli dosya var.")
                # Fernet is not a streaming format: explicitly bound legacy RAM use.
                token = read_bounded(path, 256 * 1024 * 1024)
                try:
                    plain = fernet.decrypt(token)
                except InvalidToken as exc:
                    raise IntegrityError(
                        "Eski dosya doğrulanamadı; anahtar yanlış veya veri bozuk."
                    ) from exc
                entry = self._store_stream(io.BytesIO(plain), event, name, len(plain))
                added.append(entry["id"])
                candidate["files"][name] = entry
                del plain, token
            if not added:
                raise UsageError("En az bir eski dosya seçin.")
            self._commit(candidate)
            return {"migrated": len(added)}
        finally:
            self._discard_unreferenced(added)
