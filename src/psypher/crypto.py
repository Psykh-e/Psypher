"""Small, versioned wrappers around maintained cryptographic primitives.

Never implement a cipher, nonce counter, or password KDF in application code.
Secretstream owns nonce management; HKDF separates all key purposes.
"""

import base64
import binascii
import hashlib
import json
import secrets
import struct
from collections.abc import Callable
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as sodium
from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id

from .errors import AccessError, IntegrityError, UsageError

VERSION = 1
SUITE = "XCHACHA20POLY1305-SECRETSTREAM-ARGON2ID13"
CHUNK_SIZE = 1024 * 1024
MEMLIMIT = 256 * 1024 * 1024
OPSLIMIT = 3
MAX_HEADER = 64 * 1024
MAX_CATALOG = 8 * 1024 * 1024
MAGIC = b"PSYOBJ1\x00"
Progress = Callable[[int], None] | None


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_json(data: bytes, limit: int) -> dict:
    if len(data) > limit:
        raise IntegrityError("Format boyut sınırı aşıldı.")
    try:
        value = json.loads(
            data,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IntegrityError("Geçersiz veya bozuk format.") from exc


def encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode(value: object, length: int) -> bytes:
    try:
        if not isinstance(value, str) or len(value) > length * 2 + 8:
            raise ValueError()
        result = base64.b64decode(value, validate=True)
        if len(result) != length:
            raise ValueError()
        return result
    except (ValueError, binascii.Error) as exc:
        raise IntegrityError("Geçersiz anahtar zarfı.") from exc


def identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise IntegrityError("Geçersiz nesne/kasa kimliği.")
    return value


def new_id() -> str:
    return secrets.token_hex(16)


def derive(material: bytes, vault_id: str, purpose: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(vault_id),
        info=("psypher/v1/" + purpose).encode("ascii"),
    ).derive(material)


def validate_password(password: str) -> None:
    try:
        length = len(password.encode("utf-8")) if isinstance(password, str) else 0
    except UnicodeError as exc:
        raise UsageError("Parola geçerli UTF-8 metni olmalı.") from exc
    if not isinstance(password, str) or len(password) < 12 or length > 1024:
        raise UsageError("Yeni parola en az 12 karakter, en fazla 1024 UTF-8 baytı olmalı.")


def _password_key(password: str, slot: dict, vault_id: str, keyfile: bytes | None) -> bytes:
    try:
        encoded = password.encode("utf-8") if isinstance(password, str) else None
    except UnicodeError as exc:
        raise AccessError("Parola geçerli UTF-8 metni olmalı.") from exc
    if encoded is None or len(encoded) > 1024:
        raise AccessError("Parola veya anahtar dosyası doğrulanamadı.")
    if slot["keyfile"] and (keyfile is None or len(keyfile) != 32):
        raise AccessError("Bu kasa için 32 baytlık anahtar dosyası gerekli.")
    if not slot["keyfile"] and keyfile is not None:
        raise UsageError("Bu kasada anahtar dosyası etkin değil.")
    try:
        stretched = argon2id.kdf(
            32,
            encoded,
            decode(slot["salt"], 16),
            opslimit=slot["opslimit"],
            memlimit=slot["memlimit"],
        )
    except (RuntimeError, MemoryError) as exc:
        raise AccessError(
            "Argon2id için yeterli bellek yok; güvenlik profili düşürülmedi."
        ) from exc
    material = stretched + (keyfile if keyfile is not None else bytes(32))
    return derive(material, vault_id, "password-wrap/keyfile=" + str(int(slot["keyfile"])))


def seal(data: bytes, key: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(24)
    return nonce + sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(data, aad, nonce, key)


def unseal(data: bytes, key: bytes, aad: bytes) -> bytes:
    if len(data) < 40:
        raise IntegrityError("Eksik şifreli veri.")
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(data[24:], aad, data[:24], key)
    except CryptoError as exc:
        raise IntegrityError("Şifreli veri doğrulanamadı.") from exc


def _slot_aad(header: dict, name: str) -> bytes:
    slot = {k: v for k, v in header[name].items() if k not in {"nonce", "wrapped"}}
    return canonical(
        {
            "version": header["version"],
            "suite": header["suite"],
            "vault_id": header["vault_id"],
            "slot": name,
            "settings": slot,
        }
    )


def _wrap(header: dict, name: str, master: bytes, key: bytes) -> None:
    blob = seal(master, key, _slot_aad(header, name))
    header[name].update(nonce=encode(blob[:24]), wrapped=encode(blob[24:]))


def create_header(
    password: str,
    recovery: bytes,
    keyfile: bytes | None = None,
    master: bytes | None = None,
    vault_id: str | None = None,
) -> tuple[dict, bytes]:
    validate_password(password)
    if len(recovery) != 32 or (keyfile is not None and len(keyfile) != 32):
        raise UsageError("Anahtarlar tam olarak 32 bayt olmalı.")
    master = master if master is not None else secrets.token_bytes(32)
    header = {
        "version": VERSION,
        "suite": SUITE,
        "vault_id": vault_id or new_id(),
        "generation": new_id(),
        "password": {
            "salt": encode(secrets.token_bytes(16)),
            "opslimit": OPSLIMIT,
            "memlimit": MEMLIMIT,
            "keyfile": keyfile is not None,
        },
        "recovery": {},
    }
    _wrap(
        header,
        "password",
        master,
        _password_key(password, header["password"], header["vault_id"], keyfile),
    )
    _wrap(header, "recovery", master, derive(recovery, header["vault_id"], "recovery-wrap"))
    return header, master


def validate_header(header: dict) -> None:
    try:
        if set(header) != {"version", "suite", "vault_id", "generation", "password", "recovery"}:
            raise ValueError()
        if (
            type(header["version"]) is not int
            or header["version"] != VERSION
            or header["suite"] != SUITE
        ):
            raise ValueError()
        identifier(header["vault_id"])
        identifier(header["generation"])
        password = header["password"]
        if not isinstance(password, dict) or set(password) != {
            "salt",
            "opslimit",
            "memlimit",
            "keyfile",
            "nonce",
            "wrapped",
        }:
            raise ValueError()
        if (
            type(password["memlimit"]) is not int
            or password["memlimit"] != MEMLIMIT
            or type(password["opslimit"]) is not int
            or password["opslimit"] != OPSLIMIT
            or type(password["keyfile"]) is not bool
        ):
            raise ValueError()
        decode(password["salt"], 16)
        if not isinstance(header["recovery"], dict) or set(header["recovery"]) != {
            "nonce",
            "wrapped",
        }:
            raise ValueError()
        for name in ("password", "recovery"):
            decode(header[name]["nonce"], 24)
            decode(header[name]["wrapped"], 48)
    except (ValueError, TypeError, KeyError) as exc:
        raise IntegrityError("Desteklenmeyen veya bozuk kasa başlığı.") from exc


def unlock(
    header: dict,
    password: str | None = None,
    keyfile: bytes | None = None,
    recovery: bytes | None = None,
) -> bytes:
    validate_header(header)  # Bounds are checked BEFORE the expensive KDF.
    name = "recovery" if recovery is not None else "password"
    if recovery is not None:
        if len(recovery) != 32:
            raise AccessError("Kurtarma anahtarı doğrulanamadı.")
        key = derive(recovery, header["vault_id"], "recovery-wrap")
    else:
        if password is None:
            raise AccessError("Parola gerekli.")
        key = _password_key(password, header[name], header["vault_id"], keyfile)
    try:
        return unseal(
            decode(header[name]["nonce"], 24) + decode(header[name]["wrapped"], 48),
            key,
            _slot_aad(header, name),
        )
    except IntegrityError as exc:
        raise AccessError("Erişim bilgileri doğrulanamadı veya anahtar zarfı bozuk.") from exc


def rewrap_password(header: dict, master: bytes, password: str, keyfile: bytes | None) -> dict:
    validate_password(password)
    if keyfile is not None and len(keyfile) != 32:
        raise UsageError("Anahtar dosyası tam olarak 32 bayt olmalı.")
    result = parse_json(canonical(header), MAX_HEADER)
    result["password"] = {
        "salt": encode(secrets.token_bytes(16)),
        "opslimit": OPSLIMIT,
        "memlimit": MEMLIMIT,
        "keyfile": keyfile is not None,
    }
    _wrap(
        result,
        "password",
        master,
        _password_key(password, result["password"], result["vault_id"], keyfile),
    )
    return result


def object_context(vault_id: str, object_id: str) -> bytes:
    return canonical(
        {"version": VERSION, "suite": SUITE, "vault_id": vault_id, "object_id": object_id}
    )


def encrypt_stream(
    source: BinaryIO, target: BinaryIO, key: bytes, context: bytes, progress: Progress = None
) -> tuple[int, str]:
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    target.write(MAGIC)
    target.write(sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key))
    digest = hashlib.sha256()
    size = 0
    index = 0
    while True:
        chunk = source.read(CHUNK_SIZE)
        final = not chunk
        tag = (
            sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
            if final
            else sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        )
        length = len(chunk) + sodium.crypto_secretstream_xchacha20poly1305_ABYTES
        aad = context + struct.pack(">QI", index, length)
        encrypted = sodium.crypto_secretstream_xchacha20poly1305_push(state, chunk, aad, tag)
        target.write(struct.pack(">I", length))
        target.write(encrypted)
        digest.update(chunk)
        size += len(chunk)
        if progress:
            progress(size)
        if final:
            return size, digest.hexdigest()
        index += 1


def _exact(source: BinaryIO, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = source.read(length - len(result))
        if not part:
            raise IntegrityError("Şifreli akış eksik veya kesilmiş.")
        result.extend(part)
    return bytes(result)


def decrypt_stream(
    source: BinaryIO,
    target: BinaryIO | None,
    key: bytes,
    context: bytes,
    progress: Progress = None,
    expected_size: int | None = None,
) -> tuple[int, str]:
    if _exact(source, len(MAGIC)) != MAGIC:
        raise IntegrityError("Geçersiz nesne biçimi.")
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    sodium.crypto_secretstream_xchacha20poly1305_init_pull(state, _exact(source, 24), key)
    digest = hashlib.sha256()
    size = 0
    index = 0
    while True:
        length = struct.unpack(">I", _exact(source, 4))[0]
        if not 17 <= length <= CHUNK_SIZE + 17:
            raise IntegrityError("Geçersiz şifreli parça boyutu.")
        try:
            plain, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(
                state, _exact(source, length), context + struct.pack(">QI", index, length)
            )
        except CryptoError as exc:
            raise IntegrityError("Dosya bütünlüğü doğrulanamadı.") from exc
        if tag == sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            if plain or source.read(1):
                raise IntegrityError("Geçersiz sonlandırma veya akış sonunda ek veri.")
            if expected_size is not None and size != expected_size:
                raise IntegrityError("Dosya boyutu katalogla eşleşmiyor.")
            return size, digest.hexdigest()
        if tag != sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE or not plain:
            raise IntegrityError("Geçersiz akış etiketi.")
        size += len(plain)
        if expected_size is not None and size > expected_size:
            raise IntegrityError("Dosya beklenen boyutu aşıyor.")
        if target is not None:
            target.write(plain)
        digest.update(plain)
        if progress:
            progress(size)
        index += 1
