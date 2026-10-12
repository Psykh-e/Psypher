# Psypher kasa formatı 1

2.0.0b1 uygulamasının kasa format sürümü `1`dir. Bilinmeyen sürüm/suite veya
alanlar reddedilir; pickle, eval, otomatik downgrade ve algoritma pazarlığı yoktur.

```text
vault/
  CURRENT                        # 32 küçük hex karakter: aktif nesil
  .lock                          # OS exclusive byte/file lock
  objects/<32hex>                # değişmez şifreli dosya nesnesi
  generations/<32hex>/
    header.json                  # açık erişim zarfları; <=64 KiB
    catalog.enc                  # nonce + AEAD şifreli katalog; <=8 MiB +40
  BACKUP                         # yalnızca yedeklerde PSYBACKUP1 + LF
```

JSON: UTF-8/ASCII, anahtarları sıralı, boşluksuz, ensure_ascii=True; yinelenen
anahtar/NaN/Infinity reddedilir. ID'ler 16 rastgele baytın küçük hex gösterimidir.

## Anahtar hiyerarşisi

Ana anahtar M: 32 güvenli rastgele bayt. HKDF-SHA256: çıktı 32, salt=bytes(vault_id),
info=`psypher/v1/` + amaç. Parola UTF-8 olarak olduğu gibi kullanılır; strip,
Unicode normalizasyonu veya küçük harfe dönüştürme yapılmaz. En fazla 1024 bayt.

- P=Argon2id13.kdf(32, password, salt16, opslimit3, memlimit268435456).
- Parola zarfı KEK=HKDF(P || K, `password-wrap/keyfile=0|1`).
  K=anahtar dosyasındaki 32 bayt; faktörsüz kullanımda 32 sıfır bayt. Mod bağlama dahil.
- Kurtarma zarfı KEK=HKDF(R, `recovery-wrap`); R=32 rastgele bayt.
- Nesne anahtarı=HKDF(M, `object/<object-id>`).
- Katalog anahtarı=HKDF(M, `catalog/<generation-id>`).

Başlık alanları: version, suite, vault_id, generation, password, recovery.
Suite=`XCHACHA20POLY1305-SECRETSTREAM-ARGON2ID13`.
Password alanları: salt(base64/16), opslimit(3), memlimit(268435456), keyfile(bool),
nonce(base64/24), wrapped(base64/48). Recovery: nonce ve wrapped.
Zarf şifrelemesi XChaCha20-Poly1305-IETF AEAD; plaintext M.
AAD=canonical JSON `{version,suite,vault_id,slot,settings}`; settings ilgili
slotun nonce/wrapped dışındaki alanlarıdır. Her sarma yeni rastgele nonce kullanır.

Katalog AAD=`psypher/catalog/v1/` || SHA256(canonical(header)); tüm başlık
bağlanır. `catalog.enc` = nonce24 || ciphertext || tag16. Katalog version, files,
directories, status içerir. Files: güvenli göreli yol → {id,size,sha256}.
Directory listesi boş klasörleri de içerir. Tüm adlar Windows'a uygun, benzersiz
casefold ve hiyerarşi doğrulamalıdır. Katalog üst sınırı 20.000 toplam kayıt / 8 MiB.
Status: recovery_confirmed_at, verified ve backup (null veya at/content_digest).
Content_digest = SHA256(canonical({files,directories})); kontrolü kataloğa bağlar.
Kontrol kayıtları güncel disk bozulması testi değil, geçmiş işlem kanıtıdır.

## Akış nesnesi

Prefix: ASCII `PSYOBJ1` + NUL (8 bayt), ardından secretstream header 24 bayt.
Çerçeve: ciphertext_len uint32 big-endian || secretstream ciphertext.
Her plaintext parça 1..1048576 bayt, MESSAGE etiketi; son çerçeve boş plaintext
ve FINAL etiketidir. Boş dosya yalnızca FINAL içerir. Uzunluk 17..1048593.
AAD = canonical({version,suite,vault_id,object_id}) || index(uint64 BE) ||
ciphertext_len(uint32 BE). İndeks 0'dan başlar. FINAL sonrası tek bayt bile reddedilir.
Tam çözme sonunda plaintext boyutu ve SHA256 katalogla karşılaştırılır.
Uzunluklar okunmadan sınırlandırılır; dosya belleğe tamamen alınmaz.

## İşlem protokolü

1. Kaynak salt okunur açılır, fstat bilgileri kaydedilir.
2. Rastgele geçici nesne yazılır, fsync ve tam readback doğrulaması yapılır.
3. Kaynak değişmediği kontrol edilir; nesne atomik olarak yayımlanır.
4. Yeni nesil header/katalog yazılır ve fsync/readback yapılır.
5. CURRENT geçici dosyası yeni nesli işaret eder; atomik replace ile aktif olur.
6. Eski nesiller temizlenir; başarıdan önce/sonra çökme eski/yeni nesli bırakır.

Nesillerden otomatik fallback yapılmaz: bozuk aktif kayıt bütünlük hatasıdır.
Önceki nesiller ve yetim nesneler anahtar iptali veya kullanıcı snapshot özelliği
değildir. Kurtarma/yedek kopyaları aynı vault_id/M taşır, bağımsız yerel kopyalardır.
Parola değişimi yalnızca erişim zarfını yeniler, tarihsel kopyaları iptal etmez.

## Kaynaklar

[libsodium secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream),
[PyNaCl Argon2id](https://pynacl.readthedocs.io/en/latest/api/pwhash/),
[cryptography HKDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf).
