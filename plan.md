# Psypher 2.0 — Güvenlik Odaklı Konsol Kasası

## Hedef

Python 3.12 üzerinde, Windows 10/11 öncelikli, tamamen yerel kasa.
Türkçe menü ve CLI aynı çekirdeği kullanır. Kaynak dosyalar değiştirilmez.
Parola, isteğe bağlı anahtar dosyası ve bağımsız kurtarma anahtarı kullanılır.
Bulut, GUI, sanal sürücü ve özel kriptografi kapsam dışındadır.
“Kırılamaz” iddiası yerine test edilebilir güvenlik özellikleri sunulur.

## Mimari kararlar

- PyNaCl/libsodium XChaCha20-Poly1305 secretstream; 1 MiB parçalar ve zorunlu FINAL.
- Argon2id: 256 MiB, üç geçiş, rastgele salt; sessiz zayıflatma yok.
- Rastgele 256 bit ana anahtar; HKDF-SHA256 ile amaç/kasa/nesne ayrımı.
- Parola ve kurtarma için ayrı AEAD anahtar zarfları.
- Şifreli katalog, rastgele nesne isimleri, değişmez nesiller ve atomik CURRENT.
- Özel izinli dosyalar, OS kilidi, güvenli yollar, doğrulama sonrası yayımlama.
- Eski Fernet formatı yalnızca okunarak taşınır; orijinaller korunur.

## Aşamalar ve kabul ölçütleri

| Aşama | İşler | Kabul ölçütü | Durum |
|---|---|---|---|
| 0 | Paket, tehdit modeli, format, hatalar, test ve CI | Import yan etkisiz; şartname belgeli | Tamamlandı |
| 1 | KDF, anahtar dosyası, zarf, HKDF, akış | Yanlış sır ve kurcalama güvenle reddediliyor | Tamamlandı |
| 2 | Init/add/list/export/remove/verify, katalog ve işlemler | Kaynaklar korunuyor; kesintilerde tutarlılık | Tamamlandı |
| 3 | Kurtarma, erişim değişimi, yedek/restore/migrate | Uçtan uca geri yükleme ve eski veri koruması | Tamamlandı |
| 4 | Menü, CLI, önizleme, ilerleme, iptal ve durum ekranı | Aynı çekirdek, anlaşılır Türkçe, güvenli otomasyon | Tamamlandı |
| 5 | Kaynak sınırları, Windows paket, denetim, yayın | Testler, 10 GiB ölçüm; dış inceleme yoksa beta | Beta doğrulandı; kararlı yayın kapıları açık |

Bir aşamanın doğrulaması tamamlanmadan bağımlı aşama tamamlandı sayılmaz.

## Arayüz

`init`, `add`, `list`, `export`, `remove`, `verify`, `backup`, `restore`,
`passwd`, `keyfile`, `recover`, `migrate`, `doctor`.
Parametresiz açılışta menü; 5 dakika boşta kalınca kilitlenme.
Parolalar gizli istem veya ayrı dosya tanıtıcısı; argv/env kabul edilmez.
JSON çıktısı ve 0/2/3/4/5 çıkış kodları. Ctrl+C: 130.
Kurtarma anahtarı ayrı konuma kaydedilip yeniden doğrulanır.
Durum ekranı gerçek kontrol tarihlerini gösterir; yapay güvenlik puanı yoktur.

## Doğrulama

Boş/Unicode/uzantısız/iç içe dosyalar; yanlış parola ve anahtarlar;
başlık/katalog/akış kurcalama, eksik FINAL, ek veri;
disk dolması, izin, iptal, çökme, kilit; yol kaçışı, symlink ve junction;
hedef çakışması; her yazma sınırında hata enjeksiyonu;
yedek geri yükleme ve kaynak özeti eşleşmesi; sır sızıntısı kontrolü;
10 GiB akışta sabit bellek; Windows çalıştırılabilir dosya ve temiz kurulum.

Bağımsız güvenlik incelemesi bu çalışma ile sağlanamaz. Tamamlanana kadar beta.
Aktif zararlı yazılım, bellek silme, SSD güvenli silme ve bütün kasa rollback
tespiti garanti edilmez. Parola değişimi eski yedek erişimini iptal etmez.

## Uygulama ve doğrulama kaydı

- 126 otomatik test geçti; gerçek süreç ölümü, yazma hatası ve sessiz yazma bozulması dahil.
- Runtime ve geliştirme kilit dosyalarının pip-audit taraması: bilinen açık bulunmadı.
- Gerçek 10 GiB dosya: şifreleme/readback 54,031 sn; doğrulanmış export 32,063 sn.
- Akışta örneklenen RSS artışı 3,25 MiB; ayrı Argon2id maliyeti 256 MiB.
- Windows portable paket ve temiz venv wheel: proje dışında 19'ar CLI senaryosu.
- Lint, biçim ve paket bağımlılık tutarlılığı kontrolleri geçti.
- İlk Windows CI tanımlandı; uzaktaki GitHub Actions çalıştırması burada yapılmadı.
- Bağımsız güvenlik incelemesi, gerçek temiz Windows 10/11 VM testi ve yayıncı
  kod imzası tamamlanmadı. Sürüm 2.0.0b1 beta olarak işaretlendi.

Kanıt özeti: [docs/VALIDATION.md](docs/VALIDATION.md).
Kararlı yayın inceleme listesi: [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).
