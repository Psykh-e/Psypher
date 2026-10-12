# Yerel doğrulama kaydı — 2.0.0b1

Ortam: Windows 11 x64, CPython 3.12.10. Bu kayıt bağımsız güvenlik incelemesi
veya temiz işletim sistemi kurulumu testi değildir. Gerçek kullanıcı kasası
oluşturulmadı; geçici üretilmiş veriler kullanılıp temizlendi.

| Kontrol | Sonuç |
|---|---|
| pytest | 126 test geçti; 55,60 saniye |
| Ruff lint ve format | Başarılı |
| pip check | Bozuk bağımlılık yok |
| Runtime pip-audit --strict | Bilinen açık yok |
| Geliştirme pip-audit --strict | Bilinen açık yok |
| Ani süreç ölümü | Nesne/başlık/katalog/CURRENT öncesi-sonrası altı noktada tutarlı nesil |
| Yazma/iptal hatası | Kaynak korunuyor, doğrulanmamış çıktı yayımlanmıyor |
| Sessiz başlık/işaretçi bozulması | Aktif nesil değiştirilmeden reddediliyor |
| Windows DACL / junction / kilit | İzin, bağlantı ve ayrı süreç testleri geçti |
| Taşınabilir Windows EXE | Proje dışında, Python olmayan PATH ile 19 senaryo |
| Yeni venv'e kurulan wheel | Proje dışında 19 senaryo |
| Wheel içeriği | Eski config, örnek dosyalar veya EXE içermiyor |
| Eski giriş noktası | Yeni beta CLI'ye güvenle yönlendiriyor |

Dağıtım senaryoları init, keyfile generate/enable/disable, add önizlemesi,
Unicode/boş dosya içe aktarma, list, verify, doctor, export, backup, restore,
Fernet migrate, passwd, eski parola reddi, recover ve remove işlemlerini kapsar.

## 10 GiB gerçek dosya

- Boyut: 10.737.418.240 bayt.
- İçe aktarma + tam şifreli readback: 54,031 saniye.
- Tam doğrulanmış dışa aktarma: 32,063 saniye.
- Toplam test: 107,656 saniye (kurulum, son hash ve temizleme dahil).
- Akış başlangıcı RSS: 30.343.168 bayt.
- Örneklenen en yüksek akış RSS: 33.751.040 bayt.
- Örneklenen artış: 3.407.872 bayt = 3,25 MiB.
- Argon2id'nin ayrı kilit açma bellek maliyeti: 268.435.456 bayt.
- Kaynak korundu; export SHA256 katalogla eşleşti; geçici dosyalar kaldırıldı.

RSS ölçümü düzenli örneklenen işlem belleğidir; OS dosya cache'i ve kilit
açmadaki ayrı KDF maliyeti akış metriğine dahil değildir. Bu değerler bu
makineye aittir; diğer donanımlar için hız garantisi değildir.

Yerel ayrıntılı JSON raporları `.validation/streaming-10gib.json`,
`.validation/executable.json`, `.validation/wheel.json` altında bulunur.
Yeniden çalıştırma komutları README'dedir.

## Bekleyen yayın kapıları

Bağımsız güvenlik incelemesi, temiz Windows 10/11 VM doğrulaması, yayıncı
kod imzası ve uzaktaki CI çalıştırması yapılmadı. Linux/macOS resmi kararlı
destek olarak ilan edilmedi. Bu nedenle beta etiketi korunur.
