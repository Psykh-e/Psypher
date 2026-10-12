# Güvenlik ve sorumlu bildirim

Psypher 2.0 **beta** durumundadır; bağımsız güvenlik incelemesi tamamlanmadı.
Testlerin geçmesi bir güvenlik sertifikası değildir. Benzersiz veya kırılamaz
bir şifreleme algoritması geliştirilmez; bakımı yapılan libsodium ve
cryptography kütüphaneleri kullanılır.

## Korunan özellikler

- Kilitli kasada dosya içeriği, isimleri, klasör yolları ve içerik özetleri şifrelidir.
- Argon2id parola tahminini maliyetli hale getirir: 256 MiB, üç geçiş; otomatik zayıflatma yok.
- İsteğe bağlı rastgele anahtar dosyası, normal erişimde parola ile birlikte gerekir.
- Katalog ve dosya akışlarında kimlik doğrulama; tam FINAL ve özet kontrolü.
- Kasa/nesne/amaç bağlamlarına ayrılmış anahtarlar; kopyalama ve parça değiştirme reddedilir.
- Kaynak dosyalara yazılmaz. Tamamlanmamış içe aktarma aktif kataloğa alınmaz.
- Yedek ve dışa aktarma doğrulanmadan nihai hedefe geçirilmez.
- Windows'ta dosya/dizinler doğrudan oluşturulurken korumalı DACL uygulanır:
  mevcut kullanıcı ve SYSTEM. POSIX'te 0600/0700 izinleri.
  Windows'ta izinleri kalıcı desteklemeyen FAT/exFAT ve ağ hedefleri reddedilir.
- İşletim sistemi kilidi aynı kasanın eşzamanlı oturumlarını engeller.

## Sınırlar ve operasyonel davranış

- Açık kaynak dosyalar kasaya eklenince hâlâ açıktır. Tam cihaz koruması değildir.
- Kasa açıkken zararlı yazılım, keylogger, yönetici veya aynı kullanıcıyla çalışan
  saldırgan sırları okuyabilir. İşletim sistemi ele geçirilmesine dayanıklılık iddiası yoktur.
- Python nesnelerinde kusursuz anahtar/parola sıfırlama, swap/dump koruması yoktur.
  Oturum kilidi referansları bırakır ve OS kilidini açar; belleği sertifikalı silmez.
- Dosya ve nesne sayısı, yaklaşık boyutlar ve işlem zamanları disk düzeninden görülebilir.
- Tüm eski kasa görüntüsünün geri konulması, güvenilir harici sayaç olmadan tespit edilmez.
- Parola/anahtar/kurtarma değişimi ana anahtarı yeniden sarar. Önceden kopyalanmış
  zarflar, yedekler ve kasa kopyaları eski bilgilerle açılabilir; anahtar iptali değildir.
- Normal işlemler eski katalog nesillerini temizler. Güncelleme sonrası zorla kapanma
  veya izin hatası eski bir nesil bırakabilir. `doctor` sayısını gösterir; bir sonraki
  başarılı değişiklik temizliği tekrar dener. Eski sırların ifşa edildiğini düşünüyorsanız
  yeni kasa oluşturup verileri taşıyın ve eski kopyaları ayrı değerlendirin.
- Silme, katalog kaydını ve erişilemeyen nesneyi kaldırır; SSD/snapshot üzerinde
  güvenli fiziksel silme garantisi yoktur. Çökme sonrası yetim şifreli nesneler kalabilir.
- Dışa aktarma açık dosya üretir. Normal hata/iptalde geçici dosya silinir; zorla
  süreç sonlandırma veya elektrik kesintisi özel izinli `.psypher-export-*` dosyası
  bırakabilir. Hedef dizini kontrol edip kaldırın; güvenli silme garantisi yoktur.
- Toplu dışa aktarma dosya başına atomiktir: iptalden önce tamamlanan dosyalar
  geçerli açık kopyalar olarak kalır. Toplu içe aktarma tek katalog işlemi olarak yapılır.
- Atomik yeniden adlandırma ve dosya flush kullanılır. Windows'ta dizin fsync API'si
  bulunmadığı için ani güç kaybında dayanıklılık depolama donanımı/OS'e bağlıdır.
  Ağ sürücüleri ve güvenilir olmayan dosya sistemleri ilk resmi destek kapsamı dışındadır.
- Windows 10/11 x64 ve Python 3.12 önceliklidir. Diğer platformlar CI/provizyonel durumdadır.
- Yeni parolalarda 12 karakter altı reddedilir; düşük entropili uzun parolalar hâlâ zayıftır.
- Katalog 8 MiB / 20.000 kayıtla, eski Fernet tokenları 256 MiB ile sınırlıdır.
- Kurtarma anahtarı ayrı bir erişim yolu olduğundan normal parola/anahtar dosyası
  gereksinimini bypass eder. Ayrı saklanmalı; uygulama veya geliştirici sunucusunda tutulmaz.

## Açık bildirim kanalı

Özel güvenlik bildirimleri için özgün proje iletişim adresi:
**psykhe.sh@proton.me**. Gerçek anahtar, parola veya hassas dosya göndermeyin.
Etkilenen sürümü, tehdit modelini, sahte verilerle yeniden üretim adımlarını ve
beklenen/gerçek davranışı paylaşın. Bu depo bir yanıt süresi veya güvenlik
incelemesi hizmeti garantisi vermez.

İnceleme kapsamı ve yayın engelleri: [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).
