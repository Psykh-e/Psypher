# Psypher 2.0 tehdit modeli

## Varlıklar ve güven sınırı

Dosya içeriği, adlar, katalog ve ana anahtar korunacak varlıklardır. Kasa
kapalıyken saldırgan şifreli klasörün tamamını okuyabilir, değiştirebilir,
kopyalayabilir veya silebilir. Parola, ayrı anahtar dosyası ve kurtarma anahtarı
elinde değildir. Kullanıcının işletim sistemi ve uygulama çalıştırma ortamı
güvenilirdir. Fiziksel cihaz hırsızlığında kaynakların/secret dosyalarının ayrı
korunması ve OS disk şifrelemesi kullanıcı sorumluluğudur.

## Eşleme

| Tehdit | Mekanizma | Kalan sınır |
|---|---|---|
| Çevrimdışı parola tahmini | Argon2id 256 MiB/3; isteğe bağlı bağımsız anahtar | Parola entropisi, faktörlerin aynı yerde çalınması |
| İçerik/ad okumak | Secretstream ve şifreli katalog | Boyut/sayı/zaman, kaynak açık dosyalar |
| Parça silme/değiştirme/sıralama | Akış doğrulaması, sıra/boyut AAD, FINAL, SHA256 | Bütün kasanın tarihsel geri alınması |
| Başlık ayarları değiştirme | Zarf AAD, katalog AAD içinde tüm başlık özeti | Hasar erişimi engelleyebilir; DoS önlenemez |
| Nesne/kasa karıştırma | Kasa/nesne kimliğine bağlı HKDF ve AAD | Geçerli bütün eski görüntü rollback |
| Çökme, disk dolması, iptal | Şifreli staging, readback, aktif nesil geçişi | Güç kaybı donanım davranışı; yetim staging |
| Kötü amaçlı yol/junction | Güvenli isim, bileşen ve fstat kontrolü | Aktif aynı kullanıcı/OS saldırganı kapsam dışı |
| Eşzamanlı yazma | OS exclusive lock | Kilide uymayan dış yazıcı erişimi engelleyebilir |
| Parola kaybı | Kullanıcıdaki ayrı 256 bit kurtarma anahtarı | Tüm erişim yolları kayıpsa kurtarma yok |
| Bozuk yedek | Tam çözme/doğrulama, yeni hedef | Bit bozulmasını onarmaz; başka sağlam yedek gerekir |

## Hedeflenmeyen iddialar

Aktif malware koruması, gizli dosyaların tamamen varlık gizlemesi, fiziksel
güvenli silme, tüm eski kopyaların iptali, güvenilir harici durum olmadan
rollback tespiti, bağımsız sertifikasyon veya post-kuantum güvenlik iddiası yoktur.
Secretstream'in rekey davranışı, diskte saklanan ana anahtar sonradan ifşa
olduğunda kalıcı dosyalar için forward secrecy vaadi olarak pazarlanmaz.
