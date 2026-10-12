# Bağımsız güvenlik incelemesi ve yayın kapısı

Durum: **Yapılmadı.** Bu dosya dış incelemenin yerini tutmaz. Sürüm beta kalır.

İncelemeciye tehdit modeli, format şartnamesi, bağımlılık listesi ve testler
birlikte verilmelidir. Gerçek kullanıcı sırları veya dosyaları paylaşılmamalıdır.

- [ ] HKDF alan ayrımı, parola/faktör bileşimi ve kurtarma bypass modelinin incelemesi.
- [ ] Zarf ve katalog AAD kapsamı; suite/sürüm/type/boyut sınırları.
- [ ] Secretstream çerçeveleme, FINAL, boş dosya, kısa okuma, büyük dosya.
- [ ] İşlem sınırları, CURRENT atomikliği, hata enjeksiyonu ve gerçek process kill.
- [ ] Windows DACL, dosya tanıtıcıları, kilit ve junction davranışı.
- [ ] Dosya yolları, TOCTOU sınırı, dosya çakışması ve özel dosyalar.
- [ ] Menüde timeout, hata ve iptal sonrası sır referansları.
- [ ] Yedek/geri yükleme ve eski Fernet migrasyonunun veri koruması.
- [ ] Argon2id/format kaynak tüketimi ve saldırgan kontrollü başlıklar.
- [ ] Parola değişiminin tarihsel kopyalara etkisinin kullanıcıya doğru anlatılması.
- [ ] Bağımlılık, paket tedarik zinciri, dağıtım ve yayıncı imzası.
- [ ] Temiz Windows 10/11 x64 VM üzerinde kurulum ve tüm kurtarma akışları.

Kararlı yayın için kritik/yüksek bulgular kapatılmalı, diğer bulgular gerekçesiyle
kayıt altına alınmalıdır. Yayıncı kod imzası sağlanana kadar imzalı yayın iddiası
yapılmamalıdır. Otomatik pip-audit sonucu yalnızca bilinen bağımlılık açıklarını
tarar; tasarımın güvenli olduğunu kanıtlamaz.
