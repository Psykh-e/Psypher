# Psypher 2.0

Tamamen yerel, şifreli **konsol kasası**. Türkçe menü ve otomasyon CLI'si aynı
çekirdeği kullanır. Dosyalar kasaya kopyalanır; kaynak dosyalar değiştirilmez.

**Sürüm: 2.0.0b1 — beta.** Bağımsız güvenlik incelemesi henüz tamamlanmadı.
“Kırılamaz” veya “post-kuantum sertifikalı” iddiası yoktur. Gerçek koruma ve
sınırlar [SECURITY.md](SECURITY.md) içinde açıklanır.

## Kurulum (Windows 10/11, Python 3.12)

```powershell
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m pip install --no-deps .
.venv/Scripts/psypher.exe
```

Menüde kasa konumunu açıkça seçin. İlk kurulumda en az 12 karakterlik parola
ve kasadan ayrı bir kurtarma dosyası gerekir. Kurtarma anahtarını dosyadan
yeniden girerek doğrulayın. İsterseniz ikinci bir 32 baytlık anahtar dosyası
etkinleştirin. Güçlü ve benzersiz bir parola kullanın; uzunluk tek başına güç
garantisi değildir.

Kasaya dosya eklemek, açık kaynak kopyasını şifrelemez veya silmez. Cihazın
tamamını korumak için işletim sisteminin disk şifrelemesini ayrıca kullanın.
Kurtarma ve anahtar dosyalarını mümkünse ayrı bir cihazda, yedeklerini güvenli
bir yerde saklayın.
Windows'ta kasa ve üretilen sır dosyaları için NTFS/ReFS gibi kalıcı özel
izinleri destekleyen yerel konumlar gerekir; FAT/exFAT ve ağ hedefleri reddedilir.

## Komutlar

Örneklerde `psypher` yerine `.venv/Scripts/psypher.exe` kullanılabilir.
Parolalar terminalde gizli sorulur; argv veya ortam değişkeninde taşınmaz.

```powershell
psypher init --vault D:/Kasalar/Kisisel.psyvault --recovery-out E:/Kurtarma/kisisel.recovery
psypher add --vault D:/Kasalar/Kisisel.psyvault C:/Belgeler --dry-run
psypher add --vault D:/Kasalar/Kisisel.psyvault C:/Belgeler
psypher list --vault D:/Kasalar/Kisisel.psyvault
psypher verify --vault D:/Kasalar/Kisisel.psyvault
psypher export --vault D:/Kasalar/Kisisel.psyvault Belgeler --destination D:/Cikarilan
psypher backup --vault D:/Kasalar/Kisisel.psyvault --destination E:/Yedekler/kisisel.psybackup
psypher restore --vault E:/Yedekler/kisisel.psybackup --destination D:/Kasalar/GeriYuklenen.psyvault
psypher doctor --vault D:/Kasalar/Kisisel.psyvault
psypher passwd --vault D:/Kasalar/Kisisel.psyvault
psypher remove --vault D:/Kasalar/Kisisel.psyvault Belgeler/eskidosya.txt
```

Kaynaklar kendiliğinden taranmaz. Dosya uzantısı sınırlaması yoktur. Boş
dosyalar ve klasörler korunur. Aynı isimli kayıtları eklemek ve mevcut açık
dosyaların üzerine yazmak reddedilir. Dosya ve klasör adları Windows'a uygun
olmalıdır; symlink/junction, özel dosyalar ve yol kaçışı kabul edilmez.

### Anahtar dosyası ve kurtarma

```powershell
psypher keyfile generate --out E:/Kurtarma/kisisel.key
psypher keyfile enable --vault D:/Kasalar/Kisisel.psyvault --new-keyfile E:/Kurtarma/kisisel.key
psypher list --vault D:/Kasalar/Kisisel.psyvault --keyfile E:/Kurtarma/kisisel.key
psypher keyfile disable --vault D:/Kasalar/Kisisel.psyvault --keyfile E:/Kurtarma/kisisel.key
psypher recover --vault D:/Kasalar/Kisisel.psyvault --recovery-in E:/Kurtarma/kisisel.recovery --recovery-out E:/Kurtarma/yeni.recovery
```

Kurtarma anahtarı **tek başına** kasayı açabilir; parolayı ve anahtar dosyasını
bypass eden, kullanıcı kontrollü bağımsız erişim yetkisidir. Kaybedilirse ve
normal erişim de yoksa veri kurtarılamaz. Kurtarma yeni parola ve yeni kurtarma
anahtarı oluşturur. `recover --new-keyfile ...` ile yeni anahtar dosyası da
etkinleştirilebilir. Parola değişimi nesneleri yeniden şifrelemez; eski kasa
kopyaları veya yedekler eski bilgilerle açılabilir.

### Eski sürümden taşıma

```powershell
psypher migrate --vault D:/Kasalar/Kisisel.psyvault --legacy-key E:/Eski/psykhe.key C:/Eski/test.txt_psykhenc
```

Eski Fernet dosyaları yalnızca okunur; yeni kasada güvenli nesnelere dönüşür.
Orijinaller ve eski anahtar değiştirilmez. Fernet akış formatı olmadığı için
her eski şifreli dosya **256 MiB ile sınırlıdır**; daha büyük dosyalar açıkça
reddedilir. Eski `config.cfg` kullanılmaz. `Psypher/psypher.py` artık güvenli
yeni giriş noktasına yönlendirir; 1.x kodu Git geçmişindedir. `Psypher/test*`
dosyaları salt okunur örnek/test girdileridir, uygulama paketi içine alınmaz.

## Otomasyon ve JSON

`--json` yalnızca tek JSON sonucu üretir; ilerleme stdout'a karışmaz.
`--secrets-fd N` üzerinden **tek satır UTF-8 JSON** okunur. Windows'ta stdin
borusu için `--secrets-fd 0` kullanılır. Sırlar argv veya env içine konulmaz.
Onay isteyen işlemlerde `--yes` gerekli; eksik bilgi etkileşimsiz ortamda hata
verir. Sır kanalı bir JSON satırı veya EOF ile kapatılmalıdır.

## Eski sürüm ekran görüntüleri

Encryption:

![encryption](https://github.com/Psykh-e/Psypher/assets/66534576/7bbee344-d576-4831-8d1d-52baf957a997)

Decryption:

![decryption](https://github.com/Psykh-e/Psypher/assets/66534576/b446a501-7436-4e70-a273-e65359846160)

```python
import getpass
import json
import subprocess

secret = {"password": getpass.getpass("Kasa parolası: ")}
result = subprocess.run(
    ["psypher", "doctor", "--vault", "D:/Kasalar/Kisisel.psyvault",
     "--json", "--secrets-fd", "0"],
    input=(json.dumps(secret) + "\n").encode(),
    capture_output=True,
)
secret.clear()
print(result.stdout.decode())
```

Desteklenen sır alanları: `password`, `new_password`, `recovery_key`,
`recovery_confirmation`, `new_recovery_key`, `new_recovery_confirmation`.
Kurtarma alanları 32 rastgele baytın 64 karakterlik hex gösterimidir.
Otomasyonla `init` için üretilmiş kurtarma anahtarı ve aynı tekrar doğrulaması
gerekir; araç `--recovery-out` konumuna özel izinlerle kaydeder ve geri okur.
`recover` yeni kurtarma alanlarını ister. Sır JSON'unu loglamayın veya genel
erişimli bir dosyaya kaydetmeyin.

Çıkış kodları: `0` başarı, `2` kullanım/onay, `3` erişim/kilit, `4` bütünlük,
`5` dosya sistemi, `130` iptal. Menü beş dakika boşta kalınca kilitlenir.

## Güvenlik durumunu okumak

`doctor` erişim yöntemini, Argon2id profilini, son kurtarma doğrulamasını,
tam bütünlük kontrolünü ve doğrulanmış yedek tarihini gösterir. Tarihler UTC'dir.
Kontrol kaydından sonra katalog değiştiyse ayrıca belirtilir. Bir kayıt, o
anda gerçekleştirilen kontrolü anlatır; dosyaların sonradan bozulmadığı
anlamına gelmez. Güncel kontrol için `verify` çalıştırın. Yapay puan yoktur.

## Geliştirme ve doğrulama

```powershell
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
.venv/Scripts/python.exe -m pip install --no-deps --no-build-isolation -e .
.venv/Scripts/ruff.exe check src tests scripts
.venv/Scripts/ruff.exe format --check src tests scripts
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m pip_audit -r requirements.txt --strict
.venv/Scripts/python.exe scripts/benchmark_streaming.py --gib 10
./scripts/build_windows.ps1
```

10 GiB testi geçici dizinde gerçek dosyalar oluşturur; kaynak, şifreli nesne
ve dışarı aktarma için **en az 35 GiB boş alan** ayırın. Test sonunda temizler.
Akış bellek ölçümü, kilit açmadaki ayrı 256 MiB Argon2id maliyetinden ayrıdır.
Windows dağıtımı `dist/Psypher/Psypher.exe` ve yanındaki `_internal` klasörünü
birlikte gerektirir. Paket beta ve imzasızdır; SHA256 dosyası bir yayıncı
imzasının yerini tutmaz. Henüz gerçek temiz Windows VM doğrulaması ve bağımsız
güvenlik incelemesi yapılmış sayılmaz.

[Yol haritası](plan.md) · [Kasa formatı](docs/FORMAT.md) ·
[Tehdit modeli](docs/THREAT_MODEL.md) · [İnceleme listesi](docs/SECURITY_REVIEW.md) ·
[Doğrulama sonuçları](docs/VALIDATION.md)

Lisans: Apache-2.0. Değiştirilen 1.x giriş noktası ve yeni 2.0 kodu bu depodaki
geliştirme çalışmasının parçasıdır; özgün proje atıfları Git geçmişinde korunur.
Özgün proje: [Psykh-e/Psypher](https://github.com/Psykh-e/Psypher).
