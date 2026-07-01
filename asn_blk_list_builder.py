import requests
import os
import sys
import io

# Windows cp1252 encoding sorununu cozer
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Dosyalarin kaydedilecegi klasorun adi
OUTPUT_DIR = "ASN_BLACKLIST"

# Eger klasor yoksa otomatik olarak olustur
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)
    print(f"📁 '{OUTPUT_DIR}' klasoru olusturuldu.")

# Istediginiz ASN numaralarini bu listeye ekleyebilirsiniz.
asn_list = ["AS206264", "AS51852", "AS4134", "AS4837", "AS43624", "AS14956", "AS41853",
            "AS210083", "AS197695", "AS214996", "AS16276", "AS14061", "AS20473", "AS9009",
            "AS60068", "AS24940", "AS63949", "AS51167", "AS13335", "AS39832", "AS45102",
            "AS36352", "AS40676", "AS3223", "AS46261", "AS57043", "AS200020", "AS62240",
            "AS49453", "AS59711", "AS202425", "AS47890", "AS35913", "AS44050", "AS50673",
            "AS60117", "AS58065", "AS132199", "AS132203", "AS209854", "AS133199", "AS34665",
            "AS399042", "AS136787", "AS199524", "AS135052", "AS132335", "AS397660",
            "AS133111", "AS132225"]


def download_asn_list(asn):
    url = f"https://asn.ipinfo.app/api/text/list/{asn}"
    
    # Dosya yolunu 'ASN_BLACKLIST/ASXXXX.txt' olacak sekilde ayarladik
    filename = os.path.join(OUTPUT_DIR, f"{asn}.txt")

    print(f"[{asn}] kontrol ediliyor...")

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            # API'den gelen yeni veriyi hazirliyoruz
            new_content = response.text.strip()

            # 1. KONTROL: Dosya zaten var mi ve icerigi yeni gelen veriyle BIREBIR ayni mi?
            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as file:
                    old_content = file.read().strip()

                if new_content == old_content:
                    print(f" ➖ Atlandi: {asn}.txt zaten en guncel halinde.")
                    return  # Ayniysa burada fonksiyonu durdur, diske yazma islemi yapma.
                else:
                    action_msg = "Guncellendi"  # Dosya var ama icerik degismis
            else:
                action_msg = "Yeni Indirildi"  # Dosya hic yokmus, ilk kez iniyor

            # 2. KAYIT: Eger buraya kadar geldiyse dosya ya yoktur ya da guncellenmistir, yazdiriyoruz.
            with open(filename, "w", encoding="utf-8") as file:
                file.write(new_content)

            # Bilgi amacli icindeki IP sayisini bulalim
            line_count = len([line for line in new_content.split('\n') if line])
            print(f" ✓ {action_msg}! ({line_count} prefix -> {filename})")

        else:
            print(f" ✗ [HATA] {asn} cekilemedi. (HTTP Status: {response.status_code})")

    except Exception as e:
        print(f" ✗ [HATA] {asn} sorgulanirken baglanti hatasi olustu: {e}")


# Indirilecek dosyalar icin ekranda ayrac
print("Senkronizasyon islemi baslatiliyor...\n" + "=" * 55)

# Listede ayni ASN yanlislikla 2 kez yazildiysa bile 1 kez indirmesi icin set() kullaniyoruz
for asn in set(asn_list):
    download_asn_list(asn)

print("=" * 55)
print(f"Islem Tamamlandi! Butun txt dosyalari '{OUTPUT_DIR}' klasorunun icine kaydedildi.")
