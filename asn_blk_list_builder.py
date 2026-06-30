import requests
import os

# İstediğiniz ASN numaralarını bu listeye ekleyebilirsiniz.
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
    filename = f"{asn}.txt"

    print(f"[{asn}] kontrol ediliyor...")

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            # API'den gelen yeni veriyi hazırlıyoruz
            new_content = response.text.strip()

            # 1. KONTROL: Dosya zaten var mı ve içeriği yeni gelen veriyle BİREBİR aynı mı?
            if os.path.exists(filename):
                with open(filename, "r") as file:
                    old_content = file.read().strip()

                if new_content == old_content:
                    print(f" ➖ Atlandı: {filename} zaten en güncel halinde.")
                    return  # Aynıysa burada fonksiyonu durdur, diske yazma işlemi yapma.
                else:
                    action_msg = "Güncellendi"  # Dosya var ama içerik değişmiş
            else:
                action_msg = "Yeni İndirildi"  # Dosya hiç yokmuş, ilk kez iniyor

            # 2. KAYIT: Eğer buraya kadar geldiyse dosya ya yoktur ya da güncellenmiştir, yazdırıyoruz.
            with open(filename, "w") as file:
                file.write(new_content)

            # Bilgi amaçlı içindeki IP sayısını bulalım
            line_count = len([line for line in new_content.split('\n') if line])
            print(f" ✓ {action_msg}! ({line_count} prefix -> {filename})")

        else:
            print(f" ✗ [HATA] {asn} çekilemedi. (HTTP Status: {response.status_code})")

    except Exception as e:
        print(f" ✗ [HATA] {asn} sorgulanırken bağlantı hatası oluştu: {e}")


# İndirilecek dosyalar için ekranda ayraç
print("Senkronizasyon işlemi başlatılıyor...\n" + "=" * 55)

# Listede aynı ASN yanlışlıkla 2 kez yazıldıysa bile 1 kez indirmesi için set() kullanıyoruz
for asn in set(asn_list):
    download_asn_list(asn)

print("=" * 55)
print("İşlem Tamamlandı! ASN listeleri başarıyla senkronize edildi.")