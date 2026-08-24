import glob
import io
import os
import sys
import requests

# Windows cp1252 encoding sorununu cozer
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

# Dosyalarin kaydedilecegi klasorun adi
OUTPUT_DIR = "ASN_BLACKLIST"

# Eger klasor yoksa otomatik olarak olustur
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)
    print(f"📁 '{OUTPUT_DIR}' klasoru olusturuldu.")

# Istediginiz ASN numaralarini bu listeye ekleyebilirsiniz.
asn_list = [
    "AS206264", "AS51852", "AS4134", "AS4837", "AS43624", "AS14956", "AS41853",
    "AS210083", "AS197695", "AS214996", "AS16276", "AS14061", "AS20473", "AS9009",
    "AS60068", "AS24940", "AS63949", "AS51167", "AS13335", "AS39832", "AS45102",
    "AS36352", "AS40676", "AS3223", "AS46261", "AS57043", "AS200020", "AS62240",
    "AS49453", "AS59711", "AS202425", "AS47890", "AS35913", "AS44050", "AS50673",
    "AS60117", "AS58065", "AS132199", "AS132203", "AS209854", "AS133199", "AS34665",
    "AS399042", "AS136787", "AS199524", "AS135052", "AS132335", "AS397660",
    "AS133111", "AS132225", "AS398101", "AS213407", "AS203114", "AS207326", "AS47585", "AS206668", "AS213958", "AS48925", "AS16276", "AS9541", "AS57844", "AS200010", "AS215391", "AS203545"
]


def download_asn_list(asn):
    url = f"https://asn.ipinfo.app/api/text/list/{asn}"

    # Dosya yolunu 'ASN_BLACKLIST/ASXXXX.txt' olacak sekilde ayarladik
    filename = os.path.join(OUTPUT_DIR, f"{asn}.txt")

    print(f"[{asn}] kontrol ediliyor...")

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            new_content = response.text.strip()

            if os.path.exists(filename):
                with open(filename, "r", encoding="utf-8") as file:
                    old_content = file.read().strip()

                if new_content == old_content:
                    print(f" ➖ Atlandi: {asn}.txt zaten en guncel halinde.")
                    return
                else:
                    action_msg = "Guncellendi"
            else:
                action_msg = "Yeni Indirildi"

            with open(filename, "w", encoding="utf-8") as file:
                file.write(new_content)

            line_count = len([line for line in new_content.split("\n") if line])
            print(f" ✓ {action_msg}! ({line_count} prefix -> {filename})")

        else:
            print(f" ✗ [HATA] {asn} cekilemedi. (HTTP Status: {response.status_code})")

    except Exception as e:
        print(f" ✗ [HATA] {asn} sorgulanirken baglanti hatasi olustu: {e}")


def create_combined_lists():
    print("\n" + "=" * 55)
    print("Nihai (Kombine) Listeler Olusturuluyor...")

    all_prefixes = set()

    # Butun indirilen txt dosyalarini oku ve kumeye ekle (tekrarlari onler)
    for asn in set(asn_list):
        filepath = os.path.join(OUTPUT_DIR, f"{asn}.txt")
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        all_prefixes.add(clean_line)

    sorted_prefixes = sorted(list(all_prefixes))
    total_ips = len(sorted_prefixes)
    print(f"Toplam {total_ips} adet benzersiz IP blogu bulundu.")

    # Eski nihai dosyalari temizle (kalinti kalmamasi icin)
    for old_file in glob.glob("blk_ASN-List*.txt"):
        os.remove(old_file)

    CHUNK_SIZE = 130000

    if total_ips == 0:
        with open("blk_ASN-List.txt", "w", encoding="utf-8") as f:
            pass
        print(" ✓ IP bulunamadi, bos 'blk_ASN-List.txt' olusturuldu.")
        return

    # IP listesini 130.000'lik parcalara (chunk) bol
    chunks = [sorted_prefixes[i:i + CHUNK_SIZE] for i in range(0, total_ips, CHUNK_SIZE)]

    if len(chunks) == 1:
        # Toplam IP 130.000'den azsa tek dosya olustur
        filename = "blk_ASN-List.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(chunks[0]) + "\n")
        print(f" ✓ {total_ips} prefix -> '{filename}' dosyasina kaydedildi.")
    else:
        # Toplam IP 130.000'den fazlaysa numaralandirarak bol
        for idx, chunk in enumerate(chunks, 1):
            filename = f"blk_ASN-List_{idx}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")
            print(f" ✓ Parca {idx}: {len(chunk)} prefix -> '{filename}' dosyasina kaydedildi.")


# 1. ASAMA: Dosyalari indir veya guncelle
print("Senkronizasyon islemi baslatiliyor...\n" + "=" * 55)
for asn in set(asn_list):
    download_asn_list(asn)

# 2. ASAMA: Biten dosyalari birlestir ve bol
create_combined_lists()

print("=" * 55)
print("Islem Tamamlandi! Butun dosyalar hazir.")
