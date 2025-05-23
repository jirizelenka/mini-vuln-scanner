from scanner import Scanner
from shodan_cli import ShodanClient
from urllib.parse import urlparse
import socket
from dotenv import load_dotenv
import os

load_dotenv()  # pouziti env pro ulozeni api key

# for an XSS attack you can try http://testphp.vulnweb.com/artists.php?artist=1. it's an Acunetix test webpage, all legal

def get_ip_from_url(url):
    try:
        domain = urlparse(url).netloc
        return socket.gethostbyname(domain)
    except Exception as e:
        print(f"[chyba při překladu domény] {e}")
        return None

if __name__ == "__main__":
    test_url = input("Zadej URL k otestování: ").strip()

    # --- Krok 1: Test XSS ---
    print("\n[+] Spouštím test XSS...")
    scanner = Scanner()
    is_vulnerable = scanner.is_vulnerable(test_url)

    if is_vulnerable:
        print("[!] URL je pravděpodobně zranitelná na XSS.")
    else:
        print("[✓] XSS zranitelnost nebyla detekována.")

    # --- Krok 2: Shodan informace ---
    print("\n[+] Načítám informace ze Shodan.io...")
    ip = get_ip_from_url(test_url)

    if ip:
        shodan_client = ShodanClient()
        result = shodan_client.get_host_info(ip)
        print("[SHODAN VÝSTUP]")
        for key, value in result.items():
            print(f"{key}: {value}")
    else:
        print("[!] Nepodařilo se získat IP adresu z URL.")