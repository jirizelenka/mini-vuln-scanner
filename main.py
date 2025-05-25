import os
from typing import Dict, Any
from dotenv import load_dotenv
from scanner import Scanner
from virustotal_cli import VirusTotalClient

load_dotenv()

# for an XSS attack you can try http://testphp.vulnweb.com/artists.php?artist=1. it's an Acunetix test webpage, all legal

def print_vt_report(vt_report: Dict[str, Any]) -> None:
    stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    if stats:
        print("VirusTotal test:")
        print(f"  Malicious:   {stats.get('malicious', 0)}")
        print(f"  Suspicious:  {stats.get('suspicious', 0)}")
        print(f"  Harmless:    {stats.get('harmless', 0)}")
        print(f"  Undetected:  {stats.get('undetected', 0)}")
        print(f"  Timeout:     {stats.get('timeout', 0)}")
    else:
        print("VirusTotal nic nenalezl.")

def main() -> None:
    url: str = input("Zadej URL k jednoduchému testu: ").strip()
    scanner = Scanner()
    vt_client = VirusTotalClient(api_key=os.getenv("VT_API_KEY"))

    print("[*] Kontroluji XSS ...")
    if scanner.is_vulnerable(url):
        print("[!] URL je zranitelná vůči XSS útoku!")
    else:
        print("[+] URL není zranitelná vůči XSS útoku.")

    print("[*] Načítám informace z VirusTotal...")
    try:
        vt_report = vt_client.get_url_report(url)
        print_vt_report(vt_report)
    except Exception as e:
        print(f"Chyba VirusTotal: {e}")

if __name__ == "__main__":
    main()
