import os
import flet as ft
from scanner import Scanner
from virustotal_cli import VirusTotalClient
from dotenv import load_dotenv

load_dotenv()

def main(page: ft.Page):
    page.title = "Mini Vulnerability Scanner"
    page.window_width = 600
    page.window_height = 400
    page.window_resizable = False

    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.vertical_alignment = ft.MainAxisAlignment.CENTER

    # TextField URL
    url_input = ft.TextField(label="Zadej URL k otestování:", width=500)

    # Text result
    result_text = ft.TextField(value="", width=500, height=200, multiline=True, read_only=True)

    # Button
    def on_scan_click(e):
        url = url_input.value.strip()
        if not url:
            result_text.value = "Prosím, zadej platnou URL."
            page.update()
            return

        result_text.value = "[*] Kontroluji XSS zranitelnost...\n"
        page.update()

        scanner = Scanner()
        vulnerable = scanner.is_vulnerable(url)
        if vulnerable:
            result_text.value += f"[+] URL {url} je zranitelná vůči XSS.\n"
        else:
            result_text.value += f"[+] URL není zranitelná vůči XSS.\n"

        result_text.value += "[*] Načítám informace z VirusTotal...\n"
        page.update()

        vt_api_key = os.getenv("VT_API_KEY")
        if not vt_api_key:
            result_text.value += "Chyba: API klíč pro VirusTotal není nastaven.\n"
            page.update()
            return

        vt_client = VirusTotalClient(api_key=vt_api_key)
        try:
            report = vt_client.get_url_report(url)
            malicious = report.get("malicious", 0)
            suspicious = report.get("suspicious", 0)
            undetected = report.get("undetected", 0)
            harmless = report.get("harmless", 0)
            timeout = report.get("timeout", 0)

            result_text.value += f"VirusTotal report:\n"
            result_text.value += f" - Malicious: {malicious}\n"
            result_text.value += f" - Suspicious: {suspicious}\n"
            result_text.value += f" - Undetected: {undetected}\n"
            result_text.value += f" - Harmless: {harmless}\n"
            result_text.value += f" - Timeout: {timeout}\n"

        except Exception as ex:
            result_text.value += f"Chyba VirusTotal: {ex}\n"

        page.update()

    scan_button = ft.ElevatedButton(text="Spustit test", on_click=on_scan_click)

    # Layout
    page.add(
        ft.Column(
            [
                url_input,
                scan_button,
                result_text
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=20,
        )
    )

if __name__ == "__main__":
    ft.app(target=main)
