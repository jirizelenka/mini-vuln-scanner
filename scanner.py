import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads import XSS_PAYLOAD

class Scanner:
    def __init__(self, url):
        self.url = url

    def scan(self):
        parsed = urlparse(self.url) # parsing url
        query = parse_qs(parsed.query) # creating a dictionary

        for payload in XSS_PAYLOAD:
            print(f"[-] Testuji XSS payload: {payload}")

            modified_query = {k: payload for k in query}
            new_query = urlencode(modified_query, doseq=True) # doseq mi spravne posklada query - https://docs.python.org/3/library/urllib.parse.html
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    print(f"[!] Úspěch, tento web je zranitelný! {test_url}")
                else:
                    print("[ ] Zranitelnost se nepodařila nalézt.")
            except requests.RequestException as e:
                print(f"[!] Chyba: {e}")
