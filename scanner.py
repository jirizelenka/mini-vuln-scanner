from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests
from payloads import XSS_PAYLOADS

class Scanner:
    def __init__(self, payloads=None):
        self.payloads = payloads or XSS_PAYLOADS

    def is_vulnerable(self, url):
        parsed = urlparse(url)  # parsing url
        query_params = parse_qs(parsed.query)

        vulnerable = False
        for param in query_params:
            original = query_params[param][0]
            query_params[param][0] = self.payloads
            new_query = urlencode(query_params, doseq=True) # doseq mi spravne posklada query - https://docs.python.org/3/library/urllib.parse.html
            new_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(new_url, timeout=5)
                if any(payload in response.text for payload in self.payloads):
                    print(f"[!] XSS zranitelnost nalezena na {new_url}")
                    vulnerable = True
            except requests.RequestException as e:
                print(f"[chyba] {new_url}: {e}")

            # iterace
            query_params[param][0] = original

        return vulnerable
