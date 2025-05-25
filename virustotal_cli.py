import os
import requests
import base64
from typing import Dict, Any
from dotenv import load_dotenv
load_dotenv()

class VirusTotalClient:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.headers = {"x-apikey": self.api_key}

    def _encode_url(self, url: str) -> str:
        # Base64url encode without padding
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return encoded

    def get_url_report(self, url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"error": "API key for VirusTotal is not set"}

        encoded_url = self._encode_url(url)
        endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": f"VirusTotal API error: {e}"}
