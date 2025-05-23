import shodan
import os

class ShodanClient:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("SHODAN_API_KEY")
        self.api = shodan.Shodan(self.api_key)

    def get_host_info(self, ip_or_domain):
        try:
            host = self.api.host(ip_or_domain)
            return {
                'ip': host.get('ip_str'),
                'org': host.get('org'),
                'os': host.get('os'),
                'ports': host.get('ports'),
                'data': [item.get('data') for item in host.get('data', [])]
            }
        except shodan.APIError as e:
            return {'error': str(e)}
