import unittest
from unittest.mock import MagicMock
from shodan_cli import ShodanClient

class TestShodanClient(unittest.TestCase):
    def test_get_host_info_mock(self):
        client = ShodanClient(api_key="dummykey")
        mock_data = {
            'ip_str': '1.2.3.4',
            'org': 'TestOrg',
            'os': 'Linux',
            'ports': [80, 443],
            'data': [{'data': 'HTTP/1.1 200 OK'}]
        }

        # pouziti mocku, neni vhodne testovat primo api
        client.api.host = MagicMock(return_value=mock_data)

        result = client.get_host_info("1.2.3.4")
        self.assertEqual(result['ip'], '1.2.3.4')
        self.assertIn(80, result['ports'])

if __name__ == '__main__':
    unittest.main()