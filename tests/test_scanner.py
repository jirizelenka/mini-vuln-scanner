import unittest
from scanner import Scanner

class TestScanner(unittest.TestCase):
    def test_is_vulnerable_false(self):
        scanner = Scanner()
        url = "http://example.com/?name=John"
        result = scanner.is_vulnerable(url)
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()