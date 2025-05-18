from scanner import Scanner

# for an XSS attack you can try http://testphp.vulnweb.com/artists.php?artist=1. it's an Acunetix test webpage, all legal
if __name__ == "__main__":
    url = input("Vlož URL pro testování (např. https://example.com/index.php?q=test): ")
    scanner = Scanner(url)
    scanner.scan()
