# mini-vuln-scanner
__Simple tool for testing web endpoints (e.g. XSS, SQLi)__

### Features

- Sends HTTP requests for URLs or endpoints that you specify
- Try to inject different payloads into the parameters (e.g. XSS, SQLi)
- Parses responses and looks for "vulnerability indicators" (e.g. alert(, syntax error, etc.)
- Saves results to CSV or SQLite
- Allows unit tests of individual parts