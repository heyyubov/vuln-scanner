# Vulnerability Scanner

A simple Python-based vulnerability scanner for educational purposes.
Features:
- TCP port scanning
- HTTP security header analysis
- Basic reflected XSS detection
- Basic SQL Injection error pattern detection
- Optional directory brute-force

## Usage
```bash
python3 vuln_scanner.py --target https://example.com --ports 1-1024 --threads 50 --wordlist wordlist.txt

