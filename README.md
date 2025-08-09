# vuln-scanner

A simple vulnerability scanner for learning and portfolio purposes.

---

## Description

This tool performs:

- Port scanning on specified or common ports  
- Checks for common HTTP security headers  
- Tests for reflected XSS vulnerabilities  
- Tests for SQL injection error patterns  
- Optional directory brute-forcing using a wordlist  

---

## Requirements

- Python 3.6+  
- `requests` library

Install dependencies using:

```bash
pip install -r requirements.txt
```
## Usage
Run the scanner with the following command:
```bash
python vuln_scanner.py --target example.com --ports 80,443 --threads 40 --wordlist wordlist.txt --json report.json
```
| Argument     | Shortcut | Description                                                  | Default       |
| ------------ | -------- | ------------------------------------------------------------ | ------------- |
| `--target`   | `-t`     | Target URL or IP address to scan (required)                  | *none*        |
| `--ports`    | `-p`     | Ports or port ranges to scan (e.g., `80,443,1-1000`)         | Common ports  |
| `--threads`  | `-T`     | Number of concurrent threads                                 | 40            |
| `--wordlist` | `-w`     | Path to wordlist file for directory brute-forcing (optional) | *none*        |
| `--json`     | `-j`     | Output JSON report filename. Use `no` to skip saving         | `report.json` |

