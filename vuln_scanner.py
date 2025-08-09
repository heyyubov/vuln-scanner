#!/usr/bin/env python3

import argparse
import socket
import concurrent.futures
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import re
import json
import time
from pathlib import Path

# --------- CONFIG ----------
TCP_TIMEOUT = 0.7
HTTP_TIMEOUT = 8
COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,3306,5432,5900,6379,9200]
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"unclosed quotation mark after the character string",
    r"SQLSTATE\[",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"pg_query\(\)",
    r"ORA-01756", r"Oracle error"
]
XSS_DETECTION_TOKEN = "<sCaNnErToken>"

def parse_port_range(s):
    if not s:
        return COMMON_PORTS
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def scan_port(host, port, timeout=TCP_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            res = s.connect_ex((host, port))
            return port, (res == 0)
    except Exception:
        return port, False

def run_port_scan(host, ports, threads=50):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(scan_port, host, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            p, open_ = f.result()
            results[p] = open_
    return results

def fetch_url(url):
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        return r
    except Exception:
        return None

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_security_headers(resp):
    got = {}
    headers = resp.headers if resp else {}
    for h in SECURITY_HEADERS:
        got[h] = headers.get(h)
    got["Server"] = headers.get("Server")
    return got

def inject_params_and_test(url, method="GET"):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        base_query = {"test": ["1"]}
    else:
        base_query = qs

    findings = {"xss": [], "sqli": []}
    for param in base_query:
        xss_payload = XSS_DETECTION_TOKEN
        sqli_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", " OR 1=1 -- "]

        # Test XSS
        new_q = base_query.copy()
        new_q[param] = [xss_payload]
        qenc = urlencode({k: v[0] for k,v in new_q.items()})
        new_url = urlunparse(parsed._replace(query=qenc))
        try:
            r = requests.get(new_url, timeout=HTTP_TIMEOUT, allow_redirects=True)
            body = r.text if r is not None else ""
            if XSS_DETECTION_TOKEN in body:
                findings["xss"].append({
                    "param": param,
                    "url": new_url,
                    "evidence_snippet": extract_snippet(body, XSS_DETECTION_TOKEN)
                })
        except Exception:
            pass

        # Test SQLi
        for sp in sqli_payloads:
            new_q[param] = [sp]
            qenc = urlencode({k: v[0] for k,v in new_q.items()})
            new_url = urlunparse(parsed._replace(query=qenc))
            try:
                r = requests.get(new_url, timeout=HTTP_TIMEOUT, allow_redirects=True)
                body = r.text if r is not None else ""
                for pat in SQL_ERROR_PATTERNS:
                    if re.search(pat, body, re.IGNORECASE):
                        findings["sqli"].append({
                            "param": param,
                            "payload": sp,
                            "url": new_url,
                            "matched_pattern": pat
                        })
                        break
            except Exception:
                pass

    return findings

def extract_snippet(body, token, radius=40):
    i = body.find(token)
    if i == -1:
        return ""
    start = max(0, i - radius)
    end = min(len(body), i + len(token) + radius)
    return body[start:end].replace("\n"," ")

def dir_brute(target_base, wordlist_path, threads=30):
    found = []
    parsed = urlparse(target_base)
    if not parsed.scheme:
        target_base = "http://" + target_base
    if not wordlist_path or not Path(wordlist_path).exists():
        return found
    words = [w.strip() for w in open(wordlist_path, "r", encoding="utf-8", errors="ignore") if w.strip()]
    def test_word(w):
        url = target_base.rstrip("/") + "/" + w
        try:
            r = requests.get(url, timeout=4)
            if r.status_code < 400:
                return (url, r.status_code)
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(test_word, w) for w in words]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                found.append({"url": res[0], "status": res[1]})
    return found

def run_all(target, ports, threads, wordlist=None):
    report = {"target": target, "timestamp": time.time(), "port_scan": {}, "http": {}, "vulns": {}, "dir_brute": []}
    parsed = urlparse(target)
    host = parsed.hostname or target

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    report["resolved_ip"] = ip
    report["port_scan"] = run_port_scan(ip, ports, threads=threads)

    url_to_check = target
    if not parsed.scheme:
        url_to_check = "http://" + target
    r = fetch_url(url_to_check)
    if r:
        report["http"]["status_code"] = r.status_code
        report["http"]["final_url"] = r.url
        report["http"]["headers"] = dict(r.headers)
        report["http"]["sec_headers"] = check_security_headers(r)
        report["vulns"] = inject_params_and_test(r.url)
    else:
        report["http"]["error"] = "no-response"

    if wordlist:
        report["dir_brute"] = dir_brute(url_to_check, wordlist, threads=max(10, threads//2))

    return report

def main():
    ap = argparse.ArgumentParser(description="Simple vulnerability scanner for learning / portfolio")
    ap.add_argument("--target", "-t", required=True, help="Target host or URL (e.g. https://example.com or example.com)")
    ap.add_argument("--ports", "-p", default="", help="Ports or ranges, e.g. 1-1024,80,443")
    ap.add_argument("--threads", "-T", type=int, default=40, help="Thread pool size")
    ap.add_argument("--wordlist", "-w", default="", help="Optional wordlist for directory brute-force")
    ap.add_argument("--json", "-j", default="report.json", help="Output JSON report filename (or 'no' to skip)")
    args = ap.parse_args()

    ports = parse_port_range(args.ports) if args.ports else COMMON_PORTS
    print(f"[+] Starting scan of {args.target}")
    rep = run_all(args.target, ports, args.threads, wordlist=args.wordlist)

    open_ports = [p for p,o in rep["port_scan"].items() if o]
    print(f"[+] Resolved IP: {rep.get('resolved_ip')}")
    print(f"[+] Open ports: {open_ports}")
    if rep["http"].get("status_code"):
        print(f"[+] HTTP: {rep['http']['final_url']} (status {rep['http']['status_code']})")
        print("[+] Security headers (found):")
        for k,v in rep["http"]["sec_headers"].items():
            print(f"    {k}: {v}")
    if rep.get("vulns"):
        if rep["vulns"].get("xss"):
            print(f"[!] Possible reflected XSS on params: {[i['param'] for i in rep['vulns']['xss']]}")
        if rep["vulns"].get("sqli"):
            print(f"[!] Possible SQLi error patterns: {[i['param'] for i in rep['vulns']['sqli']]}")
    if args.wordlist:
        print(f"[+] Dir bruteforce found: {len(rep['dir_brute'])} entries")

    if args.json and args.json.lower() != "no":
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON report written to {args.json}")

if __name__ == "__main__":
    main()
