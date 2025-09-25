#!/usr/bin/env python3
"""
es_find_flags_auth.py

Simple script that searches localhost:9200 for:
 - Flag2: .ps1 script that mentions "password" and extracts a literal password if present
 - Flag1: AnyDesk-related files (AnyDesk*)

Usage:
  python3 es_find_flags_auth.py --user elastic --pass 'YourPassword'
"""

import argparse
import json
import requests
import re
from requests.auth import HTTPBasicAuth

ES_HOST = "http://localhost:9200"
DEFAULT_SIZE = 50

def post_search(body, user, pw, verify=True):
    url = f"{ES_HOST.rstrip('/')}/_search"
    headers = {"Content-Type": "application/json"}
    try:
        resp = requests.post(url, headers=headers, data=json.dumps(body), auth=HTTPBasicAuth(user, pw), timeout=20, verify=verify)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as he:
        if resp.status_code == 401:
            print("[!] 401 Unauthorized: check username/password")
        else:
            print("[!] HTTP error:", he)
        return None
    except Exception as e:
        print("[!] Request error:", e)
        return None

def extract_password(text):
    if not text:
        return None
    # simple patterns used in workshop: variable assignment or --with-password usage
    m = re.search(r'\$[A-Za-z0-9_]*password[A-Za-z0-9_]*\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
    if m:
        return m.group(1)
    m2 = re.search(r'--with-password\s+["\']?([^"\s"\']+)', text, re.IGNORECASE)
    if m2:
        return m2.group(1)
    # fallback: any quoted token that looks like a password (6-40 chars)
    m3 = re.search(r'["\']([A-Za-z0-9@#$%^&*()_\-+={}[\]:;<>.,?/\\]{6,40})["\']', text)
    if m3:
        return m3.group(1)
    return None

def find_flag2(user, pw, verify):
    print("[*] Searching for Flag 2 (ps1 scripts mentioning 'password') ...")
    body = {
        "size": DEFAULT_SIZE,
        "_source": ["@timestamp","host.name","file.path","file.name","powershell.file.script_block_text","message","process.command_line"],
        "query": {
            "bool": {
                "must": [
                    {"wildcard": {"file.name": "*ps1*"}},
                    {"query_string": {"default_field": "message", "query": "*password*"}}
                ]
            }
        },
        "sort": [{"@timestamp":{"order":"desc"}}]
    }
    data = post_search(body, user, pw, verify=verify)
    if not data:
        return None
    hits = data.get("hits", {}).get("hits", [])
    for h in hits:
        src = h.get("_source", {}) or h.get("fields", {})
        script = None
        if isinstance(src, dict):
            script = src.get("powershell.file.script_block_text") or src.get("message")
            # sometimes fields are lists
            if isinstance(script, list):
                script = "\n".join(script)
        pwd = extract_password(script if script else "")
        if pwd:
            return {
                "password": pwd,
                "script_path": src.get("file",{}).get("path") if isinstance(src.get("file"), dict) else src.get("file.path"),
                "host": (src.get("host") or {}).get("name") if isinstance(src.get("host"), dict) else src.get("host.name")
            }
    return None

def find_flag1(user, pw, verify):
    print("[*] Searching for Flag 1 (AnyDesk-related files/processes) ...")
    body = {
        "size": DEFAULT_SIZE,
        "_source": ["@timestamp","host.name","file.path","file.name","process.command_line","process.name","message"],
        "query": {
            "bool": {
                "should": [
                    {"wildcard": {"file.name": "*AnyDesk*"}},
                    {"wildcard": {"file.path": "*AnyDesk*"}},
                    {"query_string": {"default_field":"process.command_line", "query":"*anydesk*"}}
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [{"@timestamp":{"order":"desc"}}]
    }
    data = post_search(body, user, pw, verify=verify)
    if not data:
        return None
    hits = data.get("hits", {}).get("hits", [])
    for h in hits:
        src = h.get("_source", {}) or h.get("fields", {})
        file_path = (src.get("file") or {}).get("path") if isinstance(src.get("file"), dict) else src.get("file.path")
        file_name = (src.get("file") or {}).get("name") if isinstance(src.get("file"), dict) else src.get("file.name")
        proc = (src.get("process") or {}).get("command_line") if isinstance(src.get("process"), dict) else src.get("process.command_line")
        host = (src.get("host") or {}).get("name") if isinstance(src.get("host"), dict) else src.get("host.name")
        return {"file_name": file_name, "file_path": file_path, "process_cmd": proc, "host": host}
    return None

def main():
    parser = argparse.ArgumentParser(description="Simple ES flag finder (requires ES username & password).")
    parser.add_argument("--user", required=True, help="Elasticsearch username (basic auth)")
    parser.add_argument("--pass", required=True, dest="password", help="Elasticsearch password (basic auth)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification (for self-signed dev clusters)")
    args = parser.parse_args()

    verify = not args.insecure

    f2 = find_flag2(args.user, args.password, verify)
    f1 = find_flag1(args.user, args.password, verify)

    print("\n==== Results ====")
    if f1:
        print("Flag 1 (AnyDesk):")
        print("  file_name:", f1.get("file_name"))
        print("  file_path:", f1.get("file_path"))
        print("  host:", f1.get("host"))
        print("  process_cmd (truncated):", (f1.get("process_cmd") or "")[:300])
    else:
        print("Flag 1: not found (or unauthorized)")

    if f2:
        print("\nFlag 2 (password extracted):")
        print("  password:", f2.get("password"))
        print("  script_path:", f2.get("script_path"))
        print("  host:", f2.get("host"))
    else:
        print("\nFlag 2: not found (or unauthorized)")

if __name__ == "__main__":
    main()
