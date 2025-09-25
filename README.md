# Incident Report — Flags 1 & 2 (AnyDesk) — **Sanitized for public repo**

> This README is a **sanitized** version of an incident write-up from a training lab.
> All sensitive identifiers (passwords, hostnames, IPs, usernames, and real file-system owners) have been redacted or replaced with placeholders. Use this as a learning template — do **not** paste real logs or secrets into a public repo.

---

## Executive summary

During a hands-on threat-hunting exercise I identified two artifacts showing the use of AnyDesk (remote-access tooling):

* **Flag 1 (AnyDesk ID file):** a file (e.g. `C:\Users\Public\Documents\AnyDesk_ID.txt`) was created by `powershell.exe`. This file is typically used to capture the local AnyDesk ID during automated installs.
* **Flag 2 (Unattended password):** a PowerShell script (script block captured via EventID 4104) contained a literal unattended access password and a target AnyDesk ID. The script downloaded AnyDesk, installed it, and piped the password into AnyDesk with `--with-password`.

Both findings were discovered using Elasticsearch/Kibana queries (KQL) and are supported by Sysmon and PowerShell operational logs. The examples below are intentionally generic — replace the placeholders with values appropriate to your lab/environment when you run these queries locally.

---

## Exclusion variables (why & what to exclude)

When hunting, exclude known-good binaries and lab tools that generate noise. Example exclusions (replace with the equivalents in your environment):

**Common exclusions used in queries (sanitized examples)**

* `C:\Windows\System32\calc.exe`
* `C:\Windows\System32\taskmgr.exe`
* `C:\Users\<localuser>\Desktop\SomeEditor.exe`
* `C:\lab\tools\lab-client.exe`  *(example lab tool — replace with your lab binary name)*
* `C:\Users\<localuser>\Desktop\Code.exe`
* `C:\Program Files\OneDrive\OneDriveSetup.exe`

**Why:** These produce many benign file-create/process events and can drown out the suspicious rows; excluding them helps surface the high-signal items (installer artifacts, script blocks, etc.).

---

## Elasticsearch (HTTP/DSL) — Python-friendly body examples

Below are example query bodies you can use with the Elasticsearch `_search` endpoint (via `requests` or the Elasticsearch client). These bodies include `must_not` clauses to exclude noisy, known-good paths. **Update the wildcard patterns to match your environment and mapping.**

> NOTE: these examples use wildcards for readability. If your fields are `keyword` typed (case-sensitive), switch to exact matches or use lowercase fields as appropriate.

### Flag 2 (PS1 scriptblocks mentioning "password", with exclusions)

```python
body = {
  "size": 50,
  "_source": ["@timestamp","message","file.path","file.name","powershell.file.script_block_text"],
  "query": {
    "bool": {
      "must": [
        {"wildcard": {"file.name": "*ps1*"}},
        {"query_string": {"default_field": "message", "query": "*password*"}}
      ],
      "must_not": [
        {"wildcard": {"file.path": "*\\Windows\\System32\\calc.exe"}},
        {"wildcard": {"file.path": "*\\Windows\\System32\\taskmgr.exe"}},
        {"wildcard": {"file.path": "*\\Users\\<localuser>\\Desktop\\SomeEditor.exe"}},
        {"wildcard": {"file.path": "*\\lab\\tools\\lab-client.exe"}},
        {"wildcard": {"file.path": "*\\Users\\<localuser>\\Desktop\\Code.exe"}}
      ]
    }
  },
  "sort": [{"@timestamp":{"order":"desc"}}]
}
```

### Flag 1 (AnyDesk-related files/processes, with exclusions)

```python
body = {
  "size": 50,
  "_source": ["@timestamp","file.path","file.name","process.command_line"],
  "query": {
    "bool": {
      "should": [
         {"wildcard": {"file.name": "*AnyDesk*"}},
         {"wildcard": {"file.path": "*AnyDesk*"}},
         {"query_string": {"default_field":"process.command_line", "query":"*anydesk*"}}
      ],
      "minimum_should_match": 1,
      "must_not": [
         {"wildcard": {"file.path": "*\\Program Files\\OneDrive*"}},
         {"wildcard": {"file.path": "*\\Users\\<localuser>\\Desktop\\Code.exe*"}},
         {"wildcard": {"file.path": "*\\lab\\tools\\*"}}
      ]
    }
  },
  "sort": [{"@timestamp":{"order":"desc"}}]
}
```

> Tip: tune `size` and time ranges, and adapt the exclusion list to reflect hosts/tools in your environment.

---

## Flags (short answers — sanitized)

**Flag 1**

* File (example): `C:\Users\Public\Documents\AnyDesk_ID.txt`
* Created by: `powershell.exe` (SYSTEM)
* Host: `<REDACTED-HOSTNAME>`
* Evidence timestamp: `<REDACTED-DATETIME>`

**Flag 2**

* Password (REDACTED in public repo): `<REDACTED_PASSWORD>`
* Found in: `C:\Users\Public\Documents\<script>.ps1` (PowerShell ScriptBlock event 4104)
* Evidence: script contained an assignment like `$unattendedPassword = "<REDACTED_PASSWORD>"` and used `echo $unattendedPassword | & $anydeskExe <TARGET_ID> --with-password`

> **Do not** publish the real password, hostnames, or target IDs in a public repository. Keep them in your incident artifacts store or a secured internal report.

---

## MITRE ATT&CK mapping (concise)

* **T1059.001 — PowerShell** — script execution & staging.
* **T1105 — Ingress Tool Transfer** — `Invoke-WebRequest` (download of a tool).
* **T1219 — Remote Access Tools** — AnyDesk used for remote access.
* **T1547.001 — Registry Run Keys / Startup Folder** — potential persistence (installer `--start-with-win`).
* **T1027 — Obfuscated Files or Information** — watch for encoded/obfuscated PowerShell in other cases.

---

## Detections & alert tuning (with exclusions)

1. **High severity — PowerShell scriptblocks that download AnyDesk or include `--with-password`**

```kql
winlog.event_id:4104 and powershell.file.script_block_text:/download.anydesk.com|--with-password|Invoke-WebRequest|OutFile/i
and not powershell.file.script_block_text:/lab-client|SomeEditor|calc/i
```

2. **Medium severity — File-create events for AnyDesk artifacts**

```kql
event.code:11 and file.name:*AnyDesk* and not file.path:*OneDrive* and not file.path:*lab-client*
```

3. **Low severity — AnyDesk on command line (filter common installers)**

```kql
process.command_line:*anydesk* and not process.command_line:*OneDriveSetup.exe* and not process.command_line:*lab-client*
```

---

## Triage & containment (summary — sanitized)

* Isolate affected host(s) and preserve artifacts (script(s), installer, registry keys, relevant events).
* Kill AnyDesk process and block the executable/hash via EDR; collect full evidence before removing persistence.
* Hunt across the estate using the queries above and apply the exclusions to reduce false positives.
* Rotate credentials where compromise is suspected. Reimage hosts if you cannot ensure clean removal of persistence.

---

## How to publish this repo safely

1. **Sanitize artifacts**: never upload raw logs, passwords, or internal hostnames.
2. **Use placeholders** in prose for any sensitive string (examples used above).
3. **Provide sample, synthetic data** if you want to demonstrate output.
4. **Document clearly** what has been redacted in the README so reviewers know the repo is safe to browse.

---

## Example disclaimer you can add at top of repo

> **Sanitization notice:** This repository contains only sanitized examples, queries, and small demo scripts. All real hostnames, IPs, credentials, and proprietary data have been redacted. Do not upload real incident data to this public repository.

---