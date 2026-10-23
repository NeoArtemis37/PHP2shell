<img width="2172" height="724" alt="php2shell" src="https://github.com/user-attachments/assets/2d7190f0-9b40-4375-a750-7adaeaa80b8b" />
# PHP2Shell Research — Defensive Analysis & Remediation

> A security research repository covering **CVE-2026-109618** and **CVE-2026-109619**. It documents defensive analysis, authorized lab validation, detection, and remediation. The PoC tools described below are high-impact dual-use code: use them only in a deliberately isolated lab or against assets for which you have explicit written authorization.

![Threat-intelligence dashboard illustrating attack-surface monitoring](images/attack-surface-dashboard.jpg)

*Illustrative threat-intelligence visual. This image is not evidence of a confirmed vulnerability or a verified count of exposed systems.*

## Defensive response workflow

![Defensive workflow: inventory, verify, patch, and monitor](images/defensive-workflow.svg)

## Overview

On October 21, 2026, fixes were announced for two critical vulnerabilities affecting the PHP engine. Public advisories describe potential remote code execution (RCE) and memory-disclosure risks under certain conditions. Internet exposure alone does not prove that a server is vulnerable or compromised: the installed version, package source, and configuration must be verified.

| CVE | High-level description | Reported severity |
|---|---|---|
| CVE-2026-109618 | Memory-exhaustion handling may leave request state partially initialized | Critical, CVSS 9.2 |
| CVE-2026-109619 | Internal state may persist after memory has been freed (*use-after-free*) | Critical, CVSS 9.2 |

The name **PHP2Shell** is used in several public write-ups.

## Affected versions and fixes

According to the public advisories reviewed on October 23, 2026:

| PHP branch | First fixed version |
|---|---:|
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 |

Earlier versions in these branches should be treated as potentially vulnerable until verified with the relevant vendor. PHP 8.1 and older branches are end-of-life upstream; some distributions or commercial support providers may supply backported fixes. Check your vendor's advisory before deciding whether a package is patched.

## Proof-of-concept (PoC) tools

The following tools are intended for **controlled, authorized testing only**. The script headers supplied for this project describe capabilities that can disclose source files, enumerate local-file-inclusion (LFI) paths, dump `/etc/passwd`, trigger command execution, open reverse shells, or perform broad multi-target scans. Those capabilities can compromise systems; do not point them at public hosts or third-party infrastructure.

> **Repository status:** these descriptions document the supplied script headers. Place reviewed scripts in `poc/` before using this section; the scripts are not included merely because they are documented here. Review each file and its dependencies before execution.

| Script | Stated purpose | Risk / safe handling |
|---|---|---|
| `poc/php2shell_rev.py` | Listener and PHP2Shell chain validation, including reverse-shell variants | **High risk.** Do not run the exploit chain on production or public targets. Prefer a disposable, network-isolated lab; never expose the listener to the public Internet. |
| `poc/lfi_hunt.py` | PHP behavior checks, endpoint discovery, and LFI-oriented probing | **High risk.** Probing can disclose source or local files and may create load. Restrict it to a lab application you own. |
| `poc/wild_scan.py` | Multi-target scanning and exploitation workflows, including PHP2Shell and an ERPNext authorization issue | **Very high risk.** It describes mass scanning, file disclosure, command execution, and shell functionality. Do not use it against arbitrary target lists or public ranges. |

### Safe preparation and inspection

Use a disposable VM/container network with a deliberately vulnerable test application, no production credentials, no sensitive files, and outbound networking disabled unless the lab specifically requires it. Take a snapshot first. Keep the target and test client on a private, host-only network, and record the exact lab IPs in your test notes.

From the repository root, inspect the scripts and their supported options without starting a scan or exploit:

```bash
python3 --version
python3 -m py_compile poc/php2shell_rev.py poc/lfi_hunt.py poc/wild_scan.py
python3 poc/php2shell_rev.py --help
python3 poc/lfi_hunt.py --help
python3 poc/wild_scan.py --help
```

`py_compile` checks syntax only; it does not establish that a PoC is safe or correct. Read the code before running it, and confirm the meaning of every option from the script itself. Avoid options that enable shell access, file dumping, exploitation, or multi-target operation unless a specific, documented lab exercise requires them. If a test does not need exploitation to answer the research question, use a non-invasive version check or a vendor-provided test instead.

### Lab test record

For every run, record: authorization/scope, lab topology, script commit or SHA-256, command options, UTC timestamp, target version, expected behavior, observed result, and cleanup steps. Do not commit real credentials, session cookies, public target lists, listener IPs, captured secrets, or unredacted logs. Redact IP addresses and hostnames in screenshots unless disclosure is authorized.

### Responsible use boundaries

- Test only systems you own or are explicitly authorized to assess.
- Do not use the scripts for internet-wide scanning, persistence, data extraction, or unauthorized access.
- Treat any successful command execution as a security incident; stop testing, preserve minimal evidence, and notify the system owner.
- Never describe an asset as vulnerable based on FOFA/Shodan exposure alone; validate its version and patch status using authorized methods.

## Defensive checks

Run these commands only on systems you administer or are explicitly authorized to assess.

### 1. Check the CLI version

```bash
php -v
php --ini
```

### 2. Identify PHP-FPM services

```bash
systemctl list-units --type=service --all | grep -E 'php.*fpm'
```

### 3. Identify installed binaries and packages

**Debian / Ubuntu**

```bash
dpkg -l 'php*' 2>/dev/null | grep '^ii'
apt-cache policy php8.2-fpm php8.3-fpm php8.4-fpm php8.5-fpm 2>/dev/null
```

**RHEL / Fedora / derivatives**

```bash
rpm -qa | grep -i '^php'
```

The CLI version may differ from the version used by Apache, PHP-FPM, a container, a hosting control panel, or an application that embeds PHP. Check every environment actually running in production.

## Remediation plan

1. Inventory web servers, applications, containers, control panels, and appliances that include or run PHP.
2. Prioritize internet-facing services and systems that process untrusted requests.
3. Install the fixed version provided by your operating system or vendor. Avoid mixing packages from unrelated sources without a supported migration plan.
4. Restart or reload affected services according to your organization's change procedures, then verify the version actually running.
5. If an immediate patch is not possible, temporarily reduce exposure (for example, through network isolation or access restrictions) and follow vendor guidance. Temporary mitigations do not replace patching.
6. Review web, application, and system logs for unexpected processes, unusual files, newly created accounts, and abnormal outbound connections.
7. Record the status of each asset: detected version, evidence source, patch applied, timestamp, post-update verification, and any indicators requiring investigation.

## Attack-surface data: interpret carefully

Internet asset-search engines such as FOFA and Shodan can help identify exposed services, but their results are leads—not proof of vulnerability. Banners may be missing, hidden, outdated, or inaccurate. Scan or test only assets you are authorized to assess. Do not publish third-party IP addresses, hostnames, or data without permission.

## References

- Kaspersky Securelist — [Critical RCE vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619)](https://securelist.com/tr/php2shell-critical-vulnerabilities-in-php/121596/)
- Google Cloud — [Responding to core PHP vulnerabilities](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619/)
- Canadian Centre for Cyber Security — [Alert AL26-026: Critical vulnerabilities affecting PHP](https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-affecting-php-cve-2026-109618-cve-2026-109619)
- NHS England Digital — [Critical Vulnerabilities in PHP (PHP2Shell)](https://nhsd-proxy.openprescribing.net/cyber-alerts/2026/cc-4875)

*Last reviewed: October 23, 2026. Versions and recommendations may change; consult vendor advisories before making production changes.*

## Scope and disclaimer

This repository is for defensive security research and remediation. It does not replace an official vendor advisory, an organization-specific risk assessment, or an incident-response procedure.
