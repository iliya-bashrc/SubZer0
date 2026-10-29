#!/usr/bin/env python3
"""Time the Briefing on a throttled "slow phone" in headless Chrome (stdlib only, no npm).

  python3 scripts/speed_check.py --site _site [--chrome google-chrome] [--budget 6]

Serves the built site locally with gzip (like GitHub Pages), opens it through the Chrome
DevTools Protocol with 1.6 Mbps / 150 ms / 4x CPU, and reports when the Briefing is on screen
and when the full index is verified. Fails only when the Briefing takes longer than --budget
seconds (median of --runs), so a noisy CI machine does not cause false alarms.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import http.server
import json
import os
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

GZ = (".json", ".html", ".js", ".css", ".svg", ".txt", ".xml", ".webmanifest")


def serve(site: Path) -> tuple[http.server.ThreadingHTTPServer, int]:
    root = site.resolve()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if not path.startswith("/SubZer0/"):
                self.send_error(404)
                return
            f = (root / path[len("/SubZer0/"):]).resolve()
            if root not in f.parents and f != root:
                self.send_error(404)
                return
            if f.is_dir():
                f = f / "index.html"
            if not f.is_file() and f.with_suffix(".html").is_file():
                f = f.with_suffix(".html")
            if not f.is_file():
                self.send_error(404)
                return
            data = f.read_bytes()
            ctype = {".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".html": "text/html",
                     ".svg": "image/svg+xml", ".woff2": "font/woff2", ".png": "image/png"}.get(f.suffix, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            if f.suffix in GZ:
                data = gzip.compress(data, 6)
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class CDP:
    """Just enough of a WebSocket client (RFC 6455) to drive one DevTools target."""

    def __init__(self, ws_url: str):
        host, rest = ws_url[len("ws://"):].split("/", 1)
        h, p = host.split(":")
        self.s = socket.create_connection((h, int(p)), timeout=60)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /{rest} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            resp += self.s.recv(4096)
        if b" 101 " not in resp.split(b"\r\n", 1)[0]:
            raise RuntimeError("websocket handshake failed: " + resp[:80].decode(errors="replace"))
        self.buf = resp.split(b"\r\n\r\n", 1)[1]
        self.n = 0

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise RuntimeError("devtools closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _frame(self) -> tuple[int, bytes]:
        b1, b2 = self._read(2)
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._read(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._read(8))[0]
        return b1 & 0x0F, self._read(ln)

    def send(self, method: str, **params):
        self.n += 1
        payload = json.dumps({"id": self.n, "method": method, "params": params}).encode()
        mask = os.urandom(4)
        head = bytes([0x81])
        ln = len(payload)
        head += bytes([0x80 | ln]) if ln < 126 else bytes([0x80 | 126]) + struct.pack(">H", ln) if ln < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", ln)
        self.s.sendall(head + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))
        want, msg = self.n, b""
        while True:
            op, data = self._frame()
            if op == 0x8:
                raise RuntimeError("devtools closed the connection")
            msg += data
            if op in (0x1, 0x0):
                try:
                    j = json.loads(msg)
                except ValueError:
                    continue  # fragmented frame, keep reading
                msg = b""
                if j.get("id") == want:
                    if "error" in j:
                        raise RuntimeError(f"{method}: {j['error']}")
                    return j.get("result", {})

    def eval(self, expr: str):
        r = self.send("Runtime.evaluate", expression=expr, returnByValue=True)
        return (r.get("result") or {}).get("value")


PROBE = ("(()=>({boot:!!document.getElementById('boot'),q:document.querySelectorAll('#p0 .queue-item').length,"
         "full:!!document.getElementById('views'),err:!!document.querySelector('#p0 .empty .chip.crit')}))()")


def one_run(chrome: str, url: str, timeout: float) -> dict:
    prof = tempfile.mkdtemp(prefix="sz-chrome-")
    port = 9300 + os.getpid() % 500
    proc = subprocess.Popen([chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
                             f"--remote-debugging-port={port}", "--remote-allow-origins=*", f"--user-data-dir={prof}",
                             "--window-size=390,844", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2))
                page = next(t for t in tabs if t.get("type") == "page")
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("chrome did not start")
        c = CDP(page["webSocketDebuggerUrl"])
        c.send("Network.enable")
        c.send("Network.setCacheDisabled", cacheDisabled=True)
        c.send("Network.emulateNetworkConditions", offline=False, latency=150,
               downloadThroughput=1.6e6 / 8, uploadThroughput=750e3 / 8)
        c.send("Emulation.setCPUThrottlingRate", rate=4)
        c.send("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=2, mobile=True)
        t0 = time.monotonic()
        c.send("Page.navigate", url=url)
        out = {"briefing": None, "full": None}
        while time.monotonic() - t0 < timeout:
            s = c.eval(PROBE) or {}
            t = time.monotonic() - t0
            if s.get("err"):
                raise RuntimeError("the page showed an integrity error")
            if out["briefing"] is None and s.get("q") and not s.get("boot"):
                out["briefing"] = round(t, 2)
            if s.get("full") and out["briefing"] is not None:
                out["full"] = round(t, 2)
                break
            time.sleep(0.05)
        return out
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(prof, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", type=Path, required=True)
    ap.add_argument("--chrome", default=shutil.which("google-chrome") or shutil.which("chromium") or "chromium")
    ap.add_argument("--budget", type=float, default=6.0, help="max seconds until the Briefing is on screen")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args(argv)
    srv, port = serve(args.site)
    try:
        runs = [one_run(args.chrome, f"http://127.0.0.1:{port}/SubZer0/", args.timeout) for _ in range(args.runs)]
    finally:
        srv.shutdown()
    br = [r["briefing"] for r in runs if r["briefing"] is not None]
    fl = [r["full"] for r in runs if r["full"] is not None]
    med_b = statistics.median(br) if br else None
    med_f = statistics.median(fl) if fl else None
    lines = ["### Slow-phone speed check", "", "1.6 Mbps · 150 ms · 4x CPU · 390×844", "",
             "| run | Briefing on screen | full index verified |", "|---|---:|---:|"]
    lines += [f"| {i + 1} | {r['briefing']} s | {r['full']} s |" for i, r in enumerate(runs)]
    lines += ["", f"median Briefing **{med_b} s** (budget {args.budget:g} s) · full index {med_f} s"]
    print("\n".join(lines))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n\n")
    if med_b is None or len(br) < len(runs):
        print("::error::the Briefing never appeared in at least one run", file=sys.stderr)
        return 1
    if med_b > args.budget:
        print(f"::error::Briefing took {med_b} s on a slow phone (budget {args.budget:g} s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
