"""GFW test matrix: the same tests from abroad (this server) and from inside China (the probe).

Tests
  IPv4 ICMP    ping loss and latency
  IPv4 TCP     any port; open / refused (host reachable, nothing listening) / timeout (dropped)
  IPv4 UDP     QUIC version-negotiation probes to a UDP port: every QUIC server (hysteria2, TUIC,
               HTTP/3) must answer them, so nothing has to run on the target (checks stay read-only).
               An ICMP "port unreachable" also proves UDP gets through.
  IPv6 TCP     same as IPv4 TCP, to the target's IPv6 address (Globalping when the probe has no IPv6)
  Cloudflare   a Cloudflare-proxied hostname of the target: edge reachability and colo
               (``/cdn-cgi/trace``), whether the origin answers through Cloudflare (no 52x),
               timings, and the edge's download speed from China (free plan: often routed abroad)

One Python script runs in both places (standard library only), so both views are comparable.
"""

from __future__ import annotations

import asyncio
import json
import sys

from .ssh import run

PROBE_SCRIPT = r'''
import json, os, re, socket, ssl, subprocess, time
P = json.loads(__PARAMS__)
out = {"python": True}

def ping(host, v6=False):
    cmd = ["ping", "-6" if v6 else "-4", "-n", "-c", str(P.get("pings", 6)), "-i", "0.3", "-W", "2", host]
    try:
        text = subprocess.run(cmd, capture_output=True, text=True, timeout=40).stdout
    except Exception:
        return {"ok": None, "loss": None, "avg": None}
    m = re.search(r"([\d.]+)% packet loss", text)
    a = re.search(r"= [\d.]+/([\d.]+)/", text)
    loss = float(m.group(1)) if m else None
    return {"ok": loss is not None and loss < 100, "loss": loss, "avg": float(a.group(1)) if a else None}

RANK = {"open": 3, "refused": 2, "timeout": 1, "unreachable": 0, "error": 0}

def tcp(host, port, fam):
    best = {"state": "error", "ms": None}
    for _ in range(3):
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(4)
        t = time.perf_counter()
        try:
            s.connect((host, port))
            st = "open"
        except ConnectionRefusedError:
            st = "refused"
        except (socket.timeout, TimeoutError):
            st = "timeout"
        except OSError as e:
            st = "unreachable" if e.errno in (101, 113, 99) else "error"
        finally:
            s.close()
        ms = round((time.perf_counter() - t) * 1000, 1)
        better = RANK[st] > RANK[best["state"]]
        faster = st == best["state"] and st in ("open", "refused") and ms < (best["ms"] or 1e9)
        if better or faster:
            best = {"state": st, "ms": ms if st in ("open", "refused") else None}
        if st == "open":
            break
    return best

def quic(host, port, fam, n):
    res = {"sent": 0, "replies": 0, "refused": False, "error": None}
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(0.7)
        s.connect((host, port))
    except OSError as e:
        res["error"] = str(e.errno)
        return res
    for _ in range(n):
        # QUIC long header with a reserved version (0x?a?a?a?a): servers must reply with Version Negotiation
        pkt = bytes([0xc3]) + bytes.fromhex("1a2a3a4a") + bytes([8]) + os.urandom(8) + bytes([8]) + os.urandom(8)
        pkt += os.urandom(1200 - len(pkt))
        try:
            s.send(pkt)
            res["sent"] += 1
            if s.recv(2048):
                res["replies"] += 1
        except ConnectionRefusedError:
            res["refused"] = True
        except (socket.timeout, TimeoutError):
            pass
        except OSError:
            pass
    s.close()
    return res

def cloudflare(host):
    r = {"host": host}
    try:
        t0 = time.perf_counter()
        # IPv4 first: probes rarely have IPv6, and a failing IPv6 attempt would distort the timings
        addr = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        t0 = time.perf_counter()
        raw = socket.create_connection(addr, timeout=8)
        r["connect_ms"] = round((time.perf_counter() - t0) * 1000)
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        r["tls_ms"] = round((time.perf_counter() - t0) * 1000)
        def get(path):
            req = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vps-console-gfw\r\nConnection: keep-alive\r\n\r\n"
            tls.sendall((req % (path, host)).encode())
            data, first, start = b"", None, time.perf_counter()
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                first = first or time.perf_counter()
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            m = re.search(rb"content-length:\s*(\d+)", head, re.I)
            want = int(m.group(1)) if m else 0
            while want and len(body) < min(want, 65536):
                chunk = tls.recv(4096)
                if not chunk:
                    break
                body += chunk
            status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else 0
            return status, body, round(((first or time.perf_counter()) - start) * 1000)
        st, body, ttfb = get("/cdn-cgi/trace")
        r["edge_status"] = st
        for k in ("colo", "loc", "ip"):
            m = re.search((k + r"=(\S+)").encode(), body)
            r[k] = m.group(1).decode() if m else ""
        st2, _, ttfb2 = get("/")
        r["origin_status"], r["ttfb_ms"] = st2, ttfb2
        tls.close()
    except Exception as e:
        r["error"] = type(e).__name__
    if P.get("speed"):
        try:
            t0 = time.perf_counter()
            raw = socket.create_connection(("speed.cloudflare.com", 443), timeout=8)
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname="speed.cloudflare.com")
            tls.sendall(b"GET /__down?bytes=2000000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\n"
                        b"Connection: close\r\n\r\n")
            got = 0
            tls.settimeout(15)
            while time.perf_counter() - t0 < 15:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                got += len(chunk)
            r["speed_kbps"] = round(got * 8 / 1000 / max(0.001, time.perf_counter() - t0))
        except Exception as e:
            r["speed_error"] = type(e).__name__
    return r

def has_v6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect(("2606:4700:4700::1111", 443))
        s.close()
        return True
    except OSError:
        return False

if P.get("ipv4"):
    out["icmp4"] = ping(P["ipv4"])
    out["tcp4"] = {str(p): tcp(P["ipv4"], p, socket.AF_INET) for p in P.get("tcp_ports", [])}
    out["udp4"] = {str(p): quic(P["ipv4"], p, socket.AF_INET, P.get("udp_probes", 20)) for p in P.get("udp_ports", [])}
if P.get("ipv6"):
    out["ipv6_capable"] = has_v6()
    if out["ipv6_capable"]:
        out["icmp6"] = ping(P["ipv6"], v6=True)
        out["tcp6"] = {str(p): tcp(P["ipv6"], p, socket.AF_INET6) for p in P.get("tcp_ports", [])}
if P.get("cf_host"):
    out["cf"] = cloudflare(P["cf_host"])
print("GFWJSON" + json.dumps(out))
'''


def script(params: dict) -> str:
    return PROBE_SCRIPT.replace("__PARAMS__", repr(json.dumps(params)))


def parse_output(text: str) -> dict | None:
    for line in text.splitlines():
        if line.startswith("GFWJSON"):
            try:
                return json.loads(line[7:])
            except ValueError:
                return None
    return None


async def from_here(params: dict, timeout: float = 150) -> dict | None:
    proc = await asyncio.create_subprocess_exec(sys.executable, "-I", "-", stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(script(params).encode()), timeout)
    except TimeoutError:
        proc.kill()
        return None
    return parse_output(out.decode(errors="replace"))


async def from_probe(conn, params: dict, timeout: float = 150) -> dict | None:
    res = await run(conn, "command -v python3 >/dev/null || { echo NOPYTHON; exit 0; }; python3 -I -",
                    timeout=timeout, stdin=script(params))
    if "NOPYTHON" in res.stdout:
        return {"python": False}
    return parse_output(res.stdout)


# ---------------------------------------------------------------- verdicts
def _tcp_verdict(abroad: dict, china: dict) -> dict:
    reach_abroad = {p for p, r in abroad.items() if r["state"] in ("open", "refused")}
    reach_china = {p for p, r in china.items() if r["state"] in ("open", "refused")}
    if not reach_abroad:
        return {"verdict": "down", "ports": []}
    blocked = sorted(reach_abroad - reach_china, key=int)
    if blocked and not reach_china:
        return {"verdict": "ip_blocked", "ports": blocked}
    if blocked:
        return {"verdict": "port_blocked", "ports": blocked}
    return {"verdict": "ok", "ports": []}


def _udp_verdict(abroad: dict, china: dict) -> dict:
    out = {}
    for p, a in abroad.items():
        c = china.get(p) or {}
        a_ok = a.get("replies", 0) > 0 or a.get("refused")
        if not a_ok:
            out[p] = {"verdict": "inconclusive", "loss": None}
            continue
        if c.get("refused") and not c.get("replies"):
            out[p] = {"verdict": "ok", "loss": None}
            continue
        sent = c.get("sent") or 0
        if not sent:
            out[p] = {"verdict": "inconclusive", "loss": None}
            continue
        loss_c = round(100 * (1 - c.get("replies", 0) / sent), 1)
        loss_a = round(100 * (1 - a.get("replies", 0) / max(1, a.get("sent") or 1)), 1)
        if c.get("replies", 0) == 0:
            out[p] = {"verdict": "blocked", "loss": loss_c}
        elif loss_c - loss_a >= 15:
            out[p] = {"verdict": "lossy", "loss": loss_c}
        else:
            out[p] = {"verdict": "ok", "loss": loss_c}
    return out


def _cf_verdict(cf: dict | None) -> str:
    if not cf:
        return "not_tested"
    if cf.get("error"):
        return "edge_blocked"
    if 520 <= int(cf.get("origin_status") or 0) <= 530:
        return "origin_unreachable"
    if cf.get("edge_status") == 200:
        return "ok"
    return "edge_blocked"


def matrix(abroad: dict | None, china: dict | None, gp6: dict | None = None) -> dict:
    """Rows for the result page plus advice keys."""
    a, c = abroad or {}, china or {}
    rows: list[dict] = []
    advice: list[str] = []
    if "icmp4" in a:
        ok_a, ok_c = a["icmp4"].get("ok"), c.get("icmp4", {}).get("ok")
        verdict = "down" if not ok_a else ("ok" if ok_c else ("blocked" if ok_c is False else "unknown"))
        rows.append({"test": "icmp4", "abroad": a["icmp4"], "china": c.get("icmp4"), "verdict": verdict})
    tcp4 = None
    if a.get("tcp4"):
        tcp4 = _tcp_verdict(a["tcp4"], c.get("tcp4", {})) if c.get("tcp4") is not None else {"verdict": "unknown"}
        rows.append({"test": "tcp4", "abroad": a["tcp4"], "china": c.get("tcp4"), **tcp4})
    udp = _udp_verdict(a.get("udp4", {}), c.get("udp4", {})) if a.get("udp4") else {}
    for p, v in udp.items():
        rows.append({"test": "udp4", "port": p, "abroad": a["udp4"][p], "china": c.get("udp4", {}).get(p), **v})
    tcp6 = None
    if a.get("tcp6") is not None or c.get("tcp6") is not None or gp6:
        if c.get("tcp6") is not None and a.get("tcp6"):
            tcp6 = _tcp_verdict(a["tcp6"], c["tcp6"])
            rows.append({"test": "tcp6", "abroad": a.get("tcp6"), "china": c["tcp6"], "source": "probe", **tcp6})
        elif c.get("tcp6") is not None:  # this server has no IPv6: judge from the China side alone
            ok = any(r["state"] in ("open", "refused") for r in c["tcp6"].values())
            tcp6 = {"verdict": "ok" if ok else "ip_blocked", "ports": []}
            rows.append({"test": "tcp6", "abroad": None, "china": c["tcp6"], "source": "probe", **tcp6})
        elif gp6 is not None:
            ok = gp6.get("reachable")
            tcp6 = {"verdict": "ok" if ok else ("ip_blocked" if ok is False else "unknown")}
            rows.append({"test": "tcp6", "abroad": a.get("tcp6"), "china": gp6, "source": "globalping", **tcp6})
    cf_v = None
    if "cf" in c or "cf" in a:
        cf_v = _cf_verdict(c.get("cf"))
        rows.append({"test": "cf", "abroad": a.get("cf"), "china": c.get("cf"), "verdict": cf_v})
    t4 = (tcp4 or {}).get("verdict")
    if t4 == "ip_blocked":
        if (tcp6 or {}).get("verdict") == "ok":
            advice.append("advice.use_ipv6")
        if cf_v == "ok":
            advice.append("advice.use_cf")
        if not advice:
            advice.append("advice.change_ip")
    elif t4 == "port_blocked":
        advice.append("advice.change_port")
    elif t4 == "ok":
        advice.append("advice.direct_ok")
    if any(v["verdict"] in ("lossy", "blocked") for v in udp.values()):
        advice.append("advice.udp_poor")
    if cf_v == "ok" and (c.get("cf") or {}).get("loc") and (c.get("cf") or {}).get("colo") and \
            (c["cf"].get("speed_kbps") or 0) < 20000:
        advice.append("advice.cf_slow")
    if cf_v == "origin_unreachable":
        advice.append("advice.cf_origin")
    if china is None:
        advice = ["advice.no_probe"]
    elif china.get("python") is False:
        advice = ["advice.probe_no_python"]
    return {"rows": rows, "advice": advice}
