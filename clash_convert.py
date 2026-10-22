#!/usr/bin/env python3
"""Convert plain share links (links.txt) into a Mihomo/Clash-Meta YAML config.

Supports vless / vmess / trojan / ss / hysteria2 share URIs. Nodes whose
transport cannot be represented safely are skipped and counted.
Output is a minimal but complete config: proxies + two groups + MATCH rule.
"""
import base64
import json
import re
import sys
from urllib.parse import parse_qs, unquote, urlparse


def b64dec(s: str) -> str:
    s = re.sub(r"\s+", "", s.strip())
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def q1(q: dict, key: str, default: str = "") -> str:
    v = q.get(key, [default])
    return v[0] if v else default


def parse_vless(uri: str):
    u = urlparse(uri)
    q = parse_qs(u.query)
    p = {"name": "", "type": "vless", "server": u.hostname, "port": u.port,
         "uuid": unquote(u.username or ""), "udp": True}
    net = q1(q, "type", "tcp")
    security = q1(q, "security")
    sni = q1(q, "sni") or q1(q, "host")
    if security == "tls":
        p["tls"] = True
        if sni:
            p["servername"] = sni
    elif security == "reality":
        p["tls"] = True
        ro = {}
        if q1(q, "pbk"):
            ro["public-key"] = q1(q, "pbk")
        if q1(q, "sid"):
            ro["short-id"] = q1(q, "sid")
        if ro:
            p["reality-opts"] = ro
        if sni:
            p["servername"] = sni
    if q1(q, "fp"):
        p["client-fingerprint"] = q1(q, "fp")
    if q1(q, "flow"):
        p["flow"] = q1(q, "flow")
    if net == "ws":
        p["network"] = "ws"
        opts = {}
        if q1(q, "path"):
            opts["path"] = unquote(q1(q, "path"))
        if q1(q, "host"):
            opts["headers"] = {"Host": q1(q, "host")}
        if opts:
            p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        if q1(q, "serviceName"):
            p["grpc-opts"] = {"grpc-service-name": q1(q, "serviceName")}
    elif net in ("tcp", ""):
        pass
    else:
        return None  # xhttp / httpupgrade / kcp etc: skip
    p["name"] = unquote(u.fragment) if u.fragment else ""
    return p


def parse_vmess(uri: str):
    j = json.loads(b64dec(uri[len("vmess://"):].split("#")[0]))
    p = {"name": j.get("ps", ""), "type": "vmess", "server": j.get("add", ""),
         "port": int(j.get("port", 0)), "uuid": j.get("id", ""),
         "alterId": int(j.get("aid", 0) or 0), "cipher": "auto", "udp": True}
    if str(j.get("tls", "")).lower() in ("tls", "true"):
        p["tls"] = True
    if j.get("sni"):
        p["servername"] = j["sni"]
    net = j.get("net", "tcp")
    if net == "ws":
        p["network"] = "ws"
        opts = {}
        if j.get("path"):
            opts["path"] = j["path"]
        if j.get("host"):
            opts["headers"] = {"Host": j["host"]}
        if opts:
            p["ws-opts"] = opts
    elif net == "grpc":
        p["network"] = "grpc"
        if j.get("path"):
            p["grpc-opts"] = {"grpc-service-name": j["path"]}
    elif net in ("tcp", ""):
        pass
    else:
        return None
    return p


def parse_trojan(uri: str):
    u = urlparse(uri)
    q = parse_qs(u.query)
    p = {"name": unquote(u.fragment) if u.fragment else "", "type": "trojan",
         "server": u.hostname, "port": u.port,
         "password": unquote(u.username or ""), "udp": True}
    if q1(q, "sni"):
        p["sni"] = q1(q, "sni")
    net = q1(q, "type", "tcp")
    if net == "ws":
        p["network"] = "ws"
        opts = {}
        if q1(q, "path"):
            opts["path"] = unquote(q1(q, "path"))
        if q1(q, "host"):
            opts["headers"] = {"Host": q1(q, "host")}
        if opts:
            p["ws-opts"] = opts
    elif net not in ("tcp", ""):
        return None
    return p


def parse_ss(uri: str):
    body = uri[len("ss://"):]
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = unquote(frag)
    if "@" in body:
        userinfo, hp = body.rsplit("@", 1)
        dec = b64dec(userinfo)
        cred = dec if ":" in dec else unquote(userinfo)
    else:
        dec = b64dec(body)
        if "@" not in dec:
            return None
        cred, hp = dec.rsplit("@", 1)
    if ":" not in cred or ":" not in hp:
        return None
    method, password = cred.split(":", 1)
    host, port = hp.rsplit(":", 1)
    return {"name": name, "type": "ss", "server": host.strip("[]"),
            "port": int(re.sub(r"\D.*$", "", port)), "cipher": method,
            "password": password, "udp": True}


def parse_hy2(uri: str):
    u = urlparse(uri)
    q = parse_qs(u.query)
    p = {"name": unquote(u.fragment) if u.fragment else "", "type": "hysteria2",
         "server": u.hostname, "port": u.port,
         "password": unquote(u.username or ""), "udp": True}
    if q1(q, "sni"):
        p["sni"] = q1(q, "sni")
    if q1(q, "insecure") in ("1", "true"):
        p["skip-cert-verify"] = True
    if q1(q, "obfs"):
        p["obfs"] = q1(q, "obfs")
        if q1(q, "obfs-password"):
            p["obfs-password"] = q1(q, "obfs-password")
    return p


PARSERS = {"vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan,
           "ss": parse_ss, "hysteria2": parse_hy2, "hy2": parse_hy2}


def yq(v) -> str:
    """YAML-safe scalar via JSON quoting."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)


def dump_map(d: dict) -> str:
    parts = []
    for k, v in d.items():
        if isinstance(v, dict):
            parts.append(f"{k}: {{{dump_map(v)}}}")
        else:
            parts.append(f"{k}: {yq(v)}")
    return ", ".join(parts)


def dump_proxy(p: dict) -> str:
    return "  - {" + dump_map(p) + "}"


def main(inp: str, outp: str) -> int:
    lines = [l.strip() for l in open(inp, encoding="utf-8", errors="ignore") if "://" in l]
    proxies, used_names, skipped = [], set(), 0
    for i, uri in enumerate(lines):
        proto = uri.split("://")[0].lower()
        fn = PARSERS.get(proto)
        if not fn:
            skipped += 1
            continue
        try:
            p = fn(uri)
        except Exception:
            p = None
        if not p or not p.get("server") or not p.get("port"):
            skipped += 1
            continue
        name = (p.get("name") or "").strip().replace("\n", " ")[:60] or f"{proto}-{i}"
        base, n = name, 2
        while name in used_names:
            name = f"{base}-{n}"
            n += 1
        used_names.add(name)
        p["name"] = name
        proxies.append(p)
    names = [p["name"] for p in proxies]
    out = []
    out.append("mixed-port: 7890")
    out.append("allow-lan: false")
    out.append("mode: rule")
    out.append("log-level: info")
    out.append("proxies:")
    out += [dump_proxy(p) for p in proxies]
    out.append("proxy-groups:")
    out.append('  - {name: "PROXY", type: select, proxies: ' +
               json.dumps(["AUTO"] + names, ensure_ascii=False) + "}")
    out.append('  - {name: "AUTO", type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, tolerance: 80, proxies: ' +
               json.dumps(names, ensure_ascii=False) + "}")
    out.append("rules:")
    out.append("  - MATCH,PROXY")
    with open(outp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"clash proxies: {len(proxies)}, skipped: {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "links.txt",
                  sys.argv[2] if len(sys.argv) > 2 else "clash.yaml"))
