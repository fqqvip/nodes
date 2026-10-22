#!/usr/bin/env python3
"""Fetch free-node subscriptions from public aggregators, merge, dedupe,
and write an import-ready subscription file (base64) + plain links file.

Sources (public, auto-updated by their maintainers):
- MatinGhanbari/v2ray-configs filtered VLESS list (updates ~every 15 min)
- free18/v2ray universal subscription (daily)
- zhlx2835/freefq v2 subscription

No liveness claims are made: this VM's egress intercepts TCP/TLS, so
reachability tests from here are meaningless. Freshness comes from the
aggregators' own update cadence.
"""
import base64
import re
import sys
import urllib.request

SOURCES = [
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://raw.githubusercontent.com/zhlx2835/freefq/main/v2",
]
PROTO_ORDER = {"vless": 0, "trojan": 1, "vmess": 2, "ss": 3, "hysteria2": 4, "hy2": 4}
MAX_NODES = 800


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "ignore")


def b64dec(s: str) -> str:
    s = re.sub(r"\s+", "", s)
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "ignore")
    except Exception:
        return ""


def extract_uris(raw: str) -> list:
    lines = [l for l in raw.splitlines() if not l.startswith("#")]
    body = "\n".join(lines).strip()
    decoded = b64dec(body)
    text = decoded if "://" in decoded else raw
    return re.findall(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s<>\"']+", text)


def main(out_sub: str, out_links: str) -> int:
    all_uris, ok_sources = [], 0
    for url in SOURCES:
        try:
            uris = extract_uris(fetch(url))
            print(f"{url.split('/')[3]}: {len(uris)} nodes")
            all_uris += uris
            ok_sources += 1
        except Exception as e:
            print(f"FAILED {url}: {e}", file=sys.stderr)
    if ok_sources == 0 or not all_uris:
        print("no nodes fetched; keeping old files", file=sys.stderr)
        return 1
    seen, uniq = set(), []
    for u in all_uris:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    uniq.sort(key=lambda u: PROTO_ORDER.get(u.split("://")[0], 9))
    uniq = uniq[:MAX_NODES]
    with open(out_links, "w") as f:
        f.write("\n".join(uniq))
    with open(out_sub, "w") as f:
        f.write(base64.b64encode("\n".join(uniq).encode()).decode())
    print(f"total unique nodes written: {len(uniq)}")
    return 0


if __name__ == "__main__":
    sub = sys.argv[1] if len(sys.argv) > 1 else "sub.txt"
    links = sys.argv[2] if len(sys.argv) > 2 else "links.txt"
    sys.exit(main(sub, links))
