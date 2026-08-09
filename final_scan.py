import asyncio
import ssl
import sys
import os
import re
import json
import ipaddress
import random
import socket
import urllib.request
import urllib.parse
from functools import lru_cache

import geoip2.database
import aiohttp

# ==================== 配置 ====================
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")
GEOIP_DB = "GeoLite2-Country.mmdb"
STATE_DIR = "state"

# 你自建的检测 API（用于最终验证）
CHECK_API = "https://check.tigaa.ccwu.cc/check"
API_CONCURRENCY = 10       # API 验证并发（你的CF扛得住）
API_TIMEOUT = 20

# 阶段零：TCP 探活
TCP_CONCURRENCY = 2500
TCP_TIMEOUT = 2.0
TCP_RETRY = 1
BATCH_SIZE = 500000

SAMPLE_N = 1800

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
SSL_CTX.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB)
except Exception:
    geo_reader = None


def get_country(ip):
    if geo_reader is None:
        return "??"
    try:
        return geo_reader.country(ip).country.iso_code or "??"
    except Exception:
        return "??"


@lru_cache(maxsize=32)
def get_ips_from_asn(asn_clean):
    cidrs = []
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            for p in data.get("data", {}).get("prefixes", []):
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception:
        pass
    if not cidrs:
        try:
            url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception:
            pass
    ip_list = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen >= 31:
                ip_list.extend([str(ip) for ip in net])
            else:
                ip_list.extend([str(ip) for ip in net.hosts()])
        except Exception:
            continue
    return ip_list


def _asn_key(name_label):
    return re.sub(r'[^\w.-]', '_', name_label)


def load_scanned_ports(key):
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = os.path.join(STATE_DIR, f"scanned_ports_{key}.txt")
    ports = set()
    try:
        with open(fname) as f:
            for line in f:
                s = line.strip()
                if s.isdigit():
                    ports.add(int(s))
    except FileNotFoundError:
        pass
    return ports


def save_scanned_ports(key, ports):
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = os.path.join(STATE_DIR, f"scanned_ports_{key}.txt")
    with open(fname, "w") as f:
        for p in sorted(ports):
            f.write(f"{p}\n")


def pick_ports(port_str, key):
    parts = re.split(r'[\s,]+', str(port_str).strip())
    all_range = set()
    for part in parts:
        if '-' in part:
            try:
                a, b = part.split('-')
                s, e = max(1, int(a)), min(65535, int(b))
                if s <= e:
                    all_range.update(range(s, e + 1))
            except ValueError:
                continue
        elif part.isdigit():
            all_range.add(int(part))
    if not all_range:
        all_range = set(range(20000, 60001))

    scanned = load_scanned_ports(key)
    available = list(all_range - scanned)
    if len(available) < SAMPLE_N:
        print(f"[*] 端口区间已抽完，清空记录重新循环", flush=True)
        scanned = set()
        available = list(all_range)
    chosen = random.sample(available, min(SAMPLE_N, len(available)))
    scanned.update(chosen)
    save_scanned_ports(key, scanned)
    return sorted(chosen)


async def tcp_alive(ip, port, sem):
    async with sem:
        for attempt in range(TCP_RETRY + 1):
            writer = None
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=TCP_TIMEOUT)
                return True
            except Exception:
                if attempt < TCP_RETRY:
                    continue
                return False
            finally:
                if writer:
                    writer.close()
                    try:
                        writer.transport.abort()
                    except Exception:
                        pass
        return False


async def api_verify(session, ip, port, sem):
    """用自建 API 验证，返回 (是否有效, 真实落地国家)"""
    async with sem:
        try:
            url = f"{CHECK_API}?proxyip={urllib.parse.quote(f'{ip}:{port}')}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)) as resp:
                data = await resp.json(content_type=None)
                if data.get("success") is True:
                    country = "??"
                    try:
                        country = data["probe_results"]["ipv4"]["exit"]["country"] or "??"
                    except Exception:
                        try:
                            country = data["probe_results"]["ipv6"]["exit"]["country"] or "??"
                        except Exception:
                            pass
                    return (True, country)
                return (False, "??")
        except Exception:
            return (False, "??")


async def main():
    asn_input = sys.argv[1] if len(sys.argv) > 1 else "8143"
    name_label = sys.argv[2] if len(sys.argv) > 2 else "RESULT"
    port_range = sys.argv[3] if len(sys.argv) > 3 else "20000-60000"

    key = _asn_key(name_label)
    asn_clean = asn_input.upper().replace("AS", "").strip()

    # 1. 拉取 ASN 的 IP
    print(f"[*] 拉取目标 ASN 的 IP 段...", flush=True)
    all_ips = get_ips_from_asn(asn_clean)
    if not all_ips:
        print("[-] 未拉取到 IP，退出。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        with open("name.txt", "w") as f:
            f.write(name_label)
        return
    random.shuffle(all_ips)
    print(f"[+] 拉取到 {len(all_ips)} 个 IP", flush=True)

    # 2. 随机抽端口
    ports = pick_ports(port_range, key)
    print(f"[*] 本次随机抽取 {len(ports)} 个端口", flush=True)

    total = len(all_ips) * len(ports)
    print(f"[*] 共 {total:,} 个目标", flush=True)

    with open("name.txt", "w") as f:
        f.write(name_label)

    # 3. 阶段零：分批 TCP 探活
    print(f"\n[0/2 TCP 探活] 并发={TCP_CONCURRENCY} 超时={TCP_TIMEOUT}s 重试={TCP_RETRY}...", flush=True)
    tcp_sem = asyncio.Semaphore(TCP_CONCURRENCY)

    async def probe(ip, port):
        ok = await tcp_alive(ip, port, tcp_sem)
        return (ip, port) if ok else None

    open_ports = []
    batch = []
    done = 0
    for ip in all_ips:
        for port in ports:
            batch.append((ip, port))
            if len(batch) >= BATCH_SIZE:
                tasks = [probe(a, b) for a, b in batch]
                results = await asyncio.gather(*tasks)
                open_ports.extend([r for r in results if r])
                done += len(batch)
                print(f"  [探活] {done:,}/{total:,} | 开放: {len(open_ports)}", flush=True)
                batch = []
    if batch:
        tasks = [probe(a, b) for a, b in batch]
        results = await asyncio.gather(*tasks)
        open_ports.extend([r for r in results if r])
        done += len(batch)
        print(f"  [探活] {done:,}/{total:,} | 开放: {len(open_ports)}", flush=True)

    print(f"[+] 探活完成！开放: {len(open_ports)} 个（过滤 {total - len(open_ports):,} 个）", flush=True)

    if not open_ports:
        print("[-] 无开放端口。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    # 4. API 验证（替代三阶段，更准 + 拿真实落地）
    print(f"\n[1/2 API 验证] 验证 {len(open_ports)} 个...", flush=True)
    api_sem = asyncio.Semaphore(API_CONCURRENCY)
    final = []  # [(ip, port, 真实落地国家)]
    async with aiohttp.ClientSession() as session:
        v_tasks = [api_verify(session, ip, port, api_sem) for ip, port in open_ports]
        v_res = await asyncio.gather(*v_tasks)
        for i, (ok, country) in enumerate(v_res):
            if ok:
                ip, port = open_ports[i]
                final.append((ip, port, country))
    print(f"[+] 验证完成！有效: {len(final)} 个", flush=True)

    # 5. 结果追加去重（地区用 API 真实落地）
    output_filename = f"{name_label}.txt"
    old_lines = set()
    try:
        with open(output_filename, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    old_lines.add(s)
    except FileNotFoundError:
        pass

    new_count = 0
    for ip, port, country in final:
        line = f"{ip}:{port}#{country} {name_label}"
        if line not in old_lines:
            new_count += 1
        old_lines.add(line)

    def sort_key(line):
        try:
            addr = line.split("#")[0]
            ip_part, port_part = addr.rsplit(":", 1)
            country = line.split("#")[1].split()[0] if "#" in line else "??"
            return (country, ipaddress.ip_address(ip_part), int(port_part))
        except Exception:
            return ("??", ipaddress.ip_address("0.0.0.0"), 0)

    sorted_lines = sorted(old_lines, key=sort_key)
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    with open("count.txt", "w") as f:
        f.write(str(new_count))

    # ==================== 脱敏输出（不打印具体 IP，只打数量）====================
    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个", flush=True)
    print(f"[+] 已保存（结果详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
