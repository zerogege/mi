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
from functools import lru_cache

import geoip2.database

# ==================== 配置 ====================
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")
GEOIP_DB = "GeoLite2-Country.mmdb"
STATE_DIR = "state"

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"

# TCP 探活（已验证不漏）
TCP_CONCURRENCY = 2500
TCP_TIMEOUT = 2.0
TCP_RETRY = 1
BATCH_SIZE = 500000

# TLS 三阶段
TLS_CONCURRENCY = 300
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5

# 每次随机抽的端口数
SAMPLE_N = 2500

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


# ==================== ASN 自动拉取 ====================
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


# ==================== 状态管理 ====================
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
    """从范围随机抽 SAMPLE_N 个，排除已抽过的，抽完清空循环。"""
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
        print(f"[*] {key} 端口区间已抽完，清空记录重新循环", flush=True)
        scanned = set()
        available = list(all_range)
    chosen = random.sample(available, min(SAMPLE_N, len(available)))
    scanned.update(chosen)
    save_scanned_ports(key, scanned)
    return sorted(chosen)


def match_domain_in_cert(sni_domain, cert_str):
    sni_domain = sni_domain.lower()
    cert_str = cert_str.lower()
    if sni_domain in cert_str:
        return True
    parts = sni_domain.split(".")
    if len(parts) >= 2:
        main_domain = ".".join(parts[-2:])
        if main_domain in cert_str or f"*.{main_domain}" in cert_str:
            return True
    if "cloudflare" in sni_domain and "cloudflare" in cert_str:
        return True
    return False


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


async def check_tls_sni(ip, port, sni, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=sni)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            ssl_obj = writer.get_extra_info('ssl_object')
            if not ssl_obj:
                return False
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if not der_cert:
                return False
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def check_http(ip, port, host, timeout_val, sem):
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=host)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout_val)
            if not data:
                return False
            resp = data.decode('latin1', errors='ignore').lower()
            return ("http/1.1 301" in resp or "http/1.1 302" in resp) and ("location:" in resp)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def full_verify(ip, port, sem):
    if not await check_tls_sni(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem):
        return False
    if not await check_http(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem):
        return False
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        if not await check_tls_sni(ip, port, CUSTOM_CF_DOMAIN.strip(), STAGE3_TIMEOUT, sem):
            return False
    return True


async def main():
    asn_input = sys.argv[1] if len(sys.argv) > 1 else "8143"
    name_label = sys.argv[2] if len(sys.argv) > 2 else "RESULT"
    port_range = sys.argv[3] if len(sys.argv) > 3 else "20000-60000"

    key = _asn_key(name_label)
    asn_clean = asn_input.upper().replace("AS", "").strip()

    # 1. 自动拉取 ASN 的所有 IP
    print(f"[*] 拉取 AS{asn_clean} 的 IP 段...", flush=True)
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

    # 2. 随机抽端口（状态记忆）
    ports = pick_ports(port_range, key)
    print(f"[*] 本次随机抽取 {len(ports)} 个端口（区间 {port_range}）", flush=True)

    total = len(all_ips) * len(ports)
    print(f"[*] {len(all_ips)} IP × {len(ports)} 端口 = {total:,} 个目标", flush=True)

    with open("name.txt", "w") as f:
        f.write(name_label)

    # 3. 阶段零：分批 TCP 探活
    print(f"\n[0/3 TCP 探活] 并发={TCP_CONCURRENCY} 超时={TCP_TIMEOUT}s 重试={TCP_RETRY}...", flush=True)
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

    # 4. TLS 三阶段验证
    print(f"\n[1-3/3 TLS 验证] 验证 {len(open_ports)} 个开放端口...", flush=True)
    tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)
    v_tasks = [full_verify(ip, port, tls_sem) for ip, port in open_ports]
    v_res = await asyncio.gather(*v_tasks)
    final = [open_ports[i] for i, ok in enumerate(v_res) if ok]
    print(f"[+] 验证完成！有效: {len(final)} 个", flush=True)

    # 5. 结果追加去重
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
    for ip, port in final:
        country = get_country(ip)
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

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个", flush=True)
    if final:
        print("本次有效端口:", flush=True)
        for ip, port in sorted(final, key=lambda x: (x[0], x[1])):
            print(f"  {ip}:{port}", flush=True)
    print(f"[+] 已保存至 {output_filename}（追加去重）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
