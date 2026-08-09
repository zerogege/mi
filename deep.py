import asyncio
import ssl
import os
import socket
import ipaddress

import geoip2.database

# ==================== 配置 ====================
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")
GEOIP_DB = "GeoLite2-Country.mmdb"

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"
STAGE1_TIMEOUT = 2
STAGE2_TIMEOUT = 1.5
STAGE3_TIMEOUT = 1.5
CONCURRENCY = 300          # 总并发（温和，别把种子IP打爆）
PORT_START = 1
PORT_END = 65535

# 种子 IP -> ASN 标签
SEEDS = {
    # Neburst
    "23.149.108.144": "Neburst",
    "152.175.214.43": "Neburst",
    "23.146.4.20": "Neburst",
    # Sharon
    "157.254.32.57": "Sharon",
    "157.254.198.27": "Sharon",
    # GOMAMI
    "64.204.66.49": "GOMAMI",
    "103.112.1.96": "GOMAMI",
    "151.244.134.232": "GOMAMI",
    "103.73.220.49": "GOMAMI",
    "103.238.130.98": "GOMAMI",
    "141.11.77.158": "GOMAMI",
    "191.101.132.166": "GOMAMI",
    "103.26.8.38": "GOMAMI",
    "178.94.14.121": "GOMAMI",
}

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


async def stage1_worker(ip, port, sem, counter, lock, total):
    ok = await check_tls_sni(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem)
    async with lock:
        counter[0] += 1
        if counter[0] % 100000 == 0:
            print(f"  [第一阶段] {counter[0]:,}/{total:,}", flush=True)
    return (ip, port) if ok else None


async def full_verify(ip, port, sem):
    """第二、三阶段完整验证"""
    if not await check_http(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem):
        return False
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        if not await check_tls_sni(ip, port, CUSTOM_CF_DOMAIN.strip(), STAGE3_TIMEOUT, sem):
            return False
    return True


async def main():
    ips = list(SEEDS.keys())
    total = len(ips) * (PORT_END - PORT_START + 1)
    print(f"[*] 深挖：{len(ips)} 个种子 IP × 全端口({PORT_START}-{PORT_END}) = {total:,} 个目标", flush=True)

    sem = asyncio.Semaphore(CONCURRENCY)
    lock = asyncio.Lock()
    counter = [0]

    # 第一阶段：全端口 TLS 探测
    print("[1/3] 第一阶段 TLS 探测...", flush=True)
    tasks = []
    for ip in ips:
        for port in range(PORT_START, PORT_END + 1):
            tasks.append(stage1_worker(ip, port, sem, counter, lock, total))
    results = await asyncio.gather(*tasks)
    pass_1 = [r for r in results if r]
    print(f"[+] 第一阶段通过: {len(pass_1)} 个", flush=True)

    if not pass_1:
        print("[!] 无通过，结束。", flush=True)
        with open("deep_result.txt", "w") as f:
            pass
        return

    # 第二、三阶段验证
    print(f"[2/3+3/3] 完整验证 {len(pass_1)} 个候选...", flush=True)
    v_tasks = [full_verify(ip, port, sem) for ip, port in pass_1]
    v_res = await asyncio.gather(*v_tasks)
    final = [pass_1[i] for i, ok in enumerate(v_res) if ok]
    print(f"[+] 最终有效: {len(final)} 个", flush=True)

    # 输出，标签用 ASN
    lines = set()
    for ip, port in final:
        country = get_country(ip)
        asn_label = SEEDS.get(ip, "DEEP")
        lines.add(f"{ip}:{port}#{country} {asn_label}")

    def sort_key(line):
        try:
            addr = line.split("#")[0]
            ip_part, port_part = addr.rsplit(":", 1)
            country = line.split("#")[1].split()[0]
            return (country, ipaddress.ip_address(ip_part), int(port_part))
        except Exception:
            return ("??", ipaddress.ip_address("0.0.0.0"), 0)

    sorted_lines = sorted(lines, key=sort_key)
    with open("deep_result.txt", "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    # 按 IP 汇总打印，方便看规律
    print("\n==================== 深挖结果（按IP）====================", flush=True)
    by_ip = {}
    for ip, port in final:
        by_ip.setdefault(ip, []).append(port)
    for ip in ips:
        ports = sorted(by_ip.get(ip, []))
        tag = SEEDS[ip]
        print(f"  {ip} [{tag}] → {ports if ports else '无'}", flush=True)

    print(f"\n[+] 共 {len(sorted_lines)} 个有效，已存 deep_result.txt", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
