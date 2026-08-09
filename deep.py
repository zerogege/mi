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
# 阶段零：TCP 探活（提速版）
TCP_CONCURRENCY = 4000
TCP_TIMEOUT = 1.0
TCP_RETRY = 0
# TLS 三阶段
TLS_CONCURRENCY = 300
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5
PORT_START = 1
PORT_END = 65535
# 种子网段 -> ASN 标签
SEEDS = {
    "23.149.108.0/24": "Neburst",
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


def expand_seeds():
    """把 SEEDS 里的 /24 段或单IP 展开成 {ip: 标签}"""
    ip_tag = {}
    for item, tag in SEEDS.items():
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
                for ip in net.hosts():
                    ip_tag[str(ip)] = tag
            else:
                ipaddress.ip_address(item)
                ip_tag[item] = tag
        except Exception:
            continue
    return ip_tag


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
    """阶段零：TCP 探活（超时+重试）"""
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
    """第一+二+三阶段完整验证"""
    if not await check_tls_sni(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem):
        return False
    if not await check_http(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem):
        return False
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        if not await check_tls_sni(ip, port, CUSTOM_CF_DOMAIN.strip(), STAGE3_TIMEOUT, sem):
            return False
    return True


async def main():
    ip_tag = expand_seeds()
    ips = list(ip_tag.keys())
    total = len(ips) * (PORT_END - PORT_START + 1)
    print(f"[*] 深挖 /24 段：{len(ips)} 个 IP × 全端口({PORT_START}-{PORT_END}) = {total:,} 个目标", flush=True)

    # ==================== 阶段零：TCP 探活 ====================
    print(f"\n[0/3 阶段零 TCP 探活] 并发={TCP_CONCURRENCY} 超时={TCP_TIMEOUT}s 重试={TCP_RETRY}...", flush=True)
    tcp_sem = asyncio.Semaphore(TCP_CONCURRENCY)

    done = [0]
    lock = asyncio.Lock()

    async def probe(ip, port):
        ok = await tcp_alive(ip, port, tcp_sem)
        async with lock:
            done[0] += 1
            if done[0] % 500000 == 0:
                print(f"  [探活进度] {done[0]:,}/{total:,}", flush=True)
        return (ip, port) if ok else None

    tcp_tasks = [probe(ip, port) for ip in ips for port in range(PORT_START, PORT_END + 1)]
    tcp_results = await asyncio.gather(*tcp_tasks)
    open_ports = [r for r in tcp_results if r]
    print(f"[+] TCP 探活完成！开放端口: {len(open_ports)} 个（过滤掉 {total - len(open_ports):,} 个关闭端口）", flush=True)

    if not open_ports:
        print("[!] 无开放端口，结束。", flush=True)
        with open("deep_result.txt", "w") as f:
            pass
        return

    # ==================== TLS 三阶段验证 ====================
    print(f"\n[1-3/3 TLS 三阶段验证] 验证 {len(open_ports)} 个开放端口...", flush=True)
    tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)
    v_tasks = [full_verify(ip, port, tls_sem) for ip, port in open_ports]
    v_res = await asyncio.gather(*v_tasks)
    final = [open_ports[i] for i, ok in enumerate(v_res) if ok]
    print(f"[+] 验证完成！最终有效: {len(final)} 个", flush=True)

    # ==================== 输出（标签用 ASN）====================
    lines = set()
    for ip, port in final:
        country = get_country(ip)
        asn_label = ip_tag.get(ip, "DEEP")
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

    # ==================== 汇总打印 ====================
    print("\n==================== 深挖结果（仅列出有开放端口的IP）====================", flush=True)

    open_by_ip = {}
    for ip, port in open_ports:
        open_by_ip.setdefault(ip, []).append(port)
    valid_by_ip = {}
    for ip, port in final:
        valid_by_ip.setdefault(ip, []).append(port)

    # 只打印有开放端口的 IP（/24 段展开后 IP 很多，全打印太长）
    for ip in ips:
        opens = sorted(open_by_ip.get(ip, []))
        if not opens:
            continue
        tag = ip_tag[ip]
        valids = sorted(valid_by_ip.get(ip, []))
        print(f"  {ip} [{tag}]  开放:{opens}  可用:{valids if valids else '无'}", flush=True)

    print(f"\n[+] 共 {len(sorted_lines)} 个可用端口，已存 deep_result.txt", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
