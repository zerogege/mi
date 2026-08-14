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
from collections import Counter
from functools import lru_cache

import geoip2.database
import aiohttp

# ==================== 配置 ====================
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "zeroo.ccwu.cc")
GEOIP_DB = "GeoLite2-Country.mmdb"
STATE_DIR = "state"

CF_SNI_1 = "www.cloudflare.com"
CF_HOST_TEST = "crypto.cloudflare.com"

# 自建检测 API（只用于最终确认少量）
CHECK_API = "https://check.tigaa.ccwu.cc/check"
API_CONCURRENCY = 20      # 从 10 提到 20，抵消重试带来的耗时
API_TIMEOUT = 30          # 从 20 提到 30，非标端口握手慢
API_RETRY = 2             # API 异常时的重试次数
PENDING_MAX_FAIL = 5      # 待确认队列里连续异常这么多轮 → 放弃

# 阶段零：TCP 探活
TCP_CONCURRENCY = 2500
TCP_TIMEOUT = 3.0         # 2.0 偏紧：跨洲握手 200-400ms，稍排队就超
TCP_RETRY = 0             # 立刻重试无效（拥塞不会在几十毫秒内消失），预算给下面的补扫
BATCH_SIZE = 500000

# 黑洞 IP 过滤：某些 IP 前的设备对所有端口都回 SYN-ACK（tarpit/黑洞），
# TCP 层看全开但握不了 TLS，会污染 hot_ports 并让 TLS 初筛白跑
BLACKHOLE_RATIO = 0.05    # 单IP开放数 ≥ 采样量的这个比例 → 判为黑洞
BLACKHOLE_MIN = 20        # 绝对下限，防止采样量小时误伤

# 阶段零点五：二次补扫（低并发 + 长超时，专治主扫被限速漏掉的）
RESCAN_CONCURRENCY = 200
RESCAN_TIMEOUT = 6.0
RESCAN_MAX_TARGETS = 60000   # 33.3个/秒 → 上限约 30 分钟

# 三阶段
TLS_CONCURRENCY = 300
STAGE1_TIMEOUT = 3
STAGE2_TIMEOUT = 2.5
STAGE3_TIMEOUT = 2.5
TLS_RETRY = 1             # 仅在"握手未完成"时重试，"明确不符"不重试

# 每次随机抽的端口数
SAMPLE_N = 1000

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


# ============ 待确认队列：本地初筛已过、但 API 未答复的条目 ============
def _pending_file(key):
    return os.path.join(STATE_DIR, f"pending_{key}.txt")


def load_pending(key):
    """返回 {(ip, port): 连续异常次数}"""
    res = {}
    try:
        with open(_pending_file(key), encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split("|")
                try:
                    ip_s, port_s = parts[0].rsplit(":", 1)
                    ipaddress.ip_address(ip_s)
                    port = int(port_s)
                except Exception:
                    continue
                fail = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
                res[(ip_s, port)] = fail
    except FileNotFoundError:
        pass
    return res


def save_pending(key, pending):
    os.makedirs(STATE_DIR, exist_ok=True)
    fname = _pending_file(key)
    tmp = fname + ".tmp"
    rows = sorted(pending.items(),
                  key=lambda x: (ipaddress.ip_address(x[0][0]), x[0][1]))
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("# ip:port|连续API异常次数（本地初筛已通过，等待API确认）\n")
        for (ip, port), fail in rows:
            f.write(f"{ip}:{port}|{fail}\n")
    os.replace(tmp, fname)


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
                    await asyncio.sleep(0.5 + random.random())   # 退避，让拥塞消散
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
    """True=证书匹配 / False=明确不匹配 / None=握手未完成（可重试）"""
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
                return None
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if not der_cert:
                return None
            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)       # True / False
        except Exception:
            return None                                       # 超时/重置/握手失败
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def check_http(ip, port, host, timeout_val, sem):
    """True=拿到301/302 / False=拿到响应但不符 / None=没拿到响应（可重试）"""
    async with sem:
        writer = None
        try:
            conn = asyncio.open_connection(ip, port, ssl=SSL_CTX, server_hostname=host)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout_val)
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            req = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Connection: close\r\n\r\n")
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout_val)
            if not data:
                return None
            resp = data.decode('latin1', errors='ignore').lower()
            return (("http/1.1 301" in resp or "http/1.1 302" in resp)
                    and ("location:" in resp))
        except Exception:
            return None
        finally:
            if writer:
                writer.close()
                try:
                    writer.transport.abort()
                except Exception:
                    pass


async def full_verify(ip, port, sem):
    """三阶段本地初筛。只对"握手未完成"重试，"明确不符"立即放弃（省时间）"""
    custom = CUSTOM_CF_DOMAIN.strip() if CUSTOM_CF_DOMAIN else ""
    stages = (
        (check_tls_sni, CF_SNI_1,      STAGE1_TIMEOUT),
        (check_http,    CF_HOST_TEST,  STAGE2_TIMEOUT),
        (check_tls_sni, custom,        STAGE3_TIMEOUT),
    )

    for attempt in range(TLS_RETRY + 1):
        retry_needed = False
        for check, arg, tmo in stages:
            if not arg:                      # 自定义域名为空 → 跳过第三阶段
                continue
            r = await check(ip, port, arg, tmo, sem)
            if r is False:
                return False                 # 明确不符，不重试
            if r is None:
                retry_needed = True
                break                        # 握手未完成，跳出去重试
        if not retry_needed:
            return True
        if attempt < TLS_RETRY:
            await asyncio.sleep(0.5 + random.random())
    return False


async def api_verify(session, ip, port, sem):
    """API 确认。返回 ("ok", country) / ("dead", "??") / ("error", "??")

    关键：区分"API 明确说不通"和"API 自己没答上来"，后者不判死。
    """
    async with sem:
        url = f"{CHECK_API}?proxyip={urllib.parse.quote(f'{ip}:{port}')}"
        for attempt in range(API_RETRY + 1):
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)
                ) as resp:
                    if resp.status != 200:
                        if attempt < API_RETRY:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        return ("error", "??")
                    ctype = (resp.headers.get("content-type") or "").lower()
                    if "json" not in ctype:
                        # CF 错误页（1027 超额 / 1102 超限）是 text/html，不是 Worker 在应答
                        if attempt < API_RETRY:
                            await asyncio.sleep(2 * (attempt + 1))
                            continue
                        return ("error", "??")
                    data = await resp.json(content_type=None)
            except Exception:
                if attempt < API_RETRY:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                return ("error", "??")

            # 到这里说明 Worker 正常应答了，success 字段可信
            if data.get("success") is True:
                country = "??"
                for fam in ("ipv4", "ipv6"):
                    try:
                        c = data["probe_results"][fam]["exit"]["country"]
                        if c:
                            country = c
                            break
                    except Exception:
                        continue
                return ("ok", country)
            return ("dead", "??")
        return ("error", "??")


async def main():
    asn_input = sys.argv[1] if len(sys.argv) > 1 else "8143"
    name_label = sys.argv[2] if len(sys.argv) > 2 else "RESULT"
    port_range = sys.argv[3] if len(sys.argv) > 3 else "20000-60000"

    key = _asn_key(name_label)
    asn_clean = asn_input.upper().replace("AS", "").strip()

    with open("name.txt", "w") as f:
        f.write(name_label)

    # 上轮遗留的待确认条目
    pending = load_pending(key)
    if pending:
        print(f"[*] 待确认队列: {len(pending)} 条（上轮 API 异常未判定）", flush=True)

    # 1. 拉取 ASN 的 IP
    print(f"[*] 拉取目标 ASN 的 IP 段...", flush=True)
    all_ips = get_ips_from_asn(asn_clean)
    if not all_ips:
        print("[-] 未拉取到 IP，退出。", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    # BGP 公告常同时含聚合段和更具体子段（如 /22 与其中的 /24），重叠部分会重复
    ip_before = len(all_ips)
    all_ips = list(dict.fromkeys(all_ips))
    if len(all_ips) < ip_before:
        print(f"[*] IP 去重: {ip_before} → {len(all_ips)}"
              f"（ASN 前缀重叠，省掉 {ip_before - len(all_ips)} 个重复IP的探测）",
              flush=True)

    random.shuffle(all_ips)
    print(f"[+] 拉取到 {len(all_ips)} 个 IP", flush=True)

    # 2. 随机抽端口
    ports = pick_ports(port_range, key)
    print(f"[*] 本次随机抽取 {len(ports)} 个端口", flush=True)

    total = len(all_ips) * len(ports)
    print(f"[*] 共 {total:,} 个目标", flush=True)

    # 3. 阶段零：分批 TCP 探活
    print(f"\n[0/2 TCP 探活] 并发={TCP_CONCURRENCY} 超时={TCP_TIMEOUT}s "
          f"重试={TCP_RETRY}...", flush=True)
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

    print(f"[+] 探活完成！开放: {len(open_ports)} 个（过滤 {total - len(open_ports):,} 个）",
          flush=True)

    # 3.2 剔除黑洞 IP：对几乎所有端口都回 SYN-ACK 的设备（tarpit/防火墙），
    #     TCP 层看全开但握不了 TLS，会污染 hot_ports 并让 TLS 初筛白跑
    bad_ips = set()
    if open_ports:
        threshold = max(BLACKHOLE_MIN, int(len(ports) * BLACKHOLE_RATIO))
        ip_cnt = Counter(ip for ip, _ in open_ports)
        bad_ips = {ip for ip, c in ip_cnt.items() if c >= threshold}
        if bad_ips:
            op_before = len(open_ports)
            open_ports = [(ip, p) for ip, p in open_ports if ip not in bad_ips]
            print(f"[*] 剔除疑似黑洞 IP {len(bad_ips)} 个"
                  f"（单IP开放 ≥ {threshold} 个端口），"
                  f"开放数 {op_before} → {len(open_ports)}", flush=True)
            for ip in sorted(bad_ips, key=lambda x: -ip_cnt[x])[:10]:
                print(f"    x {ip} (开放 {ip_cnt[ip]} 个)", flush=True)
            if len(bad_ips) > 10:
                print(f"    ... 另有 {len(bad_ips) - 10} 个", flush=True)

    # 3.5 二次补扫：主扫高并发可能因拥塞/限速漏判，
    #     把"在别的IP上开放过"的端口在全部IP上低并发重探一遍
    hot_ports = sorted({p for _, p in open_ports})
    if hot_ports:
        known = set(open_ports)
        cand = [(ip, p) for ip in all_ips if ip not in bad_ips
                for p in hot_ports if (ip, p) not in known]
        if len(cand) > RESCAN_MAX_TARGETS:
            random.shuffle(cand)
            cand = cand[:RESCAN_MAX_TARGETS]
            print(f"[*] 补扫候选超上限，随机取 {RESCAN_MAX_TARGETS:,} 个", flush=True)

        if cand:
            print(f"\n[0.5/2 二次补扫] 热门端口 {len(hot_ports)} 种 × 全部IP，"
                  f"共 {len(cand):,} 个（并发={RESCAN_CONCURRENCY} "
                  f"超时={RESCAN_TIMEOUT}s）...", flush=True)
            rescan_sem = asyncio.Semaphore(RESCAN_CONCURRENCY)

            async def reprobe(ip, port):
                async with rescan_sem:
                    writer = None
                    try:
                        conn = asyncio.open_connection(ip, port)
                        reader, writer = await asyncio.wait_for(
                            conn, timeout=RESCAN_TIMEOUT)
                        return (ip, port)
                    except Exception:
                        return None
                    finally:
                        if writer:
                            writer.close()
                            try:
                                writer.transport.abort()
                            except Exception:
                                pass

            r_res = await asyncio.gather(*[reprobe(a, b) for a, b in cand])
            found = [r for r in r_res if r]
            open_ports.extend(found)
            print(f"[+] 补扫捞回: {len(found)} 个"
                  f"（主扫漏判率约 {len(found)/len(cand)*100:.2f}%）", flush=True)

    # 4. 三阶段初筛
    stage_passed = []
    if open_ports:
        print(f"\n[1/2 三阶段初筛] 筛选 {len(open_ports)} 个"
              f"（握手失败重试 {TLS_RETRY} 次）...", flush=True)
        tls_sem = asyncio.Semaphore(TLS_CONCURRENCY)
        v_tasks = [full_verify(ip, port, tls_sem) for ip, port in open_ports]
        v_res = await asyncio.gather(*v_tasks)
        stage_passed = [open_ports[i] for i, ok in enumerate(v_res) if ok]
        print(f"[+] 初筛通过: {len(stage_passed)} 个", flush=True)
    else:
        print("[-] 无开放端口，跳过初筛。", flush=True)

    # 5. API 确认：本轮初筛通过的 + 上轮遗留的待确认（合并去重）
    verify_set = {(ip, port) for ip, port in stage_passed}
    verify_set |= set(pending.keys())
    verify_list = sorted(verify_set, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))

    final = []
    if verify_list:
        print(f"\n[2/2 API 确认] 确认 {len(verify_list)} 个"
              f"（本轮初筛 {len(stage_passed)} + 遗留 {len(pending)}，去重后）...", flush=True)
        api_sem = asyncio.Semaphore(API_CONCURRENCY)
        async with aiohttp.ClientSession() as session:
            a_res = await asyncio.gather(
                *[api_verify(session, ip, port, api_sem) for ip, port in verify_list]
            )

        dead_n = 0
        err_now = []
        gave_up = []
        for (ip, port), (st, country) in zip(verify_list, a_res):
            k = (ip, port)
            if st == "ok":
                final.append((ip, port, country))
                pending.pop(k, None)
            elif st == "dead":
                dead_n += 1
                pending.pop(k, None)          # API 明确说不通，不再挂账
            else:
                fail = pending.get(k, 0) + 1
                if fail >= PENDING_MAX_FAIL:
                    gave_up.append(k)
                    pending.pop(k, None)
                else:
                    pending[k] = fail
                    err_now.append(k)

        print(f"[+] 通过: {len(final)} | 明确不通: {dead_n} | "
              f"API异常待下轮: {len(err_now)} | 放弃: {len(gave_up)}", flush=True)
        if err_now:
            print(f"[!] 以下条目本地初筛已通过，但 API 重试 {API_RETRY} 次仍未答复，"
                  f"已挂入待确认队列，下轮自动补验：", flush=True)
            for ip, port in err_now:
                print(f"    ? {ip}:{port} (第 {pending[(ip, port)]} 次)", flush=True)
        if gave_up:
            print(f"[!] 连续 {PENDING_MAX_FAIL} 轮 API 异常，放弃：", flush=True)
            for ip, port in gave_up:
                print(f"    x {ip}:{port}", flush=True)
    else:
        print("[-] 无需 API 确认。", flush=True)

    save_pending(key, pending)

    # 6. 读旧结果 + 合并新结果
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

    old_count = len(old_lines)

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

    # ==================== 防覆盖保护 ====================
    if old_count > 20 and len(sorted_lines) < old_count * 0.5:
        print(f"[!] 合并后结果({len(sorted_lines)})远少于原有({old_count})，"
              f"疑似读取异常，跳过写入，不覆盖！", flush=True)
        with open("count.txt", "w") as f:
            f.write("0")
        return

    # 7. 写回
    with open(output_filename, "w", encoding="utf-8", newline="\n") as f:
        for line in sorted_lines:
            f.write(line + "\n")

    with open("count.txt", "w") as f:
        f.write(str(new_count))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"本次新增: {new_count} 个 | 文件累计: {len(sorted_lines)} 个 | "
          f"待确认队列: {len(pending)} 条", flush=True)
    print(f"[+] 已保存（结果详见私库）", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
