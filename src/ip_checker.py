import urllib.request
import json
import socket
import struct
import os
import ipaddress

IP_CHECK_SERVICES = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://ipinfo.io/json",
    "https://icanhazip.com"
]

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

def _parse_stun(data):
    """Parses a STUN Binding Success Response -> IPv4 string, or None."""
    if len(data) < 20 or data[0] != 0x01 or data[1] != 0x01:
        return None
    msg_len = (data[2] << 8) | data[3]
    cookie = b"\x21\x12\xA4\x42"
    i = 20
    end = min(20 + msg_len, len(data))
    while i + 4 <= end:
        atype = (data[i] << 8) | data[i + 1]
        alen = (data[i + 2] << 8) | data[i + 3]
        vs = i + 4
        if vs + alen > len(data):
            break
        if atype in (0x0020, 0x0001) and alen >= 8 and data[vs + 1] == 0x01:
            if atype == 0x0020:  # XOR-MAPPED-ADDRESS: XOR with the magic cookie
                a = bytes(data[vs + 4 + k] ^ cookie[k] for k in range(4))
            else:                # plain MAPPED-ADDRESS
                a = data[vs + 4:vs + 8]
            return "%d.%d.%d.%d" % (a[0], a[1], a[2], a[3])
        i = vs + alen
        if alen % 4:
            i += 4 - (alen % 4)
    return None

def stun_public_ip(timeout=1.0):
    """Public IP via STUN — one UDP round-trip, faster than HTTP. IP or None;
    tries each server in turn (some networks block UDP/STUN, HTTP covers those)."""
    for host, port in STUN_SERVERS:
        try:
            txid = os.urandom(12)
            msg = b"\x00\x01\x00\x00" + b"\x21\x12\xA4\x42" + txid
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(msg, (host, port))
                data, _ = s.recvfrom(2048)
            finally:
                s.close()
            ip = _parse_stun(data)
            if ip:
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except ValueError:
                    pass
        except Exception:
            continue
    return None

def fetch_public_ip(timeout=2.0, mode="auto"):
    """Resolve using the selected transport. Explicit modes never cross-fallback."""
    if mode not in ("auto", "http", "stun"):
        return None, "Invalid ip_check_mode (expected auto, http, or stun)"
    if mode != "http":
        ip = stun_public_ip(timeout=min(timeout, 1.0))
        if ip:
            return ip, None
        if mode == "stun":
            return None, "Unable to detect public IP via STUN"

    for service in IP_CHECK_SERVICES:
        try:
            req = urllib.request.Request(
                service,
                headers={"User-Agent": "ClaudeGuard/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read().decode("utf-8").strip()
                if not data:
                    continue
                if data.startswith("{"):
                    res = json.loads(data)
                    ip = res.get("ip") or res.get("ip_addr")
                    if ip:
                        return ip.strip(), None
                else:
                    # Raw IP string
                    ip = data.strip().split("\n")[0]
                    # Validate IP format
                    try:
                        ipaddress.ip_address(ip)
                        return ip, None
                    except ValueError:
                        continue
        except Exception:
            continue

    return None, "Unable to detect public IP (No Internet or API timed out)"

def is_ip_allowed(current_ip, allowed_list):
    """
    Checks if current_ip matches any IP or CIDR range in allowed_list.
    """
    if not current_ip or not allowed_list:
        return False

    try:
        user_ip_obj = ipaddress.ip_address(current_ip)
    except ValueError:
        return False

    for entry in allowed_list:
        entry = entry.strip()
        if not entry:
            continue
        try:
            # Check exact IP or CIDR range
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if user_ip_obj in net:
                    return True
            else:
                allowed_obj = ipaddress.ip_address(entry)
                if user_ip_obj == allowed_obj:
                    return True
        except ValueError:
            continue

    return False

def perform_ip_check(allowed_ips, timeout=2.0, mode="auto"):
    """
    Full helper function that returns (ip, is_allowed, error_msg).
    """
    ip, err = fetch_public_ip(timeout=timeout, mode=mode)
    if err or not ip:
        return None, False, err or "No IP detected"
    
    allowed = is_ip_allowed(ip, allowed_ips)
    return ip, allowed, None
