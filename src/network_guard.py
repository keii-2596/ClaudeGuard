import ipaddress
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HOSTS_PATH = "/etc/hosts"
BLOCK_HEADER = "# BEGIN CLAUDEGUARD BLOCKS\n"
BLOCK_FOOTER = "# END CLAUDEGUARD BLOCKS\n"

UPDATE_HEADER = "# BEGIN CLAUDEGUARD UPDATE BLOCKS\n"
UPDATE_FOOTER = "# END CLAUDEGUARD UPDATE BLOCKS\n"

# The user daemon has no root, and we no longer use sudo/sudoers. Instead it
# stages the desired /etc/hosts + pf rule under this private dir and pokes a
# trigger file; a root LaunchDaemon (com.claudeguard.helper) watches the trigger
# and applies the vetted files. See hosts_helper.c and install.sh.
CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")
PENDING_DIR = os.path.join(CONFIG_DIR, "pending")
PENDING_HOSTS = os.path.join(PENDING_DIR, "hosts.tmp")
PF_RULE_PATH = os.path.join(PENDING_DIR, "pf.rule")
REQUEST_FILE = os.path.join(PENDING_DIR, "request")

APEX_DOMAINS = [
    "claude.com",
    "claude.ai",
    "claude.usercontent.com",
    "anthropic.com",
    "anthropic.ai"
]

SUBDOMAIN_PREFIXES = [
    "", "www", "app", "api", "auth", "stats", "cdn", "assets",
    "console", "docs", "support", "feedback", "desktop-app-updates",
    "a-api", "a-cdn", "code", "status", "blog", "research", "events",
    "login", "register", "portal", "admin", "internal", "v1", "v2", "v3",
    "ws", "gateway", "proxy", "assets-proxy", "account", "settings", "billing"
]

KNOWN_RESOLVED_DOMAINS = [
    "claude.com", "www.claude.com", "console.claude.com", "docs.claude.com", "support.claude.com", "code.claude.com", "status.claude.com", "app.claude.com", "api.claude.com", "auth.claude.com",
    "claude.ai", "www.claude.ai", "app.claude.ai", "assets.claude.ai", "console.claude.ai", "a-cdn.claude.ai", "status.claude.ai", "api.claude.ai", "auth.claude.ai",
    "claude.usercontent.com", "www.claude.usercontent.com", "app.claude.usercontent.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "assets.anthropic.com", "console.anthropic.com", "docs.anthropic.com", "support.anthropic.com", "feedback.anthropic.com", "desktop-app-updates.anthropic.com", "a-api.anthropic.com", "a-cdn.anthropic.com", "status.anthropic.com", "events.anthropic.com", "portal.anthropic.com", "assets-proxy.anthropic.com", "billing.anthropic.com",
    "anthropic.ai", "www.anthropic.ai", "app.anthropic.ai", "api.anthropic.ai", "auth.anthropic.ai"
]

# External resolvers used to find the *real* server IPs. dig queries them
# directly and never consults /etc/hosts, so it still works after we've poisoned
# the hosts file with 0.0.0.0 entries.
EXTERNAL_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Anthropic's own address ranges. pf only ever blocks IPs inside these, so an
# auxiliary page hosted on a shared CDN (e.g. the status page on CloudFront, the
# trust page on Cloudflare) never drags unrelated sites down with it. Every
# account-critical domain (claude.ai, app/api/console/auth/login.*) lives here.
ANTHROPIC_NETS = [
    ipaddress.ip_network("160.79.104.0/24"),
    ipaddress.ip_network("2607:6bc0::/32"),
]

# Fallback for when external DNS is unreachable, so pf still has something to drop.
FALLBACK_IPS = ["160.79.104.10", "2607:6bc0::10"]

# Small set of domains that actually exist and share Anthropic's dedicated IPs.
# pf blocks by IP, so resolving these is enough to discover every address the
# whole domain family sits on — no need to query dozens of subdomains, most of
# which are NXDOMAIN and just slow the block down.
PF_RESOLVE_DOMAINS = [
    "claude.ai", "www.claude.ai", "app.claude.ai", "api.claude.ai", "auth.claude.ai",
    "claude.com", "www.claude.com", "app.claude.com", "api.claude.com", "console.claude.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
]

def _is_ip(text):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, text)
            return True
        except OSError:
            pass
    return False

def _in_anthropic_range(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ANTHROPIC_NETS)

def _dig(resolver, record_type, domain):
    """Returns (query_succeeded, ips). query_succeeded is False only when the
    resolver itself failed (timeout/unreachable) — an NXDOMAIN is a *successful*
    query with an empty answer, and must not trigger a pointless retry."""
    dig_bin = "/usr/bin/dig" if os.path.exists("/usr/bin/dig") else "dig"
    try:
        res = subprocess.run(
            [dig_bin, f"@{resolver}", "+short", "+time=1", "+tries=1", record_type, domain],
            capture_output=True, text=True, timeout=3
        )
    except Exception:
        return False, []
    if res.returncode != 0:
        return False, []
    ips = []
    for line in res.stdout.splitlines():
        line = line.strip()
        # +short can emit CNAME lines (trailing dot) — keep only literal IPs.
        if line and not line.endswith(".") and _is_ip(line):
            ips.append(line)
    return True, ips

def _resolve_one(domain):
    """A + AAAA for one domain. Batched dig is flaky, so it's one query each;
    per record type we stop at the first resolver that answers at all, only
    falling through to the next when a resolver is unreachable (an NXDOMAIN is a
    successful, empty answer and ends the loop)."""
    ips = set()
    for record_type in ("A", "AAAA"):
        for resolver in EXTERNAL_RESOLVERS:
            ok, found = _dig(resolver, record_type, domain)
            if ok:
                ips.update(found)
                break
    return ips

def resolve_ips(domains):
    """Resolve domains to literal IPv4+IPv6 via external DNS, bypassing the
    poisoned /etc/hosts. Domains are resolved in parallel to keep the block
    transition fast — a long resolve is a leak window before pf loads. This is
    what lets pf block the real servers even when a browser uses DoH and ignores
    the hosts file."""
    domains = list(domains)
    if not domains:
        return set()
    ips = set()
    with ThreadPoolExecutor(max_workers=min(16, len(domains))) as pool:
        for found in pool.map(_resolve_one, domains):
            ips.update(found)
    return ips

def resolve_domain_ips(domains):
    """The pf target set: Anthropic-owned IPs only (never a shared CDN), plus a
    fallback so a DNS outage can't leave pf with an empty table."""
    ips = {ip for ip in resolve_ips(domains) if _in_anthropic_range(ip)}
    ips.update(FALLBACK_IPS)
    return sorted(ips)

def generate_all_subdomains():
    domains = set(KNOWN_RESOLVED_DOMAINS)
    for apex in APEX_DOMAINS:
        domains.add(apex)
        for sub in SUBDOMAIN_PREFIXES:
            if sub:
                domains.add(f"{sub}.{apex}")
    return sorted(list(domains))

def sync_hosts_file(block_claude_domains, block_update_domains, config):
    """Block/unblock all Claude & Anthropic subdomains via /etc/hosts and pf
    (TCP + UDP QUIC)."""
    try:
        if not os.path.exists(HOSTS_PATH):
            return False, "未找到 /etc/hosts 文件"

        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()

        content = remove_section(content, BLOCK_HEADER, BLOCK_FOOTER)
        content = remove_section(content, UPDATE_HEADER, UPDATE_FOOTER)

        all_blocked = sorted(list(set(generate_all_subdomains() + config.config.get("blocked_domains", []))))

        new_blocks = ""
        if block_claude_domains:
            new_blocks += BLOCK_HEADER
            for domain in all_blocked:
                new_blocks += f"0.0.0.0\t{domain}\n"
                new_blocks += f"127.0.0.1\t{domain}\n"
                new_blocks += f"::1\t{domain}\n"
            new_blocks += BLOCK_FOOTER

        if block_update_domains:
            new_blocks += UPDATE_HEADER
            for domain in config.config.get("update_domains", []):
                new_blocks += f"0.0.0.0\t{domain}\n"
                new_blocks += f"127.0.0.1\t{domain}\n"
                new_blocks += f"::1\t{domain}\n"
            new_blocks += UPDATE_FOOTER

        final_content = content.rstrip() + "\n\n" + new_blocks if new_blocks else content.rstrip() + "\n"

        _ensure_pending()

        # pf rule blocks TCP + UDP (UDP covers HTTP/3 QUIC) to the real server
        # IPs. Using literal IPs (not domain names) is essential: pfctl would
        # otherwise resolve the names through the just-poisoned /etc/hosts and
        # build a table full of 0.0.0.0. Resolving via external DNS also means
        # the block holds even when the browser uses DoH and skips /etc/hosts.
        if block_claude_domains:
            ip_set = set(resolve_domain_ips(PF_RESOLVE_DOMAINS))
            # User-added custom domains are explicit intent — block whatever they
            # resolve to, no Anthropic-range filter.
            custom = config.config.get("blocked_domains", [])
            if custom:
                ip_set.update(resolve_ips(custom))
            table_body = " ".join(sorted(ip_set))
            pf_content = (
                f"table <claude_guard> persist {{ {table_body} }}\n"
                f"block drop out quick proto {{ tcp, udp }} to <claude_guard>\n"
            )
            with open(PF_RULE_PATH, "w", encoding="utf-8") as f:
                f.write(pf_content)
        else:
            if os.path.exists(PF_RULE_PATH):
                try:
                    os.remove(PF_RULE_PATH)
                except Exception:
                    pass

        write_hosts(final_content)

        return True, "域名拦截和防火墙规则已提交给系统网络助手"
    except Exception as e:
        return False, f"提交网络拦截设置失败：{e}"

def remove_section(text, header, footer):
    while header in text and footer in text:
        start = text.find(header)
        end = text.find(footer) + len(footer)
        text = text[:start] + text[end:]
    return text

def _ensure_pending():
    """The private staging dir the root helper reads from. 0700 + user-owned is
    what lets the helper trust its contents (it applies only files owned by the
    config dir's owner)."""
    os.makedirs(PENDING_DIR, exist_ok=True)
    try:
        os.chmod(PENDING_DIR, 0o700)
    except OSError:
        pass

def _atomic_write(path, content):
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def _apply_as_root():
    """Direct application when we already are root (installed/run as root, or
    tests). Mirrors what hosts_helper.c does."""
    subprocess.run(f"cp '{PENDING_HOSTS}' {HOSTS_PATH} && chmod 644 {HOSTS_PATH}",
                   shell=True, check=False)
    subprocess.run("/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder",
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if os.path.exists(PF_RULE_PATH):
        subprocess.run(f"/sbin/pfctl -e -f '{PF_RULE_PATH}' && /sbin/pfctl -F states",
                       shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        subprocess.run("/sbin/pfctl -d; /sbin/pfctl -F states",
                       shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

def write_hosts(content):
    """Stage the desired /etc/hosts and signal the root helper to apply it.

    No sudo, no sudoers: the LaunchDaemon com.claudeguard.helper watches the
    trigger file and runs as root. When we already are root we just apply
    directly."""
    _ensure_pending()
    _atomic_write(PENDING_HOSTS, content)

    if os.geteuid() == 0:
        _apply_as_root()
        return

    # Poke the trigger. Written in place (not renamed) so launchd's kqueue watch
    # on this exact file survives across pokes.
    with open(REQUEST_FILE, "w", encoding="utf-8") as f:
        f.write(str(time.time()))
        f.flush()
        os.fsync(f.fileno())

    # Best-effort confirm: the helper runs near-instantly, but block application
    # is security-critical, so wait (up to ~3s) until /etc/hosts reflects the
    # claude-block state we asked for.
    want_block = BLOCK_HEADER in content
    for _ in range(30):
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                if (BLOCK_HEADER in f.read()) == want_block:
                    return
        except OSError:
            pass
        time.sleep(0.1)
