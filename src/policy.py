"""Shared admission policy for macOS, Windows and Linux.

The score adapter uses the same proxycheck.io v2 source as stormzhang/ipcheck.
No ipcheck local-account diagnostics or source code are imported.
"""
import contextlib
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from src.ip_checker import fetch_public_ip, is_ip_allowed

DEFAULTS = {"access_mode": "whitelist", "risk_threshold": 50,
            "risk_cache_ttl": 21600, "detect_ip_change": False, "check_interval": 3}


def settings(data):
    result = {**DEFAULTS, **data}
    if result['access_mode'] not in ('whitelist', 'risk'):
        raise ValueError('访问规则只能为 whitelist 或 risk')
    for field, low, high in [('risk_threshold', 0, 100), ('risk_cache_ttl', 1, 604800), ('check_interval', 1, 60)]:
        value = result[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
            raise ValueError(f'{field} 须在 {low}～{high} 之间')
    if type(result['detect_ip_change']) is not bool:
        raise ValueError('detect_ip_change 必须是 true 或 false')
    mode = result.get('ip_check_mode', 'both')
    result['ip_check_mode'] = 'both' if mode == 'auto' else mode
    if result['ip_check_mode'] not in ('http', 'stun', 'both'):
        raise ValueError('检测方式只能为 http、stun 或 both')
    return result


def advanced(data):
    return data.get('access_mode', 'whitelist') != 'whitelist' or data.get('detect_ip_change', False) is not False


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=path.name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2, allow_nan=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


@contextlib.contextmanager
def locked(path, timeout=20):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, 'a+b')
    try:
        f.seek(0, 2)
        if f.tell() == 0:
            f.write(b'0')
            f.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == 'nt':
                    import msvcrt
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('策略状态正被占用，请稍后重试')
                time.sleep(0.05)
        yield
    finally:
        f.close()


def fetch_score(ip, proxy=None):
    """Strict v2 response validation; failures never become a zero score."""
    ip = str(ipaddress.ip_address(ip))
    params = {'risk': '1', 'vpn': '1'}
    key = os.environ.get('CLAUDEGUARD_PROXYCHECK_API_KEY')
    if key:
        params['key'] = key
    url = 'https://proxycheck.io/v2/' + urllib.parse.quote(ip, safe='') + '?' + urllib.parse.urlencode(params)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy})) if proxy else None
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'ClaudeGuard/1.0'})
        with (opener.open(request, timeout=6) if opener else urllib.request.urlopen(request, timeout=6)) as response:
            payload = json.loads(response.read(1048576))
        if payload.get('status') not in ('ok', 'warning'):
            raise ValueError('provider rejected request')
        raw = payload.get(ip, {}).get('risk')
        if isinstance(raw, bool) or raw is None:
            raise ValueError('no score')
        score = float(raw)
        if not math.isfinite(score) or not 0 <= score <= 100:
            raise ValueError('invalid score')
        return score
    except Exception:
        # Do not expose an API key embedded in a failed request URL.
        raise RuntimeError('风险评分暂不可用，请检查网络、查询额度或 API Key') from None


def detect(data):
    mode = data['ip_check_mode']
    modes = ('http', 'stun') if mode == 'both' else (mode,)
    with ThreadPoolExecutor(max_workers=len(modes)) as pool:
        futures = {m: pool.submit(fetch_public_ip, mode=m, proxy=data.get('http_proxy') or None) for m in modes}
        return {m: ip for m, future in futures.items() if (ip := future.result()[0]) is not None}


def _load(path):
    if not path.exists():
        return {'baseline': {}, 'jump_latched': False, 'scores': {}}
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or not isinstance(value.get('baseline'), dict) or type(value.get('jump_latched')) is not bool or not isinstance(value.get('scores'), dict):
        raise ValueError('策略状态文件损坏，请检查文件后再恢复防护')
    return value


def evaluate(data, ips, directory, acknowledge=False, expected_ips=None, now=None, score_lookup=None):
    """One cross-process transaction: jump latch, cached scores, then admission.

    Acknowledgement can reset a jump latch only after fresh, complete detection
    matches the explicitly reviewed exits. Access rules still decide admission separately.
    """
    try:
        data = settings(data)
        if not data.get('protection_enabled', True):
            return {'state': 'disabled', 'ip': None, 'detected_ips': {}, 'reason': '防护已关闭', 'scores': {}, 'error': None}
        modes = ('http', 'stun') if data['ip_check_mode'] == 'both' else (data['ip_check_mode'],)
        ips = {m: str(ipaddress.ip_address(ip)) for m, ip in ips.items() if m in modes}
        display = '; '.join(f'{m.upper()}: {ips.get(m, "未获取")}' for m in modes) if len(modes) > 1 else ips.get(modes[0])
        result = {'state': 'blocked', 'ip': display, 'detected_ips': ips, 'scores': {}, 'error': None, 'jump_latched': False}
        def deny(reason):
            return {**result, 'reason': reason, 'error': reason}
        if acknowledge and (len(ips) != len(modes) or ips != expected_ips):
            def describe(values):
                return '，'.join(f'{m.upper()}: {values.get(m, "未获取")}' for m in modes)
            return deny(f'出口与刚才确认的地址不一致，未解除跳变拦截。确认的地址：{describe(expected_ips or {})}。重新检测：{describe(ips)}。请重新检测后再确认')
        path = Path(directory) / 'admission-state.json'
        with locked(path.with_suffix('.lock')):
            state = _load(path)
            changed = {m: {'before': state['baseline'][m], 'after': ip} for m, ip in ips.items()
                       if m in state['baseline'] and state['baseline'][m] != ip}
            if data['detect_ip_change'] and changed and not acknowledge:
                state['jump_latched'] = True
                state['jump_details'] = changed
                atomic_json(path, state)  # persist before doing any network risk lookup
            if data['detect_ip_change'] and state['jump_latched'] and not acknowledge:
                return {**deny('检测到 IP 跳变，已持续拦截。请确认是否信任当前 IP'), 'jump_latched': True, 'jump_details': state.get('jump_details', {})}
            if len(ips) != len(modes):
                missing = '、'.join(m.upper() for m in modes if m not in ips)
                return deny(f'未获取到 {missing} 出口 IP，暂不放行。请检查代理连接或稍后重新检测')
            if acknowledge:
                state['jump_latched'] = False
                state.pop('jump_details', None)
                state['baseline'].update(ips)
                atomic_json(path, state)
                result['jump_acknowledged'] = True
            if data['access_mode'] == 'whitelist':
                if any(not is_ip_allowed(ip, data.get('allowed_ips', [])) for ip in ips.values()):
                    return deny('出口未通过 IP 白名单检查')
            else:
                lookup = score_lookup or (lambda ip: fetch_score(ip, data.get('http_proxy') or None))
                timestamp = time.time() if now is None else now
                fingerprint = hashlib.sha256(os.environ.get('CLAUDEGUARD_PROXYCHECK_API_KEY', '').encode()).hexdigest()[:16]
                for ip in sorted(set(ips.values())):
                    cache_key = f'proxycheck:v2:{fingerprint}:{ip}'
                    cached = state['scores'].get(cache_key, {})
                    score = cached.get('score')
                    fetched = cached.get('fetched_at', -1)
                    valid = (not isinstance(score, bool) and isinstance(score, (int, float)) and math.isfinite(score) and 0 <= score <= 100)
                    valid = valid and not isinstance(fetched, bool) and isinstance(fetched, (int, float)) and math.isfinite(fetched) and 0 <= timestamp - fetched < data['risk_cache_ttl']
                    if not valid:
                        if timestamp < cached.get('retry_after', 0):
                            return deny('风险评分查询失败，正在等待重试，暂不放行')
                        try:
                            score = lookup(ip)
                            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
                                raise ValueError('invalid score')
                        except Exception:
                            state['scores'][cache_key] = {'retry_after': timestamp + 15}
                            atomic_json(path, state)
                            return deny('未取得有效风险评分，暂不放行')
                        fetched = time.time() if now is None else now
                        state['scores'][cache_key] = {'score': score, 'fetched_at': fetched}
                        # Bound disk growth when the user rotates many exits.
                        if len(state['scores']) > 256:
                            oldest = next(iter(state['scores']))
                            del state['scores'][oldest]
                        atomic_json(path, state)
                    result['scores'][ip] = {'score': score, 'cached': bool(valid), 'fetched_at': fetched, 'provider': 'proxycheck.io'}
                    if score > data['risk_threshold']:
                        return deny(f'{ip} 的风险分为 {score:g}，超过阈值 {data["risk_threshold"]:g}')
            if data['detect_ip_change']:
                # Establish unseen transport baselines only after the whole rule passes.
                state['baseline'].update(ips)
            atomic_json(path, state)
            return {**result, 'state': 'allowed', 'reason': '出口已通过检查'}
    except Exception as exc:
        return {'state': 'blocked', 'ip': None, 'detected_ips': {}, 'scores': {},
                'reason': '策略检查失败，暂不放行', 'error': str(exc)}


def check(data, directory, acknowledge=False, expected_ips=None):
    try:
        data = settings(data)
        if not data.get('protection_enabled', True):
            return evaluate(data, {}, directory)
        return evaluate(data, detect(data), directory, acknowledge, expected_ips)
    except Exception as exc:
        return {'state': 'blocked', 'ip': None, 'scores': {}, 'detected_ips': {}, 'reason': '出口检测失败，暂不放行', 'error': str(exc)}
