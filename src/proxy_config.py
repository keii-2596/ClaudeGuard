"""Proxy environment for guarded foreground Claude Code launches."""
from urllib.parse import urlsplit


def validate_proxy(data):
    enabled = data.get('cli_http_proxy_enabled', False)
    if type(enabled) is not bool:
        raise ValueError('命令行 HTTP 代理开关必须是布尔值')
    if not enabled:
        return None
    value = data.get('http_proxy', '')
    try:
        url = urlsplit(value)
        valid = (url.scheme == 'http' and url.hostname and url.port
                 and not url.username and not url.password and url.path in ('', '/')
                 and not url.query and not url.fragment and not any(c.isspace() for c in value))
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError('请设置有效的 HTTP 代理地址，例如 http://127.0.0.1:7897，须含端口且不含账号密码')
    return value


def cli_environment(data, inherited):
    env = dict(inherited)
    proxy = validate_proxy(data)
    if proxy:
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy'):
            env[key] = proxy
        # Override shell bypass rules as well as higher-priority lowercase values.
        env['NO_PROXY'] = env['no_proxy'] = ''
    return env
