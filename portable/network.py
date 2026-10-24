"""Unprivileged client for the separately installed OS network helper."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from portable.config import atomic_json


def identity(settings):
    return hashlib.sha256(os.path.normcase(os.path.realpath(settings.path)).encode()).hexdigest()[:16]


def directory(settings):
    if sys.platform == 'win32':
        return Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'ClaudeGuardNetwork' / identity(settings)
    return Path('/var/lib/claudeguard-network') / identity(settings)


def paths(data):
    return sorted({os.path.normcase(os.path.realpath(data[key])) for key in ('cli_path', 'desktop_path') if data.get(key)})


def status(settings, data=None):
    if data is None:
        data = settings.load()
    try:
        result = json.loads((directory(settings) / 'status.json').read_text(encoding='utf-8-sig'))
        if not isinstance(result, dict) or time.time() - result['updated_at'] > 4 or result['updated_at'] > time.time() + 1:
            return {'ready': False, 'retryable': True, 'applied_state': 'unknown', 'error': '网络助手状态过期，正在等待恢复'}
        if not result.get('ready'):
            return result
        if result.get('configured_paths') != paths(data):
            raise ValueError('程序路径已变化，请重新安装网络助手')
        return result
    except FileNotFoundError:
        return {'ready': False, 'retryable': True, 'applied_state': 'unknown', 'error': '正在等待网络助手启动'}
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return {'ready': False, 'applied_state': 'unknown', 'error': str(exc)}


def publish(settings, data, verdict):
    enabled = data.get('network_guard_enabled', False)
    if not enabled and not (directory(settings) / 'manifest.json').is_file():
        return None
    import psutil
    producer_start = process_start(os.getpid()) if sys.platform.startswith('linux') else psutil.Process().create_time()
    request = {'schema': 2, 'producer_pid': os.getpid(), 'producer_start': producer_start, 'allowed': not enabled or verdict['state'] in ('allowed', 'disabled'),
               'expires_at': time.time() + min(90, data['check_interval'] + 15),
               'configured_paths': paths(data), 'nonce': uuid.uuid4().hex}
    atomic_json(settings.path.with_name('network-request.json'), request)
    state = status(settings, data)
    if enabled and not state.get('ready'):
        raise RuntimeError('网络助手未就绪：' + state.get('error', '请安装网络助手'))
    return state


def wait_allowed(settings, data, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = status(settings, data)
        if state.get('ready') and state.get('applied_state') == 'allowed':
            return state
        if state.get('error') and not state.get('retryable'):
            raise RuntimeError('网络助手未就绪：' + state['error'])
        time.sleep(0.1)
    raise RuntimeError('网络助手未确认放行，已取消启动。请检查 daemon 日志和 network status。')


def process_start(pid):
    # proc stat's command can contain spaces and parentheses.
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def guarded_spawn(settings, data, path, args, env):
    wait_allowed(settings, data)
    if sys.platform == 'win32':
        return subprocess.Popen([path, *args], env=env)
    if not sys.platform.startswith('linux'):
        raise RuntimeError('系统网络助手仅支持 Windows/Linux')
    read_fd, write_fd = os.pipe()
    process = None
    registration = None
    try:
        process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).with_name('network_bootstrap.py')),
                                    str(read_fd), path, *args], env=env, pass_fds=(read_fd,), start_new_session=True)
        os.close(read_fd)
        read_fd = None
        started = process_start(process.pid)
        folder = settings.path.with_name('network-processes')
        folder.mkdir(mode=0o700, exist_ok=True)
        registration = folder / (uuid.uuid4().hex + '.json')
        atomic_json(registration, {'pid': process.pid, 'start': started})
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            state = status(settings, data)
            if state.get('ready') and state.get('applied_state') == 'allowed' and state.get('enrolled', {}).get(str(process.pid)) == started:
                os.write(write_fd, b'1')
                return process
            if process.poll() is not None:
                raise RuntimeError('受保护启动进程提前退出')
            time.sleep(0.1)
        raise RuntimeError('进程未进入受控 cgroup，已取消启动')
    except BaseException:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        if read_fd is not None:
            os.close(read_fd)
        os.close(write_fd)
        if registration:
            registration.unlink(missing_ok=True)


def setup(settings, remove=False):
    """One explicit elevation; no elevated execution of a user-writable daemon."""
    if remove and not (directory(settings) / 'manifest.json').is_file():
        return
    import base64
    import shutil
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    if sys.platform == 'win32':
        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"
        command = "$ErrorActionPreference='Stop'; try { & " + quote(scripts / 'setup-network-windows.ps1') + ' -Config ' + quote(settings.path.resolve())
        if remove:
            command += ' -Remove'
        command += '; exit 0 } catch { Write-Error $_; exit 1 }'
        encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
        # Encoded payload contains no quotes or shell metacharacters.
        elevate = "$p=Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand " + encoded + "'; exit $p.ExitCode"
        subprocess.run(['powershell.exe', '-NoProfile', '-Command', elevate], check=True)
    elif sys.platform.startswith('linux'):
        prefix = [] if os.geteuid() == 0 else (['sudo'] if sys.stdin.isatty() else ['pkexec'])
        if prefix and not shutil.which(prefix[0]):
            raise RuntimeError('需要 sudo 或 pkexec 安装系统网络助手')
        command = prefix + ['/usr/bin/python3', '-I', str(scripts / 'setup-network-linux.py'), '--config', str(settings.path.resolve())]
        if remove:
            command.append('--remove')
        subprocess.run(command, check=True)
    else:
        raise RuntimeError('此安装器仅支持 Windows/Linux')
