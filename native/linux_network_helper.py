#!/usr/bin/python3
"""Root-only, standard-library network worker. Never executes user input."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time


def atomic(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False))
    os.chmod(temp, 0o644)
    os.replace(temp, path)


def read_request(path, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > 65536:
            raise ValueError('请求文件所有者或格式无效')
        with os.fdopen(fd, encoding='utf-8') as stream:
            fd = None
            return json.load(stream)
    finally:
        if fd is not None:
            os.close(fd)


def start_time(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


class Worker:
    def __init__(self, manifest):
        self.root = manifest.parent
        self.config = json.loads(manifest.read_text())
        self.uid = self.config['uid']
        self.name = 'claudeguard_' + self.config['id']
        self.cgroup = Path('/sys/fs/cgroup') / self.name
        self.cgroup.mkdir(exist_ok=True)
        self.applied = None
        self.enrolled = {}
        self.nft = '/usr/sbin/nft'
        if not Path(self.nft).exists():
            self.nft = '/sbin/nft'
        # A dedicated table; never flush the machine's ruleset.
        exists = subprocess.run([self.nft, 'list', 'table', 'inet', self.name], capture_output=True).returncode == 0
        if not exists:
            self.run(f'add table inet {self.name}\nadd chain inet {self.name} output {{ type filter hook output priority -10; policy accept; }}\n')
        self.apply(False)

    def run(self, rules):
        subprocess.run([self.nft, '-f', '-'], input=rules, text=True, check=True, capture_output=True, timeout=5)

    def apply(self, allowed):
        # Verify our chain still exists each time; fail closed on drift.
        current = subprocess.run([self.nft, '-j', 'list', 'chain', 'inet', self.name, 'output'], check=True, capture_output=True, text=True, timeout=5)
        entries = json.loads(current.stdout)['nftables']
        rules = [entry['rule'] for entry in entries if 'rule' in entry]
        if self.applied == allowed and ((allowed and not rules) or (not allowed and len(rules) == 1 and rules[0].get('comment') == self.name)):
            return
        text = f'flush chain inet {self.name} output\n'
        if not allowed:
            text += f'add rule inet {self.name} output socket cgroupv2 level 1 "{self.name}" counter drop comment "{self.name}"\n'
        self.run(text)
        self.applied = allowed

    def enroll(self, pid, expected=None):
        proc = Path('/proc') / str(pid)
        try:
            if proc.stat().st_uid != self.uid:
                return
            started = start_time(pid)
            if expected is not None and started != expected:
                return
            # pidfd pins identity; recheck start time immediately before migration.
            fd = os.pidfd_open(pid) if hasattr(os, 'pidfd_open') else None
            try:
                if start_time(pid) != started or proc.stat().st_uid != self.uid:
                    return
                (self.cgroup / 'cgroup.procs').write_text(str(pid))
                if start_time(pid) == started:
                    self.enrolled[str(pid)] = started
            finally:
                if fd is not None:
                    os.close(fd)
        except (OSError, ValueError, ProcessLookupError):
            return

    def tick(self):
        allowed = False
        try:
            request = read_request(Path(self.config['request']), self.uid)
            now = time.time()
            expires = request['expires_at']
            allowed = (request.get('schema') == 1 and request.get('allowed') is True
                       and isinstance(expires, (int, float)) and not isinstance(expires, bool)
                       and now < expires <= now + 90 and request.get('configured_paths') == self.config['paths'])
        except (OSError, ValueError, TypeError, KeyError):
            pass
        self.apply(allowed)
        # A paused bootstrap is enrolled before its parent releases exec.
        folder = Path(self.config['request']).with_name('network-processes')
        if folder.is_dir():
            for path in list(folder.glob('*.json'))[:256]:
                try:
                    registration = read_request(path, self.uid)
                    pid = registration['pid']
                    if type(pid) is int and pid > 1:
                        self.enroll(pid, registration['start'])
                except (OSError, ValueError, TypeError, KeyError):
                    pass
        # Also catch direct launches; unlike guarded launches this has a race window.
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    if proc.stat().st_uid == self.uid and os.path.realpath(proc / 'exe') in self.config['paths']:
                        self.enroll(int(proc.name))
                except OSError:
                    pass
        self.enrolled = {pid: started for pid, started in self.enrolled.items()
                         if self.alive(pid, started)}
        atomic(self.root / 'status.json', {'ready': True, 'updated_at': time.time(),
               'applied_state': 'allowed' if allowed else 'blocked', 'configured_paths': self.config['paths'],
               'enrolled': self.enrolled, 'backend': 'nftables-cgroup-v2'})

    @staticmethod
    def alive(pid, started):
        try:
            return start_time(pid) == started
        except OSError:
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--block', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('网络助手须以 root 运行')
    worker = Worker(args.manifest)
    if args.block:
        return
    while True:
        try:
            worker.tick()
        except Exception as exc:
            try:
                worker.apply(False)
            except Exception:
                pass
            atomic(worker.root / 'status.json', {'ready': False, 'updated_at': time.time(), 'error': str(exc)})
        time.sleep(0.25)


if __name__ == '__main__':
    main()
