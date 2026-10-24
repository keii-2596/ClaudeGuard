"""Run explicitly as root on a Linux VM; never in ordinary unittest discovery."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

source = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(source))
from portable.config import atomic_json
from portable.network import identity
from types import SimpleNamespace

if os.geteuid() != 0:
    raise SystemExit('Run using sudo on a disposable CI VM')
uid = int(os.environ['SUDO_UID'])
gid = int(os.environ['SUDO_GID'])
with tempfile.TemporaryDirectory() as temp:
    folder = Path(temp)
    folder.chmod(0o755)
    settings = SimpleNamespace(path=folder / 'config.json')
    installation = identity(settings)
    root = Path('/var/lib/claudeguard-network') / installation
    root.mkdir(parents=True)
    request = folder / 'network-request.json'
    registrations = folder / 'network-processes'
    registrations.mkdir()
    paths = [os.path.realpath('/usr/bin/true')]
    manifest = root / 'manifest.json'
    manifest.write_text(json.dumps({'id': installation, 'uid': uid, 'paths': paths, 'request': str(request)}))
    helper = subprocess.Popen(['/usr/bin/python3', '-I', str(source / 'native/linux_network_helper.py'), str(manifest)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child = None
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(5)
    port = server.getsockname()[1]
    def wait(predicate):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if helper.poll() is not None:
                raise AssertionError(helper.communicate())
            try:
                state = json.loads((root / 'status.json').read_text())
                if predicate(state):
                    return state
            except (OSError, ValueError):
                pass
            time.sleep(0.05)
        raise AssertionError('network helper did not reach expected state')
    try:
        wait(lambda s: s.get('ready') and s['applied_state'] == 'blocked')
        def demote():
            os.setgid(gid)
            os.setuid(uid)
        probe = '''import socket,sys
for line in sys.stdin:
 try:
  s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=0.8); s.close(); print('allowed',flush=True)
 except OSError: print('blocked',flush=True)
'''
        child = subprocess.Popen(['/usr/bin/python3', '-u', '-c', probe, str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, preexec_fn=demote)
        started = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        registration = registrations / 'test.json'
        atomic_json(registration, {'pid': child.pid, 'start': started})
        os.chown(registration, uid, gid)
        wait(lambda s: s.get('enrolled', {}).get(str(child.pid)) == started)
        def attempt(expected):
            child.stdin.write('probe\n'); child.stdin.flush()
            actual = child.stdout.readline().strip()
            assert actual == expected, (actual, expected)
        attempt('blocked')
        atomic_json(request, {'schema': 1, 'allowed': True, 'configured_paths': paths, 'expires_at': time.time() + 30})
        os.chown(request, uid, gid)
        wait(lambda s: s.get('applied_state') == 'allowed')
        attempt('allowed')
        request.unlink()
        wait(lambda s: s.get('applied_state') == 'blocked')
        attempt('blocked')
        print('Linux kernel blocked/allowed/reblocked loopback sockets for enrolled process')
    finally:
        if child:
            child.kill(); child.wait()
        helper.terminate(); helper.wait(timeout=10)
        server.close()
        subprocess.run(['nft', 'delete', 'table', 'inet', 'claudeguard_' + installation], check=True)
        (Path('/sys/fs/cgroup') / ('claudeguard_' + installation)).rmdir()
        shutil.rmtree(root)
