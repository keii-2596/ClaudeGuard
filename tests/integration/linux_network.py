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
    server6 = socket.socket(socket.AF_INET6)
    server6.bind(('::1', 0))
    server6.listen(5)
    endpoints = [('127.0.0.1', port), ('::1', server6.getsockname()[1])]
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
  s=socket.create_connection((line.split()[0], int(line.split()[1])), timeout=0.8); s.close(); print('allowed',flush=True)
 except OSError: print('blocked',flush=True)
'''
        child = subprocess.Popen(['/usr/bin/python3', '-u', '-c', probe, str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, preexec_fn=demote)
        started = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        registration = registrations / 'test.json'
        atomic_json(registration, {'pid': child.pid, 'start': started})
        os.chown(registration, uid, gid)
        wait(lambda s: s.get('enrolled', {}).get(str(child.pid)) == started)
        def attempt(expected):
            for address, target_port in endpoints:
                child.stdin.write(f'{address} {target_port}\n'); child.stdin.flush()
                actual = child.stdout.readline().strip()
                assert actual == expected, (address, actual, expected)
        attempt('blocked')
        producer = subprocess.Popen(['/usr/bin/sleep', '120'], preexec_fn=demote)
        producer_started = Path(f'/proc/{producer.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        atomic_json(request, {'schema': 2, 'producer_pid': producer.pid, 'producer_start': producer_started, 'allowed': True, 'configured_paths': paths, 'expires_at': time.time() + 30})
        os.chown(request, uid, gid)
        wait(lambda s: s.get('applied_state') == 'allowed')
        attempt('allowed')
        producer.kill(); producer.wait()
        wait(lambda s: s.get('applied_state') == 'blocked')
        attempt('blocked')
        print('Linux kernel blocked/allowed/reblocked loopback sockets for enrolled process')
    finally:
        if child:
            child.kill(); child.wait()
        if 'producer' in locals() and producer.poll() is None:
            producer.kill(); producer.wait()
        helper.terminate(); helper.wait(timeout=10)
        server.close()
        server6.close()
        subprocess.run(['nft', 'delete', 'table', 'inet', 'claudeguard_' + installation], check=True)
        (Path('/sys/fs/cgroup') / ('claudeguard_' + installation)).rmdir()
        shutil.rmtree(root)
    # Exercise root-owned installation and the paused-exec enrollment handshake.
    from portable.config import DEFAULTS
    settings.path.write_text(json.dumps({**DEFAULTS, 'cli_path': '/usr/bin/true', 'network_guard_enabled': True}))
    os.chown(settings.path, uid, gid)
    os.chown(folder, uid, gid)
    os.chown(registrations, uid, gid)
    installer = source / 'scripts/setup-network-linux.py'
    subprocess.run(['/usr/bin/python3', '-I', str(installer), '--config', str(settings.path)], check=True)
    try:
        producer = subprocess.Popen(['/usr/bin/sleep', '120'], preexec_fn=demote)
        producer_start = Path(f'/proc/{producer.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        atomic_json(request, {'schema': 2, 'producer_pid': producer.pid, 'producer_start': producer_start, 'allowed': True, 'configured_paths': paths, 'expires_at': time.time() + 60})
        os.chown(request, uid, gid)
        client = '''import os,sys
sys.path.insert(0,sys.argv[1])
from portable.config import Settings
from portable import network
settings=Settings(sys.argv[2]); data=settings.load()
process=network.guarded_spawn(settings,data,data['cli_path'],[],os.environ.copy())
assert process.wait(timeout=5)==0
print('Guarded Linux launch enrolled before exec')
'''
        subprocess.run(['/usr/bin/python3', '-c', client, str(source), str(settings.path)], check=True, preexec_fn=demote, timeout=30)
    finally:
        if 'producer' in locals():
            producer.kill(); producer.wait()
        subprocess.run(['/usr/bin/python3', '-I', str(installer), '--config', str(settings.path), '--remove'], check=True)
