#!/usr/bin/python3
"""Install/remove the root-owned helper. Run with sudo and explicit --config."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--config', required=True, type=Path)
parser.add_argument('--remove', action='store_true')
args = parser.parse_args()
if not sys.platform.startswith('linux') or os.geteuid() != 0:
    raise SystemExit('请在 Linux 上用 sudo 运行网络助手安装器')
config = args.config.resolve(strict=True)
uid = config.stat().st_uid
if uid == 0:
    raise SystemExit('请指定普通用户的配置文件，不支持将 Claude 作为 root 运行')
installation = hashlib.sha256(str(config).encode()).hexdigest()[:16]
name = 'claudeguard_' + installation
root = Path('/var/lib/claudeguard-network') / installation
unit_name = 'claudeguard-network-' + installation + '.service'
unit = Path('/etc/systemd/system') / unit_name
cgroup = Path('/sys/fs/cgroup') / name
if args.remove:
    subprocess.run(['systemctl', 'disable', '--now', unit_name], check=True)
    nft = shutil.which('nft')
    if nft and subprocess.run([nft, 'list', 'table', 'inet', name], capture_output=True).returncode == 0:
        subprocess.run([nft, 'delete', 'table', 'inet', name], check=True)
    unit.unlink(missing_ok=True)
    shutil.rmtree(root)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    try:
        cgroup.rmdir()
    except OSError:
        print('仍有进程使用 cgroup，空分组可在进程退出后删除。')
    print('系统网络助手和专用规则已移除。')
    raise SystemExit(0)
if not Path('/run/systemd/system').is_dir() or not Path('/sys/fs/cgroup/cgroup.controllers').exists():
    raise SystemExit('需要 systemd、cgroup v2，以及支持 nft socket cgroupv2 的 Linux 内核')
if not shutil.which('nft'):
    raise SystemExit('请先安装 nftables，例如 sudo apt install nftables')
data = json.loads(config.read_text())
paths = sorted({os.path.realpath(data.get(key, '')) for key in ('cli_path', 'desktop_path') if data.get(key)})
if not paths or any(not Path(path).is_file() for path in paths):
    raise SystemExit('请先配置至少一个有效的 Claude 原生程序路径')
root.mkdir(parents=True, exist_ok=True, mode=0o755)
os.chmod(root, 0o755)
helper = root / 'helper.py'
shutil.copyfile(Path(__file__).resolve().parents[1] / 'native/linux_network_helper.py', helper)
os.chmod(helper, 0o755)
manifest = root / 'manifest.json'
manifest.write_text(json.dumps({'id': installation, 'uid': uid, 'paths': paths,
                                'request': str(config.with_name('network-request.json'))}))
os.chmod(manifest, 0o644)
# Check kernel/nft support and install an initial block before enabling service.
subprocess.run(['/usr/bin/python3', '-I', str(helper), str(manifest), '--block'], check=True)
unit.write_text('[Unit]\nDescription=ClaudeGuard network enforcement\nAfter=network.target\n\n[Service]\nType=simple\n'
                + 'ExecStart=/usr/bin/python3 -I ' + str(helper) + ' ' + str(manifest) + '\n'
                + 'ExecStopPost=/usr/bin/python3 -I ' + str(helper) + ' ' + str(manifest) + ' --block\n'
                + 'Restart=always\nRestartSec=1\nUMask=0022\n\n[Install]\nWantedBy=multi-user.target\n')
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemctl', 'enable', unit_name], check=True)
subprocess.run(['systemctl', 'restart', unit_name], check=True)
print('系统网络助手已安装，当前默认阻断。请回到普通用户终端启用 network_guard_enabled 并启动守护。')
