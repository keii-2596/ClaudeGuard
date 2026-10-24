"""OS adapters. Never change system firewall rules or kill by process name."""
import os
from pathlib import Path
import subprocess
import sys

import psutil


def normalized(path):
    return os.path.normcase(os.path.realpath(path))


def stop_tree(process):
    """psutil checks PID identity before termination; do not target this guard."""
    if process.pid == os.getpid():
        raise ValueError("不能终止守护自身")
    try:
        children = process.children(recursive=True)
        targets = children + [process]
        for target in targets:
            try:
                target.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(targets, timeout=2)
        for target in alive:
            try:
                target.kill()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass


def enforce(paths):
    paths = {normalized(p) for p in paths if p and Path(p).is_file()}
    failures = []
    for process in psutil.process_iter(["pid", "exe", "username"]):
        try:
            # A per-user guard never interferes with another user's applications.
            if process.info["username"] != psutil.Process().username():
                continue
            executable = process.info.get("exe")
            if executable and normalized(executable) in paths:
                stop_tree(process)
        except (psutil.AccessDenied, OSError) as exc:
            failures.append(str(exc))
        except psutil.NoSuchProcess:
            continue
    return failures


def spawn(path, args):
    if not path or not Path(path).is_file():
        raise ValueError("请先设置有效的程序路径")
    if Path(path).suffix.lower() in (".cmd", ".bat", ".ps1"):
        raise ValueError("请指定原生可执行文件")
    return subprocess.Popen([path, *args], start_new_session=(os.name != "nt"))


def autostart(python, entry, config_path, enabled, system=None):
    system = system or sys.platform
    command = [str(python), str(entry), "--config", str(config_path), "daemon"]
    if system == "win32":
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            if enabled:
                winreg.SetValueEx(key, "ClaudeGuard", 0, winreg.REG_SZ, subprocess.list2cmdline(command))
            else:
                try:
                    winreg.DeleteValue(key, "ClaudeGuard")
                except FileNotFoundError:
                    pass
    elif system.startswith("linux"):
        folder = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd/user"
        folder.mkdir(parents=True, exist_ok=True)
        service = folder / "claudeguard.service"
        if enabled:
            # systemd has its own quoting rules; no shell is involved.
            def quote(arg):
                return '"' + arg.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'
            service.write_text("[Unit]\nDescription=ClaudeGuard\n\n[Service]\nExecStart=" +
                               " ".join(quote(x) for x in command) +
                               "\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n", encoding="utf-8")
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            subprocess.run(["systemctl", "--user", "enable", "claudeguard.service"], check=True)
        else:
            if not service.exists():
                return
            subprocess.run(["systemctl", "--user", "disable", "claudeguard.service"], check=True)
            service.unlink(missing_ok=True)
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    else:
        raise ValueError("此自启动适配器仅供 Windows 和 Linux 使用")
