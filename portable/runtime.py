import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import psutil

from portable.config import atomic_json
from portable.platforms import enforce, spawn, stop_tree
from src.ip_checker import perform_ip_check
from src import policy
from src.proxy_config import cli_environment
from portable.config import default_path
from portable import network


def check(data, policy_dir=None):
    if policy.advanced(data):
        return policy.check(data, policy_dir or default_path().parent)
    if not data["protection_enabled"]:
        return {"state": "disabled", "ip": None, "error": None}
    ip, allowed, error = perform_ip_check(data["allowed_ips"], mode=data["ip_check_mode"], proxy=data["http_proxy"] or None)
    return {"state": "allowed" if allowed else ("blocked" if ip else "offline"), "ip": ip, "error": error}


class InstanceLock:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, "a+b")

    def __enter__(self):
        self.file.seek(0)
        if os.name == "nt":
            import msvcrt
            self.file.write(b"0")
            self.file.flush()
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return self

    def __exit__(self, *args):
        self.file.close()


def daemon(settings):
    state_path = settings.path.with_name("portable-state.json")
    settings.path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(handlers=[RotatingFileHandler(settings.path.with_name("portable.log"), maxBytes=1048576, backupCount=2, encoding="utf-8")], level=logging.INFO)
    with InstanceLock(settings.path.with_name("portable.lock")):
        previous = None
        last_data = None
        while True:
            try:
                data = settings.load()
                if data != last_data and data.get('network_guard_enabled'):
                    network.publish(settings, data, {'state': 'blocked'})
                last_data = data
                verdict = check(data, settings.path.parent)
                verdict['network'] = network.publish(settings, data, verdict)
                # Unverified exits also stop protected processes, including on resume.
                errors = []
                if verdict["state"] not in ("allowed", "disabled"):
                    errors = enforce([data["cli_path"], data["desktop_path"]])
                verdict.update({"pid": os.getpid(), "process_created": psutil.Process().create_time(),
                                "checked_at": time.time(), "mode": data["ip_check_mode"], "enforcement_errors": errors})
                atomic_json(state_path, verdict)
                event = (verdict["state"], verdict["ip"], tuple(errors))
                if event != previous:
                    logging.info("state=%s ip=%s errors=%s", *event)
                    previous = event
                interval = data["check_interval"]
            except Exception:
                # Keep guarding the last known targets, never reuse an allowed verdict.
                errors = []
                if last_data:
                    try:
                        network.publish(settings, last_data, {'state': 'blocked'})
                    except Exception:
                        pass
                if last_data and last_data["protection_enabled"]:
                    errors = enforce([last_data["cli_path"], last_data["desktop_path"]])
                atomic_json(state_path, {"state": "error", "checked_at": time.time(),
                                        "pid": os.getpid(), "process_created": psutil.Process().create_time(),
                                        "enforcement_errors": errors})
                logging.exception("配置或出口检测失败，等待下一轮重试")
                interval = 3
            time.sleep(interval)


def daemon_process(settings):
    try:
        state = json.loads(settings.path.with_name("portable-state.json").read_text(encoding="utf-8"))
        process = psutil.Process(state["pid"])
        if abs(process.create_time() - state["process_created"]) < 0.001 and process.is_running():
            return process
    except (OSError, ValueError, KeyError, psutil.Error):
        pass
    return None


def start_daemon(settings):
    if daemon_process(settings):
        return
    python = Path(sys.executable)
    if os.name == "nt" and python.with_name("pythonw.exe").exists():
        python = python.with_name("pythonw.exe")
    settings.path.parent.mkdir(parents=True, exist_ok=True)
    with open(settings.path.with_name("portable-console.log"), "ab") as output:
        return subprocess.Popen([str(python), str(Path(__file__).with_name("main.py")), "--config", str(settings.path), "daemon"],
                         stdout=output, stderr=output, start_new_session=(os.name != "nt"))


def launch(settings, target, args):
    data = settings.load()
    verdict = check(data, settings.path.parent)  # Never trust a cached verdict at launch.
    if verdict["state"] not in ("allowed", "disabled"):
        raise ValueError(f"已阻止启动：{verdict['ip'] or verdict['error'] or '出口未通过检查'}")
    env = cli_environment(data, os.environ) if target == "cli" else os.environ.copy()
    if data.get('network_guard_enabled'):
        if not network.paths(data) or not data.get(target + '_path'):
            raise ValueError('请先设置要保护的程序路径，并安装网络助手')
        start_daemon(settings)
        process = network.guarded_spawn(settings, data, data[target + '_path'], args, env)
    elif target == "cli":
        process = spawn(data[target + "_path"], args, env=env)
    else:
        process = spawn(data[target + "_path"], args)
    tracked = psutil.Process(process.pid)
    try:
        while process.poll() is None:
            data = settings.load()
            if check(data, settings.path.parent)["state"] not in ("allowed", "disabled"):
                stop_tree(tracked)
                return 1
            time.sleep(data["check_interval"])
        return process.returncode
    finally:
        # Closing the launcher also stops the session it owns.
        if process.poll() is None:
            stop_tree(tracked)
