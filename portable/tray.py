"""Windows notification-area controls. The daemon remains the enforcement owner."""
import json
import logging
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

import psutil

from portable.config import atomic_json, config_fingerprint
from portable.platforms import autostart, stop_tree
from portable.runtime import InstanceLock, check, daemon_process, start_daemon

COLORS = {"allowed": "#39B97B", "blocked": "#E06464", "offline": "#E9AD48",
          "error": "#E06464", "waiting": "#E9AD48", "stopped": "#8894A6", "disabled": "#8894A6"}
LABELS = {"allowed": "守护运行中 · 出口已通过", "blocked": "守护运行中 · 出口被拦截",
          "offline": "守护运行中 · 无法确认出口", "error": "守护异常 · 请查看日志",
          "waiting": "守护启动中 / 等待最新检测", "stopped": "守护未运行", "disabled": "防护已关闭"}


def snapshot(settings, now=None):
    """Never paint an old successful probe as active protection."""
    data = settings.load()
    process = daemon_process(settings)
    result = {"state": "stopped", "ip": None}
    if process:
        try:
            result = json.loads(settings.path.with_name("portable-state.json").read_text(encoding="utf-8"))
            checked = result.get("checked_at", 0)
            age = (time.time() if now is None else now) - checked
            modified = settings.path.stat().st_mtime if settings.path.exists() else 0
            if (result.get("pid") != process.pid or
                    abs(result.get("process_created", 0) - process.create_time()) >= .001 or
                    age < 0 or age > max(30, data["check_interval"] + 20) or checked < modified or
                    (result.get("state") == "allowed" and
                     result.get("config_fingerprint") != config_fingerprint(data))):
                result = {"state": "waiting", "ip": None}
            elif result.get("enforcement_errors"):
                result = {**result, "state": "error"}
            elif data["network_guard_enabled"] and result.get("state") == "allowed":
                kernel = result.get("network", {})
                if not kernel.get("ready") or kernel.get("applied_state") != "allowed":
                    result = {**result, "state": "error"}
        except (OSError, ValueError, TypeError, psutil.Error):
            result = {"state": "waiting", "ip": None}
    if not data["protection_enabled"]:
        result = {**result, "state": "disabled"}
    if result.get("state") not in LABELS:
        result = {**result, "state": "error"}
    return data, bool(process), result


def autostart_enabled():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            return bool(winreg.QueryValueEx(key, "ClaudeGuard")[0])
    except FileNotFoundError:
        return False


def stop_tray(settings):
    try:
        state = json.loads(settings.path.with_name("tray-state.json").read_text(encoding="utf-8"))
        process = psutil.Process(state["pid"])
        if abs(process.create_time() - state["process_created"]) < .001:
            # The daemon can be a child of the tray; never terminate its tree.
            process.terminate()
            try:
                process.wait(timeout=2)
            except psutil.TimeoutExpired:
                process.kill()
    except (OSError, ValueError, KeyError, psutil.NoSuchProcess):
        pass


def make_icon(state):
    from PIL import Image, ImageDraw
    image = Image.new("RGBA", (64, 64))
    draw = ImageDraw.Draw(image)
    draw.polygon([(32, 3), (55, 12), (53, 36), (45, 49), (32, 60), (19, 49), (11, 36), (9, 12)],
                 fill=COLORS.get(state, COLORS["error"]))
    if state == "allowed":
        draw.line([(20, 31), (28, 39), (44, 22)], fill="white", width=6)
    elif state in ("stopped", "disabled"):
        draw.line([(21, 31), (43, 31)], fill="white", width=6)
    else:
        draw.line([(32, 19), (32, 34)], fill="white", width=6)
        draw.ellipse((29, 41, 35, 47), fill="white")
    return image


class Tray:
    def __init__(self, settings):
        import pystray
        self.api = pystray
        self.settings = settings
        self.entry = Path(__file__).with_name("main.py").resolve()
        self.python = Path(sys.executable).with_name("pythonw.exe")
        self.commands = queue.Queue()
        self.closed = threading.Event()
        self.window = None
        self.probe = ""
        self.signature = None
        self.icon = pystray.Icon("ClaudeGuard", make_icon("stopped"), "ClaudeGuard")

    def notify(self, text):
        self.icon.notify(str(text)[:240], "ClaudeGuard")

    def submit(self, callback):
        def action(icon, item):
            self.commands.put(callback)
        return action

    def set_value(self, key, value):
        data = self.settings.load()
        data[key] = value
        self.settings.save(data)
        self.probe = ""

    def open_settings(self):
        if self.window and self.window.poll() is None:
            # Restore the existing settings process, including a minimized window.
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            user32.IsWindowVisible.argtypes = [wintypes.HWND]
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.SetForegroundWindow.argtypes = [wintypes.HWND]
            user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
            def visit(hwnd, _):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value == self.window.pid and user32.IsWindowVisible(hwnd):
                    user32.ShowWindow(hwnd, 9)
                    user32.SetForegroundWindow(hwnd)
                return True
            user32.EnumWindows(callback_type(visit), 0)
            return
        self.window = subprocess.Popen([str(self.python), str(self.entry), "--config", str(self.settings.path), "gui"])

    def inspect(self):
        self.probe = "正在检测出口…"
        self.refresh()
        verdict = check(self.settings.load(), self.settings.path.parent)
        labels = {"allowed": "通过", "blocked": "未通过", "offline": "无法确认出口", "disabled": "防护已关闭"}
        self.probe = "手动检测：" + labels.get(verdict["state"], "异常")
        if verdict.get("ip"):
            self.probe += " · " + str(verdict["ip"])
        self.notify(self.probe + "\n" + str(verdict.get("reason") or verdict.get("error") or ""))

    def start(self):
        data = self.settings.load()
        if not (data["cli_path"] or data["desktop_path"]):
            raise ValueError("请先在设置中选择要保护的原生程序。")
        if data["protection_enabled"] and data["access_mode"] == "whitelist" and not data["allowed_ips"]:
            raise ValueError("请先在设置中填写可信 IP 白名单，再启动守护。")
        start_daemon(self.settings)
        self.notify("已请求启动守护，检测完成后托盘会更新状态。")

    def stop(self):
        process = daemon_process(self.settings)
        if process:
            stop_tree(process)
        self.notify("后台守护已停止。若安装了系统网络助手，放行凭据到期后将恢复阻断。")

    def boot(self, enabled):
        autostart(self.python, self.entry, self.settings.path.resolve(), enabled)

    def quit(self):
        self.closed.set()
        self.icon.stop()

    def refresh(self):
        item, menu = self.api.MenuItem, self.api.Menu
        data, running, result = snapshot(self.settings)
        boot = autostart_enabled()
        visible_result = {key: result.get(key) for key in ("state", "ip", "reason", "error")}
        signature = (json.dumps((data, visible_result), sort_keys=True), running, boot, self.probe)
        if signature == self.signature:
            return
        self.signature = signature
        state = result["state"]
        def choice(key, value, label):
            return item(label, self.submit(lambda: self.set_value(key, value)),
                        checked=lambda _: data[key] == value, radio=True)
        def toggle(key, label):
            return item(label, self.submit(lambda: self.set_value(key, not self.settings.load()[key])),
                        checked=lambda _: bool(data[key]))
        entries = [item(LABELS[state], None, enabled=False),
                   item("当前出口：" + str(result.get("ip") or "未获取"), None, enabled=False)]
        if result.get("reason") or result.get("error"):
            entries.append(item(str(result.get("reason") or result["error"])[:100], None, enabled=False))
        if self.probe:
            entries.append(item(self.probe, None, enabled=False))
        entries += [menu.SEPARATOR,
                    item("打开设置…", self.submit(self.open_settings), default=True),
                    item("重新检测出口", self.submit(self.inspect)),
                    menu.SEPARATOR, toggle("protection_enabled", "开启防护"),
                    item("停止守护" if running else "启动守护", self.submit(self.stop if running else self.start)),
                    item("出口检测", menu(choice("ip_check_mode", "both", "HTTP + STUN"),
                                          choice("ip_check_mode", "http", "仅 HTTP"),
                                          choice("ip_check_mode", "stun", "仅 STUN"))),
                    item("访问规则", menu(choice("access_mode", "whitelist", "固定 IP 白名单"),
                                          choice("access_mode", "risk", "风险评分"))),
                    toggle("detect_ip_change", "检测 IP 跳变"),
                    item("白名单 / 代理 / 解除跳变拦截…", self.submit(self.open_settings)),
                    menu.SEPARATOR,
                    item("登录时启动托盘和守护", self.submit(lambda: self.boot(not autostart_enabled())),
                         checked=lambda _: boot),
                    item("打开日志目录", self.submit(lambda: os.startfile(str(self.settings.path.parent)))),
                    menu.SEPARATOR,
                    item("退出托盘（保留守护）", self.submit(self.quit))]
        self.icon.icon = make_icon(state)
        self.icon.title = ("ClaudeGuard · " + LABELS[state])[:127]
        self.icon.menu = menu(*entries)
        self.icon.update_menu()

    def worker(self):
        while not self.closed.is_set():
            try:
                try:
                    callback = self.commands.get(timeout=2)
                except queue.Empty:
                    callback = None
                if callback:
                    callback()
                if not self.closed.is_set():
                    self.refresh()
            except Exception as exc:
                logging.exception("托盘操作失败")
                self.signature = None
                error = "操作失败：" + str(exc)
                changed = self.probe != error
                self.probe = error
                self.icon.icon = make_icon("error")
                self.icon.title = "ClaudeGuard · 操作失败"
                if changed:
                    self.notify(self.probe)
                # Keep settings and exit reachable even with a corrupt config.
                item, menu = self.api.MenuItem, self.api.Menu
                self.icon.menu = menu(item("打开配置目录", self.submit(lambda: os.startfile(str(self.settings.path.parent)))),
                                      item("退出托盘（保留守护）", self.submit(self.quit)))

    def run(self, start_guard=False):
        def ready(icon):
            icon.visible = True
            if start_guard:
                self.commands.put(self.start)
            threading.Thread(target=self.worker, daemon=True, name="ClaudeGuardTray").start()
        try:
            self.icon.run(setup=ready)
        finally:
            self.closed.set()


def show(settings, start_guard=False):
    if sys.platform != "win32":
        raise ValueError("系统托盘目前仅支持 Windows；其他平台请使用 gui。")
    settings.path.parent.mkdir(parents=True, exist_ok=True)
    lock = InstanceLock(settings.path.with_name("tray.lock"))
    try:
        lock.__enter__()
    except OSError:
        lock.file.close()
        return  # A second shortcut click must not create another tray icon.
    state = settings.path.with_name("tray-state.json")
    try:
        from logging.handlers import RotatingFileHandler
        logging.basicConfig(handlers=[RotatingFileHandler(settings.path.with_name("tray.log"),
                            maxBytes=1048576, backupCount=2, encoding="utf-8")], level=logging.INFO)
        atomic_json(state, {"pid": os.getpid(), "process_created": psutil.Process().create_time()})
        Tray(settings).run(start_guard=start_guard)
    finally:
        state.unlink(missing_ok=True)
        lock.__exit__()
