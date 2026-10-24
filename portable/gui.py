import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import sys

from portable.platforms import autostart, stop_tree
from portable.runtime import check, daemon_process, launch, start_daemon

LABELS = {"both": "同时检查 HTTP 和 STUN", "http": "只检查 HTTP", "stun": "只检查 STUN"}


def show(settings):
    root = tk.Tk()
    root.title("ClaudeGuard 设置")
    root.geometry("680x570")
    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)
    data = settings.load()
    status = tk.StringVar(value="尚未检测")
    ttk.Label(frame, textvariable=status, wraplength=620).pack(anchor="w", pady=(0, 12))
    ttk.Label(frame, text="检测方式").pack(anchor="w")
    mode = tk.StringVar(value=LABELS[data["ip_check_mode"]])
    ttk.Combobox(frame, textvariable=mode, values=list(LABELS.values()), state="readonly").pack(fill="x")
    ttk.Label(frame, text="IP 白名单（每行一个 IP 或 CIDR 网段）").pack(anchor="w", pady=(10, 0))
    ips = tk.Text(frame, height=5)
    ips.insert("1.0", "\n".join(data["allowed_ips"]))
    ips.pack(fill="x")
    variables = {}
    for key, title in [("cli_path", "Claude Code 原始程序路径"), ("desktop_path", "桌面端可执行文件路径（可不填）"),
                       ("http_proxy", "HTTP 代理地址（可不填，示例：http://127.0.0.1:7897）")]:
        ttk.Label(frame, text=title).pack(anchor="w", pady=(8, 0))
        row = ttk.Frame(frame)
        row.pack(fill="x")
        variable = tk.StringVar(value=data[key])
        variables[key] = variable
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        if key != "http_proxy":
            def browse(v=variable):
                path = filedialog.askopenfilename(parent=root)
                if path:
                    v.set(path)
            ttk.Button(row, text="浏览…", command=browse).pack(side="right")
    enabled = tk.BooleanVar(value=data["protection_enabled"])
    ttk.Checkbutton(frame, text="开启防护", variable=enabled).pack(anchor="w", pady=10)

    def save():
        try:
            current = settings.load()
            current.update({k: v.get().strip() for k, v in variables.items()})
            current.update({"allowed_ips": [x.strip() for x in ips.get("1.0", "end").splitlines() if x.strip()],
                            "ip_check_mode": next(k for k, v in LABELS.items() if v == mode.get()),
                            "protection_enabled": enabled.get()})
            settings.save(current)
            status.set("配置已保存，后台守护将在下一轮检测时采用新设置。")
            return True
        except Exception as exc:
            messagebox.showerror("保存失败", str(exc), parent=root)
            return False

    def inspect():
        if not save():
            return
        status.set("正在检测出口…")
        def work():
            try:
                result = check(settings.load())
                labels = {"allowed": "已通过白名单检查", "blocked": "出口未通过检查", "offline": "暂时无法确认出口 IP", "disabled": "防护已关闭"}
                text = labels[result["state"]] + "\n" + (result["ip"] or result["error"] or "")
            except Exception as exc:
                text = f"检测失败：{exc}"
            root.after(0, lambda: status.set(text))
        threading.Thread(target=work, daemon=True).start()

    def action(fn):
        try:
            fn()
        except Exception as exc:
            messagebox.showerror("操作失败", str(exc), parent=root)

    def start():
        if save():
            start_daemon(settings)
            status.set("已请求启动后台守护。关闭此窗口不会停止守护。")

    def stop():
        process = daemon_process(settings)
        if process:
            stop_tree(process)
        status.set("后台守护已停止。")

    def boot(on):
        python = Path(sys.executable)
        if sys.platform == "win32" and python.with_name("pythonw.exe").exists():
            python = python.with_name("pythonw.exe")
        autostart(python, Path(__file__).with_name("main.py").resolve(), settings.path.resolve(), on)
        status.set("登录自启动已开启。" if on else "登录自启动已关闭。")

    row = ttk.Frame(frame)
    row.pack(fill="x", pady=5)
    for title, callback in [("保存", save), ("检测出口", inspect), ("启动守护", start), ("停止守护", stop)]:
        ttk.Button(row, text=title, command=lambda cb=callback: action(cb)).pack(side="left", padx=(0, 6))
    row = ttk.Frame(frame)
    row.pack(fill="x", pady=5)
    ttk.Button(row, text="开启登录自启动", command=lambda: action(lambda: boot(True))).pack(side="left", padx=(0, 6))
    ttk.Button(row, text="关闭登录自启动", command=lambda: action(lambda: boot(False))).pack(side="left")
    ttk.Label(frame, text="本版通过进程监控拦截，不修改系统防火墙。直接启动原程序可能在被终止前发出请求。", wraplength=620).pack(anchor="w", pady=8)
    root.mainloop()
