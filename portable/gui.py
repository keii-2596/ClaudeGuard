import json
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import sys

from src import policy
from portable.platforms import autostart, stop_tree
from portable.runtime import check, daemon_process, launch, start_daemon

LABELS = {"both": "同时检查 HTTP 和 STUN", "http": "只检查 HTTP", "stun": "只检查 STUN"}


def show(settings):
    root = tk.Tk()
    root.title("ClaudeGuard 设置")
    root.geometry("720x680")
    root.minsize(560, 400)
    outer = ttk.Frame(root)
    outer.pack(fill="both", expand=True)
    canvas = tk.Canvas(outer, highlightthickness=0)
    scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    frame = ttk.Frame(canvas, padding=18)
    content = canvas.create_window((0, 0), window=frame, anchor="nw")
    frame.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda event: canvas.itemconfigure(content, width=event.width))
    try:
        data = settings.load()
    except (ValueError, OSError) as exc:
        messagebox.showerror("配置读取失败", f"{exc}\n\n请检查配置文件：{settings.path}", parent=root)
        root.destroy()
        return
    status = tk.StringVar(value="尚未检测")
    ttk.Label(frame, textvariable=status, wraplength=620).pack(anchor="w", pady=(0, 12))
    ttk.Label(frame, text="检测方式").pack(anchor="w")
    mode = tk.StringVar(value=LABELS[data["ip_check_mode"]])
    ttk.Combobox(frame, textvariable=mode, values=list(LABELS.values()), state="readonly").pack(fill="x")
    ttk.Label(frame, text="访问规则").pack(anchor="w", pady=(10, 0))
    access_labels = {"whitelist": "固定 IP 白名单", "risk": "风险评分"}
    access = tk.StringVar(value=access_labels[data["access_mode"]])
    ttk.Combobox(frame, textvariable=access, values=list(access_labels.values()), state="readonly").pack(fill="x")
    policy_numbers = {}
    ttk.Label(frame, text="风险分阈值（超过此值时拦截，0～100）").pack(anchor="w", pady=(8, 0))
    policy_numbers["risk_threshold"] = tk.StringVar(value=str(data["risk_threshold"]))
    ttk.Entry(frame, textvariable=policy_numbers["risk_threshold"]).pack(fill="x")
    advanced = ttk.Frame(frame)
    def toggle_advanced():
        if advanced.winfo_manager():
            advanced.pack_forget()
            advanced_button.configure(text="更多设置…")
        else:
            advanced.pack(fill="x", after=advanced_button)
            advanced_button.configure(text="收起更多设置")
    advanced_button = ttk.Button(frame, text="更多设置…", command=toggle_advanced)
    advanced_button.pack(anchor="w", pady=8)
    ttk.Label(advanced, text="评分缓存时间（秒，最长 604800）").pack(anchor="w")
    policy_numbers["risk_cache_ttl"] = tk.StringVar(value=str(data["risk_cache_ttl"]))
    ttk.Entry(advanced, textvariable=policy_numbers["risk_cache_ttl"]).pack(fill="x")
    jump = tk.BooleanVar(value=data["detect_ip_change"])
    ttk.Checkbutton(frame, text="检测 IP 跳变，变化后须手动确认才能解除拦截", variable=jump).pack(anchor="w", pady=8)
    ttk.Label(frame, text="风险评分模式会向 proxycheck.io 查询出口 IP，评分在有效期内会缓存在本机。", wraplength=620).pack(anchor="w")
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
            current.update({key: float(var.get()) for key, var in policy_numbers.items()})
            current['access_mode'] = next(key for key, label in access_labels.items() if label == access.get())
            current['detect_ip_change'] = jump.get()
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
                result = check(settings.load(), settings.path.parent)
                labels = {"allowed": "已通过白名单检查", "blocked": "出口未通过检查", "offline": "暂时无法确认出口 IP", "disabled": "防护已关闭"}
                text = labels[result["state"]] + "\n" + (result.get("reason") or "") + "\n" + (result["ip"] or result["error"] or "")
                for ip, score in result.get('scores', {}).items():
                    text += f"\n{ip}：{score['score']:g}/100（{'缓存' if score['cached'] else '刚查询'}）"
            except Exception as exc:
                text = f"检测失败：{exc}"
            root.after(0, lambda: status.set(text))
        threading.Thread(target=work, daemon=True).start()

    def acknowledge():
        if not save():
            return
        current = settings.load()
        def confirm(observed):
            display = "\n".join(f"{key.upper()}：{ip}" for key, ip in observed.items()) or "未获取出口"
            if not messagebox.askokcancel("信任当前 IP 并解除拦截？", display + "\n\n如果这是你主动切换的线路，可以确认信任。程序会重新检测 IP，确认地址未变后，解除跳变拦截，并将当前 IP 设为新的检测基准。白名单和风险评分仍会单独检查，不通过时继续拦截。", parent=root):
                return
            def apply():
                result = policy.check(current, settings.path.parent, acknowledge=True, expected_ips=observed)
                root.after(0, lambda: status.set(('已解除跳变拦截。\n' if result.get('jump_acknowledged') else '') + result['reason']))
            threading.Thread(target=apply, daemon=True).start()
        def probe():
            try:
                observed = policy.detect(policy.settings(current))
                root.after(0, lambda: confirm(observed))
            except Exception:
                root.after(0, lambda: status.set("未能确认出口，请检查网络后重试。"))
        threading.Thread(target=probe, daemon=True).start()

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
    ack_button = ttk.Button(frame, text="信任当前 IP 并解除拦截…", command=lambda: action(acknowledge))
    action_row = row
    def refresh_ack():
        try:
            current = settings.load()
            state = json.loads(settings.path.with_name("admission-state.json").read_text(encoding="utf-8"))
            visible = current["protection_enabled"] and current["detect_ip_change"] and isinstance(state, dict) and state.get("jump_latched") is True
        except (OSError, ValueError, TypeError):
            visible = False
        if visible:
            ack_button.pack(anchor="w", pady=5, after=action_row)
        else:
            ack_button.pack_forget()
        root.after(1000, refresh_ack)
    refresh_ack()
    row = ttk.Frame(frame)
    row.pack(fill="x", pady=5)
    ttk.Button(row, text="开启登录自启动", command=lambda: action(lambda: boot(True))).pack(side="left", padx=(0, 6))
    ttk.Button(row, text="关闭登录自启动", command=lambda: action(lambda: boot(False))).pack(side="left")
    ttk.Label(frame, text="本版通过进程监控拦截，不修改系统防火墙。直接启动原程序可能在被终止前发出请求。", wraplength=620).pack(anchor="w", pady=8)
    root.mainloop()
