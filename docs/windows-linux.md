# Windows 与 Linux 版本

Windows/Linux 版使用 Python 实现，提供中文设置窗口、出口检测、启动前检查、运行中进程拦截和登录自启动。它与 macOS 版共用 HTTP、STUN 和 `both` 检测规则，但独立安装，不会覆盖 macOS 的菜单栏程序。

## 功能范围

| 功能 | Windows | Linux |
|---|---|---|
| 中文设置窗口 | Tkinter 窗口 | Tkinter 窗口，需要桌面环境 |
| 命令行启动检查 | 支持原生 Claude Code 程序 | 支持原生 Claude Code 程序 |
| 桌面端进程监控 | 按用户配置的可执行文件路径匹配 | 可配置第三方桌面客户端的可执行文件路径 |
| 登录自启动 | 当前用户的注册表 Run 项 | systemd 用户服务 |
| 系统级网络拦截 | 尚未实现 | 尚未实现 |
| 自动更新锁定、固定模型 | 尚未移植 | 尚未移植 |

本版无需管理员权限，不改 hosts 和防火墙。后台守护只处理当前用户的进程，并按完整的可执行文件路径匹配，避免只凭进程名关闭无关程序。

**通过守护入口启动，才能在启动原程序前检查出口。** 如果绕过入口，直接启动原程序，后台守护会在检测后将它终止，但这段时间内程序可能已发出网络请求。因此本版提供的是启动检查和进程监控，尚不具备 macOS 版的系统级连接阻断。

## 安装

### Windows

需要 Python 3.10 或更新版本，安装时保留 Python Launcher 和 Tcl/Tk 组件。下载或克隆仓库后，在源码目录的 PowerShell 中执行：

```powershell
.\scripts\install-windows.ps1
```

安装器会在 `%LOCALAPPDATA%\ClaudeGuard` 创建独立虚拟环境，安装 psutil，并在桌面创建 ClaudeGuard 快捷方式。双击快捷方式打开设置窗口。

配置文件保存在 `%APPDATA%\ClaudeGuard\config.json`。首次使用需要填写 IP 白名单、检测方式，以及 Claude 原生程序路径。Windows 的 `.cmd`、`.bat`、`.ps1` 启动脚本不受支持，请选择原始 `.exe`。

命令行入口：

```powershell
$Python = "$env:LOCALAPPDATA\ClaudeGuard\venv\Scripts\python.exe"
$Entry = "$env:LOCALAPPDATA\ClaudeGuard\portable\main.py"
& $Python $Entry status
& $Python $Entry run cli --version
```

### Linux

需要 Python 3.10 或更新版本、venv 和 pip。使用图形界面时还需要 Tkinter，Debian/Ubuntu 通常由 `python3-tk` 包提供。无桌面环境时可以只用命令行。

```bash
bash scripts/install-linux.sh
~/.local/bin/claudeguard gui
```

程序默认安装在 `~/.local/share/ClaudeGuard`，配置默认保存在 `~/.config/claudeguard/config.json`。安装路径遵循 `XDG_DATA_HOME`，配置路径遵循 `XDG_CONFIG_HOME`。

安装器还会创建桌面应用入口和 `~/.local/bin/claudeguard` 命令。若 `~/.local/bin` 已在 PATH 中，之后可以直接使用 `claudeguard`。

```bash
claudeguard run cli --version
```

Linux 版主要用于 Claude Code。桌面端监控需要用户自行配置已有客户端的可执行文件路径，不附带或安装 Claude 桌面客户端。

## 配置出口与保护对象

在设置窗口填写以下内容后，点击“保存”，再点击“检测出口”：

- **检测方式：** `both` 要求 HTTP 和 STUN 的出口都在白名单中，`http` 和 `stun` 只检查对应协议
- **IP 白名单：** 每行一个 IP 或 CIDR 网段，留空会阻止启动
- **程序路径：** 指定 Claude Code 或桌面客户端的原生可执行文件，可只配置其中一项
- **HTTP 代理：** 可以显式填写 `http://127.0.0.1:7897` 一类地址。留空时沿用 Python 能读取的系统或环境变量代理设置

HTTP 查询服务与 Claude 仍须使用同一条出站线路。显式代理只作用于出口检测，不会替 Claude 设置代理，也不会改变 STUN 的 UDP 路由。

后台监控按原始可执行文件路径识别程序。不要填写 Python、Node.js、Shell 等通用解释器，否则无法区分 Claude 与其他程序。程序升级导致路径变化后，需要重新确认路径。

以下为 Linux 命令示例，Windows 使用上文的 `$Python` 和 `$Entry` 调用同样的子命令：

```bash
claudeguard set ip_check_mode http
claudeguard add-ip 203.0.113.10
claudeguard set cli_path /absolute/path/to/claude
claudeguard set http_proxy http://127.0.0.1:7897
claudeguard run cli --version
```

IP 与程序路径均为示例，使用前需要替换。

## 风险评分与 IP 跳变

设置窗口还支持风险分阈值、评分缓存和 IP 跳变检测。它们独立于 HTTP/STUN 检测方式，详细行为见[白名单、风险评分与 IP 跳变](access-policy.md)。

## 后台守护与自启动

点击“启动守护”后，后台进程会持续检测。关闭设置窗口不会停止守护。检测到非白名单出口、无法确认出口或检测配置异常时，会停止已配置的保护对象。

默认在一轮检测完成后等待 3 秒再检测，实际响应时间还包括网络查询和进程终止耗时。进程拦截依赖当前用户对目标进程的操作权限。目标程序自行脱离进程树、提权或改用其他可执行文件时，可能超出当前监控范围。

在设置窗口点击“开启登录自启动”，或运行：

```bash
claudeguard autostart enable
claudeguard start
```

Windows 使用当前用户的 Run 项，Linux 使用 `claudeguard.service` 用户服务，两者都在用户登录后生效。自启动仅启动后台守护，不自动打开设置窗口。Linux 需要可用的 systemd 用户会话。

停止守护和关闭自启动分别执行：

```bash
claudeguard stop
claudeguard autostart disable
```

设置窗口或命令行关闭防护后，后台守护保留运行，但不再限制配置中的程序：

```bash
claudeguard set protection_enabled false
```

状态记录保存在配置文件旁的 `portable-state.json`，日志为 `portable.log` 和 `portable-console.log`。`status` 会重新检测当前出口，不凭历史缓存放行。

## 卸载

在源码目录执行对应脚本：

```powershell
.\scripts\uninstall-windows.ps1
```

```bash
bash scripts/uninstall-linux.sh
```

卸载会关闭自启动、停止守护并移除程序。IP 白名单配置会保留，方便重新安装。

## 验证

```bash
python -m pip install -r portable/requirements.txt
python -m unittest discover -s tests -v
```

仓库中的 Cross-platform checks 会在 Windows、Ubuntu 和 macOS 上运行 Python 3.10/3.12 测试。覆盖配置校验、协议选择、启动拦截、运行中检测失败、精确路径匹配、真实子进程终止、单实例锁、GUI 构建与自启动配置。Linux GUI 测试在 Xvfb 下运行。

CI 验证不等于用户机器上的完整网络验收。安装后应使用自己的代理线路核对出口，再分别验证放行与拦截。
