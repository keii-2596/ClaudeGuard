# Windows 与 Linux 版本

Windows/Linux 版使用 Python 实现，提供中文设置窗口、出口检测、启动前检查、运行中进程拦截和登录自启动。它与 macOS 版共用 HTTP、STUN 和 `both` 检测规则，但独立安装，不会覆盖 macOS 的菜单栏程序。

## 功能范围

| 功能 | Windows | Linux |
|---|---|---|
| 中文设置窗口 | Tkinter 窗口 | Tkinter 窗口，需要桌面环境 |
| 命令行启动检查 | 支持原生 Claude Code 程序 | 支持原生 Claude Code 程序 |
| 桌面端进程监控 | 按用户配置的可执行文件路径匹配 | 可配置第三方桌面客户端的可执行文件路径 |
| 登录自启动 | 当前用户的注册表 Run 项 | systemd 用户服务 |
| 系统级网络拦截 | WFP 按 exe 路径阻断 IPv4/IPv6 出站连接 | nftables 按 cgroup v2 阻断 IPv4/IPv6 出站流量 |
| 自动更新锁定、固定模型 | 尚未移植 | 尚未移植 |

基础的启动检查和进程监控按普通用户运行。系统网络拦截需额外安装管理员网络助手：Windows 使用 SYSTEM 计划任务，Linux 使用 root systemd 服务。助手代码和配置清单保存在系统目录，普通用户守护只能提交有时限的放行凭据，不能让助手执行任意命令。

建议通过 `claudeguard run cli` 或 `run desktop` 启动。Linux 会先暂停启动进程，等助手将进程放入受控 cgroup 后再执行 Claude，避免程序先联网再被归组。直接启动原始程序仍有被识别和归组前的窗口。Windows 的 WFP 规则按安装时登记的 exe 路径生效，包括本机代理连接，不依赖域名解析。

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

HTTP 查询服务与 Claude 仍须使用同一条出站线路。勾选“Claude Code 始终使用 HTTP 代理”后，新启动的受保护命令行会话采用配置的代理，不改变 STUN 的 UDP 路由。

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

## 安装系统网络助手

先保存 Claude 原生程序路径，再在设置窗口的“更多设置”中点击“安装/修复网络助手”。Windows 会出现 UAC 授权，Linux 需要 sudo 或 polkit。安装后勾选“启用系统网络拦截”，保存并启动普通用户守护。

命令行执行顺序如下，Windows 使用前文的 `$Python $Entry` 替换 `claudeguard`：

```bash
claudeguard network install
claudeguard set network_guard_enabled true
claudeguard start
claudeguard network status
claudeguard run cli
```

### Windows 网络限制

需要 64 位 Windows、Windows PowerShell 5.1 和正常运行的 Base Filtering Engine。助手直接使用 WFP 的 ALE_AUTH_CONNECT V4/V6 层，按应用路径阻止新连接，包含 TCP、UDP 及本机代理连接，不依赖 Windows 防火墙域名规则。不安装第三方驱动，也不清空其他软件的规则。

助手保存在 `%ProgramData%\ClaudeGuardNetwork`，只允许管理员和 SYSTEM 修改。开机任务负责启动助手，用户登录自启动负责启动普通用户守护。WFP 按程序路径匹配，安装清单中的路径对使用该路径的用户都生效，多用户机器应使用每用户独立安装的 Claude。桌面端目录中的现有 exe 辅助程序也会登记，升级新增的程序需要重新安装网络助手。

### Linux 网络限制

需要 systemd、统一 cgroup v2、nftables，以及支持 `socket cgroupv2` 的内核和 nft 用户工具。发行版限制或容器未开放这些能力时，安装器会报错，不会降级成已启用状态。

助手建立独立的 cgroup 和 nftables inet 表，不修改系统其他表。受保护启动的进程先进入 cgroup，再执行原程序，普通子进程会继承分组。阻断规则匹配整个分组，覆盖直连和本机代理连接。原始入口直接启动的程序由助手扫描完整路径后归组，仍有短暂窗口。已有单实例桌面程序可能把启动请求转交给旧进程，应先退出旧实例，再使用受保护入口启动。

### 阻断状态与故障处理

安装后的默认状态是阻断。守护只有在检查通过或用户明确关闭防护时，才提交短期放行凭据。凭据有效期为轮询间隔加 15 秒、最长 90 秒，助手每约 250 毫秒检查一次。凭据缺失、损坏、过期或程序路径与安装清单不同，助手都会阻断。

网络助手失联时，启动入口拒绝启动，普通用户守护也会终止已配置程序。Windows 的阻断过滤器为持久规则，Linux 规则留在专用表中。若助手在放行状态异常退出，最后一次放行可能持续到助手重启，所以应使用安装器创建的任务或服务运行助手，不把它当作绝对不会漏请求的隔离边界。Windows 任务失败后会尝试重启，Linux 服务退出时会先恢复阻断并尝试重启。

IP 变化仍由轮询或网络事件发现。新增网络层解决的是判定需要阻断后的执行，以及 Linux 受保护启动前的进程归组，不能消除出口变化到检测完成之间的时间窗口。

`network status` 会显示助手的实际状态和错误。修改 CLI 或桌面端路径后必须再次 `network install`。停止用户守护后，放行凭据到期会恢复阻断。关闭系统拦截勾选项时，运行中的守护会刷新放行凭据，但停止守护后仍会到期阻断。彻底解除限制应卸载助手：

```bash
claudeguard network remove
```

卸载需要管理员权限，只删除本项目登记的 WFP 规则或 nftables 表，不重置系统防火墙。

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

卸载会关闭自启动、停止守护，先移除已安装的系统网络助手和专用规则，再移除普通用户程序。助手清理失败时停止卸载，保留修复入口。IP 白名单配置会保留，方便重新安装。

## 验证

```bash
python -m pip install -r portable/requirements.txt
python -m unittest discover -s tests -v
```

仓库中的 Cross-platform checks 会在 Windows、Ubuntu 和 macOS 上运行 Python 3.10/3.12 测试。覆盖配置校验、协议选择、启动拦截、运行中检测失败、精确路径匹配、真实子进程终止、单实例锁、GUI 构建与自启动配置。Linux GUI 测试在 Xvfb 下运行。

Windows CI 还会实际安装 WFP 过滤器，验证指定 exe 的本机 TCP 连接依次被阻断、放行和再次阻断。Linux CI 以 root 创建测试 cgroup 和 nftables 表，验证普通用户进程的本机 TCP 连接执行同样的变化，测试结束后清理规则。

CI 验证不等于用户机器上的完整网络验收。安装后应使用自己的代理线路核对出口，再分别验证放行与拦截。
