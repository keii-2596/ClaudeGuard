# ClaudeGuard 中文版

ClaudeGuard 是一个运行在 macOS 菜单栏的 Claude 防护工具。它检查当前公网出口是否在你设置的白名单中，通过后才允许启动 Claude 桌面端或 Claude Code。检测到出口不符合要求时，会关闭对应会话，并阻断相关域名的连接。

本项目基于 [ivblz/ClaudeGuard](https://github.com/ivblz/ClaudeGuard) 修改，增加了可选择的出口检测方式，并将菜单、弹窗和命令行提示改为中文。保留原项目的 MIT 许可证。

[English](README.md) | [Русский](README.ru.md)

## 访问规则与 IP 跳变

支持固定 IP 白名单或风险分阈值两种规则。风险分采用与 ipcheck 相同的 proxycheck.io 来源，并按 IP 缓存在本机。还可以开启 IP 跳变检测，变化后即使新出口在白名单中，也会持续拦截，直到用户确认。详细设置见[白名单、风险评分与 IP 跳变](docs/access-policy.md)。

## Windows 与 Linux

新增 Windows/Linux 版本，提供中文设置窗口、命令行启动检查、进程监控和登录自启动。与下文 macOS 版相比，暂不包含系统级网络拦截。安装与配置见 [Windows 与 Linux 版本](docs/windows-linux.md)。

## macOS 安装与启动

需要 macOS 和 Xcode 命令行工具。安装时会在本机编译程序，并请求管理员权限，用于注册负责域名和防火墙规则的系统网络助手。

```bash
git clone https://github.com/keii-2596/ClaudeGuard.git
cd ClaudeGuard
./install.sh
```

安装后，菜单栏会出现盾牌图标。点击图标即可查看状态、管理白名单、切换检测方式。程序会在登录 macOS 后自动启动。

第一次安装时，如果询问是否将当前 IP 加入白名单，请先确认它就是你希望允许使用的出口。也可以跳过，之后手动添加：

```bash
claudeguard add-ip 203.0.113.10
```

上面的 IP 是示例地址，实际使用时请换成你的出口 IP。白名单为空时会阻止启动。安装器默认禁止 Claude 自动更新，菜单中可以改为允许。

## 选择出口检测方式

桌面端和命令行都可能走代理，也都可能直连。选择哪种检测方式，应看 Claude 实际使用的线路。

| 菜单选项 | 配置值 | 放行条件 |
|---|---|---|
| 同时检查 HTTP 和 STUN | `both` | 两个出口都在白名单中 |
| 只检查 HTTP | `http` | HTTP 查询得到的出口在白名单中 |
| 只检查 STUN | `stun` | UDP STUN 查询得到的出口在白名单中 |

默认使用 `both`。两种查询分别完成后再统一判断，不采用最先返回的结果。任一已确认出口不在白名单就拦截，如果只取得一边的结果且该出口在白名单，则暂不放行。两个出口可以不同，只要都在白名单中即可。旧配置中的 `auto` 会按 `both` 处理。

如果 HTTP 经过代理、UDP 直连，两个出口可能不同。只希望检查 Claude 使用的代理出口时，可以在菜单中选择“出口检测 → 只检查 HTTP”，或运行：

```bash
claudeguard set-ip-check-mode http
claudeguard status
```

HTTP 查询服务也需要与 Claude 走同一条代理线路。程序会沿用系统或进程的代理设置，不会替你修改分流规则。完整配置见[出口检测配置](docs/ip-check-mode.md)。

## 查看状态与管理白名单

菜单栏会显示“已通过白名单检查”“已拦截”“暂时无法确认出口 IP”或“防护已关闭”。`both` 模式下会分别显示 HTTP 和 STUN 的检测结果。

常用命令如下：

```bash
claudeguard status                   # 查看当前状态
claudeguard list-ips                 # 查看白名单
claudeguard add-ip 203.0.113.10       # 添加 IP
claudeguard add-ip 203.0.113.0/24     # 添加网段
claudeguard remove-ip 203.0.113.10    # 移除 IP
claudeguard launch-desktop           # 检查出口后启动桌面端
claudeguard doctor                   # 检查并修复启动入口
```

`claudeguard` 不带参数时会显示完整帮助。命令名、配置键和模式参数仍使用英文，提示与说明使用中文。

## 暂停防护与卸载

关闭防护：

```bash
claudeguard disable-protection
```

重新开启：

```bash
claudeguard enable-protection
```

“退出 ClaudeGuard”或 `claudeguard stop` 只是停止菜单栏守护，已经写入的网络限制不会自动解除。需要暂时恢复访问时，应先关闭防护。

卸载时，在源码目录运行：

```bash
./uninstall.sh
```

## 验证源码改动

```bash
python3 -m unittest discover -s tests -v
swiftc -O src/main.swift -o /tmp/ClaudeGuardMenuBar-check
```

测试不会启动守护，也不会改动本机白名单和网络设置。macOS 上会同时检查 Swift 的 `both` 判定逻辑。
