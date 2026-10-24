# 出口检测配置

使用 HTTP 代理时，HTTP 请求可能经过代理，UDP STUN 则可能直连。两者返回不同公网 IP 时，原版菜单栏守护会采用最先返回的结果，导致同一网络有时放行、有时拦截。本 fork 允许用户选择用于白名单判断的检测方式。

## 模式选择

| `ip_check_mode` | 菜单栏守护 | CLI 和桌面启动器的备用检测 |
|---|---|---|
| `auto` | STUN 与 HTTP 并行，采用最先返回的 IP | 先查询 STUN，失败后查询 HTTP |
| `http` | 仅查询 HTTP 服务 | 仅查询 HTTP 服务 |
| `stun` | 仅查询 UDP STUN | 仅查询 UDP STUN |

未配置时默认为 `auto`，保留原版行为。显式选择 `http` 或 `stun` 后，检测失败不会改用另一种协议。无法确认 IP 时判为 `offline`，拒绝新启动并阻断相关域名，沿用原版对已经运行的客户端的离线处理方式。无效模式也不会发起探测或放行。

`http` 决定的是用于判断白名单的出口检测方式，拦截范围仍包括客户端和相关网络连接。它不会把防火墙改为只拦 HTTP 流量。

## 设置方式

安装此 fork 后，在菜单栏 **IP Detection** 中选择模式，或运行：

```bash
claudeguard set-ip-check-mode http
claudeguard status
```

也可以在 `~/.config/claudeguard/config.json` 中添加以下字段，保留文件中的其他配置：

```json
{
  "ip_check_mode": "http"
}
```

菜单切换会触发重新检测。命令行或手动修改配置后，后台守护在下一轮检查时生效，正常轮询间隔为 3 秒。CLI 只复用模式和白名单均与当前配置一致的守护判定，避免切换后继续使用旧模式的放行结果。

HTTP 探测沿用系统或进程的代理设置，不修改代理路由。需要将查询服务与 Claude 配置为同一条出站线路。不同查询服务之间也可能存在分流，选择 `http` 并不能自动消除代理规则的差异。

## 验证

```bash
python3 -m unittest discover -s tests -v
swiftc -O src/main.swift -o /tmp/ClaudeGuardMenuBar-check
```

回归测试覆盖两种显式模式的协议隔离、查询失败时不跨协议回退、白名单判断、配置持久化，以及切换模式或白名单后拒绝复用旧缓存。Swift 编译用于检查菜单栏程序的构建兼容性。
