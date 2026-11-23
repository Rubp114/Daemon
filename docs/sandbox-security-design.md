# 云侧沙箱安全管控方案设计

> 版本：v1.2　日期：2026-11-23
> v1.2 变更：依据《实施清单》v1.2 的环境确认终态**全面改写**。核心：环境为**全程无 root、容器定义不可改**（A4 平台结论），原"root Daemon + 内核硬边界"架构不成立，改为"**插件层裁决 + Exec Broker v2（spawn 包装 + userns 沙箱 + seccomp user-notify）+ 云侧权威 + supervisor 自愈**"；§4.9 改写为"现实边界与兜底"；§10 反连专项按新机制重排；新增 §11 无 root 风险披露。可行性依据：T1/T2（userns）、T5/T9（seccomp-notify）、T10/T10b（Node permission）、T3/T4（freezer/fanotify 出局）实测。
>
> 运行环境终态（2026-11 实测，清单第一部分）：华为云 CCE K8s Pod，内核 5.10.0-182 **aarch64**，cgroup v1；容器登录即 sandbox（uid 1001），**任何路径无 root，容器启动配置不可改**；supervisord（Python 版）管理常驻进程（配置 `/home/sandbox/supervisord.conf`）；AppArmor 无、SELinux Disabled、**fanotify 不可用**、cgroup fs 只读；出站直连开放、云元数据平台已封、SA token 未挂载、K8s API 不可达；OpenClaw **6.6**（channel 插件体系，源码 `xy_channel`）。

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
- 攻击载荷藏在**脚本体内**（`python3 evil.py`、`curl x | bash`、pip/npm 安装时执行任意代码）——**不产生工具调用，命令字符串匹配看不见**；
- 混淆/编码绕过（base64、软链接改名、shell 内建、解释器 `-c`）；
- 反弹 shell：经合法出站通道（HTTPS/WebSocket 隧道、chisel/frp/ssh -R）建立交互式控制通道；
- **攻击者与安全组件同 uid（uid 1001）**：可杀 Broker、篡改本地策略缓存、读取同主凭证文件、调用 supervisor 无认证 RPC 摘除安全组件——这些不再被内核阻止，纳入模型（§11 如实披露与补偿）。

### 2.2 设计原则

1. **内联拦截，而非旁路监控**：三个同步裁决点——工具调用前（插件层 `before_tool_call`）、派生前（launcher 包装）、执行中（seccomp user-notify 拦 execve）。事后读 /proc 杀进程只做 L3 补充，不做防线。
2. **名单管"让不让跑"，沙箱管"跑了能怎样"，审计管"跑过留痕"**：其中"沙箱"从"容器级内核配置"改为"**每次 exec 的 launch 时沙箱**"（userns+mountns+netns，T1/T2 实测可行）——容器定义不可改，但每个子进程的执行环境由我们逐次构造。
3. **最小权限按次构造**：exec 子进程默认无网（netns 零外网）、敏感路径 bind-ro/遮蔽、tmpfs noexec、解释器权限收敛（Python audit hook / Node permission）。
4. **策略云侧权威**：名单/授权由云侧签名推送；本地缓存与 Agent 同主可改 → 验签失败即 fail-close 拒绝加载，篡改只能造成可用性破坏而非提权。
5. **诚实分层**：硬保证只来自"进程级沙箱边界 + 云侧 scope"；同 uid 组件间的相互可达（杀 Broker、摘除 supervisor 程序）以**自愈 + 心跳可观测 + 全量审计**补偿，不假装不可穿透（§11）。

## 3. 总体架构

```
                        ┌─────────────────────────────┐
                        │      云侧控制面              │
                        │  · 策略中心（名单/版本/签名） │
                        │  · 审批服务（灰名单确认）     │
                        │  · 授权范围服务（scope）      │
                        │  · OBS（制品快照/审计）       │
                        │  · 心跳/失管告警              │
                        └───────▲─────────┬───────────┘
              签名策略 pull/心跳 │         │ 审批回执/事件上报
        ┌───────────────────────┼─────────┼───────────────────┐
        │ 沙箱容器（全部 uid 1001，无 root）                   │
        │                                                       │
        │  ┌─ OpenClaw gateway（supervisor 管理） ──────────┐   │
        │  │ xy_channel 插件层（gateway 进程内）            │   │
        │  │  · 本地策略引擎：三名单匹配、tokenize/解码      │   │
        │  │  · before_tool_call → block / requireApproval │   │
        │  │  · resolve_exec_env → 注入管控 env            │   │
        │  │  · 脚本扫描（本地规则）+ OBS 云扫客户端        │   │
        │  │  · 事件总线（L-A/L-B 事件源）→ HIPS/云侧       │   │
        │  │  · scope 代发云侧调用                          │   │
        │  └──────┬───────────────────────────▲────────────┘   │
        │    exec 工具调用                    │ 裁决/env        │
        │  ┌──────▼───────────┐   Unix socket │                │
        │  │ safe-launcher     │───────────────┼───┐            │
        │  │（每次 exec 的包装）│  policy/fd    │   │            │
        │  │ 建 userns 沙箱    │               │   │            │
        │  └──────┬───────────┘               │   │            │
        │         │ fork                       │   │            │
        │  ┌──────▼─────────────────────────┐ │   │            │
        │  │ exec 子进程（launch 时沙箱）    │ │   │            │
        │  │ · userns+mountns：bind-ro/遮蔽  │ │   │            │
        │  │   /tmp noexec、仅 workdir 可写  │ │   │            │
        │  │ · netns 零外网，唯一出口经 ─────┼─┼───┘            │
        │  │   Broker 用户态网络栈           │ │                │
        │  │ · seccomp filter：execve→notify │ │                │
        │  │ · 解释器钩子（Py audit/Node     │ │                │
        │  │   permission via env）          │ │                │
        │  └─────────────────────────────────┘ │                │
        │  ┌─ safe-broker（supervisor program，Go/arm64 静态）─┐│
        │  │ · 策略缓存/验签/热更新（fail-close）              ││
        │  │ · 用户态网络栈：出站唯一通道（域名/IP/端口/大小/  ││
        │  │   超时/会话策略，可选 TLS 拦截[拍板]）            ││
        │  │ · seccomp-notify listener：execve 运行时裁决      ││
        │  │ · /proc 检测器（fd/pty/父子关系）→SIGSTOP→取证→杀 ││
        │  │ · 事件聚合 → 云侧/HIPS；心跳上报（失管可观测）    ││
        │  └──────────────────────────────────────────────────┘│
        │  supervisord（autorestart 拉起 safe-broker）           │
        │  平台 self_heal（/opt/bin，非 sandbox 可写）兜底       │
        └───────────────────────────────────────────────────────┘
```

### 组件职责

| 组件 | 身份 | 职责 | 隔离依据 |
|------|------|------|----------|
| 插件层 | gateway 进程内（sandbox） | 工具调用裁决（L-A）、审批触发、env 注入（L-B）、脚本扫描、OBS、事件总线、scope 代发 | 无（与 Agent 同进程/同 uid）——靠云侧验签与审计补偿 |
| safe-launcher | exec 包装进程 | 逐次构造 userns+mountns+netns 沙箱、装 seccomp filter、连 Broker | 内核命名空间（对子进程硬隔离） |
| exec 子进程 | sandbox（沙箱内） | 业务命令执行 | launch 时沙箱：无网/ro-bind/noexec/解释器权限 |
| safe-broker | supervisor program（sandbox） | 出站唯一通道与策略、execve 运行时裁决（L-C）、/proc 检测、事件聚合、心跳 | 无内核隔离 → 自愈+心跳+审计（§11） |
| supervisord / self_heal | sandbox / 平台 | 常驻拉起；supervisord 死→平台重启 | 平台段（/opt）可信，配置段同主（§11） |
| 云侧控制面 | — | 策略/审批/scope/OBS/失管告警的唯一权威源 | 签名密钥不出控制面 |

## 4. 分需求详细设计

### 4.1 需求 1：默认权限范围

两层定义（容器层已由平台固化、不可改 → 权限收敛全部落在**逐次 exec 的 launch 层**）：

**launch 时沙箱（safe-launcher 逐次构造，Agent 不可改）**
- userns + mountns：敏感路径（`/etc`、`~/.ssh`、`/home/sandbox/.openclaw/.xiaoyienv`、策略缓存目录）bind-ro 遮蔽或置空；`/tmp` tmpfs `noexec,nosuid,nodev`；仅 workdir 可写
- netns：默认零外网，唯一出口经 Broker 用户态网络栈（§4.5）
- `no_new_privs` + seccomp filter：禁 `ptrace`、`mount`（沙箱内再嵌套）、`reboot` 等；execve 转 notify（§4.3 L-C）
- 解释器权限：Python audit hook（`os.system`/`subprocess`/`socket`/灰路径 open → 抛异常+事件）；Node `--permission --allow-fs-read/write=<workdir>`（拒 child_process/worker）

**逻辑层（云侧下发 scope JSON）**：同 v1.1——工作目录范围、可访问云服务、默认授权项（§5）。

### 4.2 需求 2：文件安全（灰/白名单）

| 名单 | 机制 | 说明 |
|------|------|------|
| 白名单 | launch 挂载层 | workdir 可写；其余路径 ro/遮蔽/不可见。天然"非白即拒"，语言无关（T2 实测） |
| 灰名单 | 插件层确认 | L-A 解析命令中的路径（tokenize/cd 跟踪/软链展开）→ 命中灰名单 → `requireApproval`；**补充**：Python audit hook / Node permission 在解释器层拦截灰路径 open（脚本体内访问同样触发，转入事件+拒） |
| 黑名单（隐含） | 挂载遮蔽 | 沙箱内直接不可达（`.xiaoyienv`、凭证、策略缓存） |

- ~~fanotify FAN_OPEN_PERM~~ 已实测不可用（T4），**阻塞式内核文件灰名单取消**；审计如需，用 inotify（workspace 范围）或以 OBS 制品链 + 命令层事件替代。
- 兜底：子进程无特权（nnp + userns），无法 chmod/mount 逃逸沙箱。

### 4.3 需求 3：命令安全（黑/白/灰名单）

三层裁决，逐层变硬、与语言无关性递增：

**L-A 工具调用裁决（插件层 `before_tool_call`，SDK 已验证）**
- 解析 token（递归解码 base64/hex、展开软链、跟踪 cd 链）→ 本地三名单匹配
- 黑 → `{block:true, blockReason}`（结构化错误码+策略 ID）
- 灰 → **`requireApproval`**（title/description/severity/**timeoutBehavior: "deny"**/allowedDecisions/onResolution）→ 走 OpenClaw 原生审批（channel 已有 approval-bridge 文案层）
- 白 → 放行；默认策略：default-allow 常规开发命令、高危类目拦（拍板决策 1）
- 修复 CSPL 现状缺口：**CLARIFY 必须转审批**（现状放行）；扫描异常 **fail-close 可配**（现状 fail-open）

**L-B spawn 包装（`resolve_exec_env` 注入，T10b 已验证注入可行）**
- `PYTHONPATH` → sitecustomize 装 audit hooks（脚本体内的 `os.system`/`subprocess`/socket 在解释器层断）
- `NODE_OPTIONS=--permission …`（Node 24：child_process 默认拒）
- `LD_PRELOAD` → execve-shim（动态二进制 execve 转发 Broker）——减速带，静态/Go 二进制由 L-C 覆盖

**L-C 系统调用裁决（safe-launcher 装 filter + safe-broker listener，T9 实测成立）**
- launcher 在 exec 目标前装 seccomp filter（nnp，`SECCOMP_FILTER_FLAG_NEW_LISTENER`）：`execve/execveat` → RET_USER_NOTIF；filter 跨 exec/fork 继承、目标不可移除
- **脚本体内任何语言（含静态/Go 二进制）的进程派生都到 Broker 同步裁决**，复用 L-A 同一套名单；灰名单在 syscall 层无法挂起等审批 → 同步拒并提示改走工具调用层
- `connect/bind/listen` 默认不入 filter：出站由 netns+Broker 网络栈硬管（§4.5），性能与硬度兼优；userns 不可用环境的备选才启用 connect notify

**脚本感知（内容层，与 CSPL 已有链路整合）**

| 调用形式 | 动作 |
|----------|------|
| `python3 x.py` / `bash x.sh` | L-A 读脚本 → 本地规则（`socket+dup2+pty` 组合直接黑）→ 可疑转审批；同时 OBS 上传云扫（§4.8） |
| `python3 -c "…"` / 管道入解释器 | 内联代码等同脚本扫描 |
| `curl … \| bash` | 远程代码执行，默认黑名单或强灰 |
| `pip/npm/yum install` | 安装即执行任意代码 → **默认灰名单**（yum 在线安装使"镜像不预装"只是减速带） |

### 4.4 需求 4：批量删除审批

- L-A tokenize：`rm` 带 `-r`/通配符/多参数，或展开目标数 > 阈值 N → `requireApproval`；
- **删除改隔离**：实际执行为 `mv` 到 workdir 内隔离区（`/.quarantine/<ts>/`，sandbox 可写即可，无需 root），确认后真删，误删可恢复；
- 脚本体内的删除：脚本整体按灰名单对待（§4.3 内容扫描），且已上传 OBS 可审计（§4.8）；解释器钩子（L-B）在 `os.remove`/`shutil.rmtree` 上置审计事件。

### 4.5 需求 5：安全网关

**(a) 出站管控——容器内主管道 + 平台兜底**

- **主管道（容器内自助，T1 实测）**：exec 子进程 netns 零外网；safe-broker 运行**用户态网络栈**（Go：gVisor netstack 类），是沙箱唯一出站通道：
  - 域名/IP 黑白名单（URL 黑名单拦截）；CONNECT 限 443；协议仅 HTTP/HTTPS
  - 请求体大小限制、连接/读超时、单连接字节上限、beacon 节律检测
  - DNS 由 Broker 代理解析（防 DNS 隧道；限速/记录类型/高熵子域）
  - **TLS 拦截[拍板项]**：流量既经 Broker，拦截点天然在位；私有 CA 预置依赖镜像需求（平台需求单），证书固定失败的连接本身即告警
- **平台兜底（需求单，唯一平台通道）**：NetworkPolicy egress 默认拒绝，放行云侧服务网段（控制面/OBS/HIPS/审批）+ DNS；维持 169.254.169.254 封禁现状——即使 userns 被绕过，平台层仍有第二道
- 应用层减速带：env 注入 `http_proxy` 指向 Broker（覆盖自觉走代理的工具）

**(b) 入站管控**
- 平台现状零暴露（需求单确认无 Service/Ingress/NodePort 暴露、非 hostNetwork）
- Agent 本地服务仅监听 `127.0.0.1`（自律 + Broker /proc 检测发现非 loopback listen 即事件）
- 需对外暴露的服务经**云侧 gateway 反向代理**显式开通 + 鉴权；规则云侧管控

### 4.6 需求 6：HIPS 入侵检测

- **事件源统一**：L-A 裁决记录（block/approval）、L-B 解释器钩子事件、L-C execve 拦截、Broker 网络事件（拦截/beacon/长会话）、/proc 检测命中——全部进插件层事件总线；
- 对接：JSON over socket/HTTPS 推给 HIPS（冯经理），Schema 含 ts/pid/uid/事件类型/对象/判定/策略 ID；HIPS 判定可回写 → 转阻断（kill 指令经 Broker 执行）；
- 分工：沙箱侧**喂数据 + 执行阻断**，HIPS **检测判定**。

### 4.7 需求 7：用户授权范围

- 插件层维护 **scope token**：默认授权（云侧下发）+ 交互授权（审批时累积，可设有效期/次数——OpenClaw 原生 allow-always 的作用域需与 E1 对齐收敛）；
- **凭证现实模型（T8 实测暴露成立）**：`.xiaoyienv` 与 Agent 同主可读，"凭证 Agent 不可读"在无 root 下**做不到** → 转向：
  1. 云侧调用凭证改发**短期 scope token**（对接 PICOD 鉴权模型：static 公钥 + TTL），本地仅存短期缓存；
  2. 即使泄露，能力受 scope 限制 + 云侧可吊销 + 调用全审计；
  3. `.xiaoyienv` 在 launch 沙箱中遮蔽（§4.2），exec 子进程不可读——**凭证面收窄到 gateway 进程内**，而 gateway 进程内存与 Agent 派生进程同 uid 可读属 §11 披露风险。

### 4.8 需求 8：制品上传 OBS

- **复用已有链路**：CSPL `upload_file.ts`（exec 命令→提取代码文件→SHA256→OBS）+ `plugin-scope/skill_scope_hook.ts`（`before_install`：hash+zip 上传+云扫 ACCEPT/REJECT 阻断）已覆盖主链路；
- 本方案补：内容哈希去重缓存、云扫判定回写本地名单（allow/grey/deny 按哈希缓存）、skill/plugin/专家团安装全量纳入；
- OBS 快照链 + 事件总线 = "哪段代码、什么时间、干了什么"的完整审计。

### 4.9 现实边界与兜底（无 root 版）

无论入口层是否被绕过，以下对每个 **exec 子进程**生效（由 launcher 逐次构造，内核保证）：

| 攻击意图 | 拦截点 | 硬度 |
|----------|--------|------|
| 直连外网外发数据 | netns 零外网；唯一出口 Broker 网络栈（策略+审计） | 硬（内核命名空间） |
| 读敏感文件（凭证/策略/其他会话） | 路径遮蔽/bind-ro（mountns）+ 解释器钩子 | 硬（挂载层） |
| 写工作目录外文件 | 仅 workdir 可写；其余 ro | 硬 |
| 落地二进制执行 | /tmp noexec；execve 经 Broker 裁决（L-C） | 硬-中（L-C 依赖 Broker 存活，§11） |
| ptrace 其他进程/提权 | nnp + seccomp 禁 ptrace/mount；userns 内无额外权限 | 硬 |
| 脚本体内派生（os.system 等） | L-B 解释器钩子 + L-C execve 裁决 | 中-硬 |
| **杀 safe-broker / 摘 supervisor 程序 / 改本地策略缓存** | **无内核阻挡（同 uid）** → supervisor 拉起 + 心跳失管告警 + 验签 fail-close + 全量审计 | **软（§11 披露）** |
| 端口暴露到宿主 | 平台零暴露 + loopback 自律 + /proc 检测 | 平台硬 |

## 5. 策略配置 Schema（v2 草案）

```json
{
  "version": 42,
  "signature": "<云侧签名>",
  "scope": {
    "workdir": ["/home/workspace", "/home/sandbox/.openclaw/workspace"],
    "cloud_services": ["obs", "approval", "policy", "hips"],
    "default_grants": ["fs:read:workdir", "net:egress:broker"]
  },
  "files": {
    "whitelist_mount": ["/home/workspace/**", "/home/sandbox/.openclaw/workspace/**"],
    "greylist": ["**/.env", "**/*.pem", "**/id_rsa*"],
    "readonly": ["/etc/**", "/opt/**"],
    "hidden": ["/home/sandbox/.openclaw/.xiaoyienv", "/home/sandbox/.openclaw/safe/**"]
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
    "greylist": ["rm -r *", "pip install *", "npm install *", "yum install *", "curl *", "wget *"],
    "delete_threshold": 3,
    "approval": { "timeout_behavior": "deny", "timeout_ms": 120000 }
  },
  "exec_control": {
    "userns_sandbox": true,
    "seccomp_notify_execve": true,
    "interpreter_hooks": { "python_audit": true, "node_permission": true },
    "ld_preload_shim": true
  },
  "network": {
    "egress": {
      "mode": "broker_netstack",
      "domain_blacklist": ["*.evil.com"],
      "domain_whitelist": [],
      "new_domain_policy": "grey",
      "protocols": ["http", "https"],
      "connect_allow_ports": [443],
      "tls_intercept": false,
      "websocket": "grey",
      "max_request_bytes": 10485760,
      "max_session_seconds": 300,
      "beacon_detect": true,
      "deny_ip_ranges": ["169.254.169.254/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      "allow_ip_ranges": ["<云侧服务网段>"]
    },
    "ingress": { "expose_via_gateway_only": true }
  },
  "reverse_shell": {
    "fd_socket_scan_interval_ms": 2000,
    "pty_audit": true,
    "abnormal_parent_detect": true,
    "on_detect": "sigstop_forensics_kill_report"
  },
  "obs": { "bucket": "sandbox-artifacts", "dedup_by_hash": true },
  "hips": { "endpoint": "/run/safe/hips.sock", "enabled": true },
  "broker": { "heartbeat_interval_ms": 30000, "self_check_rpc": true }
}
```

- 验签与版本号后热更新；缓存落盘 sandbox 拥有（同主可改 → **验签 fail-close**：加载失败拒绝启动管控组件并上报告警）。
- `deny_ip_ranges` 含 `10.0.0.0/8` 时注意：K8s DNS（10.247.3.10）与云侧服务网段必须在 Broker 侧显式例外（清单 C7 实测结论）。

## 6. 关键接口（v2 草案）

**工具调用裁决（OpenClaw 原生，无需自建 RPC）**
```jsonc
// before_tool_call 返回：
{ "block": true, "blockReason": "E_DENY_PIPE_EXEC" }
// 或：
{ "requireApproval": { "title": "高风险命令确认", "description": "…",
    "severity": "warning", "timeoutMs": 120000, "timeoutBehavior": "deny",
    "allowedDecisions": ["allow-once", "allow-always", "deny"],
    "onResolution": "…" } }
```

**环境注入（OpenClaw 原生）**
```jsonc
// resolve_exec_env（toolName=exec, host=gateway|sandbox|node）返回合并 env：
{ "PYTHONPATH": "/home/sandbox/.openclaw/safe/hooks:…",
  "NODE_OPTIONS": "--permission --allow-fs-read=/home/workspace …",
  "LD_PRELOAD": "/home/sandbox/.openclaw/safe/execve-shim.so",
  "HTTP_PROXY": "http://127.0.0.1:18080", "HTTPS_PROXY": "http://127.0.0.1:18080" }
```

**launcher ↔ Broker（容器内 Unix socket，内部接口）**
```jsonc
→ {"method": "prepare_exec", "policy_ver": 42, "cmd_fingerprint": "…"}
← {"verdict": "run", "sandbox": {"net": "broker", "mounts": "default", "notify_fd": "<passed>"}}
```

**HIPS 事件**（同 v1.1 Schema，事件源扩展为 L-A/L-B/L-C/Broker 网络/检测器）

## 7. 环境约束与机制可用性终态（实测定稿）

| 能力 | 状态（实测） | 采用路径 |
|------|--------------|----------|
| 容器配置变更 / root | ❌ 平台结论不可改 | 全部管控容器内用户态实现 |
| unprivileged userns + netns/mountns | ✅ T1/T2 | **网络与文件硬隔离主路径**（launch 时沙箱） |
| no_new_privs + seccomp user-notify | ✅ T5/T9 | L-C execve 运行时裁决 |
| Node permission（v24）+ NODE_OPTIONS 注入 | ✅ T10/T10b | L-B Node 侧解释器收敛 |
| Python ≥3.8 audit hook | ✅ 3.12.10 | L-B Python 侧 |
| cgroup freezer | ❌ 只读（T3） | L3 处置 SIGSTOP→取证→SIGKILL |
| fanotify（含审计类） | ❌ EPERM（T4） | 文件审计改 inotify（workspace）/OBS 链 |
| iptables / NET_ADMIN | ❌ | 平台 NetworkPolicy（需求单）+ Broker 网络栈 |
| AppArmor / SELinux | ❌ / Disabled | mountns 遮蔽替代 |
| supervisord | ⚠️ 可用但配置同主、RPC 无认证 | 常驻拉起可用；防摘除不可保证（§11） |
| SA token / K8s API | ✅ 未挂载 / 不可达 | 横向面小，需求单列为保持项 |

## 8. 落地路线图（v2 重排）

| 阶段 | 内容 | 覆盖需求 |
|------|------|----------|
| P0 | 插件层策略引擎：本地三名单 + tokenize/解码 + `requireApproval` 灰名单闭环（CLARIFY 转审批、fail-close 可配）+ 事件总线雏形 + **T11 联调** | 3（命令层） |
| P1 | safe-launcher + safe-broker 骨架（Go arm64 静态）：userns 沙箱逐次构造（mountns 遮蔽/ro-bind/tmpfs noexec）、netns+用户态网络栈出站策略、supervisor 注册、心跳 | 1, 2(白), 5(a) |
| P2 | L-B 解释器钩子（Python audit hook、Node permission、LD_PRELOAD shim 评估）+ L-C seccomp-notify execve 裁决 | 3（脚本体内） |
| P3 | 批量删除隔离区 + 灰名单审批体验（channel approval-bridge 文案）+ OBS 上传整合去重 | 4, 2(灰), 8 |
| P4 | scope token（云侧短期）+ 凭证面收窄（`.xiaoyienv` 遮蔽）+ 审批授权累积 ledger | 7 |
| P5 | HIPS 联调（冯经理）+ /proc 反连检测（SIGSTOP 版）+ beacon/长会话检测 + 平台需求单跟踪落地 | 6, 5(b), 反连 |

工程要点：Broker/launcher 用 Go 静态编译（arm64）；插件层 TS 复用 xy_channel 现有 CSPL/safe_exec 结构；所有"装 filter/建 ns"逻辑只在 launcher，保持单一代码路径。

## 9. 与原方案（及 v1.1）的差异说明

| 原方案 | v1.2 | 原因 |
|--------|------|------|
| root Daemon + PID 1 | 插件层（gateway 内）+ supervisor 常驻 safe-broker（同 uid） | 任何路径无 root，容器定义不可改（A4） |
| iptables owner match 封出站 | exec 沙箱 netns 零外网 + Broker 用户态网络栈 | 无 NET_ADMIN；T1 实测 userns 可行 |
| fanotify 灰名单阻塞确认 | 插件层 requireApproval + mountns 遮蔽 + inotify 审计 | T4 实测 fanotify 全不可用 |
| 容器级只读 fs / cap-drop / seccomp | launch 时逐次沙箱（mountns ro-bind / nnp+seccomp） | 容器不可配；T2/T5/T9 实测可行 |
| cgroup freezer 冻结取证 | SIGSTOP→取证→SIGKILL | T3 实测 cgroup fs 只读 |
| 凭证 Daemon 持有 Agent 不可读 | 云侧短期 scope token + 挂载遮蔽 + 泄露面限额 | T8 实测同主可读 |
| "Agent 无法杀 Daemon/改策略" | **不再承诺** → 自愈+心跳+验签 fail-close+审计（§11） | 同 uid 无内核隔离 |
| 读 /proc 发现违规后 kill | 三层同步裁决（L-A/L-B/L-C）+ /proc 仅作 L3 补充 | TOCTOU 竞态（v1.1 已述） |

---

## 10. 反弹 Shell 防御（v2 重排）

> 底线目标（修正）：**即使攻击者在 exec 子进程内获得任意代码执行，也无法出网绕过 Broker、无法读到被遮蔽的凭证/策略、无法持久化**；对"杀安全组件"类攻击，保证**失管可观测、状态可恢复、行为全留痕**（不再承诺组件不可穿透，§11）。

### 10.1 攻击面在新架构下的处境

| 手法 | 处境（v2） |
|------|------------|
| 原始 TCP 反连（bash /dev/tcp、nc -e、python socket） | **先天死亡**：netns 零外网，connect 无处可去；L-C execve 层还有名单兜底 |
| Bind shell（nc -l） | **先天死亡**：平台零暴露 + 沙箱内 listen 无路由可达；/proc 检测补刀 |
| SSH 反向隧道 | 镜像裁剪 ssh client（需求单）；协议层 Broker 仅放 HTTP/HTTPS |
| **隧道化反连（主战场）** | 骑在 Broker 通道上：CONNECT 限 443、WS 灰名单、新域名灰名单、beacon/长会话检测、可选 TLS 拦截 |
| DNS 隧道 | DNS 由 Broker 代理解析：限速/记录类型/高熵检测 |
| 横向移动 | 元数据平台已封（保持项）；SA token 未挂载、K8s API 不可达（实测）；Broker deny RFC1918（DNS/云侧例外） |

### 10.2 防御分层（机制已替换为 v2 对应物）

**L0 通道切断**：netns 零外网（T1）+ 平台 NetworkPolicy（需求单）。
**L1 代理层管控（主战场）**：全部收敛到 safe-broker 用户态网络栈一点——端口白名单、TLS 拦截[拍板]、`websocket: grey`、`new_domain_policy: grey`、行为检测（`max_session_seconds`/字节上限/beacon）、DNS 代理解析。
**L2 进程层减速带**：镜像不预装 nc/socat/ssh（yum 可装回 → 仅是减速带）；命令黑名单特征串；脚本扫描规则；launch 沙箱 noexec tmpfs；L-B 解释器钩子（Python audit / Node permission）。
**L3 运行时检测**：Broker 周期扫 /proc（fd0/1/2 为 socket、pty 分配、异常父子关系）；命中处置 **SIGSTOP→采集（cmdline/五元组/父链）→SIGKILL→事件上报**（freezer 已实测不可用，T3）。
**L4 爆炸半径（诚实版）**：

| 攻击者想 | 实际结果 |
|----------|----------|
| 提权 root | 无 root 可提（全体 uid 1001）；nnp+seccomp 无路径 |
| 直连 C2 绕过 Broker | netns 零外网 → 无处可连 |
| 偷云凭证/横向 | 凭证文件被遮蔽（§4.7）；SA token/元数据/API 三面皆空（实测） |
| **杀 Broker / 摘 supervisor 程序** | **能做到** → supervisor 拉起恢复；心跳缺失云侧告警；行为留痕可追责（§11） |
| 持久化 | 仅 workdir 可写；平台重启即清（tmpfs noexec + 平台镜像还原） |
| 读敏感数据 | 遮蔽路径不可达；灰路径触发审批/事件 |

**结论**：反连 shell 的最大爆炸半径 ≤ 一个"无网、无凭证、无持久化"的 exec 沙箱内权限；组件级破坏可恢复、可观测。底线由 **launch 时沙箱（内核命名空间）+ 云侧 scope** 保证，不依赖检测永远有效，也不依赖安全组件不可穿透。

## 11. 无 root 现实下的风险披露（诚实清单）

以下风险来自"全进程同 uid、容器不可配"的硬约束，无法在设计内消除，列明缓解与接受理由：

| # | 风险 | 缓解 | 残余接受 |
|---|------|------|----------|
| R1 | Agent 可 kill safe-broker / launcher | supervisor autorestart 拉起；Broker 心跳上云，缺失即告警；kill 行为本身产生事件 | 接受：失管窗口秒级~分钟级，可观测可恢复 |
| R2 | Agent 可改 `/home/sandbox/supervisord.conf` 摘除安全程序，或经 **无认证 XML-RPC（127.0.0.1:9001）** 停程序/shutdown supervisord | Broker 周期自检 RPC 状态 + 心跳；平台 self_heal 兜底重启；**平台需求单**：评估 RPC 加认证或关 inet_http_server | 接受：失管直至平台介入，云侧可见 |
| R3 | 本地策略缓存/插件代码与 Agent 同主可改 | 验签 fail-close（缓存被改→拒绝加载→告警）；插件代码完整性哈希上云巡检 | 接受：只能破坏可用性，不能伪造授权 |
| R4 | `.xiaoyienv`（PERSONAL-API-KEY）同主可读 | 挂载遮蔽使 exec 子进程不可达；云侧改短期 scope token | 接受：gateway 进程面残留（同 uid 内存可读），靠 scope 限额+吊销+审计 |
| R5 | userns 沙箱被内核 0day/Nday 逃逸（5.10 aarch64 攻击面） | 平台补丁基线（需求单）；L1 网络管控独立于 userns（Broker 通道策略） | 接受：内核 CVE 属平台治理面 |
| R6 | seccomp-notify 的 Broker 死亡 → 被挂起 syscall ENOSYS（可用性） | notify fd 双份托管（launcher+broker）；supervisor 拉起；事件告警 | 接受：fail-closed 方向正确，影响为可用性非安全性 |
| R7 | 放行域名上的 C2（CDN/域前置） | new_domain grey + 行为检测 + 云侧 scope 限额 | 接受并审计（v1.1 已述） |

**平台需求单**（上述 R2/R5 及网络/镜像类事项）见《平台需求单》文档，是 C6 的落地物。
