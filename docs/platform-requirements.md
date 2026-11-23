# 平台需求单（C6 落地物）

> 版本：v1.0　日期：2026-11-23　配套：《云侧沙箱安全管控方案设计》v1.2、《实施清单》v1.2
> 背景：沙箱容器定义不可改、全程无 root（A4 平台结论）。以下事项是容器内方案无法自助、**只能由平台侧落地**的部分，按"必须 / 保持 / 评估"分级。除注明外均不改变现有容器启动配置的框架，属于配置项增改或现状确认。
> 对接方：平台/基础设施团队（CCE Pod spec、镜像构建、网络策略）。

---

## A. 必须项（安全主链路依赖）

| # | 事项 | 具体内容 | 依据 |
|---|------|----------|------|
| A1 | **egress NetworkPolicy** | 对沙箱 Pod 下发 NetworkPolicy：出站默认拒绝；放行：①云侧控制面/审批/OBS/HIPS 服务网段与端口（清单另附）；②集群 DNS（10.247.3.10:53）；③（可选）内部 resolver | 容器内 userns 沙箱是主防线，本项为**平台层第二道**：即使 userns 被绕过，直连外网仍被平台拒绝。设计 §4.5/§10.2 L0 |
| A2 | **维持云元数据封禁** | `169.254.169.254` 当前平台侧已不可达（D1 实测），要求列入平台基线、不随版本退化，并提供回归验证手段 | 防凭证窃取横向；设计 §10.1 |
| A3 | **镜像裁剪与预置**（镜像构建方） | ①删除 **ssh client**（反连隧道现成工具，B2 实测存在）；②评估 **gcc** 去留（可在沙箱内自编译反连工具；若构建链必需则保留并说明）；③预置**私有根 CA** 到系统信任库（若拍板启用 TLS 拦截，D6）；④内置 `safe-launcher` / `safe-broker` 二进制（Go 静态编译，**arm64**）与目录规划（`/home/sandbox/.openclaw/safe/`） | 设计 §4.3 L2、§4.5、§8-P1 |
| A4 | **supervisor 安全加固评估** | 现状：`[inet_http_server] 127.0.0.1:9001` **无认证**，本地任意进程可调用 XML-RPC 停/起任意 program 或 shutdown supervisord（T7b 实测）。请求：①加 username/password 或关闭 inet_http_server（改 unix socket + 文件权限）；②将 `safe-broker` 纳入平台视角的关键进程清单 | 设计 §11-R2；不加认证前，安全组件可被 Agent 经 RPC 摘除，只能"失管可观测"无法"防摘除" |
| A5 | **supervisord.conf 完整性** | 该文件位于 `/home/sandbox`（与 Agent 同主可写）。请求平台自愈链（`/opt/bin/self_heal.py`）增加：配置完整性检查（哈希基线）或被改时回滚重启 | 设计 §11-R2 |

## B. 保持项（现状良好，要求不退化）

| # | 事项 | 现状（实测） | 要求 |
|---|------|--------------|------|
| B1 | SA token 不挂载 | `/var/run/secrets/kubernetes.io/serviceaccount/` 不存在（T6） | 保持 `automountServiceAccountToken: false` |
| B2 | K8s API 不可达 | `https://10.247.0.1:443` 连接失败（D2 小样） | 保持（与 A1 策略一致） |
| B3 | 非 root 运行 | 全体进程 uid 1001（A8/C1） | 保持，**不要**因任何需求放开容器内 root/sudo |
| B4 | 容器零暴露 | 无端口发布（推定，C3 待平台确认回执） | 保持；任何暴露需求经云侧 gateway 反代 |
| B5 | cgroup fs 只读 | 实测只读（T3） | 保持现状即可（无需改） |
| B6 | `KUBERNETES_SERVICE_HOST` 清理 | env 中为空（B8） | 保持 |

## C. 确认项（需平台回执的事实）

| # | 事项 | 待确认内容 |
|---|------|-----------|
| C1 | privileged 基线 | 确认 Pod `securityContext.privileged=false`、无 hostPID/hostIPC |
| C2 | 网络模式 | 确认非 hostNetwork（C2 关闭项的回执） |
| C3 | 暴露面 | 确认无 Service/Ingress/NodePort 指向沙箱 Pod |
| C4 | self_heal 行为 | `/opt/bin/self_heal.py` 的职责边界：supervisord 死亡→容器/Pod 重启的触发链路与时长（设计 §11 依赖其兜底） |
| C5 | 内核补丁基线 | 内核 5.10.0-182（hce2 aarch64）的 CVE 补丁节奏；**unprivileged userns 开放是既定策略**（T1 实测可用）——知悉并确认不计划关闭（关闭将击穿设计 §4.1 的 launch 沙箱主路径，需提前预警） |
| C6 | seccomp 默认策略 | 确认容器运行时未禁用非特权 seccomp filter（T5/T9 实测可用，同为知悉确认） |

## D. 变更沟通机制

- A/B 类任一项的计划变更（尤其 B3 放开 root、C5 关闭 userns、A2 元数据策略变化）需**提前通知安全方案侧**——这些是容器内方案的支柱假设，单方面变化会静默降级整体安全水位。
- 建议将本需求单的回执纳入《实施清单》E 组跟踪（每项：接受/拒绝/排期）。

---

## 附：本需求单不请求的事项（避免评审误会）

- **不请求**容器内 root、sudo、NET_ADMIN、SYS_ADMIN 等任何提权——方案已按"全程无 root"设计（Broker v2：userns 沙箱 + seccomp user-notify，均经 T1/T2/T5/T9 实测可行）；
- **不请求**修改容器启动命令/entrypoint——安全组件经 supervisord 注册常驻（模板已验证：`[program:x] autorestart=true killasgroup=true`）；
- **不请求**变更 cgroup 配置。
