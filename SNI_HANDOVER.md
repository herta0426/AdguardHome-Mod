# SNI 专用交接文档

> 状态日期：2026-10-18
> 适用代码：本仓库 `codex/client-v2` 分支
> 当前基线：本地 `d865d7f6`，对应远端 `herta0426/AdguardHome-Mod:codex/client-v2` 的 `08b4e9829e1c80fb2c0fcd71375a473bc8f97189`（两者 Git tree 相同）

本文只讨论 AdGuard Home 的 SNI 过滤与 NFQUEUE 链路。它不是 AdGuard Home 的完整交接文档，也不讨论内核本身如何修复。

## 1. 先看结论

目前不能把 SNI 当成“已经完全稳定”的功能。当前比较可靠的基线是远端 `08b4e982...`：

- callback 明确退出后，队列可以重建；
- verdict 写失败时，callback 会停止并尝试重建；
- 但 callback 卡死、旧队列 `Close` 卡住、或者重建只失败一次，进程内都不一定能恢复；
- `b602ac4...` 的 timerfd watchdog 已经确认会引入 SNI 正常处理中断的回归，不能直接恢复使用。

另外还有两个需要分开的已知问题：

1. **跨 TCP 段的 ClientHello 可能根本不会进入拼接逻辑。** 这是当前代码路径上的确定性缺陷，不只是查询日志显示问题。
2. **压测或异常流量之后，进程可能失去恢复能力。** 现有自愈只覆盖“callback 返回了错误”的情况，覆盖不了“callback 或旧队列关闭卡住”的情况。

现场看到的“队列行还在、`id_seq` 还在增长”，只能证明 NFQUEUE listener 还活着，不能证明 SNI 已经正确解析并写入查询日志。反过来，`querylog.json` 文件时间停在十几分钟前，也不能单独证明 SNI 失效，因为查询日志文件是按内存条数批量刷盘的。

## 2. 版本与现场对照

### 2.1 版本边界

| 本地提交 | 远端提交 | 状态 | 说明 |
| --- | --- | --- | --- |
| `d865d7f6` | `08b4e982...` | 已知正常基线 | callback 错误后重建队列，并处理缺失 payload |
| `cfc2753e` | `2b491aed...` | 未完全确认 | 在上一版基础上增加可恢复 verdict 写错误的有界重试 |
| `f7ca87d5` | `b602ac4e...` | 有问题 | 新增 timerfd 健康 watchdog 和强制关闭/重建路径，出现 SNI 正常流量停止处理的回归 |
| `550dca56` | `01e992fb...` | 回退提交 | 回退 `b602`，回到 `2b491` 对应代码树 |
| `54c2114c` | `3420b2ea...` | 文档提交 | 增加过一版队列恢复方案文档 |

当前工作树已经回到 `d865d7f6`，远端分支也已经指向 `08b4e982...`。PR [#18](https://github.com/liuzq2002/AdguardHome-Mod/pull/18) 当前指向该提交。

不要为了“让旧 watchdog 代码看起来更积极”而回退到 `f7ca87d5`/`b602ac4e` 的 timerfd 实现。那里的风险不是参数调小一点就能解决的：旧队列尚未真正 unbind 时就去 bind 同一个 queue number，会触发 `EBUSY`、netlink sequence mismatch 或后续 watcher 直接退出。

### 2.2 一次现场 dump 的正确读法

一次真机 dump 中看到类似：

```text
7 2076 5 2 65531 0 0 88016 1
```

对应 `/proc/net/netfilter/nfnetlink_queue` 的列为：

| 列 | 含义 | 本例 |
| --- | --- | --- |
| 1 | queue number | `7` |
| 2 | peer port ID，也就是绑定该队列的用户态进程 | `2076` |
| 3 | 当前未裁决包数 `queue_total` | `5` |
| 4 | copy mode | `2` |
| 5 | copy range | `65531` |
| 6 | 内核因队列满等原因丢弃的累计数 | `0` |
| 7 | 用户态投递失败累计数 | `0` |
| 8 | 累计入队序号 `id_sequence` | `88016` |
| 9 | 内核输出中固定为 `1` 的尾列 | `1` |

因此这一行说明的是：

- 队列号是 7；
- peer PID 是 2076；
- 采样瞬间有 5 个包在等待判决；
- 内核 dropped 为 0；
- `id_seq` 已经到 88016。

它**不能**说明：

- 当前查到的 SNI 是否正确；
- 正常浏览器的 ClientHello 是否被解析；
- querylog 是否写入了对应条目；
- 注入的 RST 是否到达客户端。

`queue_total=5` 是很常见的瞬时 burst，不是故障阈值。看队列必须看趋势：持续接近 `1024`、`id_seq` 不增长、或者 `dropped` 持续增长，才是有意义的异常信号。

## 3. 当前数据路径

### 3.1 启动条件

SNI 过滤不是独立开关，只在 `filtering.blocking_mode: strong` 时启动：

- 生命周期入口：[internal/home/dns.go](internal/home/dns.go:149) 的 `sniFilterActive`；
- 启停同步：[internal/home/dns.go](internal/home/dns.go:164) 的 `syncSNIFilter`；
- 默认 queue number 和端口：[internal/home/config.go](internal/home/config.go:527)。

当前配置里已经没有 `sni_filter.enabled`。强模式开启时无条件注册队列；旧 YAML 里若还留着这个键，不要拿它判断当前是否生效。

因此排查“完全没有 SNI”时，第一步必须确认当前拦截模式确实是强力模式，而不是默认模式。

### 3.2 外部规则

AdGuard Home 不安装 iptables 规则，规则由 Magisk 模块脚本维护。当前设备脚本（20261010）大致做两件事：

1. 在 `filter` 表建立 `AGH_SNI` 链并挂到 `OUTPUT`；
2. 对配置端口中的 TCP 载荷包执行 `NFQUEUE --queue-num <queue_num> --queue-bypass`。

脚本还会处理：

- `-o lo -j RETURN`，排除 loopback；
- 纯 ACK 不排队；
- IPv4 和 IPv6 各一份规则；
- 按配置拒绝 UDP/443，迫使 HTTP/3 回到 TCP TLS。

规则和 AGH 配置必须一致：

- 规则里的 queue number 必须等于 YAML 的 `sni_filter.queue_num`；
- 规则的端口集合必须覆盖 YAML 的 `sni_filter.ports`；
- 缺少 IPv6 规则时，IPv6 网站不会有 SNI 记录；
- `--queue-bypass` 在队列实例不存在或没有 listener 时会把包直接放行，所以“没有断网”不等于“SNI 正常”。

当前设备脚本使用 `-m multiport` 合并端口。目标设备已经证明能安装这条规则，但某些 Android 内核没有 `xt_multiport`，那时整条链可能装不上。换设备时应先用 `iptables -C` 和 `iptables -S AGH_SNI` 验证，不要假设所有 ROM 一样。

还要核对当前部署脚本是否真的带有 `connbytes`。附件中的 20261010 脚本只有：

```sh
--tcp-flags ALL ACK -j RETURN
--tcp-flags SYN,FIN,RST NONE -j NFQUEUE --queue-num <n> --queue-bypass
```

它没有 `-m connbytes --connbytes ...`。在这种情况下，目标端口上的所有非纯 ACK 数据包都会进入 NFQUEUE，而不是只有 ClientHello 开头的一小段。上传、下载和代理流量都会放大内核复制和用户态判决压力；这与旧 `HANDOVER.md` 中描述的“只取前 20 KB”不是同一套规则。部署前应以设备上的实际脚本为准，不能只看文档。

### 3.3 用户态处理

核心路径：

```text
NFQUEUE callback
  -> handlePacket
  -> isTLSHandshake 快速判断
  -> parsePacketInto / inspect
  -> sniffSNI
  -> CheckHostRules
  -> NF_ACCEPT / NF_DROP
  -> logConnection
```

代码位置：

- [internal/snifilter/firewall_linux.go](internal/snifilter/firewall_linux.go:521) `handlePacket`
- [internal/snifilter/snifilter.go](internal/snifilter/snifilter.go:565) `isTLSHandshake`
- [internal/snifilter/snifilter.go](internal/snifilter/snifilter.go:351) `inspect`
- [internal/snifilter/clienthello.go](internal/snifilter/clienthello.go:71) `sniffSNI`
- [internal/snifilter/snifilter.go](internal/snifilter/snifilter.go:428) `logConnection`

命中规则时会给两端构造并发送 RST，并把该连接标记为已拦截；之后属于这条连接的包（不只是重传的首段）继续返回 `NF_DROP`。未命中时返回 `NF_ACCEPT`，包继续走内核原来的路由。

2026-10-18 起入口闸门从 `isTLSHandshake` 换成 `needsInspect`：以 ClientHello 开头的新包照旧短路放行，已跟踪连接的续包（以及已判决为拦截的连接的后续包）也会进入 `inspect`，这是“后续包继续 DROP”成立的前提。同一批改动还带来两点行为：

- 暂停保护时队列不重建，只在判决层放行：连接照样解析、照样写 SNI 查询日志，但不发 RST、不返回 `NF_DROP`；恢复后已判决为拦截的连接立即重新 DROP。
- 规则仍然排除 SYN，所以 flow 的起始序号只能乐观同步；如果某条连接的**第一个进入队列的段不是 ClientHello 开头**，这条连接不会被跟踪，也就不会被拦截（见第 5 节）。

### 3.4 查询日志表现

client_v2 里的对应关系已经接上：

- `FilteredSNI` 显示为“已阻止（SNI）”，归入“已阻止”；
- `NotFilteredSNI` 显示为“已处理（SNI）”，归入“已处理”；
- SNI 记录详情会显示目标地址，不显示 DNS 协议；
- 接口侧可以用 `reason=12`/`reason=13` 区分被阻止和放行的 SNI 条目。

因此“状态列显示已处理”并不代表它不是 SNI；要看原因列或展开详情。若界面只看到 DNS 记录、完全没有 SNI 条目，再按下一节的顺序排查。

## 4. 当前已确认的问题

### P0：跨 TCP 段的 ClientHello 实际上拼不起来

> **状态：已修复。** 提交 `f8c30d85`（“Reassemble the TCP segments of the sniffed connections”）把闸门换成 `needsInspect` 并加入按 TCP 序号的拼接；跨段、乱序、重传与“已拦截连接的续包”都有回归测试，GitHub Actions 的 `go test ./...` 全绿。下面是修复前的问题描述，保留作背景。

`sniffSNI` 本身支持“TLS handshake 跨多个 record”的情况，并且有对应单元测试。但 NFQUEUE 入口还有一层 `isTLSHandshake`：

```text
payload[0] == 0x16
payload[1] == 0x03
payload[5] == 0x01
```

它只检查“当前这个 TCP 包的 payload 是否以 TLS ClientHello 开头”。第一个包会通过并进入 `inspect`；如果 ClientHello 没有在第一个包内结束，`inspect` 会保存这半段并返回 `errNeedMore`。但是下一个 TCP 续包的 payload 从握手中间开始，`isTLSHandshake` 会返回 false，`inspect` 根本不会被调用，后续字节不会进入 `flow.handshake`。

结果是：

- 手工构造一个完整且足够小的 ClientHello，可以正常出现 SNI 记录；
- 浏览器或 App 的真实 ClientHello 一旦跨 TCP 段，可能完全没有 SNI 记录；
- 解析器“支持跨 record”不能抵消入口“只接受以 ClientHello 开头的包”这个限制。

这不是“查询日志显示问题”，而是握手重组路径的问题。修复方向应当是：

- 对已经存在且尚未判决的 flow，在收到续包时仍然进入 `inspect`；
- 记录 TCP sequence，按序拼接，重复段和乱序段不要直接 append；
- 对没有 flow 的新包保留快速短路，不要把所有普通数据包都送进解析器；
- 增加一个真实的“跨两个 TCP 段 ClientHello”回归测试。

### P0：压测/卡死后没有可靠的进程内自愈

当前 `handlePacket` 在以下情况会返回非零：

- 收到没有 packet ID 的 NFQUEUE 属性；
- `SetVerdict` 失败；
- 其他由 nfqueue 回调报告的非临时错误。

返回值会让 callback 停止，并通过 eventfd 唤醒 watcher。watcher 随后调用 `reopenQueue`，当前实现见 [internal/snifilter/firewall_linux.go](internal/snifilter/firewall_linux.go:291)。

这个机制有两个边界：

1. **callback 自己卡住时不会触发。** 没有错误返回就没有 eventfd，socket 也未必出现 `EPOLLHUP/EPOLLERR`。此时队列可能还有包，但用户态不再消费。
2. **`reopenQueue` 不是无限重试。** 如果旧 `nf.Close()` 阻塞，或者新 queue bind 失败，watcher 记录错误后直接返回；它不会在下一个周期继续尝试。相关返回位置见 [internal/snifilter/firewall_linux.go](internal/snifilter/firewall_linux.go:413)。

所以“callback 抛错能自愈”和“整个 SNI 工作流卡死能自愈”不是同一件事。前者已有覆盖，后者不能只靠当前 watcher 解决。

不要恢复 `b602` 的 timerfd watchdog。它在旧队列关闭未完成时继续 bind 新队列，容易产生 `EBUSY`、netlink sequence mismatch，并让 watcher 退出。这个回归已经在 `550dca56` 回退。

### P1：TCP 流状态没有序列号重组

`flow.handshake` 现在只是按 callback 到达顺序 `append` 字节，没有记录 TCP sequence，也没有处理：

- 重传；
- 乱序；
- 重叠段；
- 同一连接中的重复 ClientHello 片段。

正常的本机 `OUTPUT` 流量通常比较容易保持顺序，但在丢包、重传、代理和压测环境下不能假设永远有序。最坏情况下，重复片段会让 `sniffSNI` 返回 `errNotTLS`，随后 `inspect` 会把连接标记为已判决并放行，导致本该拦截或记录的域名被漏掉。

这也是“跨 TCP 段修复”的一部分；只修入口判断而不修 sequence 管理，仍然会在重传场景下出现间歇性漏判。

### P1：查询日志文件的时间不能直接代表 SNI 事件时间

SNI 条目先进入 querylog 内存 buffer，达到 `querylog.size_memory` 后才异步刷盘。默认值见 [internal/home/config.go](internal/home/config.go:472)，当前默认是 `1000` 条。

因此：

- 管理界面搜索的是内存 buffer 加文件；
- `querylog.json` 文件的时间停在十几分钟前，可能只是还没有达到刷盘阈值；
- 判断“是否有 SNI 记录”应以管理界面或 `/control/querylog` 返回为准，不要只看磁盘文件；
- 如果界面也没有，再检查 `queryLog.Add` 是否真的被调用、`ShouldLog` 是否过滤了域名，以及 SNI 是否解析成功。

### P1：没有可靠的压测临界值

现有 `nfstress` POC 能制造 NFQUEUE 压力，但它本身并没有完整验证 SNI 正确性和恢复能力：

- 它主要发送不完整 ClientHello 或固定载荷，不能用它证明正常浏览器路径；
- 它可以制造大量 flow 和队列积压，但不能区分 callback 卡死、旧队列关闭卡死、还是重建失败；
- 当前没有可信的“正常手机流量阈值”和“极端恶意流量阈值”数据；
- 队列最大值是 1024，单次 `queue_total` 高不代表永久故障，必须看 `id_seq`、`queue_total` 和 `dropped` 的时间序列。

在拿到真机可重复数据前，不应把 POC 的 pps/cps 数字写进发布说明或作为容量承诺。

## 5. 其他已知限制

| 限制 | 影响 | 处理方式 |
| --- | --- | --- |
| QUIC/HTTP3 的 SNI 加密 | TCP SNI 过滤看不到 HTTP/3 | 规则拒绝 UDP/443，迫使回退 TCP；代价是牺牲 HTTP/3 |
| ECH（Encrypted Client Hello） | SNI 不再明文可见 | 当前无解，只能依赖 DNS/代理侧策略 |
| IPv4 分片 | 非首片没有 TCP 头，不能直接解析 | 非首片跳过；首片会解析并打 debug（“fragmented ClientHello, the SNI is likely missed”）。要彻底解决得靠上游重组或规则避免分片 |
| IPv6 扩展头 | 已支持 hop-by-hop/routing/dest-opts/AH/首片，ESP、no-next-header、非首片放弃 | 之前带扩展头的包会被整包放行且无 SNI 记录，2026-10-18 起由 `upperLayer` 统一处理；闸门与解析共用同一个 walk |
| 规则排除 SYN | flow 的起始序号只能乐观同步 | 若某连接第一个进入队列的段不是 ClientHello 开头，该连接不被跟踪（可被恶意 App 利用）。建议模块脚本**不要再排除 SYN**，让 `nextSeq` 从 SYN 的 seq+1 精确初始化 |
| 按客户端规则 | 只看全局过滤规则，不看客户端 IP | SNI 层只能使用全局规则；客户端区分应在 DNS/代理层做 |
| `uids`、`drop_quic` 配置 | AGH 不负责安装这些规则 | 实际行为由 Magisk 模块脚本决定；不要以为改 YAML 就自动改 iptables。启动时会 warn 提示这两个键不生效 |
| RST 注入 | 依赖 raw socket 和 `rp_filter` | 严格 `rp_filter` 下可能变成连接挂起而不是快速失败 |
| 队列满 | `--queue-bypass` 不能救队列满 | 队列满会丢包并增加 `queue_dropped`，需要看第 6 列 |
| 队列实例缺失 | `--queue-bypass` 会静默放行 | 最常见、也最危险的“看起来没断网但 SNI 已死”状态 |
| flow 上限 | 最多跟踪 `16384` 条 flow；另有全局握手缓冲预算 `16 MiB` 与乱序缓冲 `4 段/4 KiB × 256 flow` | 达到上限时不再清空整张表：先淘汰最旧的已判决连接，再淘汰最旧的未判决连接，仍不够就放弃本次新建（fail-open 并计数）。淘汰与预算触发都会写结构化 Warn |
| 暂停保护 | 暂停时 SNI 队列保持运行，只停止拦截 | 连接仍被解析并写查询日志（原因仍是 `FilteredSNI`、`IsFiltered` 仍为真，因为规则判定没变），但实际放行；界面暂时无法区分“已拦”和“暂停期间记录但放行” |
| 查询日志量 | 每条被解析的连接都可能写入 | 高流量设备可能快速刷掉查询日志；需要结合 `size_memory`、轮转和忽略域名配置 |

## 6. 排查“仪表盘完全没有 SNI”

按下面顺序做，不要跳步：

1. 确认 `filtering.blocking_mode` 是 `strong`，不是默认模式。
2. 确认当前 AGH 进程 PID 与队列第 2 列一致。
3. 确认 `/proc/net/netfilter/nfnetlink_queue` 中存在 YAML 的 `queue_num`。
4. 检查 IPv4 和 IPv6 的 `AGH_SNI` 链是否都存在。
5. 生成真实 TLS 流量，观察第 8 列 `id_sequence` 是否增长。
6. 观察 `queue_total` 是否在流量停止后回到 0，第 6、7 列 dropped 是否持续增长。
7. 在管理界面用域名搜索，确认出现“已处理（SNI）”或“已阻止（SNI）”。
8. 如果 `id_seq` 增长但界面没有记录，重点查 ClientHello 是否跨段、是否 ECH、是否被 `querylog.ignored` 过滤。
9. 如果队列行消失，重点查 callback 停止、旧队列关闭卡住、或 Magisk 规则/进程重启。

常用命令：

```sh
adb shell "su -c 'cat /proc/net/netfilter/nfnetlink_queue'"
adb shell "su -c 'iptables -t filter -S AGH_SNI'"
adb shell "su -c 'ip6tables -t filter -S AGH_SNI'"
adb shell "su -c 'pidof AdGuardHome'"
adb shell "su -c 'tail -n 300 /data/adb/agh/agh-self.log'"
```

关键日志：

```text
sni filter started
waiting for the packets
the nfqueue needs to be re-registered
re-registering the nfqueue
ipv4 reverse path filtering is strict
```

如果看到 `re-registering` 反复出现，说明 callback 或 verdict 路径在持续失败，不是单纯查询日志问题。如果看到一次 `re-registering` 后日志停止，且队列行也不再存在，说明 watcher 已经退出或 `nf.Close()` 卡住，需要外部 supervisor。

## 7. 故障判读表

| 现象 | 优先判断 | 下一步 |
| --- | --- | --- |
| 队列行不存在，但 iptables 链存在 | 没有 listener，`--queue-bypass` 正在放行 | 查 AGH 启动日志和进程；重启核心 |
| 队列行存在，peer PID 不对 | 队列被别的进程占用或旧进程残留 | 找 PID，杀旧进程，检查 queue number 冲突 |
| `id_seq` 不增长 | 没有包入队，或 callback 已卡死 | 先制造真实 TCP/443 流量，再看 callback 日志 |
| `id_seq` 增长，`queue_total` 持续接近 1024 | 队列消费过慢或 callback 卡住 | 看 dropped、AGH CPU/RSS、抓栈和日志 |
| `queue_total` 高且 `dropped` 增长 | 已达到单消费者上限或输入洪泛 | 先限流/缩小规则范围，再评估吞吐 |
| 队列正常但界面只有 DNS 记录 | SNI 解析/日志路径未走到 | 检查跨 TCP 段、ECH、ports、querylog ignored |
| querylog 文件时间很旧，但界面能看到新记录 | 只是尚未达到刷盘阈值 | 不需要重启；不要把它当 SNI 故障 |
| `sni_filter.enabled` 读到 true | 旧诊断脚本越界读到了别的配置段 | 当前代码没有这个键，忽略该字段 |

## 8. 恢复策略

### 8.1 当前可接受的恢复层次

1. **callback 明确返回错误**：由现有 eventfd + watcher 重建队列。
2. **watcher 重建成功一次**：恢复；但如果重建失败，当前 watcher 不会自动继续重试。
3. **callback 或 `nf.Close()` 卡死**：进程内没有可靠的自愈手段。
4. **AGH 被 OOM/panic 杀死**：只能由 Magisk service 或外部 supervisor 重启。

### 8.2 推荐的下一步：模块级外部 watchdog

外部 watchdog 应该做“观察 + 最终重启”，不要做“在进程内强制关闭回调”，因为一个 queue number 同时只能有一个 owner。

建议逻辑：

- 每 1 到 2 秒读取 `/proc/net/netfilter/nfnetlink_queue`；
- 队列行消失，或 `queue_total` 连续多个采样点不下降且 `id_seq` 不增长，判定为卡死；
- 连续 N 次异常后才触发，避免瞬时 burst 误杀；
- `kill` AGH 进程，让模块现有的 service loop 重新拉起；
- 恢复后重新验证队列绑定和真实域名 SNI 记录。

优点是不会和旧队列 bind 竞争，恢复后进程状态最干净。代价是恢复期间会有短暂 DNS/HTTP 中断。

### 8.3 `inotifyd` 不适合这个场景

`inotifyd` 监听文件系统事件，不能提供：

- `/proc` 文件内容变化的可靠事件；
- “内容在长时间内没有变化”的超时事件；
- 队列深度趋势和 `dropped` 速率。

因此不要用 `inotifyd` 替代队列健康监控。它最多能观察配置文件被替换，不能判断 NFQUEUE 是否卡死。

### 8.4 不建议恢复 `b602` 的 timerfd watchdog

`b602` 的做法会导致：

- 旧 `nf.Close()` 还没完成就尝试打开同一个 queue；
- 新 bind 失败；
- watcher 记录错误后退出；
- 后续不再监控。

如果以后仍要重做 timerfd，必须满足：

- 只做告警，不直接强杀未完成的旧队列；
- 确认旧 queue 已经从内核消失后再 bind；
- 连续多次异常才触发；
- 重启进程作为最后手段，由外部 supervisor 完成。

## 9. 验证与验收

### 9.1 正常流量

不能只用手工构造的完整 ClientHello 验证。至少做两组：

1. 用手机浏览器访问一个正常网站，确认查询日志出现 `已处理（SNI）`；
2. 故意访问一个命中拦截列表的 HTTPS 域名，确认出现 `已阻止（SNI）` 并且连接快速失败。

同时覆盖 IPv4 和 IPv6。只测 IPv4 会漏掉 `ip6tables` 规则缺失的问题。

### 9.2 跨段 ClientHello

这是必须补的真实回归场景：

- 手工构造一个 ClientHello，使 SNI 落在第二个 TCP 段；
- 第一段进入队列后，第二段必须仍然进入同一 flow 的解析；
- 最终必须能生成 SNI 查询日志；
- 如果命中规则，必须对后续包继续 DROP，不能只在第一段发一次 RST 就放行。

当前代码在这一点上不满足验收，不能把现有手工小包测试当成通过。

### 9.3 压测后恢复

至少记录以下时间序列：

- 第 8 列 `id_seq`
- 第 3 列 `queue_total`
- 第 6、7 列 dropped
- AGH RSS、CPU、PID
- `re-registering` 日志次数

通过标准：

1. 压测期间允许出现短暂 `queue_total` 上升；
2. 压测停止后 10 秒内 queue 回到 0；
3. `dropped` 不持续增长；
4. 不出现重复的重建风暴或 netlink sequence mismatch；
5. 不重启 AGH 的情况下，普通浏览器流量重新出现 SNI 查询日志；
6. 失败时保留现场，不要只记录“AGH 卡了”。

#### 9.3.1 AGH 侧自己打的指标（`internal/snifilter`）

这一批指标全部由 AGH 自己产生，不依赖模块脚本，也不需要额外工具。所有日志的 key 都是稳定的，可以直接 grep。

| 日志 | 级别 / 周期 | 关键字段 | 说明 |
| --- | --- | --- | --- |
| `nfqueue state` | Debug / 10 秒 | `queue_num`、`queue_total`、`queue_threshold`、`id_seq`、`id_seq_delta`、`dropped`、`user_dropped` | 每 10 秒的队列采样，默认级别看不到，需要 verbose |
| `the nfqueue is backed up` | Warn / 每次积压触发一次 | `queue_total`、`samples`、`id_seq`、`id_seq_per_sec`、`dropped_delta`、`user_dropped_delta` | `queue_total` 连续 3 次（≈30 秒）达到 `queue_threshold`（`maxQueueLen` 的 3/4，即 768） |
| `the nfqueue is dropping the packets` | Warn / 每段丢包触发一次 | `dropped`、`dropped_delta`、`user_dropped`、`user_dropped_delta`、`id_seq` | 内核丢包或投递失败在增长 |
| `sni filter counters` | Info / 60 秒，且只在计数有变化时才打 | `sni_pkts_received`、`sni_pkts_inspected`、`sni_truncated`、`sni_names_parsed`、`sni_querylog_written`、`sni_resets_sent`、`sni_verdict_errors` | 累计值，空闲时不打，所以不会刷屏 |
| `the packet is truncated by the nfqueue copy range` | Debug / 首次 + 每 512 个 | `src`、`dst`、`payload_len`、`truncated_packets` | 包比拷贝范围长，载荷不参与握手重组，只放行 |

这两个后台 goroutine（`watchQueueHealth`、`watchCounters`）都随 `Filter` 的 ctx 退出，而且**只读**：不重建队列、不 rebind、不动 iptables，见 §8.4。读不到 `/proc/net/netfilter/nfnetlink_queue`（容器里没有 procfs、非 Linux、队列刚被 unbind）时只在 Debug 记一条然后静默跳过，不影响过滤本身，也不会让进程或测试变红。

判读顺序：看 60 秒的 `sni_pkts_*` 差值，不要看绝对值。

1. `sni_pkts_received` 不涨：包根本没进队列。查模块规则、`queue_num` 是否与 YAML 一致、`--queue-bypass`。这时 SNI 日志本来就该是空的，和队列卡死无关。
2. `sni_pkts_received` 涨、`sni_pkts_inspected` 不涨：包进了队列但没过 `needsInspect`（不是 TLS、端口/UID 不匹配）。这是设计内的放行，不是故障。
3. `sni_truncated` 涨：拷贝范围太小，包被截断，载荷按设计不参与握手重组（只放行，不污染序号账本）。把 `internal/snifilter/firewall_linux.go` 的 `queueCopyRange` 调大（16384 → 32768 或更大）再观察；这类大段通常来自 GSO/LRO 合并。
4. `sni_pkts_inspected` 涨、`sni_names_parsed` 不涨且 `sni_truncated` 不涨：ClientHello 没拼起来（跨段、乱序、或连接还没来得及看就结束）。
5. `sni_names_parsed` 涨、`sni_querylog_written` 不涨：被 `ShouldLog` 过滤了，属于配置问题，不是抓包问题。
6. `sni_resets_sent` 涨但客户端不快速失败：RST 没送达，查 §5 里的 raw socket 与 `rp_filter`（启动时也会有一条对应 Warn）。
7. `sni_verdict_errors` 涨：队列需要重建，同时应能在日志里看到 `re-registering`，两者次数应该对得上。

区分**队列积压**和 **DNS 侧坏了**：

- `queue_total` 持续 ≥ 768 而 `id_seq` 不涨（`id_seq_per_sec` ≈ 0）：包进了队列没人收，是用户态卡住，也就是历史上“callback 卡死”的形态。
- `queue_total` 正常、`sni_pkts_received` 也不涨、SNI 日志没了：包没到队列，先查规则和 `queue_num`，不要去怀疑解析。
- 现场说的“只剩 SNI 在处理”：只要 `sni_pkts_received` 还在涨，就说明 netfilter 这条链路是活的；DNS 挂掉是另一条链路的问题，两者不要混为一谈。
- `dropped` 是内核累计丢包，`user_dropped` 是投递失败，任意一个增长都要看，不要只看第 6 列。

**拷贝范围**：本分支把队列的拷贝范围从内核默认的 64 KiB 显式改成 `queueCopyRange = 16384`（`internal/snifilter/firewall_linux.go`）。取值理由：OUTPUT 钩子看到的是 GSO/LRO 合并后的段，常见 4 KiB 到 64 KiB，4 KiB 太紧；16 KiB 覆盖绝大多数实际段，同时仍只有原来 64 KiB 的 1/4。所以 `/proc/net/netfilter/nfnetlink_queue` 第 5 列现在应该读到 `16384`；如果现场还是 `65531`，说明跑的是旧二进制，先确认版本再按 §2.2 读。

超过拷贝范围的包**不会被静默丢掉**：解析层用 IP 头声明的长度判断“实收字节数少于声明长度”，把这种包标记为截断，`addSegmentLocked` 直接跳过它（不 append、不推进 `nextSeq`、不进 pending），`inspect` 里放行并计入 `sni_truncated`。截断只影响拷进用户态的那一份，不影响裁决和 RST；连接也不会被强行判定，所以一次能装进拷贝范围的重传仍然可以正常解析。

## 10. 代码改动优先级

### 第一批（功能正确性）

- 修复跨 TCP 段的 ClientHello 拼接；（2026-10-18 完成，见 §4 P0 状态）
- 给 flow 增加 sequence/去重处理；（完成）
- 补跨段、重传、乱序的测试；（完成：`internal/snifilter/reassembly_test.go`）
- 保持新 flow 的快速短路，避免把所有 443 流量都送进完整解析器。（完成：`needsInspect` 先做无锁前缀比对）

### 第二批（可恢复性）

- 在 Magisk 模块侧增加外部 watchdog；
- 明确区分“callback 返回错误”和“callback 卡死”；
- 只有在旧队列确认销毁后才允许新建同号队列；
- 记录恢复动作和原因，便于判断是重建成功还是 supervisor 重启。

### 第三批（可观测性）

- 增加计数器：收到的包、进入解析的 flow、解析成功 SNI、无 SNI、查询日志写入、RST 发送、队列重建；
- 把计数器暴露到日志或调试接口；
- 让现场能区分“包没进队列”“包进了但没解析”“解析了但没写日志”。

## 11. 责任边界与相关文件

| 范围 | 位置 | 责任 |
| --- | --- | --- |
| SNI 解析、flow、判决 | [internal/snifilter/snifilter.go](internal/snifilter/snifilter.go) | 本仓库维护 |
| ClientHello 解析 | [internal/snifilter/clienthello.go](internal/snifilter/clienthello.go) | 本仓库维护 |
| NFQUEUE、verdict、RST、watcher | [internal/snifilter/firewall_linux.go](internal/snifilter/firewall_linux.go) | 本仓库维护 |
| 启停与强力模式 | [internal/home/dns.go](internal/home/dns.go) | 本仓库维护 |
| 查询日志存储与刷盘 | [internal/querylog/qlog.go](internal/querylog/qlog.go) | AdGuard Home 原有逻辑 |
| 查询日志 SNI 文案与目标地址 | [client_v2/src/components/QueryLog/helpers.ts](client_v2/src/components/QueryLog/helpers.ts) | client_v2 |
| `AGH_SNI` iptables 链 | Magisk 模块的 `scripts/iptables.sh` | 模块侧维护，不在本仓库 |
| NFQUEUE 内核行为 | Linux netfilter | 不靠改内核解决；只做用户态和 supervisor 兜底 |

## 12. 交接时必须带走的事实

- 当前稳定基线是 `08b4e982...`，不是 `b602ac4e...`。
- `b602` 的 timerfd 强制重建路径已经被回退，不要直接恢复。
- 单次 `queue_total=5` 不是故障；看趋势和 `id_seq`。
- `querylog.json` 文件时间滞后不等于 SNI 失效；界面和接口才反映内存 buffer。
- 真实浏览器需要覆盖 IPv4/IPv6；手工 ClientHello 只能证明正控制。
- 跨 TCP 段 ClientHello 目前有确定的入口缺陷，必须补测试和修复。
- callback 退出可以由进程内 watcher 处理；callback/关闭卡死必须由外部 supervisor 兜底。
- `inotifyd` 不能替代 NFQUEUE 健康监控。
