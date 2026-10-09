# 更新日志

本 mod 的主要改动记录在这里，上游项目的改动见 [AdGuard Home 更新日志][upstream]。

[upstream]: https://github.com/AdguardTeam/AdGuardHome/blob/master/CHANGELOG.md

## 未发布

### 新增

- **强力模式**（`filtering.blocking_mode: strong`）：被拦截的域名回**空解析（NODATA）**，同时对命中规则的 TLS 连接注入 RST。也就是把上面那条 SNI 阻断与 DNS 拦截合成一个开关：应用自己走 DoH（443 端口）或直连 IP 时本来绕过 DNS 过滤，现在也会被 RST 断掉。选这个模式会自动启用 SNI 过滤——`sni_filter` 段里已经没有 `enabled` 键，代码里也没有因为配置没开而跳过注册的路径；在界面里切换时，DNS 那一半立刻生效，RST 那一半会在配置保存时同步启停，不用重启。实现见 `internal/dnsforward/msg.go` 的 `BlockingModeStrong` 分支与 `internal/home/dns.go` 的 `syncSNIFilter`。
- **SNI 拦截加固**（`internal/snifilter/`）：NFQUEUE 回调新增**快速短路**——只做纯字节比对，非 ClientHello 包零分配、不写日志地立刻放行，只有可能带 SNI 的包才进连接表；包结构与握手缓冲用 `sync.Pool` 复用。**删除 `sni_filter.enabled`**：strong 模式下无条件注册队列，配置与代码里都不再有「因为没开而跳过注册」的路径。新增**队列丢失自愈**：用 `epoll` 监听 netlink socket 的 `EPOLLHUP`/`EPOLLERR`（不可用时退回 `poll`），内核断开队列时立刻重建并重新注册，事件驱动、不轮询。
- **SNI 进查询日志**：每条解析出 SNI 的 TLS 连接都会写进查询日志，放行的也写——域名就是 SNI，能看到实际连了哪些域名。记录的原因与 DNS 查询分开：被拦的是 `FilteredSNI`（界面显示「已阻止（SNI）」，同时仍归入「已阻止」筛选），放行的是 `NotFilteredSNI`（界面显示「已处理（SNI）」），两者都带上命中的规则——命中允许规则的 TLS 连接虽然不再显示成「允许项」，规则本身仍写在详情里。这样一眼就能分辨哪些行是 TLS 连接、哪些是 DNS 查询；接口侧也可以用 `reason=12`（被拦）与 `reason=13`（放行）单独筛。SNI 记录还带**连接的目标地址**（`destination`，形如 `192.0.2.1:443`），补上 DNS 查询本来就没有的那一维——DNS 侧只知道域名，不知道应用最终连到哪个 IP，分析时有用。主日志不再逐条打印 SNI，只在启动、停止与出错时写。
- **规则由外部脚本维护**：AdGuardHome 不再安装、清理 iptables 规则，只开 NFQUEUE、读包、发 RST；把包送进 `AGH_SNI` 链的规则交给外部脚本（Magisk 模块的 `iptables.sh` 就是这么接的，逐端口建规则，`--queue-bypass` 必带，队列号从 `sni_filter.queue_num` 读）。`sni_filter.ports` 用于用户态的快速短路（只有目的端口在列表里的包才进入解析），`uids` / `drop_quic` 仍是描述性字段，AdGuardHome 不据此安装规则，保留仅为兼容旧配置；早期为同时支持两种模式而加的 `manage_rules` 开关已删除。
- DNS 设置页的「拦截模式」重新出现两个选项：默认与强力模式（其它模式的后端实现仍在，界面不提供）。语言键 `strong` / `blocking_mode_strong` 见 `client/src/__locales/`。
- **SNI 阻断**（`sni_filter` 配置段，默认关闭，仅 Linux）：在 `filter` 表的 `OUTPUT` 链上用 NFQUEUE 读取每条 TLS 连接开头的 ClientHello，取出明文 SNI，命中过滤规则就注入 TCP RST 断开连接。它补的是 DNS 过滤的洞——应用自己走 DoH（443 端口）或直连 IP 时，DNS 层看不到；这里复用同一套过滤规则，不需要另外维护清单。需要 root 与内核支持 `connbytes`、`NFQUEUE`，缺任何一个只会记日志，不影响 DNS。新代码在 `internal/snifilter/`，配置与机制见 `doc/AdGuardHome.yaml.example` 与 [HANDOVER.md](HANDOVER.md) 第 2.6 节。
- `doc/AdGuardHome.yaml.example`：按本 mod 删减后的结构生成的配置参考模板，逐段说明哪些功能保留、哪些属于已删除功能。它只是参考，安装并不需要。
- 依赖：新增 `github.com/florianl/go-nfqueue/v2`（纯 Go，不破坏 `CGO_ENABLED=0` 的交叉编译）。

### 变更

- **同步上游基线到 AdGuardHome v1.0.0-b.1**（commit `73d4aab`，2026-09-30）：把上游 14 个提交合并进本 mod。Go 工具链与依赖升到 `go 1.27.1`、`dnsproxy v0.85.0`、`golibs v0.35.16`、`miekg/dns v1.1.73`、`quic-go v0.63.0` 等；后端带上上游的 ratelimit 白名单、dnscrypt 配置校验、`MsgHdr` 与 `slices.Backward` 等改动，前端带上过滤器与 tracker 数据更新。本 mod 有意保留的删减（`client_v2`、DHCP、安全搜索、已阻止的服务、加密设置，以及 `internal/configmgr` 的未使用重构）没有随合并复活。
- 配置迁移不再写入已删除功能的键：`internal/configmigrate` 的 v4、v18、v19、v21、v22、v26 不再生成或搬运 `use_global_blocked_services`、`safe_search`、`safesearch_cache_size`、`blocked_services`，而是把它们从老配置里删掉。迁移链路本身不变，老配置照旧能升到 schema 34。
- 同步更新迁移的测试数据与单测期望值，并修正 `internal/filtering/reason.go`、`internal/home/clients.go`、`internal/querylog/` 的 `gofmt` 对齐。
- 在线更新改用自己的更新源：新增仓库根目录的 `version.json`，`updater.DefaultVersionURL()` 指向它，发版工作流每次发版自动把它改成新版本号、发布页地址与 arm64 压缩包地址。arm64 构建默认检查更新（`--no-check-update` 可关，本地测试用的 amd64 不检查，因为不发这个包）；`--update` 也随之指向自己的版本，不会再把自己换成官方版。
- 版本号支持预发布后缀：`v2026-09-25-beta`、`v2026-09-25-rc.1` 这类 tag 会被原样用作版本号，并按 GitHub 预发布发布，不抢占「最新版本」。
- 发版只提供 arm64：Release 里放 `AdGuardHome_linux_arm64.tar.gz` 与配套的 `checksums.txt`；amd64 只上传到 Actions 产物 `AdGuardHome-linux`，供本地测试。

### 移除

- 「DHCP」功能整体删除，不再只是删界面：
  - 后端：`internal/dhcpd/**`（DHCPv4/v6 服务器、租约库、静态租约、RA，约 4200 行）、它依赖的 `internal/dhcpsvc/**`，以及 `internal/aghnet` 里只服务于 DHCP 的探测代码。
  - 接口：`/control/dhcp/status|interfaces|set_config|find_active_dhcp|add_static_lease|remove_static_lease|update_static_lease|reset|reset_leases` 九个接口，以及 `openapi/openapi.yaml`、`AGHTechDoc.md` 里对应的描述。
  - 配置：`dhcp` 配置段、`/control/status` 的 `dhcp_available`、`clients.runtime_sources.dhcp`。老配置里残留的这些键会被忽略，不影响启动。
  - 客户端与 DNS：不再按 DHCP 租约识别客户端（包括按 MAC 反查 IP），也不再从租约解析本地主机名与 PTR。
  - 依赖：`go.mod` 里删掉 `insomniacslk/dhcp`、`google/gopacket`、`gopacket/gopacket`、`go-ping/ping`、`mdlayher/ethernet`、`mdlayher/packet` 六个直接依赖。

## v2026-09-24

### 移除

- 「加密设置」选项卡及其功能：页面、路由、状态管理与 HTTP 调用。
- 查询日志筛选里的「已阻止的服务」「拦截的威胁」「被家长控制阻止」「安全搜索」。
- 首页的被拦截的恶意/钓鱼网站、被拦截的成人网站、强制安全搜索三个卡片，以及客户端排行。
- 「安全搜索」功能本身：前端代码、各搜索引擎规则文件、HTTP API。
- 「已阻止的服务」功能本身：服务清单、服务图标接口，以及客户端与统计里的相关字段。
- 查询日志「放行 / 拦截」按钮旁的「仅对此客户端拦截」「仅解除对此客户端的拦截」「不允许这个客户端」「添加为持久客户端」。
- 随上述功能一起失效的语言键。

### 变更

- 发布说明改为中文优先。
- 语言只保留 English、简体中文、繁體中文。

## v2026-09-23

本 mod 的首个版本。

### 变更

- 常规设置只保留日志配置与统计配置。
- DNS 设置删除「访问设置」，「拦截模式」只保留默认选项。
- 删除「已阻止的服务」「设置指导」「DHCP」选项卡及其页面，以及页面背后的前端代码。
- 首页不再显示被拦截的威胁、被拦截的成人网站、安全搜索与客户端排行。
- 页脚删除主页、隐私政策、问题反馈链接。
- 版本号改为日期格式，例如 `v2026-09-23`。
- 关闭在线更新检查，因为 AdGuard 的更新服务器只提供官方构建。

### 移除

- 除 Linux 以外其它操作系统的代码与构建配置。
- Snapcraft 与 Docker 构建及其脚本。
- 新版前端，以及未完成的 next API。
