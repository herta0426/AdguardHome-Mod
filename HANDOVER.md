# 交接文档：AdGuardHome-Mod

这份文档写给接手这个仓库的人，也写给以后在这个仓库里干活的 AI。看完之后，应该能独立完成四件事：改功能、发版、同步上游、排查线上问题。

日常操作（改一次东西的流程、发版步骤、在线更新维护、排错）见 [MAINTENANCE.md](MAINTENANCE.md)，本文更侧重现状与来龙去脉。

- 上游项目：<https://github.com/AdguardTeam/AdGuardHome>
- 主仓库：<https://github.com/liuzq2002/AdguardHome-Mod>（Release 发在这里）
- 主要适配对象：[Adguard-Home-For-Magisk-Mod](https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod)（把 AdGuard Home 塞进 Android / Magisk 模块）

## 1. 现状速览

- 默认分支 `main`，当前 HEAD `bf485a1d`。里面是 PR #6（删页面与功能）、#7（README 中文优先）、#8（「精简版」改名「修改版 / Mod」）。
- 已发布 `v2026-09-24`（预发布），产物三个：`AdGuardHome_linux_amd64.tar.gz`、`AdGuardHome_linux_arm64.tar.gz`、`checksums.txt`。
- 只支持 `linux/amd64` 与 `linux/arm64`，其它平台代码已经从仓库里删掉。
- 版本号是日期格式 `vYYYY-MM-DD`，规则写在 `scripts/make/version.sh`：tag 精确匹配就用 tag，否则用最后一次提交的日期。正则只认 `^v[0-9]{4}-[0-9]{2}-[0-9]{2}$`。
- 界面只保留 English、简体中文、繁體中文三种语言，语言清单在根目录 `.twosky.json`。

### 远程与分支

| 远程 | 地址 | 用途 |
| --- | --- | --- |
| `origin` | `AdguardTeam/AdGuardHome` | 上游官方仓库，只用来拉基线，绝对不要往这里推 |
| `liuzq` | `liuzq2002/AdguardHome-Mod` | 主仓库，默认分支 `main`，Release 发这里 |
| `mod` | `herta0426/AdguardHome-Mod` | 个人 fork，用来放特性分支、开 PR |

本地分支情况：`main` 跟踪 `liuzq/main`；`master` 跟踪 `mod/master`，是很旧的残留；`cleanup/linux-only`、`docs/mod-docs`、`import-mod` 是历史分支，远端已经删了，本地可以一并删掉。

`herta0426/AdguardHome-Mod` 上还有一个误发的 `v2026-09-24` Release 和同名 tag，建议删掉，避免和主仓库的版本混淆：

```sh
gh release delete v2026-09-24 --repo herta0426/AdguardHome-Mod --cleanup-tag --yes
```

## 2. 这个 mod 改了什么

### 2.1 界面

- 常规设置只留日志配置与统计配置（`client/src/components/Settings/index.tsx`）。
- DNS 设置删掉「访问设置」，拦截模式只剩 default 一个选项（`client/src/components/Settings/Dns/Config/Form.tsx` 的 `blockingModeOptions`）。
- 删掉「已阻止的服务」「设置指导」「DHCP」「加密设置」四个选项卡及页面，删掉「客户端设置」整块界面。
- 首页仪表盘不再显示被拦截的恶意/钓鱼网站、被拦截的成人网站、强制安全搜索，以及客户端排行。
- 查询日志筛选只留：所有查询记录、已过滤、已处理、已阻止、允许项、重写项；日志里的「放行 / 拦截」按钮旁只留单个按钮。
- 页脚删掉主页、隐私政策、问题反馈链接。

### 2.2 功能与代码

- 「安全搜索」：前端代码、各引擎规则文件、后端实现、HTTP API 全部删除。
- 「已阻止的服务」：服务清单（`internal/filtering/servicelist.go`，3400 多行）、图标接口、客户端与统计里的相关字段全部删除。
- 「DHCP」：界面之外，后端也整个删掉了——`internal/dhcpd/**`（约 4200 行）与它依赖的 `internal/dhcpsvc/**`、`/control/dhcp/*` 九个接口、`dhcp` 配置段、`/control/status` 的 `dhcp_available`、客户端存储里按 DHCP 租约识别客户端（含按 MAC 反查）的逻辑，以及 DNS 侧用租约解析本地主机名与 PTR 的部分（`dnsforward` 里的 `processDHCPHosts`／`processDHCPAddrs`）。go.mod 里随之删掉 6 个直接依赖（`insomniacslk/dhcp`、两个 gopacket、`go-ping/ping`、`mdlayher/ethernet`、`mdlayher/packet`）。
- 「加密设置」：删除的是前端页面、路由、状态管理与 HTTP 调用；后端的 TLS 接口（`/control/tls/status|configure|validate`、`serve_plain_dns`）**故意保留**。

### 2.3 平台与构建

- 只保留 Linux：删掉 darwin/windows/BSD 平台文件、Snapcraft、Docker、新版前端、未完成的 next API，以及只服务其它平台的第三方依赖。
- 因此 **Windows 上跑不了 `go build ./...`**，见第 4 节。

### 2.4 有意保留，不是漏删

- 查询日志与统计里的 reason / result 编号保留为占位常量（`internal/filtering/reason.go`、`internal/stats/unit.go`），否则老日志、老统计文件升级后读不出来。
- `internal/configmigrate/**` 里的迁移函数**全部保留**（v1…v34 一版都不能少，否则老配置升不上来），但 v4、v18、v19、v21、v22、v26 已经不再往配置里写 `use_global_blocked_services`、`safe_search`、`safesearch_cache_size`、`blocked_services`，而是把这些键从老配置里删掉。所以现在 `rg` 只会在迁移的注释和老的 `input.yml` 测试数据里看到这些字样。
- 注意：DHCP 曾经是「界面删了、后端保留」，后来改成一并删除（见 2.2）。所以 `/control/dhcp/*` 现在返回 404，`/control/status` 里也没有 `dhcp_available` 了；第三方管理器若因此报错，那是有意取舍。

### 2.5 一次真事：删接口会打断外部客户端

删掉「安全搜索」「已阻止的服务」时，后端那 10 个接口也一起删了。结果 AdGuard Home Manager 这类第三方管理器首页会一次性并发请求 `/stats`、`/status`、`/filtering/status`、`/safesearch/status`、`/safebrowsing/status`、`/parental/status`、`/clients`，只要有一个 404 就整页报「无法加载服务器状态」。同一批问题还包括：

- `/control/stats` 少了 `num_replaced_safesearch`
- `/control/clients` 少了 `use_global_blocked_services`
- 这两个字段在客户端模型里是非空类型，缺了会直接解析失败

结论，以后删东西之前先做三件事：

1. 仓库内 grep 调用方：`rg -n "safesearch|blocked_services|加密|encryption" client/src internal openapi AGHTechDoc.md`
2. 想一想仓库外有没有人调用（管理器、脚本、模块安装脚本）。仓库外的调用方 grep 不到，所以对**接口**要保守。
3. 真要删接口，就补一层「接口在、功能不生效」的兼容层：在 `internal/filtering/` 里新增 handler（状态永远返回未启用或空列表，写请求校验后丢弃），在 `RegisterFilteringHandlers` 注册；`/stats` 与 `/clients` 补回字段即可。这类兼容层大约百来行，加上文档和测试，半天能搞定。

### 2.6 自己加的功能：SNI 阻断（`sni_filter`）

这是本项目第一个「不只是做减法」的功能，默认关闭，只在 Linux 上生效。

**解决什么问题。** DNS 过滤看不到两类流量：应用自己走 DoH（443 端口，绕开系统 DNS），以及把 IP 写死在代码里的 Ad SDK。这两种连接的 ClientHello 里 SNI 是明文，所以能在连接建立时按域名拦掉，用的是**同一套过滤规则**，不需要另外维护清单。

**机制。**

1. 在 `filter` 表的 `OUTPUT` 链上挂自己的链 `AGH_SNI`：链首放行 loopback，然后 `-p tcp -m multiport --dports <ports> -m connbytes --connbytes 0:20000 --connbytes-dir original --connbytes-mode bytes -j NFQUEUE --queue-num <n> --queue-bypass`。`connbytes` 让每条连接只有开头 20 KB 进用户态，其余由内核直通；`--queue-bypass` 保证没人读队列时包照常走（AdGuardHome 挂了只是不拦广告，不会断网）。
2. 用户态按连接拼 TCP 载荷，用 `internal/snifilter/clienthello.go` 解析出 SNI（处理跨 TLS record、跨 TCP 段），再把 SNI 和判决结果写进查询日志，见下面「SNI 走查询日志」一条。
3. 拿 SNI 问 AGH 自己的规则引擎：`filtering.DNSFilter.CheckHostRules(host, dns.TypeA, setts)`；命中就把这条连接记成「拦截」。
4. 命中时返回 `NF_DROP`，同时用 `AF_INET/AF_INET6 + IPPROTO_RAW` 裸套接字注入两个 TCP RST：一个以「服务器」身份发给客户端（客户端立刻拿到 `ECONNRESET`，不是干等超时），一个以「客户端」身份发给服务器（顺手收掉服务端的半开连接）。之后这条连接的包继续 DROP。

**强力模式。** `filtering.blocking_mode: strong`（DNS 设置页里叫「强力模式」）把上面这套和 DNS 拦截合成一个开关：

- DNS 半边在 `internal/dnsforward/msg.go` 的 `genForBlockingMode` 里加了一个分支，直接调已有的 `NewMsgNODATA`，也就是 NOERROR + 空 answer + SOA。A/AAAA/HTTPS 走这个分支，其它 qtype 本来就走 NODATA。
- SNI 半边由 `internal/home/dns.go` 的 `syncSNIFilter` 负责：只要 `sni_filter.enabled` 为真**或**当前拦截模式是 strong，就确保 SNI 过滤在跑，否则确保它停掉。`config.Filtering` 的拦截模式是运行时可变的值，所以判断要读 `globalContext.filters.BlockingMode()`，不要读 `config.Filtering.BlockingMode`。
- `syncSNIFilter` 在两个地方被调用：`initDNS` 末尾（启动）和 `defaultConfigModifier.Apply`（每次配置写盘后，`/control/dns_config` 会走到这里）。所以「在界面里切成强力模式」不需要重启，DNS 半边立即生效、RST 半边在保存配置时同步启停。
- 启动/停止的临界区由 `homeContext.sniLock` 保护；`syncSNIFilter` 在 `globalContext.filters` 或 `globalContext.dnsServer` 为空时直接返回，避免在关机过程中把规则又装回去。

**为什么不用 TUN、也不让内核自己发 RST**（都实测过，见 [TUN.md](TUN.md) 第 8、12、13、14 节）：

- TUN 要抢默认路由，和代理模块的 TUN 零和；NFQUEUE 在 `OUTPUT` 上看一眼就放行，放行的包完全走内核原路径。
- 让内核自己发 RST 的两条路都试过、都不行：`SetVerdictWithConnMark(NF_DROP)` 设的 conntrack mark 在 iptables-nft 上不被后面的 `-m connmark` 看到；`NF_REPEAT` + packet mark 也不会重跑链。所以 RST 由 AGH 自己注入。
- 顺带一个坑：「内核 REJECT + connmark」的规则必须显式带 `-p tcp`，否则 `--reject-with tcp-reset` 报 `Invalid argument`（REJECT 也只能用在 filter 表）。

**代码位置。**

| 文件 | 干什么 |
| --- | --- |
| `internal/snifilter/snifilter.go` | 配置校验、连接表、判决（平台无关） |
| `internal/snifilter/clienthello.go` | ClientHello / SNI 解析 |
| `internal/snifilter/firewall_linux.go` | iptables/ip6tables 规则、NFQUEUE 消费、RST 注入、规则自愈 |
| `internal/snifilter/firewall_others.go` | 非 Linux 的平台桩 |
| `internal/home/{config.go,dns.go,home.go}` | `sni_filter` 配置段与生命周期（`initDNS` 启动、`Apply` 同步、`stopDNSServer`/`closeDNSServer` 关闭） |
| `internal/dnsforward/msg.go`、`internal/dnsforward/dnsforward.go` | 强力模式的 NODATA 响应与模式校验 |
| `client/src/components/Settings/Dns/Config/Form.tsx`、`client/src/helpers/constants.ts` | 拦截模式的两个选项（默认 / 强力模式） |

**配置**（细节见 `doc/AdGuardHome.yaml.example`）：

```yaml
sni_filter:
  enabled: false
  queue_num: 7          # 别用 0
  ports: [443, 8443]
  uids: []              # 例如 ["10000-19999"]，空表示所有进程
  drop_quic: false      # 打开则 REJECT UDP 443，逼 HTTP/3 回退 TCP
  manage_rules: true    # false = 规则交给外部脚本装（见下）
```

`filtering.blocking_mode: strong` 时上面这一段自动生效，不需要把 `enabled` 打开。

**规则可以搬给外部脚本**（`manage_rules: false`）：AdGuardHome 只开 NFQUEUE、读包、发 RST，不再安装/清理/自愈 iptables 规则。Magisk 模块走的就是这条：`scripts/iptables.sh` 维护 `filter` 表里的 `AGH_SNI` 链（`-o lo -j RETURN` + `-p tcp --dports … -m owner --uid-owner … -m connbytes … -j NFQUEUE --queue-num N --queue-bypass`，v4/v6 各一份），5 秒守护循环里用 `-C` 检查、缺了就重建；队列号从 `AdGuardHome.yaml` 的 `sni_filter.queue_num` 读，避免两边写死不同值。这种模式下 `ports`/`uids`/`drop_quic` 由脚本说了算，配置里那三项不生效。

外部规则的硬要求：**必须带 `--queue-bypass`**，否则 AdGuardHome 没在跑时进队列的包没人判决，443 会整段卡住；链名建议沿用 `AGH_SNI`（AGH 侧的启动日志和文档都用这个名字）。

**验证怎么做。** 规则里排除了 loopback，所以本机 127.0.0.1 上的测试服务器测不到，必须让流量真的过一张网卡。Linux 上的做法是 network namespace + veth，把 TLS 服务器放进去，客户端从宿主机连 `10.99.0.2:443`：规则里放 `||blocked.test^` 时，`sni=blocked.test` 应立刻收到 RST，`sni=allowed.test` 应正常握手。

2026-09-26 已在 WSL2（内核 6.18，iptables-nft）上跑过：IPv4/IPv6 都被 RST（11 ms / 1.7 ms），放行的连接正常（6 ms），手工 `iptables -D OUTPUT -j AGH_SNI` 后 30 秒内规则自动恢复，SIGTERM 后 v4/v6 的链与跳转都清干净；`drop_quic: true` 时 v4/v6 分别生成 `icmp-port-unreachable` 与 `icmp6-port-unreachable` 的 REJECT 规则。

**已知限制与坑。**

- 内核必须支持 `xt_connbytes` 与 `NFQUEUE`（nft 后端也行）。厂商内核可能裁剪，真机上先跑一条 `iptables -t filter -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 7 --queue-bypass` 验证。
- 注入的 RST 源地址是远端 IP，靠本机 IP 栈绕回本地 socket；`net.ipv4.conf.*.rp_filter` 若是**严格模式（1）**，这个包会被丢掉，效果退化成「连接一直挂着」（仍然拦截，只是慢）。部分 ROM 要留意。
- HTTP/3（QUIC）的 SNI 是加密的，拦不到，只能 `drop_quic: true` 逼回退 TCP。ECH 普及后这条路也会静默失效。
- 只看进程 UID、不看客户端 IP：手机上的应用都在同一台机器上，所以**按客户端区分的过滤规则在 SNI 层不生效**，只按全局规则判定（`setts.ProtectionEnabled` 恒为真）。
- **SNI 走查询日志，不走主日志**：每条解析出 SNI 的连接都会写进查询日志（`internal/snifilter/snifilter.go` 的 `logConnection`），域名就是 SNI。原因换成 SNI 专用的两个值，好把 TLS 连接与 DNS 请求分开：被拦的是 `filtering.FilteredSNI`（界面显示「已阻止（SNI）」，仍归入「已阻止」筛选），放行的是 `filtering.NotFilteredSNI`（显示「已处理（SNI）」）——过滤引擎给的原因不再写进查询日志，但命中的规则照旧带上，所以「命中允许规则」的连接改看规则列而不是「允许项」筛选。SNI 记录还多一个 **`destination`**（`AddParams.Dst` → `logEntry.Dst` → `entryToJSON` 的 `destination`，前端在响应详情里渲染成一行「目标地址」）：连接的目标 IP:端口，DNS 查询没有这一维，只有 SNI 过滤能看到应用最终连到哪个地址。主日志只在启动/停止、出错误的时候写，不再逐条打印连接；RST 发不出去也只记 debug。
- 查询日志里记的是**每条连接**（放行的也记），手机上流量大时会把查询日志刷得比较快，日志轮转要不要调（`querylog.mem_size` / `interval`）按实际用量定。
- 队列号默认 7，和别的 NFQUEUE 使用者撞车时改 `queue_num`。
- **`Filter.Start` 必须把传入的 ctx 用 `context.WithoutCancel` 脱钩**：运行时切换拦截模式时，启动请求来自 `/control/dns_config` 的 HTTP 请求，响应一写完请求 ctx 就被取消，NFQUEUE 的读取循环和规则自愈的 ticker 会一起停掉——现象是「规则装了、计数器在涨，但用户态一个包都收不到，`--queue-bypass` 把包全放了」。这个坑只会在运行时启动时出现，启动时用后台 ctx 是看不出来的。

## 3. 目录地图：想改什么去哪里

| 想改的东西 | 位置 |
| --- | --- |
| 页面路由注册 | `client/src/components/App/index.tsx`（`ROUTES`，第 43 行起） |
| 顶部导航、移动端菜单 | `client/src/components/Header/Menu.tsx`（`MENU_ITEMS`）、`client/src/components/Header/index.tsx` |
| 页脚 | `client/src/components/Footer/**` |
| URL 常量 | `client/src/helpers/constants.ts`（`MENU_URLS`、`SETTINGS_URLS`、`FILTERS_URLS`） |
| 常规设置页 | `client/src/components/Settings/index.tsx`（现在只渲染 `LogsConfig` 与 `StatsConfig`） |
| DNS 设置、拦截模式 | `client/src/components/Settings/Dns/{index.tsx,Config/Form.tsx,Upstream/**,Cache/**}` |
| 首页仪表盘卡片 | `client/src/components/Dashboard/index.tsx` |
| 查询日志与筛选 | `client/src/components/Logs/**` |
| 过滤器页面 | `client/src/components/Filters/**` |
| HTTP 接口常量（前端） | `client/src/api/Api.ts` |
| 前端状态管理 | `client/src/actions/**`、`client/src/reducers/**`、`client/src/containers/**`、`client/src/initialState.ts` |
| 语言文件 | `client/src/__locales/{en,zh-cn,zh-tw}.json`、根目录 `.twosky.json`、`client/src/i18n.ts` |
| 后端全局路由 | `internal/home/control.go`；各子系统自己注册（`internal/dnsforward/http.go`、`internal/filtering/http.go`、`internal/home/clientshttp.go`、`internal/stats/http.go`、`internal/querylog/http.go`） |
| 鉴权与权限分级 | `internal/home/middlewares.go` |
| 配置结构 | `internal/home/config.go`；历史迁移在 `internal/configmigrate/**` |
| 配置参考模板 | `doc/AdGuardHome.yaml.example`（只是参考，安装不需要；由程序自己生成） |
| SNI 阻断（自己加的功能） | `internal/snifilter/**`；配置段 `sni_filter`；生命周期在 `internal/home/dns.go` |
| 统计接口与编号 | `internal/stats/http.go`、`internal/stats/unit.go` |
| 过滤原因编号 | `internal/filtering/reason.go` |
| 版本号生成 | `scripts/make/version.sh`、`Makefile` |
| 前端产物如何进二进制 | `main.go`（`//go:embed build`）、`internal/home/home.go`（`fs.Sub(clientBuildFS, "build/static")`） |
| CI 与发版 | `.github/workflows/build-linux.yml` |
| 构建脚本 | `Makefile`、`scripts/make/*.sh` |

## 4. 本地环境

| 组件 | 位置 / 版本 |
| --- | --- |
| Go | `C:\Users\juana\tools\go\bin\go.exe`，1.26.8（`go.mod` 也要求 1.26.8） |
| Node | 24.x（前端构建用） |
| WSL | `archlinux`，里面同样装了 Go 1.26.8，**跑测试要用它** |

两个必须记住的坑：

1. Windows 上直接 `go build ./...` 会报一堆 `undefined: setRlimit`、`undefined: newARPDB` 之类的错。这不是代码坏了，而是 Windows 平台文件已经被删。要么交叉编译（`GOOS=linux GOARCH=amd64`），要么进 WSL。
2. `go test ./...` 必须在 Linux/WSL 里跑。

```powershell
# 交叉编译检查（PowerShell，Windows 侧）
cd C:\Users\juana\Documents\ChatGPT\Adguardhome
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
& C:\Users\juana\tools\go\bin\go.exe build ./...
```

```sh
# 跑测试（WSL）
wsl -d archlinux -- bash -lc 'cd /mnt/c/Users/juana/Documents/ChatGPT/Adguardhome && \
  export GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct CGO_ENABLED=0 && go test ./...'
```

另外两条 PowerShell 注意点：

- 这个环境里 `Remove-Item` 被策略拦截，删文件用 `[System.IO.File]::Delete((Resolve-Path path))`，删目录用 `[System.IO.Directory]::Delete($p, $true)`，仓库内文件优先用 `git rm`。
- 想精确还原某些文件的本地改动：`git restore --source=HEAD --worktree -- <文件列表>`。

## 5. 常用命令

```sh
make js-deps        # 前端依赖
make js-build       # 前端构建，产物进 build/static
make js-lint        # 前端 lint
make js-typecheck   # 前端类型检查
make js-test        # 前端单测
make go-build       # 后端构建，产物 ./AdGuardHome
make go-os-check    # 交叉检查 linux/amd64 与 linux/arm64
make go-test        # 后端测试（带 race）
make quick-build    # 前端 + 后端一把梭
make build-release SIGN=0   # 出 dist/ 里的两个压缩包
mkdir -p dist && make pack-release SIGN=0
```

改了前端一定要先 `make js-build`，否则打进二进制里的还是旧的 `build/static`。

### 重新生成配置模板

`doc/AdGuardHome.yaml.example` 的内容必须来自真跑起来的程序，不能凭印象手写。拿一个 Linux 二进制（本机可以先在 Actions 里 `workflow_dispatch`，产物从 `AdGuardHome-linux` 下载）：

```sh
# 首次启动的权限检查要求 root，DNS 端口别用 53/5353（可能被占用）
sudo ./AdGuardHome --no-check-update -w /tmp/agh-tpl --web-addr 127.0.0.1:3053 &
curl -s -X POST http://127.0.0.1:3053/control/install/configure \
  -H 'Content-Type: application/json' \
  -d '{"language":"zh-cn","username":"admin","password":"templatepassword",
       "web":{"ip":"127.0.0.1","port":3053},"dns":{"ip":"127.0.0.1","port":15353}}'
cat /tmp/agh-tpl/AdGuardHome.yaml
```

把输出里的端口、`users`、`safe_fs_patterns` 换成模板该有的占位值（`127.0.0.1:3000`、`53`、`/data/adb/agh/bin/data/userfilters/*`），保留中文注释，然后校验：

```sh
mkdir -p /tmp/agh-check && cp doc/AdGuardHome.yaml.example /tmp/agh-check/AdGuardHome.yaml
./AdGuardHome --check-config -w /tmp/agh-check   # 必须输出 "configuration file is ok"
```

注意：`--check-config -c <不在工作目录里的文件>` 会走「首次启动」分支并真的起一个服务，别那样用。

## 6. 手动跑起来验证

改完接口或页面，最靠谱的验证是真的把二进制跑起来。准备一个干净的工作目录（不要用手机上或本机在跑的实例）：

```sh
go build -o /tmp/agh-mod .
mkdir -p /tmp/agh-conf
cat > /tmp/agh-conf/AdGuardHome.yaml <<'YAML'
http:
  address: 127.0.0.1:3053
dns:
  bind_hosts:
    - 127.0.0.1
  port: 55353
users: []
schema_version: 29
YAML
/tmp/agh-mod --no-check-update -w /tmp/agh-conf >/tmp/agh.log 2>&1 &
curl -s http://127.0.0.1:3053/control/status
```

两个经验：

- 所有写接口都必须带 `Content-Type: application/json`，否则返回 `415 only content-type application/json is allowed`，看起来像是接口没了、其实是请求头没带。
- 前端页面打了补丁但界面没变，多半是浏览器缓存了旧的 `main.*.js`，硬刷新（手机浏览器清一次站点数据）再试。

## 7. 发版流程

1. 在最新 `main` 上开分支：`git checkout -b codex/<改动名> main`
2. 改完按第 15 节清单自测
3. 推到 fork：`git push mod codex/<改动名>`
4. 开 PR 到主仓库：`gh pr create --repo liuzq2002/AdguardHome-Mod --base main --head herta0426:codex/<改动名>`
5. 合并 PR
6. 本地同步 `main` 后打 tag 并推送：

```sh
git fetch liuzq && git checkout main && git merge --ff-only liuzq/main
git tag v2026-09-25
git -c credential.helper=manager push liuzq v2026-09-25
```

7. 工作流 `.github/workflows/build-linux.yml` 自动接管：先跑 lint 与测试，再构建两个架构，最后把 `dist/` 里的三个文件附到 Release 上。

几个细节：

- 同一天要重发：`version.sh` 只认 `vYYYY-MM-DD`，所以要么删掉旧 Release 与 tag 后在同一个提交上重建同名 tag，要么等第二天再打。
- 手动试构建（不打 tag）：在 Actions 页面手动 `workflow_dispatch`，产物在 Artifacts 里，验证没问题再打 tag。
- Release 说明是中文的，写在 workflow 里；改发版文案就改那里。

## 8. 以后该干什么

按优先级：

1. 删掉 `herta0426/AdguardHome-Mod` 上误发的 `v2026-09-24` Release 与 tag（命令见第 1 节）。
2. 清理本地历史分支：`git branch -D cleanup/linux-only docs/mod-docs import-mod`。
3. 清理确认无引用的死代码。已知 `client/src/components/Settings/Dhcp/`、`StaticLeases/` 只剩空目录（git 里已经没有文件，删掉只是让本地干净）。其它目录建议用 `rg -n "Settings/Dhcp|SetupGuide|Encryption" client/src` 这类反查确认没有 import 后再删。
4. 体积优化（要实测，不要盲改）：
   - 本地交叉编译实测：arm64 约 37 MB、amd64 约 40 MB（未剥离符号）。
   - 可以评估 `-trimpath`、`-ldflags "-s -w"`、`GOAMD64=v1`（保持兼容性）等开关；每次都要在手机上实跑 DNS 与 Web 界面，确认没崩再发。
   - 语言包、图标、未引用组件是另一条线，删之前先确认没有动态引用。
5. 同步上游基线（第 10 节），建议上游每次发版后或每月一次。
6. 想加自己的功能（这是项目定位里说好的方向），从第 12.4 节开始。
7. 顺手修掉一处不一致：`scripts/make/md-lint.sh` 还在检查已经被删掉的 `CONTRIBUTING.md` 与 `SECURITY.md`，直接把这两行列删掉即可（CI 目前不跑这个脚本，所以一直没暴露）。
8. 盯一眼上游 `client_v2` 的成熟度：现在上游默认前端已经换成它了，等它稳了再评估迁移，判断依据与迁移清单见第 11 节。

## 9. AI 该干什么、能干什么、需要干什么

**能干什么**

- 读代码、定位问题、给出证据（改哪个文件、哪一行、为什么）
- 写和改前后端代码、补测试、跑 `gofmt`/`go test`/`go build`/前端 lint
- 起本地实例、用 curl 验证接口行为
- 改文档（README、AGHTechDoc、openapi、CHANGELOG）
- 按第 7 节流程开分支、推 fork、开 PR、合并、打 tag 发版

**需要干什么**

- 改动前先说清方案与影响面；动手后给出：改了哪些文件、怎么验证的（命令与结果）、影响面、回滚方法。
- 前端改动必须跑 `make js-lint js-typecheck js-test`，后端必须跑 `gofmt -l internal/` + WSL `go test ./...` + 两个架构的交叉编译。
- 删任何后端接口或配置字段前，先 grep 调用方，并评估仓库外的调用者（第 2.5 节）。
- 同步上游后，必须重新确认「已经删掉的东西没有复活」（第 10 节检查清单）。

**需要先问过才能做**

- 推送、打 tag、发 Release、删除远端 release/tag、改仓库设置、force push。**没得到明确同意就不发布。**

**不要做**

- 不要动本机正在跑的官方 AdGuard Home（Windows 服务 `AdGuardHome`，装在 `C:\Program Files (x86)\AdGuardHomeForWindows`，占着 3000 和 53，网卡 DNS 指向 127.0.0.1）——那是用户自己封装的，不属于本项目。
- 不要动 `C:\H11111\adguard-home-manager`（第三方管理器项目）里的文件，除非用户明确要求。
- 不要把 `build/static`、`dist/` 这类构建产物提交进仓库。
- 不要用 `git reset --hard`、`git checkout --` 这类粗暴命令清理工作区；要还原就按文件精确 `git restore`。

## 10. 以后升级上游基线要干什么

### 10.1 准备

```sh
git fetch origin --tags
git log -1 --format='%h %ci' origin/master     # 记下新基线
git merge-base main origin/master              # 记下当前基线
```

如果 `github.com` 拉不动（国内常见连接被重置），见第 13 节。

### 10.2 先试合并，别直接改 main

```sh
git checkout -b sync/upstream-<日期> main
git merge --no-commit --no-ff origin/master    # 先看冲突，不提交
```

### 10.3 冲突高危区（每次都会撞）

| 区域 | 为什么冲突 |
| --- | --- |
| `client/src/components/App/index.tsx`、`Header/Menu.tsx`、`Settings/**` | 我们删过页面、改过设置页结构 |
| `client/src/__locales/*.json`、`.twosky.json`、`i18n.ts` | 我们删过语言与语言键 |
| `client/src/helpers/constants.ts` | 拦截模式、筛选状态等常量 |
| `client/src/api/Api.ts` | 我们删过接口常量 |
| `internal/filtering/**` | 删过安全搜索与已阻止的服务 |
| `internal/home/{control.go,config.go,clients.go,clientshttp.go}` | 删过字段与接口注册 |
| `internal/stats/{http.go,unit.go}`、`internal/querylog/**` | 保留的占位编号 |
| `openapi/openapi.yaml`、`AGHTechDoc.md`、`README*.md`、`CHANGELOG.md` | 文档差异最大 |
| 全部 `*_windows.go`、`*_darwin.go`、`*_bsd.go`、`*_freebsd.go` 等 | 上游会重新带回非 Linux 平台文件，必须再删一遍 |

### 10.4 合并后必做检查

```sh
# 1. 平台文件有没有复活
rg --files internal | rg "_(windows|darwin|freebsd|openbsd|netbsd|solaris)\.go$"

# 2. 被删的功能有没有复活
rg -n "safesearch|blocked_services|safe_search" internal client/src openapi/openapi.yaml

# 3. 依赖与文档是否同步，然后跑完整验证
gofmt -l internal/                 # 必须无输出
go mod tidy && git diff --exit-code go.mod go.sum
go test ./...
make js-deps js-lint js-typecheck js-test js-build
```

预期结果：平台文件只剩 Linux；`safesearch` / `blocked_services` 只应该出现在 `internal/configmigrate/**` 与保留的占位常量、注释里；两个架构都能构建。

### 10.5 收尾

- 用 `git diff --stat` 对比二进制体积（改了构建参数时要重新实测并记录）。
- 在 `CHANGELOG.md` 里加一条「同步上游 <版本/日期>」并写明保留与重新删除的内容。
- 合并到 `main` → 按第 7 节发版；先在 Actions 里手跑一次试构建，产物在手机上实跑再打 tag。

## 11. 上游新版前端（client_v2）：为什么不用、以后怎么迁、怎么不冲突

### 11.1 现状：上游有两套前端、两套后端

| 项目 | 我们的 fork | 上游 `master` |
| --- | --- | --- |
| 经典前端 | `client/`（React，package 名 `dashboard` 0.1.0），`Makefile` 里 `CLIENT_DIR = client` | 文件还在，但 Makefile 与 CI 默认都不再构建它（CI 可用 `client_dir` 输入切回） |
| 新版前端 | 整棵删除（`client_v2/`，约 840 个文件） | `client_v2/`（SolidJS，package 名 `dashboard` 3.0.0，webpack + vitest + orval），`Makefile` 里 `CLIENT_DIR = client_v2` |
| 新版后端 | 整棵删除（`internal/next/`，28 个文件） | `internal/next/`，靠 `NEXTAPI=1`（`scripts/make/go-build.sh` 变成 `--tags=next`）和根目录 `main_next.go`（`//go:build next`）构建 |

上游把默认前端切到 `client_v2` 是在提交 `09ae3ccd`（`AGDNS-3549-new-ui-edge`）；根目录 `main.go` 与 `main_next.go` 都 embed 同一个 `build/` 目录，所以「用哪套前端」和「用哪套后端」是两件可以分开决定的事。

### 11.2 一个关键事实：v2 前端并不需要新后端

`client_v2/orval.config.ts` 里写着：

```ts
input: { target: '../openapi/openapi.yaml' },
output: { baseUrl: 'control', ... }
```

也就是说，**新的 SolidJS 界面是通过 orval 从我们的 `openapi/openapi.yaml` 生成客户端、继续调用 `/control/*` 老接口**。真正的新东西是 `internal/next/` 那套服务，它提供的是另一套 API：`/api/v1/settings/all`、`/api/v1/settings/dns`、`/api/v1/settings/http`、`/api/v1/system/info`、`/health-check`。

由此有两个直接结论：

1. 迁移 v2 前端不等于迁移后端；只要 `/control/*` 还在，前端可以单独换。
2. 删 `/control/*` 接口的代价比以前更大：v2 的 API 客户端是**从 openapi 规范生成的**，接口在规范里被删掉、服务端也删掉，v2 编译出来的客户端就会直接打到 404（第 2.5 节那次事故就是这么来的）。删接口时记得同步改 `openapi/openapi.yaml`，否则两代前端都会踩。

### 11.3 为什么现在不用 v2

1. 体积与内存优先：Magisk 模块的机器很小，`client_v2` 额外依赖 SolidJS、chart.js、`countries-and-timezones`、`ipaddr.js` 等一堆东西，产物与运行内存都会变大；我们只需要一个能管 DNS 的最小界面。
2. 我们所有的改动都是围绕经典版做的：删页面、删接口、删语言、只留默认拦截模式，全是按 `client/` 的目录结构与 i18n 流程改的，换 v2 等于把这些改动重做一遍（v2 里 `BlockedServices`、`Dhcp`、`Encryption`、`Clients`、`SetupGuide` 这些页面都还在，见 `client_v2/src/components/`）。
3. v2 自己还在演进：上游把新版后端标成未完成——`internal/next/changelog.md` 还是 `v0.108.0` 的 DRAFT，里面「New HTTP API」一节还写着 TODO，连文档都没定稿。跟着它跑容易反复返工。
4. 我们不需要新架构：`internal/next` 是把 cmd / configmgr / dnssvc / websvc 重写一遍的实验分支，对「Android 上跑一个 DNS 服务器」这个目标没有直接收益。
5. 现在没有收益驱动：v2 的新功能（私有反向 DNS、无活动时段、Top* 统计页）都不是模块用户提的需求。

### 11.4 如果上游 v2 进入 beta，迁移要做什么

先做评估，再决定走哪条路。

**路线 A：只换前端（推荐先试）**

1. 把上游前端拉回来并试构建：

```sh
git checkout origin/master -- client_v2
# 把 Makefile 里的 CLIENT_DIR 改成 client_v2
make js-deps js-build
```

2. 工具链与 CI 同步：
   - `.github/workflows/build-linux.yml` 里 `cache-dependency-path` 现在写的是 `client/package-lock.json`，要改成新前端的 lock 文件；
   - Node 版本（workflow 里现在是 24）、npm 镜像配置沿用第 13 节；
   - `make js-lint`、`make js-typecheck`、`make js-test`、`make js-build` 的目标会自动跟着 `CLIENT_DIR` 走，但要确认 v2 的脚本名一致（v2 用的是 `build-prod`、`lint`、`typecheck`、`test`，目前一致）。
3. 语言：v2 用自己的一套流程（`client_v2/src/__locales/*.json` + `client_v2/scripts/generate-locales.js`、`check-translations.js`），语言里有 `en`、`zh-cn`、`zh-hk`、`zh-tw`。按我们的三语策略，只留 English / 简体中文 / 繁體中文，其余语言文件删掉，并把校验脚本里的语言清单一起改掉（否则 `check-locales` 会失败）。
4. 重做我们已有的删改（对应第 2 节）：
   - 删除或隐藏 `client_v2/src/components/{BlockedServices,Dhcp,Encryption,Clients,SetupGuide}`；
   - 路由表 `client_v2/src/components/Routes/Paths.ts` 里删掉对应路由（`Dhcp`、`Encryption`、`Guide`、`BlockedServices`、`Clients*`、`InactivitySchedule`、`TopClients`、`TopQueriedDomains`、`TopBlockedDomains`、`TopUpstreams` 按需保留/删除）；
   - 常规设置只留日志与统计；DNS 设置里拦截模式只留默认；首页去掉被拦截威胁/成人网站/安全搜索卡片与客户端排行；页脚链接；
   - 语言文件里对应的键一起清理。
5. 体积与体验对比：两个版本都构建一次，比较 `build/static` 与二进制体积、手机上首屏与日志页的加载速度（SolidJS 版首次加载通常更重，日志页尤其明显）。
6. 验收：真机上跑 DNS、看日志、切语言、改设置、确认不白屏，再按第 15 节清单收尾。

**路线 B：连新后端（`internal/next`）一起上**

只在确有需求时做：

1. 拉回 `internal/next/**` 与 `main_next.go`，恢复 Makefile 的 `NEXTAPI`，用 `-tags next` 构建；
2. 新 API 是 `/api/v1/...`，与 `/control/*` 并存但职责不同，我们的删改要在新的 `websvc`（`settings.go`、`dns.go`、`system.go`）里再做一遍；
3. 文档与测试要重写，而 v2 API 上游自己都还没定稿，跟进成本高；两套 API 并存期间还要同时维护；
4. 结论：除非上游明确把 v2 定为唯一默认、`client/` 被移除，否则不建议走这条。

### 11.5 怎么让两边不冲突

1. 记住「我们的补丁点」短清单：`client/src/components/App/index.tsx`、`client/src/components/Header/Menu.tsx`、`client/src/components/Settings/**`、`client/src/helpers/constants.ts`、`client/src/api/Api.ts`、`.twosky.json` 与 `__locales/**`、`internal/filtering/**`、`internal/home/{control.go,config.go,clientshttp.go,clients.go}`、`internal/stats/**`、`openapi/openapi.yaml`、`AGHTechDoc.md`、`README*.md`、`CHANGELOG.md`。同步上游时只重点复核这些文件，其余尽量跟随上游。
2. 能用新文件解决就别改上游文件：新增页面、新增 handler 都单独放文件，只在必须接入的地方改一行（路由表、handler 注册、菜单）。改得越少，冲突越少，迁移到 v2 时也更容易搬运。
3. 删除类改动要留档：删了什么、为什么、怎么恢复，写进 `CHANGELOG.md`；同步后按第 10.4 节的命令检查「有没有复活」。
4. 打开 `git rerere`，让同样的冲突只手工解一次：

```sh
git config rerere.enabled true
git config rerere.autoupdate true
```

5. 「删干净」和「好迁移」是个取舍，值得按功能分别判断：
   - 体积优先（现在的做法）：直接删代码，同步上游时按清单重删一遍，体积最小；
   - 迁移友好：对少量关键功能改用开关隐藏（前端保留组件、后端保留 handler），代价是体积与维护成本都留一份。v1 与 v2 的页面结构完全不同，如果预计一年内要迁 v2，至少把「接口层」保留成兼容形态（保留 handler，或在 openapi 里标注 deprecated），别把接口从规范里删掉。
6. 同步节奏别攒：上游每个大版本后或每月同步一次，locale 与常量表这类文件的冲突成本会随版本数指数上升。

## 12. 增删改查手册

### 12.1 查

```sh
# 某个接口在后端哪里注册、前端哪里调用
rg -n "tls/status" internal client/src openapi/openapi.yaml
rg -n "url: .*/control/" client/src/api/Api.ts

# 某个功能还剩多少残留
rg -n "safesearch|blocked_services" internal client/src openapi/openapi.yaml AGHTechDoc.md

# 某个翻译键在哪些语言里存在
rg -n "\"blocking_mode_default\"" client/src/__locales

# 谁引用了某个组件（删之前必做）
rg -n "Settings/Dhcp|from './Dhcp'|SetupGuide" client/src

# 哪些是平台专属文件
rg --files internal | rg "_linux\.go$"
```

### 12.2 改

几个真实场景：

- 恢复拦截模式的可选项：改 `client/src/components/Settings/Dns/Config/Form.tsx` 里的 `blockingModeOptions` 与 `blockingModeDescriptions`（后端的 `internal/dnsforward` 本来就支持这些值，不用动），再确认 `.twosky.json` 对应语言里有 `blocking_mode_refused`、`blocking_mode_nxdomain`、`blocking_mode_null_ip`、`blocking_mode_custom_ip` 这些键。
- 恢复首页某个卡片：在 `client/src/components/Dashboard/index.tsx` 的卡片列表里加回来，同时确认数据来源字段还在（例如统计接口的 `num_replaced_safesearch` 已经删了，要么补回字段，要么换数据源）。
- 换语言：改 `.twosky.json` 的 `languages`、`client/src/i18n.ts` 的 `resources`、以及 `client/src/__locales/<语言>.json` 三个地方。
- 改版本号规则：`scripts/make/version.sh` 的正则与 `Makefile`、workflow 的 tag 触发条件要一起改。

### 12.3 删（完整清单）

删一个界面功能时，按顺序过一遍，缺一步就会留下死代码或残留翻译：

1. 路由：`client/src/components/App/index.tsx`
2. 菜单/入口：`client/src/components/Header/Menu.tsx`、`client/src/helpers/constants.ts` 里的 URL 常量
3. 组件目录：`client/src/components/<功能>/**`
4. 状态管理：`client/src/actions/**`、`client/src/reducers/**`、`client/src/reducers/index.ts`、`client/src/containers/**`、`client/src/initialState.ts`
5. 接口常量：`client/src/api/Api.ts`
6. 翻译键：`client/src/__locales/{en,zh-cn,zh-tw}.json`（如果这个功能原来还有服务名之类的额外语言文件，也一起删）
7. 后端：handler 文件、`httpReg.Register` 调用、配置字段（`internal/home/config.go`）、统计/日志字段
8. 文档：`openapi/openapi.yaml`、`AGHTechDoc.md`、`README.md`、`README.en.md`、`CHANGELOG.md`
9. 迁移兼容：确认 `internal/configmigrate/**` 里老配置的迁移路径没被破坏
10. 验证：`gofmt -l internal/`、`go test ./...`、两个架构交叉编译、`make js-lint js-typecheck js-test js-build`，再手动跑一遍确认没白屏

### 12.4 增

加一个设置页大致要动的文件：

1. `client/src/components/<页面>/**` 写页面组件
2. 在 `client/src/components/Settings/index.tsx` 或对应父页面渲染它
3. 需要状态就加 `actions` + `reducers` + `initialState`，需要接口就加 `client/src/api/Api.ts` 常量与调用
4. 语言键：至少 `client/src/__locales/en.json` 与 `zh-cn.json`（以及 `zh-tw.json`）
5. 后端加接口：在对应子系统的 http 文件里写 handler 并在其 `Register...Handlers` 里注册（全局的放 `internal/home/control.go`）；需要权限分级的改 `internal/home/middlewares.go`
6. 文档：`openapi/openapi.yaml`、`AGHTechDoc.md`、`README.md` 的功能清单、`CHANGELOG.md`
7. 测试：后端 handler 测试 + 前端不崩（`make js-typecheck js-test`），最后手动跑一遍

加一种语言：`.twosky.json` 的 `languages` + `client/src/i18n.ts` 的 `resources` 导入 + `client/src/__locales/<语言>.json`。

## 13. 国内网络：镜像怎么加、怎么减

### 13.1 Go 模块代理

| 位置 | 现状 | 怎么加 | 怎么减 |
| --- | --- | --- | --- |
| CI | `.github/workflows/build-linux.yml` 环境变量 `GOPROXY: https://proxy.golang.org,https://goproxy.cn,direct` | 再往前插镜像，例如 `https://goproxy.cn,https://proxy.golang.org,direct` | 删掉不想要的，用逗号分隔，`direct` 放最后 |
| 本地 `make` | `Makefile` 里 `GOPROXY` 默认是 `https://proxy.golang.org` 再跟一个 `direct`，中间用竖线分隔 | 改成先用 `https://goproxy.cn`，再跟官方，最后 `direct`（同样用竖线分隔） | 同理删掉镜像项 |
| 直接跑 `go` 命令 | 看环境变量 | `export GOPROXY=https://goproxy.cn,direct` | `unset GOPROXY` 或改回官方 |

注意 Makefile 里的赋值会覆盖环境变量；想让环境变量生效，要么改 Makefile，要么 `make -e`。

### 13.2 npm

CI 里已经写好但被注释掉：

```yaml
# NPM_CONFIG_REGISTRY: https://registry.npmmirror.com
```

要用就取消注释；不要就把这行保持注释或删掉。本地可以：

```sh
npm config set registry https://registry.npmmirror.com
npm config delete registry          # 减掉，回到官方源
```

### 13.3 GitHub 网页/raw 拉不动

国内直连 `raw.githubusercontent.com` 经常连接被重置。可用已登录的 `gh` 走 API：

```sh
gh api -H "Accept: application/vnd.github.raw" \
  repos/liuzq2002/AdguardHome-Mod/contents/README.md > README.md
```

不需要时就不用这套，直接 `curl`/`git clone` 即可。

### 13.4 其它

- pip：`pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple`（以后加 Python 脚本才需要）。
- 记住 CI 跑在 GitHub 的机器上，镜像只影响下载速度；真正需要镜像是**本地构建**。

## 14. 已知坑

- Windows 跑不了 `go build ./...`（平台文件已删）；测试只能在 WSL/Linux 跑。
- 写接口不带 `Content-Type: application/json` 会 415。
- 前端改了不 `make js-build`，打进二进制里的还是旧界面。
- 浏览器/手机 WebView 会缓存旧 JS，看到旧界面先硬刷新。
- Magisk 模块每次开机把 DNS 端口和 Web 端口随机化（模块里的 `service.sh` 会 `sed` 改 `AdGuardHome.yaml` 并在 `config.prop` 里写 `redir_port`），所以「连不上管理界面」先检查端口，不是我们改坏了。
- 删接口会打断仓库外的调用方，见 2.5 节。
- 上游同步会把删掉的平台文件与功能带回来，见第 10 节。
- 本机跑着官方 AdGuard Home 服务（占用 3000/53），做本地验证要换端口，别去动它。

## 15. 每次改动的验收清单

- [ ] `gofmt -l internal/` 无输出
- [ ] WSL 里 `go test ./...` 全绿
- [ ] `GOOS=linux GOARCH=amd64 go build ./...` 通过
- [ ] `GOOS=linux GOARCH=arm64 go build ./...` 通过
- [ ] 改了前端：`make js-lint js-typecheck js-test js-build` 全过
- [ ] 改了前端或接口：真的跑一次二进制，手动点/curl 验证
- [ ] `rg` 检查有没有留下死代码、复活的功能、残留翻译键
- [ ] 文档同步：README（中英）、CHANGELOG、AGHTechDoc、openapi（涉及接口时）
- [ ] 优化类改动：记录二进制体积变化，并在手机上实跑
- [ ] 交付说明写清：改了哪些文件、怎么验证、影响面、怎么回滚
- [ ] 发布前单独确认（默认不发布）
