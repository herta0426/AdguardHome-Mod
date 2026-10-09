<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/AdguardTeam/AdGuardHome/raw/master/doc/adguard_home_darkmode.svg">
    <img alt="AdGuard Home" src="https://github.com/AdguardTeam/AdGuardHome/raw/master/doc/adguard_home_lightmode.svg" width="300px">
  </picture>
</p>

<h3 align="center">AdGuard Home 修改版（Mod）</h3>

<p align="center">全网去广告与反跟踪的 DNS 服务器，为 Magisk 模块做的定制修改版。</p>

<p align="center">简体中文 / <a href="README.en.md">English</a></p>

<p align="center">
  <a href="https://github.com/liuzq2002/AdguardHome-Mod/releases"><img src="https://img.shields.io/github/v/release/liuzq2002/AdguardHome-Mod" alt="最新版本"/></a>
  <a href="https://github.com/liuzq2002/AdguardHome-Mod/actions/workflows/build-linux.yml"><img src="https://github.com/liuzq2002/AdguardHome-Mod/actions/workflows/build-linux.yml/badge.svg" alt="构建状态"/></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="许可证"/></a>
</p>

<hr/>

[AdGuard Home] 是一个全网拦截广告和跟踪的 DNS 服务器。部署好之后，它覆盖家里的所有设备，任何设备都不需要再装客户端软件：它把跟踪域名解析到"黑洞"地址，让设备连不上那些服务器。它和 AdGuard 公共 [AdGuard DNS] 服务使用同一套代码。

本仓库是 AdGuard Home 的**非官方修改版（Mod）**，主要为 [Adguard-Home-For-Magisk-Mod] 适配。
[AdGuard Home]: https://github.com/AdguardTeam/AdGuardHome
[AdGuard DNS]: https://adguard-dns.io/
[Adguard-Home-For-Magisk-Mod]: https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod

> **非官方声明**：本项目与 AdGuard Software Ltd. 没有隶属关系，也不由官方提供支持。本项目的 mod 相关问题请在本仓库反馈，AdGuard Home 本身的问题请反馈到上游。

- [这个项目做了什么](#这个项目做了什么)
- [下载与安装](#下载与安装)
- [从源码构建](#从源码构建)
- [与上游同步](#与上游同步)
- [相关文档](#相关文档)
- [许可证](#许可证)

## 这个项目做了什么

DNS 服务、过滤规则、查询日志、客户端管理、加密和 REST API 与上游一致，删掉的是用不上的部分。

界面上的改动：

- 常规设置只保留日志配置与统计配置。
- DNS 设置删除「访问设置」，「拦截模式」只保留默认选项。
- 删除「已阻止的服务」「设置指导」「DHCP」三个选项卡及其页面。
- 删除「加密设置」选项卡及其功能，包括页面、路由、状态管理和 HTTP 调用。
- 首页仪表盘不再显示被拦截的恶意/钓鱼网站、被拦截的成人网站、强制安全搜索，以及客户端排行。
- 查询日志的筛选下拉只保留：所有查询记录、已过滤、已处理、已阻止、允许项、重写项。
- 查询日志里的「放行 / 拦截」按钮旁只保留单个按钮，去掉「仅对此客户端拦截」「仅解除对此客户端的拦截」「不允许这个客户端」「添加为持久客户端」。
- 页脚删除主页、隐私政策、问题反馈链接。

删掉的功能：

- 删除「安全搜索」功能本身：前端代码、各搜索引擎规则文件、HTTP API。
- 删除「已阻止的服务」功能本身：服务清单、服务图标接口，以及客户端与统计里的相关字段。
- 删除「DHCP」功能本身：DHCP 服务器（v4/v6、租约库、静态租约、RA）、`/control/dhcp/*` 九个接口、`dhcp` 配置段、状态接口里的 `dhcp_available`，以及 DNS 侧用 DHCP 租约解析本地主机名与 PTR 的逻辑。
- 界面只保留 English、简体中文、繁體中文三种语言。

只保留 Linux：

- 只支持并构建 `linux/amd64`（x86_64）与 `linux/arm64`。
- 删除其它操作系统的代码与构建配置、Snapcraft 与 Docker 构建、新版前端，以及未完成的 next API。
- 在线更新改用自己的更新源：官方更新服务器只提供官方构建，所以 mod 改为读取仓库根目录的 [`version.json`](version.json)，由发版工作流在每次发版时自动改成最新版本与下载地址。只有 arm64 构建会检查更新，因为发版只提供 arm64。

有意保留的部分，不是漏删：

- 查询日志与统计数据里的 reason / result 编号保留为占位常量，老日志、老统计文件升级后仍能正常读取。
- `internal/configmigrate` 的历史迁移全部保留，老版 `AdGuardHome.yaml` 才能一版一版升上来；但迁移过程中不会再往配置里写入 `safe_search` / `blocked_services` 这类已删除功能的键，反而会把老配置里的它们删掉。

本项目不只是做减法：后续会继续加入自己的功能与调整，改动都记录在 [CHANGELOG.md](CHANGELOG.md) 里。

自己加的功能：

- **强力模式**（`filtering.blocking_mode: strong`，DNS 设置页里可以选）。被拦截的域名回**空解析（NODATA）**，同时对命中规则的 TLS 连接注入 RST。应用自己走 DoH（443 端口，绕开系统 DNS）或把 IP 写死在代码里时，DNS 过滤看不到这些连接，强力模式把这个洞一起补上。选这个模式会自动打开下面的 SNI 阻断，不需要另外配置；在界面里切换即时生效，不用重启。
- **SNI 阻断**（`sni_filter` 配置段，随强力模式启用，仅 Linux）。在 `filter` 表的 `OUTPUT` 链上用 NFQUEUE 读取每条 TLS 连接开头的 ClientHello（明文），取出 SNI，命中过滤规则就注入 TCP RST，让连接在十几毫秒内失败。NFQUEUE 回调先做纯字节快速短路，非 ClientHello 包零分配放行；队列丢失时用 `epoll` 事件驱动重建。用的是**同一套过滤规则**，不需要另外维护清单。每条连接的 SNI 都会记进**查询日志**（放行的也在），被拦的显示「已阻止（SNI）」、放行的显示「已处理（SNI）」，两种情况都带上命中的规则。需要 root（Magisk 模块本来就以 root 运行）与内核支持 `connbytes`、`NFQUEUE`；缺任何一个只会记日志，不影响 DNS 服务。配置项与原理见 [doc/AdGuardHome.yaml.example](doc/AdGuardHome.yaml.example) 的 `sni_filter` 段与 [交接文档](HANDOVER.md) 第 2.6 节。

版本号使用日期，例如 `v2026-09-24`，见 `scripts/make/version.sh`。预发布在日期后面加后缀，例如 `v2026-09-25-beta`、`v2026-09-25-rc.1`；带后缀的 tag 会以「预发布」形式发布，不会抢占「最新版本」。

## 下载与安装

发版只提供 arm64 的包（手机与 Magisk 模块用的就是这个）：

- `AdGuardHome_linux_arm64.tar.gz` — arm64
- `checksums.txt` — 压缩包的 SHA-256 校验和

去 [Releases](https://github.com/liuzq2002/AdguardHome-Mod/releases) 下载。amd64 只用于本地测试，不随发版提供；需要时在 Actions 页面手动运行工作流，下载 `AdGuardHome-linux` 产物，里面同时有 amd64 与 arm64 两个包。

面板里的「更新」也是从本仓库取信息的：程序读仓库根目录的 [`version.json`](version.json)（原始地址 `https://raw.githubusercontent.com/liuzq2002/AdguardHome-Mod/main/version.json`），发版工作流每次发版会自动把它改成新版本号、发布页地址与 arm64 压缩包地址。所以装好之后，面板会提示并可以直接升级到下一个版本。如果这个地址在你的网络下连不上，可以换成镜像（例如 `https://ghfast.top/https://raw.githubusercontent.com/...` 或 jsDelivr），见 [交接文档](HANDOVER.md) 的「换更新源」一节。

```sh
tar -xzf AdGuardHome_linux_arm64.tar.gz
cd AdGuardHome
sha256sum -c --ignore-missing checksums.txt
```

替换原来的可执行文件后重启。面板「更新」处显示的版本号应当是 `v2026-09-24` 这样的日期；如果显示 `v0.107.x` 之类，说明装的还是官方原版。换过二进制之后，浏览器建议强刷一次，避免缓存到旧界面。

`doc/AdGuardHome.yaml.example` 是一份参考模板，说明了经过本 Mod 删减之后的配置长什么样：官方版本写出的 `dns.safe_search`、`dns.safesearch_cache_size`、`dns.blocked_services`、`clients[].safe_search`、`clients[].blocked_services` 等键在这里都不存在。它**不是安装必需**的，程序第一次启动会自己生成同样的配置；只有手工改配置或清理老配置时才需要对照它。换配置前先备份。

## 从源码构建

需要 Go 1.26.8 或更高版本，以及 Node.js 24。

```sh
make quick-build
```

分开执行是：

```sh
make js-deps       # npm ci
make js-build      # 把前端打包进 build/static
make go-build      # 生成 ./AdGuardHome
```

本地生成发布包：

```sh
make build-release SIGN=0
make pack-release SIGN=0
```

产物位于 `dist/`。

## 与上游同步

本仓库跟随 [AdGuard Home][AdGuard Home]。先添加上游仓库，然后把上游的改动合并到自己的分支：

```sh
git remote add upstream https://github.com/AdguardTeam/AdGuardHome.git
git fetch upstream
git merge upstream/master
```

大部分上游改动可以干净合并，下面这些文件是本项目有意改过的，冲突通常出在这里：

| 路径 | 需要保留的内容 |
| --- | --- |
| `client/src/components/App/` | 修改后的路由 |
| `client/src/components/Dashboard/` | 修改后的卡片与表格 |
| `client/src/components/Header/Menu.tsx` | 修改后的导航 |
| `client/src/components/Settings/` | 修改后的常规设置与 DNS 设置 |
| `client/src/components/ui/Footer.tsx` | 修改后的页脚 |
| `.github/`、`Makefile`、`scripts/make/` | 只保留 Linux 的构建与 CI |
| `internal/home/home.go`、`internal/updater/` | 指向本仓库 `version.json` 的更新源 |

合并完成后运行 `make quick-build` 再推送；CI 会跑 lint、测试并构建两个架构。

## 相关文档

- [交接与维护文档](HANDOVER.md)：本地环境、构建与发版、同步上游、功能的增删改查。
- [维护手册](MAINTENANCE.md)：日常改动流程、发版（含预发布）、在线更新源、上游同步与排错。
- [上游 Wiki](https://github.com/AdguardTeam/AdGuardHome/wiki)
- [上游 API 文档](https://github.com/AdguardTeam/AdGuardHome/tree/master/openapi)

## 许可证

GNU General Public License v3.0，见 [LICENSE.txt](LICENSE.txt)。本项目基于 AdGuard Home，© AdGuard Software Ltd.
