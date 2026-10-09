<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/AdguardTeam/AdGuardHome/raw/master/doc/adguard_home_darkmode.svg">
    <img alt="AdGuard Home" src="https://github.com/AdguardTeam/AdGuardHome/raw/master/doc/adguard_home_lightmode.svg" width="300px">
  </picture>
</p>

<h3 align="center">AdGuard Home Mod</h3>

<p align="center">Network-wide ads and trackers blocking DNS server, customized for the Magisk module.</p>

<p align="center"><a href="README.md">简体中文</a> / English</p>

<p align="center">
  <a href="https://github.com/liuzq2002/AdguardHome-Mod/releases"><img src="https://img.shields.io/github/v/release/liuzq2002/AdguardHome-Mod" alt="Latest release"/></a>
  <a href="https://github.com/liuzq2002/AdguardHome-Mod/actions/workflows/build-linux.yml"><img src="https://github.com/liuzq2002/AdguardHome-Mod/actions/workflows/build-linux.yml/badge.svg" alt="Build status"/></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="License"/></a>
</p>

<hr/>

[AdGuard Home] is a network-wide software for blocking ads and tracking.  Once it is set up, it covers all your home devices, and none of them needs any client-side software: it re-routes the tracking domains to a "black hole", so the devices cannot reach those servers.  It is based on the same software as the public [AdGuard DNS] servers.

This repository is an **unofficial mod** of AdGuard Home, mainly adapted for [Adguard-Home-For-Magisk-Mod], which packages AdGuard Home as a Magisk module for Android.  RAM and storage are tight there, so the parts that are not used are removed first, and the DNS server and the basic management features are kept.  Our own features will be added on top of that.

[AdGuard Home]: https://github.com/AdguardTeam/AdGuardHome
[AdGuard DNS]: https://adguard-dns.io/
[Adguard-Home-For-Magisk-Mod]: https://github.com/liuzq2002/Adguard-Home-For-Magisk-Mod

> **Unofficial.**  This project is not affiliated with, endorsed by, or supported by AdGuard Software Ltd.  Report problems with the mod in this repository, and problems with AdGuard Home itself upstream.

- [What this project does](#what-this-project-does)
- [Download and install](#download-and-install)
- [Build from source](#build-from-source)
- [Keeping up with upstream](#keeping-up-with-upstream)
- [Documentation](#documentation)
- [License](#license)

## What this project does

The DNS server, filtering, the query log, client management, encryption, and the REST API are the same as upstream.  What is gone is the part that is not used.

Admin UI changes:

- General settings keep only the query log and the statistics configuration.
- DNS settings no longer have the access settings, and the blocking mode only offers the default option.
- The Blocked services, Setup guide, and DHCP tabs are removed along with their pages.
- The Encryption settings tab is removed along with its functionality: the page, the route, the state management, and the HTTP calls.
- The dashboard no longer shows blocked threats, blocked adult websites, safe search, and top clients.
- The query log filter keeps only: all queries, filtered, processed, blocked, allowed, and rewritten.
- The query log keeps a single button next to Unblock and Block; "Block for this client only", "Unblock for this client only", "Disallow this client", and "Add as persistent client" are removed.
- The footer no longer links to the homepage, the privacy policy, and the issue tracker.

Removed features:

- Safe search itself: the frontend code, the per-engine rule files, and the HTTP API.
- Blocked services itself: the service list, the icon endpoint, and the related fields in the clients and statistics data.
- DHCP itself: the DHCP server (v4/v6, the lease database, static leases, and the router advertisements), the nine `/control/dhcp/*` endpoints, the `dhcp` configuration section, the `dhcp_available` status field, and the DNS-side resolution of local hostnames and PTR records from DHCP leases.
- Only English, Simplified Chinese, and Traditional Chinese remain as the UI languages.

Linux only:

- Only `linux/amd64` (x86_64) and `linux/arm64` are supported and built.
- The code and the build configuration for the other operating systems, the Snapcraft and Docker builds, the next-generation frontend, and the unfinished next API are removed.
- Update checks use the mod's own update source: the AdGuard update server only serves the official builds, so the mod reads [`version.json`](version.json) from the repository root instead, and the release workflow rewrites it with the latest version and archive URL on every release.  Only the arm64 builds check for updates, since that is all the releases provide.

Kept on purpose, not forgotten:

- The reason and result numbers in the query log and the statistics files are kept as reserved placeholders, so that the existing logs and statistics files stay readable after the upgrade.
- All the historical migrations in `internal/configmigrate` are kept, so that an old `AdGuardHome.yaml` can be upgraded version by version.  They no longer write the keys of the removed features, such as `safe_search` and `blocked_services`, and instead drop those keys from old configurations.

This project does more than remove things: more features and adjustments of our own are on the way, and all of them are listed in [CHANGELOG.md](CHANGELOG.md).

Features of our own:

- **Strong blocking mode** (`filtering.blocking_mode: strong`, also available in the DNS settings of the admin UI).  The blocked domains are answered with an empty **NODATA** response, and the TLS connections that match the filtering rules are reset with a TCP RST.  Applications that use their own DNS-over-HTTPS resolver on port 443 or connect to hard-coded addresses bypass DNS filtering, and this mode closes that gap as well.  Choosing the mode turns the SNI blocking below on automatically, and switching it in the UI takes effect without a restart.
- **SNI blocking** (the `sni_filter` section, enabled by the strong blocking mode, Linux only).  An NFQUEUE rule in the `OUTPUT` chain of the `filter` table reads the ClientHello at the beginning of every TLS connection, extracts the plain-text SNI, and, if the filtering rules match, injects a TCP RST that makes the connection fail in a dozen milliseconds.  The NFQUEUE callback short-circuits the packets that cannot begin a ClientHello without allocating, and an `epoll`-driven watcher re-registers the queue if the kernel drops it.  It reuses **the same filtering rules**, so no separate list is needed.  The SNI of every connection is recorded in the **query log**, including the allowed ones: the blocked rows are shown as "Blocked (SNI)" and the allowed ones as "Processed (SNI)", both with the matched rules.  It requires the root rights, which the Magisk module already has, and a kernel with `connbytes` and `NFQUEUE` support; without either of those, it only logs an error and the DNS server is unaffected.  See the `sni_filter` section of [doc/AdGuardHome.yaml.example](doc/AdGuardHome.yaml.example) and section 2.6 of [HANDOVER.md](HANDOVER.md).

Versions are dates, for example `v2026-09-24`.  See `scripts/make/version.sh`.  Pre-releases add a suffix to the date, for example `v2026-09-25-beta` or `v2026-09-25-rc.1`; tags with a suffix are published as GitHub pre-releases and never become the latest release.

## Download and install

Releases carry the arm64 build only, since that is what the phones and the Magisk module use:

- `AdGuardHome_linux_arm64.tar.gz` — arm64
- `checksums.txt` — SHA-256 hashes of the archives

Download them from [Releases](https://github.com/liuzq2002/AdguardHome-Mod/releases).  The amd64 build is for local testing only and is not shipped in the releases; run the workflow from the Actions tab and download the `AdGuardHome-linux` artifact to get both the amd64 and the arm64 archives.

The update section of the dashboard also reads from this repository: the binary fetches [`version.json`](version.json) from the repository root (`https://raw.githubusercontent.com/liuzq2002/AdguardHome-Mod/main/version.json`), and the release workflow rewrites that file with the new version, the release page URL, and the arm64 archive URL on every release.  So an installed build offers an upgrade to the next version.  If that URL is unreachable from your network, point the updater at a mirror instead; see the "换更新源" section of the [handover document](HANDOVER.md) (written in Chinese).

```sh
tar -xzf AdGuardHome_linux_arm64.tar.gz
cd AdGuardHome
sha256sum -c --ignore-missing checksums.txt
```

Replace the executable and restart.  The version shown in the update section of the dashboard should be a date such as `v2026-09-24`; if it shows `v0.107.x` or similar, the official build is still installed.  Hard-refresh the browser once after replacing the binary, so that it does not serve the cached frontend.

`doc/AdGuardHome.yaml.example` is a reference template that shows what the configuration looks like after the mod's removals: the keys that the official build writes, such as `dns.safe_search`, `dns.safesearch_cache_size`, `dns.blocked_services`, `clients[].safe_search`, and `clients[].blocked_services`, are not there.  It is **not required** for installation, since the program writes the same configuration on its first launch.  Use it when editing a configuration by hand or when cleaning up an old one, and always back the file up first.

## Build from source

Requirements: Go 1.26.8 or later and Node.js 24.

```sh
make quick-build
```

The separate steps are:

```sh
make js-deps       # npm ci
make js-build      # bundle the frontend into build/static
make go-build      # build the ./AdGuardHome binary
```

To produce the release archives locally:

```sh
make build-release SIGN=0
make pack-release SIGN=0
```

The result is written into `dist/`.

## Keeping up with upstream

The mod tracks [AdGuard Home][AdGuard Home].  Add the upstream repository once, and merge its changes into your own branch:

```sh
git remote add upstream https://github.com/AdguardTeam/AdGuardHome.git
git fetch upstream
git merge upstream/master
```

Most of the upstream changes merge cleanly.  The files below are changed on purpose and are the usual source of conflicts:

| Path | What to keep |
| --- | --- |
| `client/src/components/App/` | the modified routes |
| `client/src/components/Dashboard/` | the modified cards and tables |
| `client/src/components/Header/Menu.tsx` | the modified navigation |
| `client/src/components/Settings/` | the modified general and DNS settings |
| `client/src/components/ui/Footer.tsx` | the modified footer |
| `.github/`, `Makefile`, `scripts/make/` | the Linux-only build and CI |
| `internal/home/home.go`, `internal/updater/` | the update source pointing at this repository's `version.json` |

After merging, run `make quick-build`, then push.  The workflow lints, tests, and builds both architectures.

## Documentation

- [Handover and maintenance notes](HANDOVER.md) (written in Chinese): local environment, builds and releases, syncing with the upstream, adding and removing features.
- [Maintenance manual](MAINTENANCE.md) (written in Chinese): the day-to-day workflow, releases including pre-releases, the update source, syncing with the upstream, and troubleshooting.
- [Upstream wiki](https://github.com/AdguardTeam/AdGuardHome/wiki)
- [Upstream API description](https://github.com/AdguardTeam/AdGuardHome/tree/master/openapi)

## License

GNU General Public License v3.0, see [LICENSE.txt](LICENSE.txt).  Based on AdGuard Home, © AdGuard Software Ltd.
