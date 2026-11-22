# Xbox 网络录制

OpenWrt 的 LuCI 插件。按 Xbox 的 MAC 地址或局域网 IP 开始一次录制，收集明文 DNS 查询、TCP TLS 握手公开的 SNI 和传出流量的公网 IPv4 / IPv6 目的地址。DNS 回应和 SNI 连接可用于关联域名的网络归属。录制结束后可勾选条目，导出 Clash / Mihomo YAML 或分别生成域名和 IP MRS。

## 安装

将对应的安装包上传到路由器的 `/tmp/`。安装时会从路由器的软件源安装缺少的依赖。[下载 1.6.0 安装包](https://github.com/adian2020/Xbox-IP-/tree/main/packages/1.6.0)

**使用 opkg 的 OpenWrt（例如 23.05、24.10）**

```sh
opkg update
opkg install /tmp/luci-app-xbox-capture_1.6.0-1_all.ipk
```

**使用 apk 的 OpenWrt（例如 25.12）**

```sh
apk update
apk add --allow-untrusted /tmp/luci-app-xbox-capture-1.6.0-r1.apk
```

这里的 `--allow-untrusted` 用于安装这一个本地未签名的 APK。安装完成后重新打开 LuCI，进入 **服务 → Xbox 网络录制**。也可以用 `ubus call xbox-capture status '{}'` 确认插件已注册。

## 录制与导出

1. 在 **Xbox 地址** 点 **选择设备**。列表会显示路由器从 LAN 邻居表和有效 DHCP 租约发现的设备、IPv4、IPv6 和 MAC。选中设备后会使用其 MAC，接口可识别时自动填入。也可以从 Xbox 的 **设置 → 常规 → 网络设置 → 高级设置** 查看地址后手动填写。
2. 完全退出要录制的游戏或软件。填写名称和最长录制时间，点 **开始录制**，再启动游戏。按需要经过登录、大厅、匹配、联机或语音场景。
3. 点 **结束录制**。打开录制详情，筛选并取消勾选与游戏无关的条目。域名列会标记 `DNS` 或 `TLS SNI`，同一域名可以有两种来源。
4. 下载 YAML。按当前 Clash / Mihomo 的配置方式选择以下格式。

在 **录制记录** 可按时间或名称排序。勾选单条或点全选，再点 **删除所选** 并确认。

设备名单随路由器掌握的信息变化。设备断开后，邻居缓存或有效租约可能短时保留。路由器没有收到名称的设备会显示为「未知设备」。

### 实时抓取面板

在 **实时状态** 点 **打开抓取面板**。录制期间每两秒更新已抓到的域名、公网 IP、端口和最近新增信息的时间。可以按类型筛选、搜索或分页。实时列表遵循当前录制模式，录制结束后可从面板进入完整录制。

### 域名与公网 IP 归属

首次使用时点 **下载归属库**。更新时可查看下载量、索引读取进度和已处理条数。实时面板和录制详情会显示匹配的运营组织、ASN 和地区。中文名包含阿卡迈等常见网络组织，其余沿用数据源名称。录制详情支持用中文名、英文原名、ASN 或国家和地区筛选。

1.6.0 起，新录制会用发往 Xbox 的明文 DNS 回应（A、AAAA 和 CNAME）以及 TLS SNI 连接关联域名和公网 IP。同一域名最多显示三个不同归属。只看到域名、私网地址或 Fake IP 的条目可能没有归属标签。使用 `any` 接口时，DNS 回应关联需要已知的 Xbox 局域网 IP。旧录制继续显示 IP 归属。域名关联信息用于界面显示，DNS 回应中的地址不会额外生成 IP 规则。

归属查询在路由器上完成。IPtoASN 提供约 11 MB 的公开压缩数据，索引存入路由器临时存储。重启后可重新下载。国家或地区取自归属库，实际机房位置可能不同。ASN 标明该 IP 所在的网络，判断流量用途仍可结合域名和待机基线。[IPtoASN 数据来源和许可](https://iptoasn.com/)

### 端口与代理规则

1.3.0 起，新录制的详情会显示公网 IP 实际观察到的 TCP 和 UDP 目标端口。域名端口来自识别到该名称的 TLS 握手。只有 DNS 记录的域名会显示 `—`，因为 DNS 查询端口属于解析服务。早期录制也会显示 `—`。

Clash / Mihomo 的 `DOMAIN`、`IP-CIDR` 和 `IP-CIDR6` 按名称或地址匹配所有端口。导出的 YAML 和域名／IP MRS 可以直接用于这类匹配。若想只代理某个域名的 443 端口，可手动在 Mihomo 配置中组合 `DOMAIN` 与 `DST-PORT`。

```yaml
rules:
  - "AND,((DOMAIN,game.example),(DST-PORT,443)),Xbox"
```

### 只录新增

1. 让 Xbox 停留在主界面，选 **完整录制**，录一段背景流量，结束后将这条记录用作待机基线。已有的完整录制也可以选用。
2. 选 **只录新增**，再选 **待机基线**。插件会沿用基线的 Xbox 地址和 LAN 接口。点 **开始录制**，再打开游戏。
3. 结束录制后照常下载 YAML。录制详情和导出的规则只含本次录制中出现、基线中未出现的域名或公网 IP。

域名和 IP 分别按完整值比较。游戏和 Xbox 后台共用的域名或 IP 也会被过滤。后台服务如果在打基线时没有联网，相关条目仍可能出现在新增结果里。更换网络后可为同一台 Xbox 重新录制基线。

### Clash rules 配置

填写已有的策略组名称，例如 `Xbox`。把下载文件的条目并入现有 `rules`，通常放在匹配范围更大的规则及 `MATCH` 之前。示例使用演示地址。

```yaml
rules:
  - "DOMAIN,game.example,Xbox"
  - "IP-CIDR,8.8.4.4/32,Xbox,no-resolve"
  - "IP-CIDR6,2606:4700::1111/128,Xbox,no-resolve"
```

### Classical 规则集

把下载的文件保存为内核可读取的 `./rule_provider/xbox.yaml`，路径相对于内核使用的工作目录。将以下内容并入配置中的 `rule-providers` 和 `rules`，并把 `Xbox` 替换成已有的策略组。

```yaml
rule-providers:
  xbox-game:
    type: file
    behavior: classical
    path: ./rule_provider/xbox.yaml

rules:
  - RULE-SET,xbox-game,Xbox
```

### MRS 和 GitHub

生成和合并 MRS 需要路由器已有支持 `convert-ruleset` 的 Mihomo 内核，例如 `/usr/bin/mihomo` 或 `/etc/openclash/core/clash_meta`。录制详情中的 **导出或发布 MRS** 会根据勾选内容生成域名和 IP 文件。也可在 **GitHub 与 MRS** 选择电脑上已有的 MRS。

1. 在 GitHub 创建 Fine-grained Personal Access Token，仓库选 `adian2020/Xbox-IP-` 或要发布的仓库，授予该仓库的 **Contents → Read and write** 权限。使用 HTTPS 打开 LuCI，在 **GitHub 与 MRS** 输入令牌并点 **登录 GitHub**。令牌只在当前 LuCI 页面会话使用，刷新后需要重新登录。
2. 在 **导出或发布 MRS** 或 **上传已有 MRS** 中填写仓库、分支、仓库内目录、游戏或软件目录名和文件名。分支留空使用默认分支。默认路径形如 `rules/Forza Horizon 5/domain.mrs` 和 `rules/Forza Horizon 5/ip.mrs`。
3. 点 **发布到 GitHub**。文件名和完整路径一致时，插件把新旧 MRS 解码合并后提交，保留原规则并去重。两份规则随同一次提交更新。规则已齐全时，界面显示无新增。

IP 文件会合并重复和包含的 CIDR。只选中一种条目时只生成对应的文件。单个 MRS 上限为 512 KiB。发布需要 GitHub 仓库已有分支，并且令牌有权限向该分支提交。

将生成的文件放到 Mihomo 可读取的位置后，可以分别配置两种规则集。

```yaml
rule-providers:
  xbox-domain:
    type: file
    behavior: domain
    format: mrs
    path: ./rule_provider/xbox-domain.mrs
  xbox-ip:
    type: file
    behavior: ipcidr
    format: mrs
    path: ./rule_provider/xbox-ip.mrs

rules:
  - RULE-SET,xbox-domain,Xbox
  - RULE-SET,xbox-ip,Xbox,no-resolve
```

## 抓包范围

- 路由器只能识别设备级流量。一段录制里可能有 Xbox 系统服务、后台下载和其他软件的连接，游戏归属需要根据场景和结果判断。
- 域名来自可见的 DNS 查询或 TCP TLS SNI。DoH、DoT、ECH、QUIC 握手和录制前已建立的连接可能只有 IP。相同公网 IP 也可能被多个服务共用。
- IP 规则只包含 Xbox 实际访问的公网地址，使用单地址前缀 `/32` 或 `/128`。Clash Fake-IP、局域网、组播和常见保留地址会被排除。公共 DNS 服务器的 IP 如果被 Xbox 直接访问，也可能出现在列表中。
- 如果结果很少，确认 Xbox 流量经过填写的 LAN 接口。硬件卸载、旁路网关和 VLAN 的抓包点会影响路由器能看到的数据。按 IP 录制时，用已解 VLAN 标签的 LAN 设备，并填入 Xbox 实际使用的 IPv4 和 IPv6 地址。
- 最多保留 20 次录制，每次分别去重保存最多 2,000 个域名和 2,000 个 IP。录制时将抓包数据流交给解析器，只在 `/var/run/xbox-capture` 保存结果。路由器重启后临时记录会清空。

### 录制时一直为 0

1. 开始录制后，在 Xbox 的 **设置 → 常规 → 网络设置** 运行 **测试网络连接**，查看插件的 **目标 IP 报文** 计数。填写 IP 时，插件会尝试通过 LAN 邻居表识别 MAC。计数旁会显示实际采用的地址。
2. 如果报文数仍为 0，确认用的是 Xbox 当前有线或无线连接的 MAC，把接口改为其 VLAN 或 `any`，再开始一轮录制。两种接口都为 0 时，确认 Xbox 以这台路由器为网关。如果启用了流量分载，可暂时关闭软件和硬件分载后重启游戏测试。
3. 如果报文数在增加，但域名和公网 IP 都为 0，查看状态说明。收到 Fake-IP 时可针对 Xbox 使用真实 IP 的 DNS 模式后再录一次。只录新增时，基线已经包含的条目会正常排除。

## 命令行

```sh
xbox-capture start "Forza Horizon 5" 00:11:22:33:44:55 --interface br-lan --minutes 120
xbox-capture status
xbox-capture stop
xbox-capture sessions
xbox-capture export <录制编号> --format inline --policy Xbox
```

命令需要在路由器上由管理员运行。省略 `--format` 会导出 Classical 规则集。

命令行可用 `xbox-capture start "Forza Horizon 5" --baseline <基线录制编号>` 开始只录新增。用 `xbox-capture sessions` 查看编号。

## 从源码打包

可以用 GNU tar 直接生成跨架构 IPK。

```sh
./tools/package-ipk.sh
```

也可以把源码目录放入有 LuCI 和软件包 feeds 的 OpenWrt SDK 的 `package/luci-app-xbox-capture`。在 SDK 中选择软件包后执行下面的命令。SDK 使用目标版本的包管理器格式生成软件包。

```sh
make package/luci-app-xbox-capture/compile V=s
```

如果已有 OpenWrt SDK 的 `apk` 主机工具和 `fakeroot`，也可以直接生成跨架构 APK。

```sh
XBOX_APK=/path/to/sdk/staging_dir/host/bin/apk ./tools/package-apk.sh
```

可以用本地 Mihomo 运行 MRS 合并测试。

```sh
XBOX_CAPTURE_MIHOMO=/path/to/mihomo python3 -B -m unittest discover -s tests -v
```
