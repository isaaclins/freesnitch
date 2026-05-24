<p align="center">
  <img src="../screenshot.png" alt="PureSnitch — 适用于 macOS 的开源应用防火墙" width="800">
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ar.md">العربية</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.ja.md">日本語</a> |
  <b>简体中文</b> |
  <a href="README.zh-Hant.md">繁體中文</a>
</p>

<h1 align="center">PureSnitch</h1>

<p align="center">
  <b>看清你的 Mac 在与谁通信，阻止你不信任的连接。</b><br>
  适用于 macOS 的开源应用防火墙。无订阅、无遥测、无升级推销。
</p>

## 安装

```bash
brew tap momenbasel/puresnitch
brew install --cask puresnitch
```

或从 [Releases](https://github.com/momenbasel/puresnitch/releases/latest) 下载签名并公证的 `.dmg`，然后将 PureSnitch 拖入 `/Applications`。

## 为什么需要它

Little Snitch 是 macOS 应用防火墙的黄金标准，售价 59 美元/台。LuLu 免费且在每进程内核层面表现优秀，但规则管理器较为简陋，没有世界地图、流量图表或内置黑名单库。macOS 自带防火墙只阻止入站连接 — 对出站流量毫无作用。

PureSnitch 是第四种选择:

- **与 Little Snitch 6 相同的界面模式** — 菜单栏、世界地图、规则管理器、连接弹窗。
- **MIT 协议开源** — 阅读源码、复刻、审计皆可。
- **无遥测** — 没有分析 SDK，没有崩溃报告外发。
- **作为原生 Mac 应用构建** — 纯 SwiftUI，并非跨平台移植。
- **由 Apple 签名并公证** — 没有"无法验证开发者"提示。

## 功能

- 网络监视器，世界地图实时展示每个活动连接，按进程、域名、国家汇总
- Little Snitch 风格的完整规则管理器 — 分组、黑名单、搜索
- 内置 DNS over HTTPS，可指向 Cloudflare / Quad9 / Google 或任意 DoH 端点
- `127.0.0.1:53` 上的本地 DNS 代理，拦截每一次查询
- 通过 1Hosts、OISD、StevenBlack、HaGeZi 实现域名级阻断
- 通过 `pfctl` 锚点实现内核级 IP / CIDR / 端口阻断
- 配置文件 (default / home / public-wifi / lockdown) — 随网络自动切换

## 完整英文 README

[README.md](../README.md)
