# PureSnitch

> Open-source application firewall for macOS. Free. Notarized. Built like Little Snitch, priced like LuLu.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: macOS 14+](https://img.shields.io/badge/Platform-macOS%2014%2B-blue.svg)](https://www.apple.com/macos/)
[![Swift 5.10](https://img.shields.io/badge/Swift-5.10-orange.svg)](https://swift.org)
[![Notarized](https://img.shields.io/badge/Notarized-Apple-success.svg)](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
[![Release](https://img.shields.io/github/v/release/moamenbasel/puresnitch?include_prereleases&label=release)](https://github.com/moamenbasel/puresnitch/releases)

PureSnitch watches every outgoing connection your Mac makes, blocks the ones you don't trust, and shows you a live world map of who's talking to whom — in the style of Little Snitch, with the same menubar, the same rules manager, the same alert popups. The difference: it's free, the source is here, and the only thing it phones home for is the blocklists you choose.

```
                                                              ▲ ↑ 332 KB/s
                       ┌──────────────────────────────┐       ▼ ↓ 2.18 MB/s
       Process         │   PureSnitch Network Monitor │       █ █ █ █ █ █
       ─────────       │   ────────────────────────── │
       Dia             │                              │
       iTerm           │       (world map of every    │
       Discord         │        connection)           │
       claude          │                              │
       …               │                              │
                       └──────────────────────────────┘
```

## What it does (today, v0.1.0)

| Feature | Status |
|---|---|
| Menubar status item with live up/down throughput + bar graph | works |
| Mode picker — Alert / Silent Allow / Silent Deny | works |
| Network Monitor window with world map, process list, summary | works |
| Rules Manager — rule groups, blocklists, search, allow/deny | works |
| Connection alert popup with "remember" + scope + duration | works |
| DNS over HTTPS upstream (Cloudflare, Quad9, Google) | works |
| Local DNS proxy intercepts every DNS query | works |
| Domain blocking via blocklists (1Hosts, OISD, StevenBlack, HaGeZi, …) | works |
| IP / port blocking via `pfctl` anchor | works |
| Profiles (default, home, public-wifi, lockdown) | works |
| Live IP→country geolocation for world map | works |
| Per-process connection tracking via `lsof` + `nettop` | works |
| SQLite-backed rule & connection history | works |
| XPC bridge between GUI and privileged helper daemon | works |
| **Per-process kernel-level filtering** (Network Extension) | gated by Apple entitlement — see [Roadmap](#roadmap) |

## Install

### Homebrew (recommended)

```bash
brew tap moamenbasel/puresnitch
brew install --cask puresnitch
```

### Direct download

Grab the latest signed + notarized `.dmg` from the [Releases](https://github.com/moamenbasel/puresnitch/releases) page, double-click, drag PureSnitch.app to `/Applications`.

First launch will ask you to approve the privileged helper in System Settings → General → Login Items & Extensions → Allow in Background.

## Screenshots

### Network Monitor

Sidebar with live per-process bandwidth, world map of every active connection, summary pane with top processes/domains/countries.

![Network Monitor](docs/screenshot-monitor.png)

### Rules Manager

All Rules / Active / Deny / Temporary / Unapproved categories, Rule Groups, Blocklists in the sidebar. Each rule shows process, allow/deny chips, priority, hit count.

![Rules Manager](docs/screenshot-rules.png)

PureSnitch's UI is intentionally modeled on Little Snitch 6. If you've used LS, you already know how to use PureSnitch. Open the menubar item for the popover (mode picker + 5-min traffic graph + recent activity + denied count), right-click for the context menu.

## How it works

```
                    ┌─────────────────────────────────────┐
                    │            PureSnitch.app           │
                    │  ┌────────────────────────────────┐ │
                    │  │  SwiftUI GUI                   │ │
                    │  │  - Menubar status item         │ │
                    │  │  - Network Monitor window      │ │
                    │  │  - Rules Manager window        │ │
                    │  │  - Connection Alert popups     │ │
                    │  └──────────┬─────────────────────┘ │
                    │             │ XPC (Mach service)    │
                    │  ┌──────────▼─────────────────────┐ │
                    │  │  PureSnitchHelper (root daemon)│ │
                    │  │  - pfctl anchor manager        │ │
                    │  │  - DNS proxy (UDP/TCP :53)     │ │
                    │  │  - DoH upstream (Cloudflare)   │ │
                    │  │  - Blocklist fetch + parse     │ │
                    │  │  - nettop + lsof stream parser │ │
                    │  │  - SQLite rule store           │ │
                    │  └────────────────────────────────┘ │
                    └────────────────┬────────────────────┘
                                     │
                ┌────────────────────┼────────────────────┐
                │            macOS networking            │
                │   pfctl  ·  DNS  ·  bpf  ·  ess  ·  …  │
                └─────────────────────────────────────────┘
```

Three things actually move bytes:

1. **DNS interception** — PureSnitch runs a local DNS proxy on `127.0.0.1:53` and points the system at it. Every `getaddrinfo` your apps make passes through. Lookups for blocklisted domains return NXDOMAIN; everything else is forwarded over DoH.

2. **pfctl anchor** — PureSnitch installs a `puresnitch` anchor into `/etc/pf.conf` and writes rules to `/etc/pf.anchors/puresnitch`. Block-rules for specific IPs, CIDR ranges, or ports take effect at kernel level, regardless of which process made the connection.

3. **Process + connection observability** — `nettop -P -L 0 -x -J bytes_in,bytes_out` is parsed continuously for per-process bandwidth. `lsof -i -n -P -F pcnT` snapshots active connections every 2 s. Both feed the GUI's process list, world map, and traffic graph.

## Anatomy of a rule

A rule is a tuple of matching predicates plus an action:

```
Rule(
    processBundleId: "com.example.app"   // optional
    processPath:     "/Applications/Example.app/…"
    remoteHost:      "*.tracker.com"     // glob
    remoteIP:        "1.2.3.0/24"        // CIDR
    remotePort:      443
    direction:       outgoing | incoming | any
    action:          allow | deny | ask
    scope:           process | domain | ip | port | any
    priority:        100
    profile:         "default"
    temporary:       false
    expiresAt:       Date?
)
```

The matcher walks enabled rules in `priority` order (DESC) and applies the first match. No match = fall back to the active mode (`alert`, `silentAllow`, `silentDeny`).

## Build from source

Requirements:
- macOS 14+ with Xcode 15+
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- (For signing) a Developer ID certificate

```bash
git clone https://github.com/moamenbasel/puresnitch.git
cd puresnitch
xcodegen generate
open PureSnitch.xcodeproj
```

Or full pipeline (build + sign + notarize + DMG):

```bash
Scripts/sign_and_notarize.sh
Scripts/make_dmg.sh
```

## Project structure

```
puresnitch/
├── Sources/
│   ├── GUI/          # SwiftUI app (menubar, windows, alerts)
│   ├── Helper/       # Privileged daemon (pfctl, DNS proxy, nettop)
│   ├── NetExt/       # Network System Extension (dormant; needs Apple entitlement)
│   └── Shared/       # Rule model, SQLite store, XPC protocol, matcher
├── Resources/
│   └── Assets.xcassets/AppIcon.appiconset/
├── Scripts/
│   ├── make_icon.sh        # Generates app icon from Swift CoreGraphics
│   ├── sign_and_notarize.sh
│   └── make_dmg.sh
├── docs/                   # Screenshots, architecture
├── .github/workflows/      # CI
├── project.yml             # XcodeGen project definition
├── README.md
└── LICENSE                 # MIT
```

## Roadmap

- [x] **v0.1.0** — Signed + notarized release. DNS-level + pfctl-level firewall. Full Little Snitch-style UI.
- [ ] **v0.2.0** — System Extension path (NEFilterDataProvider) for per-process kernel filtering. Requires Apple's `com.apple.developer.networking.networkextension` entitlement. Apply at https://developer.apple.com/contact/request/networking-entitlement.
- [ ] **v0.3.0** — Internet Access Policy (`.lsiap`) file support, on par with Little Snitch's IAP feature.
- [ ] **v0.4.0** — iCloud sync of rule sets between Macs.
- [ ] **v0.5.0** — Endpoint Security Framework integration for process-event awareness.

## FAQ

**Is this a Little Snitch clone?** It's an open-source alternative with a deliberately similar interface. The blocking engine is original; no Little Snitch source or assets are used. "Little Snitch" is a registered trademark of Objective Development Software GmbH; this project is not affiliated with or endorsed by Objective Development.

**Does PureSnitch send my traffic anywhere?** No. Your DNS queries leave only as far as the DoH upstream you pick (Cloudflare by default — override in Settings). PureSnitch itself has no telemetry, no analytics, no phone-home. IP→country lookups go to ip-api.com (free tier) and can be disabled.

**Why isn't per-process blocking on par with Little Snitch?** Per-process blocking requires Apple's Network Extension entitlement, which is gated. The hook points exist in this codebase; the entitlement must be granted by Apple. Until then, blocking happens at DNS-level and packet-level (pfctl), which catches the overwhelming majority of unwanted traffic in practice — anything that resolves a hostname (basically everything except hardcoded-IP malware).

**Will this run on Intel Macs?** The release DMG is built `arm64` only. To build for Intel, change `ARCHS` to `arm64 x86_64` in `project.yml` and rebuild.

**How is it different from LuLu?** [LuLu](https://github.com/objective-see/LuLu) is excellent and has had the NE entitlement for years. PureSnitch differs in: a Little Snitch-style UI (world map, traffic graph, mode picker), DoH out-of-the-box, an opinionated blocklist library, and a written-from-scratch rule engine. Try both; use whichever fits.

**Can I use this in an enterprise?** Yes. MIT license. Distribute internally, fork, embed — no obligations.

## Contributing

PRs welcome. Style: keep diffs small, prefer behavior over comments, no new dependencies without a reason. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Acknowledgements

- [Little Snitch](https://www.obdev.at/products/littlesnitch/) by Objective Development — the canonical macOS application firewall, and the visual reference for this project's UI.
- [LuLu](https://github.com/objective-see/LuLu) by Objective-See — proof that a free, open-source Mac firewall is possible. Patrick Wardle did the hard work of getting Apple to grant the entitlement.
- [1Hosts](https://github.com/badmojr/1Hosts), [OISD](https://oisd.nl/), [StevenBlack](https://github.com/StevenBlack/hosts), [HaGeZi](https://github.com/hagezi/dns-blocklists) — community-maintained domain blocklists bundled by default.

## License

MIT © 2026 Moamen Basel. See [LICENSE](LICENSE).

---

PureSnitch is not affiliated with Apple Inc., Objective Development Software GmbH, or Objective-See. All product names, logos, and brands are property of their respective owners.
