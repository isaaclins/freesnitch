# Architecture

## Process model

FreeSnitch is a 3-process application:

```
┌──────────────────────────────────────────────────────────────────────┐
│                          FreeSnitch.app                              │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                       FreeSnitch (GUI)                         │  │
│  │  user-space, runs as the logged-in user                        │  │
│  │  Bundle: io.isaaclins.freesnitch                               │  │
│  │  - SwiftUI views (Menubar, NetworkMonitor, RulesManager, ...)  │  │
│  │  - HelperClient (NSXPCConnection over a Mach service)          │  │
│  │  - AppState (Observable, drives all views)                     │  │
│  └────────────────────────────┬───────────────────────────────────┘  │
│                               │ XPC                                  │
│  ┌────────────────────────────▼───────────────────────────────────┐  │
│  │                  FreeSnitchHelper (daemon)                     │  │
│  │  root, registered with launchd via SMAppService.daemon         │  │
│  │  Bundle: io.isaaclins.freesnitch.helper                        │  │
│  │  - PFManager     (writes /etc/pf.anchors/puresnitch + pfctl)   │  │
│  │  - DNSProxy      (NWListener on UDP/TCP 53 + DoH upstream)     │  │
│  │  - NetMonitor    (parses nettop + lsof streams)                │  │
│  │  - BlocklistManager (fetches HOSTS-format lists, parses)       │  │
│  │  - RuleStore     (SQLite at /Library/Application Support/…)    │  │
│  │  - HelperService (NSXPCListenerDelegate)                       │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
                               │
            ┌──────────────────┼────────────────────┐
            │           macOS kernel + tools         │
            │  pfctl(8)  ·  nettop(1)  ·  lsof(8)    │
            │  Network.framework  ·  dispatch  ·  …  │
            └────────────────────────────────────────┘
```

## XPC contract

Defined in `Sources/Shared/HelperProtocol.swift`:

- **HelperProtocol** - GUI → Helper. Methods: `getStatus`, `setMode`, `addRule`, `removeRule`, `listRules`, `startMonitoring`, `installPF`, `refreshBlocklists`, `setDoHUpstream`, etc.
- **HelperClientProtocol** - Helper → GUI. Methods: `notifyConnection`, `notifyTraffic`, `notifyAlert(connectionJSON, reply)`, `notifyLog`.

`notifyAlert` is the call that delivers a new connection event to the GUI in Alert mode. The GUI's `AppState.presentAlert(...)` puts up a SwiftUI sheet; the user's Allow/Deny choice is sent back through the reply block.

## DNS path

```
app → libsystem_resolver → 127.0.0.1:53 (FreeSnitch DNS proxy)
                              │
                              ├─ blocklist match? ──→ NXDOMAIN
                              │
                              ├─ rule says deny?  ──→ NXDOMAIN
                              │
                              ├─ rule says ask?   ──→ notifyAlert
                              │                       │
                              │                       ├─ allow ─→ DoH forward
                              │                       └─ deny  ─→ NXDOMAIN
                              │
                              └─ default              ──→ DoH forward (Cloudflare/Quad9/Google)
```

Both UDP and TCP DNS are handled. DoH is `application/dns-message` POST to a single configurable upstream.

## pfctl path

FreeSnitch maintains the established anchor named `puresnitch` referenced from `/etc/pf.conf`:

```
anchor "puresnitch"
load anchor "puresnitch" from "/etc/pf.anchors/puresnitch"
```

The anchor file is rewritten by the helper from `Rule[]` whenever rules change:

```
set block-policy drop
set skip on lo0
block out quick proto { tcp udp } to 198.51.100.0/24
pass out quick proto { tcp udp } to 1.1.1.1 port 443
```

`pfctl -E` enables pf, `pfctl -a puresnitch -f <file>` reloads our anchor.

## Per-process observation

- `nettop -P -L 0 -x -J bytes_in,bytes_out -s 1` runs continuously. Each line update is parsed for per-process throughput which feeds the menubar histogram + Network Monitor process list.
- `lsof -i -n -P -F pcnT` is polled every 2 s. Output is parsed into `Connection` records with PID, process path, local/remote IP+port, and an inferred bundle ID (via Info.plist of the enclosing `.app`).

## Rule matching

`RuleMatcher.decision(for:rules:defaultMode:)` walks enabled, unexpired rules in `priority DESC` order. First match wins. No match = fall back to active mode (`alert` → `.ask`, `silentAllow` → `.allow`, `silentDeny` → `.deny`).

Host glob: `*.example.com`, `.example.com` both match.
IP CIDR: `10.0.0.0/8` matches anywhere in that block.
Process: bundle ID match wins; otherwise path prefix.

## NetExt - per-process firewall (Network System Extension)

`Sources/NetExt/FilterDataProvider.swift` is a `NEFilterDataProvider` content filter, built as the `FreeSnitchNetExt` system-extension target and embedded at `Contents/Library/SystemExtensions/`. It gives true per-process filtering (Little Snitch's mechanism).

- `handleNewFlow` evaluates each socket flow with the shared `RuleMatcher`; allow → `.allow()`, deny → `.drop()`, ask → `.pause()` then resume with the user's verdict.
- App ↔ extension XPC: `Shared/IPCConnection.swift` (extension vends a mach service named by `NEMachServiceName`; the app connects and receives prompts, reusing the connection-alert UI).
- Rules reach the sandboxed extension via the app-group container (`Shared/SharedRuleBridge.swift`), mirrored by the GUI on every rule/mode change.
- Activation: `GUI/App/SystemExtensionManager.swift` (`OSSystemExtensionRequest` + `NEFilterManager`).

Shipping requires the `content-filter-provider-systemextension` entitlement (self-serve Network Extensions capability on the App ID), Developer ID signing + notarization, and the app installed in `/Applications`. See `Sources/NetExt/README.md`. The helper (pfctl + DNS) remains for rule storage and DNS blocklists.
