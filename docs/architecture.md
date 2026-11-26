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

Both UDP and TCP DNS are handled. DoH is `application/dns-message` POST to a single configurable upstream. Blocklists are enforced only in this helper DNS proxy, and only when Enforcement is enabled. They filter DNS names sent to `127.0.0.1:53`; they do not stop hardcoded IP connections or names resolved by an app's own encrypted DNS, such as Chrome and Firefox DoH. Blocklist entries are not sent to the Network Extension or written to the pfctl anchor.

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
block in quick proto tcp from 198.51.100.0/24 flags S/SA
block in quick proto udp from 198.51.100.0/24
block out quick proto { tcp udp } to any port 8443
pass out quick proto { tcp udp } to 1.1.1.1 port 443
pass in quick proto { tcp udp } from 203.0.113.9 port 51413
pass in proto { tcp udp } from 203.0.113.20
```

A rule names the remote side, so a deny's incoming half is written `from` it. That half blocks only new TCP connections (`flags S/SA`), and incoming UDP only for a deny in both directions, since a block keeps no state and must not drop replies to the Mac's own connections. A rule with only a port is written `to any port N`: pf refuses a bare `port`, and one refused line makes it refuse the whole anchor. An allow is written per direction too, as `pass out ... to` the peer and `pass in ... from` it, or both lines for a rule in both directions. It never goes in without a direction, since an undirected pass would also match the other direction, where `to` and `from` name the Mac's own side, and skip later blocks in `/etc/pf.conf`. An incoming allow with only a port stays with the Network Extension. An app's allow is written without `quick` in both directions: pf would apply it to every app, so a block after the anchor in `/etc/pf.conf` still wins. The incoming half (the last line above) keeps state that lets the Mac's replies to that peer past an address feed. The outgoing half is written `pass out proto { tcp udp } to X port N tag freesnitch_app_allow`, and the feed's block is `block out quick ... to <freesnitch_ipblock> ! tagged freesnitch_app_allow`: pf keeps a tag on the packet even when a later rule decides, so the allowed packets get past the feed and a later block in `/etc/pf.conf` still wins.

`pfctl -E` enables pf, `pfctl -a puresnitch -f <file>` reloads our anchor.

## Per-process observation

- `nettop -P -L 0 -x -J bytes_in,bytes_out -s 1` runs continuously. Each frame is parsed for per-process throughput, which feeds the Network Monitor process list.
- The menubar speed and histogram come from the interfaces' exact 64-bit byte counters (`sysctl` `net.link.generic` `IFMIB_IFDATA`; `getifaddrs` and `NET_RT_IFLIST2` truncate them to 32 bits), read once a second. nettop block-buffers into a pipe, so its frames arrive in bursts and cannot time a rate (#156).
- `lsof -i -n -P -F pcnT` is polled every 2 s. Output is parsed into `Connection` records with PID, process path, local/remote IP+port, and an inferred bundle ID (via Info.plist of the enclosing `.app`).

## Rule matching

`RuleMatcher.decision(for:rules:defaultMode:)` walks enabled, unexpired rules in `priority DESC` order. First match wins. No match = fall back to active mode (`alert` → `.ask`, `silentAllow` → `.allow`, `silentDeny` → `.deny`).

Host glob: `*.example.com` and `.example.com` both match `example.com` and its subdomains (`api.example.com`), never a name that only ends in the same text (`notexample.com`).
IP CIDR: `10.0.0.0/8` matches anywhere in that block.
Process: bundle ID match wins; otherwise the rule's path covers the process at exactly that path and anything inside it as a folder (`/usr/local/bin/node` does not match `/usr/local/bin/nodemon`, `/Applications/X.app` covers its helpers).

## NetExt - per-process firewall (Network System Extension)

`Sources/NetExt/FilterDataProvider.swift` is a `NEFilterDataProvider` content filter, built as the `FreeSnitchNetExt` system-extension target and embedded at `Contents/Library/SystemExtensions/`. It gives true per-process filtering (Little Snitch's mechanism).

- `handleNewFlow` evaluates each socket flow with the shared `RuleMatcher`; allow → `.allow()`, deny → `.drop()`, ask → `.pause()` then resume with the user's verdict.
- App ↔ extension XPC: `Shared/IPCConnection.swift` (extension vends a mach service named by `NEMachServiceName`; the app connects and receives prompts, reusing the connection-alert UI).
- Rules reach the sandboxed extension via the app-group container (`Shared/SharedRuleBridge.swift`), mirrored by the GUI on every rule/mode change.
- Activation: `GUI/App/SystemExtensionManager.swift` (`OSSystemExtensionRequest` + `NEFilterManager`).

Shipping requires the `content-filter-provider-systemextension` entitlement (self-serve Network Extensions capability on the App ID), Developer ID signing + notarization, and the app installed in `/Applications`. See `Sources/NetExt/README.md`. The helper (pfctl + DNS) remains responsible for rule storage, pfctl rules, and DNS blocklists; the Network Extension does not receive blocklist entries.

## Offline geolocation (`Sources/Shared/IPGeo.swift`)

`IPGeoCache` turns a remote IP into a country, a city and a coordinate without
ever sending an address anywhere. There is no per-connection lookup service and
no per-flow network call: whole databases are downloaded in bulk, converted into
a local index, and every lookup after that is a binary search over that index.

### Data source and attribution

The range data is **DB-IP City Lite** (IPv4 and IPv6), republished as CSV by
[sapics/ip-location-db](https://github.com/sapics/ip-location-db). It is
licensed **CC BY 4.0** and its attribution requirement is mandatory wherever its
results are shown:

> [IP Geolocation by DB-IP](https://db-ip.com/)

The string and the link live in `IPGeoCache.attribution` and are surfaced to the
UI through `AppState.geoAttribution`, so any view that draws geolocated
endpoints can render the credit. The docs site carries the same credit in its
footer. Country names and country centroids come from the Google DSPL canonical
country table.

GeoLite2 City is the other free city-level option and is deliberately not used:
it is smaller, but its EULA is more restrictive than CC BY 4.0 and its official
distribution requires a per-user MaxMind account.

### Why downloaded and not shipped

The city databases are two orders of magnitude larger than the old country file.
Shipping them inside the app bundle would add ~89 MB to every release and would
be stale the moment DB-IP publishes its next monthly build, so they are
downloaded on first run exactly like the previous country database, and cached
for 30 days, which matches DB-IP Lite's monthly release cadence.

Measured against the August 2026 databases:

| | |
|---|---|
| Download, IPv4 + IPv6 city, gzip | 48.5 MB + 40.6 MB |
| Decompressed CSV, never written to disk | 263 MB + 431 MB |
| Rows | 3.65 M IPv4 + 4.27 M IPv6 |
| Built index on disk | 141.3 MB |
| Build time, both families | ~4.2 s |
| Peak process memory while building | ~62 MB |
| Opening a cached index | < 1 ms |
| Heap held by the loaded database | none; it is memory mapped |
| Lookup throughput | ~6.5 M range searches/s |

### How it stays small at runtime

The CSVs are streamed, decompressed in 256 KB chunks, and converted once into a
fixed-width binary index: sorted range starts, a deduplicated city table, a
country table, and a UTF-8 name blob. The index is then `mmap`ed read-only, so
the parsed tables live in the page cache rather than on the heap, and a lookup
touches a handful of clean, evictable pages. Ranges are stored as starts only,
with an explicit sentinel marking each hole, which is what keeps a 128-bit IPv6
table affordable.

### Failure behaviour

- Loading always runs on a utility queue. Construction returns immediately and
  the ready callback fires exactly once, including when everything failed.
- A cached index is published before any refresh is attempted, so after the
  first run the map has coordinates immediately and a refresh is a background
  upgrade.
- Every source has a byte ceiling, the decompressed stream has a ceiling, and
  the row, city and name tables have ceilings. Anything past them is a refusal.
- A failed download, a corrupt archive, an unsorted or overlapping file, or an
  index that does not validate leaves the previously loaded database in place.
  A new index is only installed after it has been rebuilt and reopened
  successfully. The degraded state is reported through `IPGeoCache.status`
  rather than being presented as an empty map.

### Precision honesty

`Entry.precision` is `.city` only when the database actually names a city. When
it does not, the coordinate is the country centroid, `Entry.city` and
`Connection.city` are nil, and the precision is `.country`. A country answer is
a centroid, not a place anyone connected to, and the UI must not present it as
one. A geolocated coordinate is an estimate in either case.

`Scripts/test_ipgeo.sh` asserts all of the above against the real shared
sources, entirely offline.

## Network owner and on-demand lookups (`Sources/Shared/IPASN.swift`, `Sources/Shared/RDAPRecord.swift`)

Selecting a destination in the Network Monitor shows a **Selected Destination**
section: the address, the name FreeSnitch saw for it, the network owner, the AS
number, the address range and the estimated location.

The owner, ASN and range come from **DB-IP ASN Lite** (IPv4 and IPv6, CC BY
4.0, same credit as the city data), downloaded from the same
sapics/ip-location-db release as plain CSV (about 24 MB + 7 MB) and converted
into its own memory-mapped index, `dbip-asn.index` (about 12 MB), next to the
city index. It is refreshed on the same 30-day cycle and follows the same
failure rules: a failed or malformed download keeps the index already in place,
and without one the section says the data is still downloading or unavailable.
Unlike the city index each row keeps its end address, because ASN data has real
holes and the range itself is shown.

**Look Up Owner…** is the only part that sends anything, and only when clicked:
the system resolver is asked for the reverse name (PTR) of that one address, and
`https://rdap.org/ip/<address>` is fetched, which redirects to the regional
registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC) holding it. The answer is parsed
by `RDAPNetworkRecord` (bounded size, single-line bounded strings; RIPE
maintainer objects are not shown as the owner). Nothing is retried or looked up
in the background.

Anycast is not labelled: offline data can't tell it apart reliably. The location
row says instead that shared or anycast addresses can be served from many
places.
