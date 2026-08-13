# FreeSnitch CLI

The CLI is the terminal surface for the same helper and network extension used by
FreeSnitch. The executable is shipped inside the application bundle:

```text
/Applications/FreeSnitch.app/Contents/Helpers/freesnitch
```

A release build should expose that path through a symlink or shell alias if a
short `freesnitch` command is desired. Do not copy the binary out of the app
bundle. Its signature and identifier are part of the XPC trust boundary.

### Run it from anywhere

Pick one of these. Both keep the executable inside the bundle, so the signature
and identifier the helper checks stay intact.

Symlink into a directory that is already on your `PATH`:

```sh
sudo ln -sf /Applications/FreeSnitch.app/Contents/Helpers/freesnitch /usr/local/bin/freesnitch
```

Or put the bundle's `Helpers` directory on your `PATH`, which needs no
administrator rights. For zsh, the default shell on macOS:

```sh
echo 'export PATH="/Applications/FreeSnitch.app/Contents/Helpers:$PATH"' >> ~/.zshrc && exec zsh
```

For bash, use `~/.bash_profile` instead of `~/.zshrc`.

Verify either approach with:

```sh
freesnitch --version
freesnitch settings helper status
```

The symlink is resolved back to the real path inside the bundle before the CLI
identifies itself, so `Helper XPC: reachable` is expected from both setups. A
copy of the binary placed outside the bundle is not supported and will not be
trusted.

The CLI never prompts. It writes data to stdout and diagnostics to stderr.
Every command accepts `--json`.

## Help

```sh
freesnitch --help
freesnitch rules --help
freesnitch rules add --help
freesnitch settings --help
```

Help output includes examples and is part of the command surface.

## JSON contract

JSON responses use the stable `freesnitch.cli.v1` envelope:

```json
{
  "schema": "freesnitch.cli.v1",
  "command": "status",
  "ok": true,
  "exitCode": 0,
  "data": {},
  "error": null
}
```

Successful responses always contain `data` and `error: null`. Failed responses normally contain `data: null` and this error object. A
reporting command such as `doctor`, or a partial multi-rule mutation, can keep
its report in `data` while also setting `ok: false` and including `error`:

```json
{
  "schema": "freesnitch.cli.v1",
  "command": "rules list",
  "ok": false,
  "exitCode": 66,
  "data": null,
  "error": {
    "code": "helper_unreachable",
    "message": "The helper could not be reached.",
    "remediation": "Approve FreeSnitch in Login Items.",
    "exitCode": 66
  }
}
```

Dates in CLI output are ISO 8601 strings. Helper payloads using the existing
numeric date representation are accepted on input. `Rule` objects retain the
shared model fields: `id`, process identity, host and IP selectors, port,
direction, action, scope, priority, profile, group, notes, enabled,
temporary, timestamps, expiration, and hit count.

Command-specific `data` shapes are:

| Command family | `data` |
| --- | --- |
| `status` | `version`, canonical `mode`, `modeLabel`, `enforcement`, `helper`, `extensionStatus` |
| `doctor` | `healthy`, `findings`, `helper`, `extensionStatus`, `pf` |
| `rules list` | filter values, `count`, `rules`, and optional `blocklistInfo` |
| `rules show` | one complete `Rule` object |
| `rules add` | `rule`, `extensionSync`, and optional `extensionMessage` |
| `rules enable`, `disable`, `rm` | requested IDs, succeeded IDs, failures, and extension sync state |
| `rules import` | imported count, IDs, source, and extension sync state |
| `rules export` | a `freesnitch.rules.v1` document, or count and output path when writing a file |
| monitor views | `requestedLimit`, `returned`, and the relevant array |
| `monitor summary` | `topProcesses`, `topDomains`, `topCountries`, and country metadata status |
| `alerts list` | `count`, `appAttached`, `capacity`, `alerts`, and `reason` when the list is empty |
| `alerts answer` | `id`, `state`, `allow`, `decision`, `answeredBy`, `resolvedAt`, `scope`, `remember`, `ruleStored`, `ruleId`, `ruleMessage`, `message` |
| blocklists | an array of ID, name, URL, enabled state, update time, and entry count |
| settings | the changed or queried setting and its value |
| `pf` and `flush` | the existing `puresnitch` anchor diagnostic |

The traffic protocol currently exposes the helper's current sample, not a
history buffer. `traffic --limit N` therefore returns at most one sample and
says so in the response instead of inventing samples.

## Exit codes

The values are defined in `Sources/CLI/CLIContract.swift` and are stable:

| Code | Name | Meaning |
| ---: | --- | --- |
| 0 | `success` | Command completed successfully |
| 64 | `invalid_argument` | Invalid command, option, ID, URL, limit, or input file |
| 65 | `refused` | A destructive recovery command was missing `--yes` |
| 66 | `helper_unreachable` | The root helper did not answer or XPC lookup failed |
| 67 | `helper_version_mismatch` | The helper and CLI versions differ |
| 68 | `extension_not_approved` | The network extension is not approved or is not answering |
| 69 | `filter_configuration_missing` | The extension is approved but its content filter is absent or disabled |
| 70 | `snapshot_missing` | The extension is running but has no ready rule snapshot |
| 71 | `pf_anchor_failure` | The helper or read-only doctor check found a pf anchor failure |
| 72 | `operation_failed` | The helper rejected an operation or a local operation failed |
| 73 | `internal_failure` | Unexpected CLI failure |

`doctor` returns a report even when it finds problems. Its envelope contains
`ok: false`, the selected non-zero `exitCode`, the complete report in `data`,
and an error summary. If several failure classes are present, the first
actionable finding in helper, extension, snapshot, and pf order selects the exit
code.

## Status and diagnosis

```sh
freesnitch status
freesnitch status --json | jq .data
freesnitch doctor
freesnitch doctor --json | jq '.data.findings'
```

`doctor` checks:

- helper reachability and version
- system extension approval
- content filter installation and enabled state
- extension XPC reachability
- rule snapshot delivery over XPC
- read-only pf anchor syntax validation

A malformed host specification is reported as a whole-ruleset failure with the
next action. Doctor does not install, unload, or rewrite pf rules.

## Mode and settings

The mode names match the menu bar and Settings picker:

```sh
freesnitch mode alert
freesnitch mode silent-allow
freesnitch mode silent-deny
```

Settings controls are grouped under `settings`, with the original issue surface
also available as short aliases where useful:

```sh
freesnitch settings helper status
freesnitch settings helper recheck
freesnitch settings helper open-login-items
freesnitch settings speeds on
freesnitch settings launch-at-login off
freesnitch settings alerts-all-spaces on
freesnitch settings enforcement on
freesnitch settings enforcement off --yes
freesnitch settings doh https://cloudflare-dns.com/dns-query
freesnitch settings dns status
```

The helper status reports enforcement, pf, and DNS proxy state. It reports two
versions: the build the helper process is running, captured when that process
started, and the build installed on disk. After an in-place update these differ
until the daemon is restarted, and `settings helper status` and `doctor` both say
so and print the exact recovery command,
`sudo launchctl kickstart -k system/io.isaaclins.freesnitch.helper`. The helper
is never unregistered as a repair. Preference changes are written to the GUI
preference suite and notify a running GUI. `open-login-items` opens the same
System Settings pane used by the GUI.

## Rules

List filters correspond to the Rules Manager sidebar:

```sh
freesnitch rules list
freesnitch rules list --category active
freesnitch rules list --category deny
freesnitch rules list --category recent-changes
freesnitch rules list --category recently-used
freesnitch rules list --category temporary
freesnitch rules list --category unapproved
freesnitch rules list --group "Third Party Apps"
freesnitch rules list --blocklist "1Hosts (Lite)"
freesnitch rules list --search Safari --profile default
freesnitch rules show RULE_UUID
```

`active` means enabled allow rules, exactly as in the GUI. Blocklists are domain
sets rather than `Rule` records, so a blocklist filter returns its information
view and entry count, just as the GUI does.

Add and mutate rules through the helper:

```sh
freesnitch rules add \
  --process-name Safari \
  --host api.example.com \
  --action allow \
  --scope domain
freesnitch rules enable RULE_UUID OTHER_RULE_UUID
freesnitch rules disable RULE_UUID
freesnitch rules rm RULE_UUID OTHER_RULE_UUID
```

Import and export are versioned JSON. Import is an upsert/merge because that is
the behavior exposed by the existing helper protocol; it does not silently
delete rules.

```sh
freesnitch rules export --output /tmp/freesnitch-rules.json
freesnitch rules export > /tmp/freesnitch-rules.json
freesnitch rules import /tmp/freesnitch-rules.json
cat /tmp/freesnitch-rules.json | freesnitch rules import -
```

After mode and rule changes, the CLI attempts to deliver the complete snapshot
to the running extension. The helper remains the source of truth if the
extension is unavailable, and the response reports that synchronization was not
delivered.

## Monitor output

The monitor window is represented by separate terminal views:

```sh
freesnitch connections --limit 50
freesnitch traffic --limit 20
freesnitch processes --limit 20
freesnitch monitor summary --limit 5
freesnitch blocked --limit 50
freesnitch denied --limit 50
```

The summary uses the same connection and process-usage aggregation as the GUI.
Country totals require country metadata on helper connection records. When no
metadata is present, the JSON array is empty and the response explains why.

Blocklists are also available as:

```sh
freesnitch blocklists
freesnitch blocklists refresh
freesnitch blocklist BLOCKLIST_ID off
freesnitch blocklist BLOCKLIST_ID on
```

Blocklists are DNS-name filters enforced by the helper's local DNS proxy only when Enforcement is enabled. They apply to names sent to that proxy, not hardcoded IP addresses or names resolved by an app's own encrypted DNS, such as Chrome and Firefox DoH.

## Recovery operations

The CLI has the same enforcement capability as the GUI. It does not implement
firewall logic. The helper remains responsible for pf generation, DNS behavior,
and filtering decisions.

```sh
freesnitch enforcement on
freesnitch enforcement off --yes
freesnitch pf install
freesnitch pf uninstall --yes
freesnitch flush --yes
```

The helper logs enforcement changes, pf install and uninstall, and flushes as
audit events. `pkill -x FreeSnitch` remains the emergency fail-open escape
hatch.

`freesnitch pf uninstall` removes the pf anchor content only. It is a recovery
operation, not an uninstall of FreeSnitch, and it never removes the helper.

## Removing FreeSnitch

The CLI has no uninstall command, and that is deliberate: under System Integrity
Protection only the app can deactivate the system extension, because
`systemextensionsctl uninstall` refuses to run at all. Start in the app under
Settings > Uninstall, then finish with the script:

```sh
sudo bash Scripts/uninstall_freesnitch.sh --yes
sudo bash Scripts/uninstall_freesnitch.sh --yes --remove-database
```

The script refuses to remove the app while macOS still holds a record for
`io.isaaclins.freesnitch.netext`, or while the privileged helper is still
running from that bundle. `--remove-database` additionally deletes
`/Library/Application Support/FreeSnitch/freesnitch.sqlite`, which holds every
rule, profile and blocklist and can exceed 300 MB; without it that file is kept.
Only the shared `puresnitch` anchor is flushed, pf is never disabled globally,
and the empty anchor file stays because `/etc/pf.conf` still references it.

`Scripts/test_uninstall_safety.sh` exercises those guards against a fake root
with stubbed privileged tools, so it never touches the real system.

## Interactive alerts

```sh
freesnitch alerts list
freesnitch alerts list --json | jq '.data.alerts'
freesnitch alerts answer 01234567-89AB-CDEF-0123-456789ABCDEF --deny
freesnitch alerts answer 01234567-89AB-CDEF-0123-456789ABCDEF --allow --remember forever
freesnitch alerts answer 01234567-89AB-CDEF-0123-456789ABCDEF --deny --scope ip --temporary
```

`alerts list` shows every alert waiting for an answer with a stable ID, the
process, the destination name, the address, the port, and the seconds left
before the alert expires.

### The FreeSnitch app must be running

This is a property of the design, not a limitation of the CLI, and the command
says so rather than looking broken.

A connection alert is one paused flow. The network extension pauses it and asks
the **running app** over the app-group XPC channel it holds; that callback is
what resumes the flow. The helper never sees those flows, and the CLI is
deliberately not registered as a notification client, because a long-lived
privileged notification client is exactly the trust and lifetime problem issue
#25 asked not to create.

So the app registers each alert it presents in a small, expiring registry inside
the helper. `alerts list` reads that registry and `alerts answer` writes to it;
the verdict travels back to the app, which answers the extension. With the app
not running, no alert can exist, and `alerts list` returns an empty list with
the reason stated in `reason`:

```json
{
  "count": 0,
  "appAttached": false,
  "capacity": 12,
  "alerts": [],
  "reason": "No FreeSnitch app is connected to the helper. Connection alerts are raised by the network extension against the running app, so none can exist and none can be answered while the app is not running. Flows still resume with the fail-open default when their ask timeout expires."
}
```

That is not an error, so the exit code stays `0`.

### Answering

```text
freesnitch alerts answer <ID> --allow|--deny [--scope process|domain|ip|port]
                              [--remember <duration>|--temporary] [--json]
```

- `--allow` or `--deny` is required, and exactly one of them.
- `--remember <duration>` stores a rule for the decision. Use `forever`, or a
  number with `s`, `m`, `h`, or `d`, from 60 seconds up to 30 days.
- `--temporary` is shorthand for `--remember 1h`.
- `--scope` chooses what a remembered decision applies to and requires
  `--remember` or `--temporary`. Without it, the scope is `domain` when a host
  name is known and `ip` otherwise, which is what the alert panel does.
- Without `--remember` or `--temporary` only this flow is answered and no rule
  is stored, which is the alert panel with "Remember this decision" unchecked.

Rules created this way go through the same helper-owned validation and the same
policy generation as `rules add`, and appear in `freesnitch rules list`.

### Timeouts, fail-open, and answering exactly once

- An alert stays answerable for at most 55 seconds, which is deliberately
  shorter than the 60 second budget the extension gives the paused flow. The
  CLI can never hold traffic for longer than it is already held.
  `Scripts/test_pending_alerts.sh` reads both numbers out of the real sources
  and fails if that stops being true.
- An alert nobody answers changes nothing: the flow resumes with the existing
  fail-open default when the extension's own timeout expires.
- The registry is bounded at 12 outstanding alerts, like the DNS ask table.
  Past the bound nothing is queued; the alert resolves immediately with the
  fail-open default, which is what the app already does when its own alert
  queue is full.
- An alert is answered exactly once. If the app answers first, or another
  `alerts answer` gets there first, the loser is told which one answered.

Each way of failing to answer has its own error code, so a script never has to
parse prose:

| `error.code` | Meaning |
| --- | --- |
| `alert_already_answered` | The app, or another CLI answer, answered it first |
| `alert_expired` | The alert timed out; the flow already resumed fail-open |
| `alert_not_found` | No alert with that ID is or was pending on this helper |
| `alert_rule_not_stored` | The flow was answered; the remembered rule was refused |
| `pending_alerts_unsupported` | The running helper predates this feature |

All of them exit `72` (`operation_failed`), except `pending_alerts_unsupported`,
which exits `67` (`helper_version_mismatch`). Alert IDs are not reused and do
not survive a helper restart.
