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

## Interactive alerts

Pending alert interaction is not part of this release. The GUI stores pending
network-extension alert continuations in `AppState.PendingAlert`, and only its
`AppCommunicationBridge` has the answer closure. The helper protocol has no
persistent alert identifier, list operation, answer operation, remember scope,
or duration model. A one-shot CLI cannot safely list or answer a GUI-owned
continuation, so no misleading `alerts` command was added. This is the exact
plumbing needed for a future parity change.
