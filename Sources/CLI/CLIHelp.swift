import Foundation

enum CLIHelp {
    static func text(for topic: [String]) -> String {
        switch topic {
        case []: return root
        case ["status"]: return status
        case ["doctor"]: return doctor
        case ["mode"]: return mode
        case ["monitor"], ["monitor", "connections"], ["monitor", "traffic"], ["monitor", "processes"], ["monitor", "summary"], ["monitor", "blocked"], ["monitor", "denied"]: return monitor
        case ["connections"], ["traffic"], ["processes"], ["blocked"], ["denied"]: return monitor
        case ["settings"]: return settings
        case ["settings", "helper"], ["helper"]: return helper
        case ["settings", "speeds"], ["settings", "show-speeds"]: return speeds
        case ["settings", "launch-at-login"]: return launchAtLogin
        case ["settings", "alerts-all-spaces"]: return alertsAllSpaces
        case ["settings", "enforcement"]: return enforcement
        case ["settings", "mode"]: return mode
        case ["settings", "doh"]: return doh
        case ["settings", "dns"]: return dns
        case ["settings", "blocklists"]: return blocklists
        case ["settings", "blocklist"]: return blocklist
        case ["rules"]: return rules
        case ["rules", "list"]: return rulesList
        case ["rules", "show"], ["rules", "get"]: return rulesShow
        case ["rules", "add"]: return rulesAdd
        case ["rules", "enable"], ["rules", "disable"], ["rules", "rm"], ["rules", "remove"]: return rulesMutate
        case ["rules", "import"]: return rulesImport
        case ["rules", "export"]: return rulesExport
        case ["blocklists"]: return blocklists
        case ["blocklist"]: return blocklist
        case ["doh"]: return doh
        case ["enforcement"]: return enforcement
        case ["pf"]: return pf
        case ["flush"]: return flush
        default:
            return root
        }
    }

    private static let root = """
    FreeSnitch command line interface

    Usage:
      freesnitch <command> [options]

    Read and diagnose:
      status                         Show helper, enforcement, extension, and snapshot health.
      doctor                         Explain failures and the exact recovery action for each.
      monitor connections             Show the connections in the Network Monitor.
      monitor traffic                 Show the latest traffic samples.
      monitor processes               Show per-process traffic usage.
      monitor summary                Show top processes, domains, and countries.
      monitor blocked                 Show recently blocked connections.
      monitor denied                  Show recently denied connections.
      connections, traffic, processes, blocked, denied
                                     Short aliases for the monitor views.

    Settings and mode:
      mode <alert|silent-allow|silent-deny>
                                     Set the menu-bar mode.
      settings helper <status|recheck|open-login-items>
                                     Inspect or repair the helper approval path.
      settings speeds <on|off>       Set the menu-bar speed readout preference.
      settings launch-at-login <on|off>
                                     Set whether FreeSnitch launches at login.
      settings alerts-all-spaces <on|off>
                                     Set whether alerts appear on every Space.
      settings enforcement <on|off>  Set firewall enforcement. `off` needs --yes.
      settings mode <mode>           Alias for mode.
      settings doh <url>             Set the DNS over HTTPS upstream.
      settings dns status             Show local DNS proxy status.
      settings blocklists             List blocklists; add refresh to update all.
      settings blocklist <id> <on|off>
                                     Enable or disable one blocklist.

    Rules:
      rules list [filters]            List rules by the Rules Manager categories.
      rules show <id>                 Show every field of one rule.
      rules add [options]             Create a rule through the helper.
      rules enable <id>...            Enable one or more rules.
      rules disable <id>...           Disable one or more rules.
      rules rm <id>...                Remove one or more rules.
      rules import <file|->           Merge rules from a JSON export or stdin.
      rules export [--output PATH]    Export a portable JSON rule file.

    Other controls:
      blocklists [refresh]            List or refresh all blocklists.
      blocklist <id> <on|off>         Toggle one blocklist.
      doh <url>                       Alias for settings doh.
      enforcement <on|off>            Toggle enforcement. `off` needs --yes.
      pf <install|uninstall>          `uninstall` needs --yes.
      flush                           Recovery flush. Requires --yes.

    Common options:
      --json                          Emit the stable freesnitch.cli.v1 envelope.
      --yes                           Confirm a destructive recovery operation.
      --help                          Show this help or help for one command.

    Examples:
      freesnitch status --json | jq .data
      freesnitch doctor
      freesnitch rules list --category deny --search telemetry
      freesnitch rules add --process-name Safari --host example.com --action allow
      freesnitch rules disable 01234567-89AB-CDEF-0123-456789ABCDEF
      freesnitch rules export --output /tmp/freesnitch-rules.json
      freesnitch enforcement off --yes

    Interactive alerts are intentionally not exposed yet. The GUI owns pending
    alert continuations in AppState and the helper has no durable alert ID or
    answer protocol; a CLI command would otherwise be unsafe or misleading.
    """

    private static let status = """
    Usage: freesnitch status [--json]

    Shows the helper version and reachability, current mode, enforcement state,
    system extension approval and running state, filter configuration, and the
    last rule snapshot status. A reachable helper with an unhealthy extension
    still returns a health report; use doctor for remediation text.
    """

    private static let doctor = """
    Usage: freesnitch doctor [--json]

    Runs independent checks for helper reachability and version, system
    extension approval, filter configuration, extension XPC reachability and
    snapshot delivery, and pf anchor syntax. Every problem includes what is
    wrong and what to do next.
    """

    private static let mode = """
    Usage: freesnitch mode <alert|silent-allow|silent-deny> [--json]

    Changes the same mode selected by the menu bar and Settings picker. The
    canonical names are alert, silent-allow, and silent-deny. The CLI also
    accepts silentAllow and silentDeny for compatibility with the Swift model.
    """

    private static let monitor = """
    Usage: freesnitch monitor <connections|traffic|processes|summary|blocked|denied> [--limit N] [--json]

    These are text and JSON views of the Network Monitor. The helper currently
    exposes one live traffic sample, so traffic returns at most one sample and
    reports the requested limit honestly.
    """

    private static let settings = """
    Usage: freesnitch settings <action> [value] [--json]

    Actions mirror every Settings control: helper status/recheck/login-items,
    speeds, launch-at-login, alerts-all-spaces, enforcement, mode, doh, dns
    status, blocklists, and blocklist toggles. Run `freesnitch settings ACTION
    --help` for the action-specific examples.
    """

    private static let helper = """
    Usage: freesnitch settings helper <status|recheck|open-login-items> [--json]

    status reports the SMAppService registration and XPC reachability. recheck
    performs the GUI's refreshInstallState plus ping action. open-login-items
    opens the exact System Settings pane where the helper can be approved.
    """

    private static let speeds = """
    Usage: freesnitch settings speeds <on|off> [--json]

    Sets the menu-bar speed readout preference. The setting is shared with a
    running GUI through the FreeSnitch preferences notification.

    Examples:
      freesnitch settings speeds on
      freesnitch settings speeds off --json
    """

    private static let launchAtLogin = """
    Usage: freesnitch settings launch-at-login <on|off> [--json]

    Registers or unregisters the FreeSnitch GUI as a login item without a
    prompt. The status form is useful for scripts: omit on/off.
    """

    private static let alertsAllSpaces = """
    Usage: freesnitch settings alerts-all-spaces <on|off> [--json]

    Sets the same alert-window preference used by the GUI.
    """

    private static let enforcement = """
    Usage: freesnitch enforcement <on|off> [--yes] [--json]
          freesnitch settings enforcement <on|off> [--yes] [--json]

    Changes the helper's pf anchor and DNS proxy state. Turning enforcement
    off is a recovery path and requires --yes because the CLI has no dialog.
    The helper logs every request as an audit event.

    Examples:
      freesnitch enforcement on
      freesnitch enforcement off --yes
    """

    private static let dns = """
    Usage: freesnitch settings dns status [--json]

    Reports the local DNS proxy state and port. The proxy lives in the
    privileged helper and is only active while enforcement is enabled.
    """

    private static let blocklists = """
    Usage: freesnitch blocklists [refresh] [--json]
          freesnitch settings blocklists [refresh] [--json]

    Lists every configured blocklist with ID, URL, enabled state, last update,
    and entry count. `refresh` downloads all enabled lists.
    """

    private static let blocklist = """
    Usage: freesnitch blocklist <id> <on|off> [--json]

    Enables or disables one blocklist. Find IDs with `freesnitch blocklists`.
    """

    private static let doh = """
    Usage: freesnitch doh <url> [--json]

    Sets the helper's DNS over HTTPS upstream URL.

    Example:
      freesnitch doh https://cloudflare-dns.com/dns-query
    """

    private static let rules = """
    Usage: freesnitch rules <list|show|add|enable|disable|rm|import|export> [options]

    This command mirrors the Rules Manager. It supports the sidebar categories,
    group and blocklist filters, search, full details, multi-select enable,
    disable and remove, plus working import and export.
    """

    private static let rulesList = """
    Usage: freesnitch rules list [--profile NAME] [--category CATEGORY]
           [--group NAME] [--blocklist ID_OR_NAME] [--search TEXT] [--limit N] [--json]

    Categories are all, active, deny, recent-changes, recently-used, temporary,
    and unapproved. `active` matches the GUI's enabled allow rules. A blocklist
    filter returns the blocklist information view because blocklist domains are
    not Rule records in the GUI.

    Examples:
      freesnitch rules list --category active
      freesnitch rules list --group "Third Party Apps" --search Safari
      freesnitch rules list --category recently-used --json
    """

    private static let rulesShow = """
    Usage: freesnitch rules show <RULE_ID> [--json]

    Prints every field of one rule, including timestamps, profile, group,
    enabled and temporary state, expiration, hit count, and notes.
    """

    private static let rulesAdd = """
    Usage: freesnitch rules add [options] [--json]

    Options:
      --process-bundle-id ID       Match an application bundle ID.
      --process-path PATH          Match a process path or path prefix.
      --process-name NAME          Store a process display name.
      --host HOST                  Match a domain, including *.example.com.
      --ip ADDRESS_OR_CIDR         Match an IP or IPv4 CIDR.
      --port PORT                  Match a remote port from 1 through 65535.
      --direction outgoing|incoming|any
      --action allow|deny|ask      Default: ask.
      --scope process|domain|ip|port|any
      --priority N                 Default: 100.
      --profile NAME               Default: default.
      --group NAME                 Rule Manager group name.
      --notes TEXT                 Human note.
      --temporary                  Mark the rule temporary.
      --expires-at ISO8601         Optional expiration timestamp.
      --disabled                   Create the rule disabled.
      --id UUID                    Preserve a known ID when importing manually.

    Example:
      freesnitch rules add --process-name Safari --host api.example.com --action allow
    """

    private static let rulesMutate = """
    Usage: freesnitch rules <enable|disable|rm> RULE_ID [RULE_ID ...] [--json]

    Enable, disable, or remove one or more rules. These operations are sent to
    the helper and then synchronized to the running network extension when it
    is available.
    """

    private static let rulesImport = """
    Usage: freesnitch rules import <FILE|-> [--json]

    Imports a JSON export or a raw Rule array. Import is an upsert/merge, which
    matches the helper protocol and never silently deletes rules. Use - for
    standard input.
    """

    private static let rulesExport = """
    Usage: freesnitch rules export [--output PATH] [--json]

    Writes a versioned JSON document containing all rules. Without --output the
    document is written to standard output. With --json, the command response
    is the normal CLI envelope and the file is still written when requested.
    """

    private static let pf = """
    Usage: freesnitch pf <install|uninstall> [--yes] [--json]

    Installs or removes the existing FreeSnitch pf anchor through the helper.
    pf uninstall is a recovery path and requires --yes. The CLI never writes
    pf rules itself.
    """

    private static let flush = """
    Usage: freesnitch flush --yes [--json]

    Recovery path that asks the helper to flush the existing FreeSnitch pf
    anchor. It never changes rule matching or fail-open behavior.
    """
}
