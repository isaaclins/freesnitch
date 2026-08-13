import Foundation

struct CLIInvocation {
    let command: CLICommand
    let json: Bool
    let yes: Bool
    let name: String
}

enum CLICommand {
    case help(topic: [String])
    case version
    case status
    case doctor
    case mode(AppMode)
    case rules(RulesCommand)
    case monitor(MonitorCommand)
    case connections(limit: Int)
    case traffic(limit: Int)
    case processes(limit: Int)
    case blocked(limit: Int)
    case denied(limit: Int)
    case blocklists
    case refreshBlocklists
    case blocklist(id: String, enabled: Bool)
    case doh(String)
    case enforcement(Bool)
    case pf(PFCommand)
    case flush
    case settings(SettingsCommand)
}

enum RulesCommand {
    case list(RulesListOptions)
    case show(UUID)
    case add(Rule)
    case setEnabled(ids: [UUID], enabled: Bool)
    case remove(ids: [UUID])
    case importFile(String)
    case exportFile(String?)
}

struct RulesListOptions {
    var profile: String?
    var category: RuleCategory
    var group: String?
    var blocklist: String?
    var search: String?
    var limit: Int?
}

enum RuleCategory {
    case all
    case active
    case deny
    case recentChanges
    case recentlyUsed
    case temporary
    case unapproved
}

enum MonitorCommand {
    case connections(Int)
    case traffic(Int)
    case processes(Int)
    case summary(Int)
    case blocked(Int)
    case denied(Int)
}

enum PFCommand {
    case install
    case uninstall
}

enum SettingsCommand {
    case helper(HelperSettingsCommand)
    case boolean(key: String, label: String, value: Bool?)
    case enforcement(Bool?)
    case mode(AppMode)
    case doh(String)
    case dnsStatus
    case blocklists(refresh: Bool)
    case blocklist(id: String, enabled: Bool)
}

enum HelperSettingsCommand {
    case status
    case recheck
    case openLoginItems
}

private struct TokenCursor {
    let tokens: [String]
    var index: Int = 0

    var isAtEnd: Bool { index >= tokens.count }

    mutating func next() -> String? {
        guard !isAtEnd else { return nil }
        defer { index += 1 }
        return tokens[index]
    }

    mutating func value(for flag: String) throws -> String {
        guard let value = next(), !value.isEmpty else {
            throw CLIError(.invalidArgument,
                           message: "\(flag) requires a value.",
                           remediation: "Run `freesnitch --help` for usage.")
        }
        return value
    }

    func requireEnd(_ context: String) throws {
        guard isAtEnd else {
            throw CLIError(.invalidArgument,
                           message: "unexpected argument `\(tokens[index])` for \(context).",
                           remediation: "Run `freesnitch \(context) --help` for usage.")
        }
    }
}

enum CLIParser {
    static func parse(_ rawArguments: [String]) throws -> CLIInvocation {
        if rawArguments.contains("--version") || rawArguments.contains("-V") {
            return CLIInvocation(command: .version, json: false, yes: false, name: "version")
        }

        let wantsHelp = rawArguments.contains("--help") || rawArguments.contains("-h")
        let topic = rawArguments.filter { $0 != "--help" && $0 != "-h" && $0 != "--json" && $0 != "--yes" }
        if wantsHelp {
            return CLIInvocation(command: .help(topic: topic), json: false, yes: false, name: helpName(topic))
        }

        var json = false
        var yes = false
        var arguments: [String] = []
        for argument in rawArguments {
            switch argument {
            case "--json": json = true
            case "--yes": yes = true
            default: arguments.append(argument)
            }
        }
        guard let first = arguments.first else {
            return CLIInvocation(command: .help(topic: []), json: false, yes: false, name: "help")
        }

        let command: CLICommand
        switch first {
        case "status":
            let cursor = TokenCursor(tokens: Array(arguments.dropFirst()))
            try cursor.requireEnd("status")
            command = .status
        case "doctor":
            let cursor = TokenCursor(tokens: Array(arguments.dropFirst()))
            try cursor.requireEnd("doctor")
            command = .doctor
        case "mode":
            command = .mode(try parseModeCommand(Array(arguments.dropFirst()), context: "mode"))
        case "rules":
            command = .rules(try parseRules(Array(arguments.dropFirst())))
        case "monitor":
            command = .monitor(try parseMonitor(Array(arguments.dropFirst())))
        case "connections":
            command = .connections(limit: try parseLimitOnly(Array(arguments.dropFirst()), context: "connections"))
        case "traffic":
            command = .traffic(limit: try parseLimitOnly(Array(arguments.dropFirst()), context: "traffic"))
        case "processes", "process-usage":
            command = .processes(limit: try parseLimitOnly(Array(arguments.dropFirst()), context: "processes"))
        case "blocked":
            command = .blocked(limit: try parseLimitOnly(Array(arguments.dropFirst()), context: "blocked"))
        case "denied":
            command = .denied(limit: try parseLimitOnly(Array(arguments.dropFirst()), context: "denied"))
        case "blocklists":
            command = try parseBlocklists(Array(arguments.dropFirst()))
        case "blocklist":
            command = try parseBlocklist(Array(arguments.dropFirst()))
        case "doh":
            command = .doh(try parseSingleValue(Array(arguments.dropFirst()), context: "doh"))
        case "enforcement":
            command = .enforcement(try parseToggleCommand(Array(arguments.dropFirst()), context: "enforcement"))
        case "pf":
            command = .pf(try parsePF(Array(arguments.dropFirst())))
        case "flush":
            let cursor = TokenCursor(tokens: Array(arguments.dropFirst()))
            try cursor.requireEnd("flush")
            command = .flush
        case "settings":
            command = .settings(try parseSettings(Array(arguments.dropFirst())))
        case "helper":
            command = .settings(.helper(try parseHelperSettings(Array(arguments.dropFirst()))))
        default:
            throw CLIError(.invalidArgument,
                           message: "unknown command `\(first)`.",
                           remediation: "Run `freesnitch --help` to see the complete command list.")
        }

        return CLIInvocation(command: command,
                             json: json,
                             yes: yes,
                             name: commandName(for: command))
    }

    private static func parseModeCommand(_ tokens: [String], context: String) throws -> AppMode {
        var cursor = TokenCursor(tokens: tokens)
        guard let value = cursor.next() else {
            throw CLIError(.invalidArgument,
                           message: "\(context) requires a mode.",
                           remediation: "Use alert, silent-allow, or silent-deny.")
        }
        try cursor.requireEnd(context)
        guard let mode = parseMode(value) else {
            throw CLIError(.invalidArgument,
                           message: "invalid mode `\(value)`.",
                           remediation: "Use alert, silent-allow, or silent-deny.")
        }
        return mode
    }

    private static func parseSingleValue(_ tokens: [String], context: String) throws -> String {
        var cursor = TokenCursor(tokens: tokens)
        guard let value = cursor.next(), !value.hasPrefix("-") else {
            throw CLIError(.invalidArgument,
                           message: "\(context) requires a value.",
                           remediation: "Run `freesnitch \(context) --help` for usage.")
        }
        try cursor.requireEnd(context)
        return value
    }

    private static func parseToggleCommand(_ tokens: [String], context: String) throws -> Bool {
        let value = try parseSingleValue(tokens, context: context)
        guard let enabled = parseToggle(value) else {
            throw CLIError(.invalidArgument,
                           message: "invalid on/off value `\(value)`.",
                           remediation: "Use on or off.")
        }
        return enabled
    }

    private static func parseLimitOnly(_ tokens: [String], context: String, defaultLimit: Int = 100) throws -> Int {
        var cursor = TokenCursor(tokens: tokens)
        var limit = defaultLimit
        while let token = cursor.next() {
            guard token == "--limit" else {
                throw CLIError(.invalidArgument,
                               message: "unexpected argument `\(token)` for \(context).",
                               remediation: "Run `freesnitch \(context) --help` for usage.")
            }
            limit = try parseLimit(cursor.value(for: token), context: context)
        }
        return limit
    }

    private static func parseLimit(_ value: String, context: String) throws -> Int {
        guard let limit = Int(value), (1...5000).contains(limit) else {
            throw CLIError(.invalidArgument,
                           message: "invalid limit `\(value)` for \(context).",
                           remediation: "Use an integer from 1 through 5000.")
        }
        return limit
    }

    private static func parseRules(_ tokens: [String]) throws -> RulesCommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let subcommand = cursor.next() else {
            throw CLIError(.invalidArgument,
                           message: "rules requires a subcommand.",
                           remediation: "Use list, show, add, enable, disable, rm, import, or export.")
        }
        switch subcommand {
        case "list": return .list(try parseRulesList(cursor.remaining()))
        case "show", "get":
            let id = try parseUUID(try cursor.value(for: subcommand), context: "rules show")
            try cursor.requireEnd("rules show")
            return .show(id)
        case "add": return .add(try parseRuleAdd(cursor.remaining()))
        case "enable": return .setEnabled(ids: try parseUUIDs(cursor.remaining(), context: "rules enable"), enabled: true)
        case "disable": return .setEnabled(ids: try parseUUIDs(cursor.remaining(), context: "rules disable"), enabled: false)
        case "rm", "remove": return .remove(ids: try parseUUIDs(cursor.remaining(), context: "rules rm"))
        case "import":
            guard let path = cursor.next() else {
                throw CLIError(.invalidArgument, message: "rules import requires a file path.", remediation: "Use `-` to read JSON from standard input.")
            }
            try cursor.requireEnd("rules import")
            return .importFile(path)
        case "export":
            var output: String?
            while let token = cursor.next() {
                guard token == "--output" || token == "-o" else {
                    throw CLIError(.invalidArgument, message: "unexpected argument `\(token)` for rules export.", remediation: "Use `--output PATH` or omit it to write JSON to standard output.")
                }
                output = try cursor.value(for: token)
            }
            return .exportFile(output)
        default:
            throw CLIError(.invalidArgument,
                           message: "unknown rules subcommand `\(subcommand)`.",
                           remediation: "Use list, show, add, enable, disable, rm, import, or export.")
        }
    }

    private static func parseRulesList(_ tokens: [String]) throws -> RulesListOptions {
        var cursor = TokenCursor(tokens: tokens)
        var profile: String?
        var category: RuleCategory = .all
        var group: String?
        var blocklist: String?
        var search: String?
        var limit: Int?
        while let token = cursor.next() {
            switch token {
            case "--profile": profile = try cursor.value(for: token)
            case "--category": category = try parseCategory(cursor.value(for: token))
            case "--group": group = try cursor.value(for: token)
            case "--blocklist": blocklist = try cursor.value(for: token)
            case "--search", "-s": search = try cursor.value(for: token)
            case "--limit": limit = try parseLimit(cursor.value(for: token), context: "rules list")
            default:
                throw CLIError(.invalidArgument,
                               message: "unexpected argument `\(token)` for rules list.",
                               remediation: "Run `freesnitch rules list --help` for usage.")
            }
        }
        return RulesListOptions(profile: profile, category: category, group: group, blocklist: blocklist, search: search, limit: limit)
    }

    private static func parseCategory(_ value: String) throws -> RuleCategory {
        switch value.lowercased() {
        case "all": return .all
        case "active": return .active
        case "deny", "denied": return .deny
        case "recent-changes", "recentchanges": return .recentChanges
        case "recently-used", "recentlyused": return .recentlyUsed
        case "temporary": return .temporary
        case "unapproved", "ask": return .unapproved
        default:
            throw CLIError(.invalidArgument,
                           message: "unknown rule category `\(value)`.",
                           remediation: "Use all, active, deny, recent-changes, recently-used, temporary, or unapproved.")
        }
    }

    private static func parseRuleAdd(_ tokens: [String]) throws -> Rule {
        var cursor = TokenCursor(tokens: tokens)
        var id = UUID()
        var processBundleId: String?
        var processPath: String?
        var processName: String?
        var remoteHost: String?
        var remoteIP: String?
        var remotePort: Int?
        var direction: RuleDirection = .outgoing
        var action: RuleAction = .ask
        var scope: RuleScope = .domain
        var scopeExplicit = false
        var priority = 100
        var profile = "default"
        var groupName: String?
        var notes: String?
        var enabled = true
        var temporary = false
        var expiresAt: Date?

        while let token = cursor.next() {
            switch token {
            case "--id": id = try parseUUID(try cursor.value(for: token), context: "rules add --id")
            case "--process-bundle-id", "--bundle-id": processBundleId = try cursor.value(for: token)
            case "--process-path": processPath = try cursor.value(for: token)
            case "--process-name", "--process": processName = try cursor.value(for: token)
            case "--host", "--remote-host": remoteHost = try cursor.value(for: token)
            case "--ip", "--remote-ip": remoteIP = try cursor.value(for: token)
            case "--port", "--remote-port":
                let value = try cursor.value(for: token)
                guard let port = Int(value), (1...65535).contains(port) else {
                    throw CLIError(.invalidArgument, message: "invalid remote port `\(value)`.", remediation: "Use an integer from 1 through 65535.")
                }
                remotePort = port
            case "--direction":
                let value = try cursor.value(for: token)
                guard let parsed = RuleDirection(rawValue: value.lowercased()) else {
                    throw CLIError(.invalidArgument, message: "invalid direction `\(value)`.", remediation: "Use outgoing, incoming, or any.")
                }
                direction = parsed
            case "--action":
                let value = try cursor.value(for: token)
                guard let parsed = RuleAction(rawValue: value.lowercased()) else {
                    throw CLIError(.invalidArgument, message: "invalid action `\(value)`.", remediation: "Use allow, deny, or ask.")
                }
                action = parsed
            case "--scope":
                let value = try cursor.value(for: token)
                guard let parsed = RuleScope(rawValue: value.lowercased()) else {
                    throw CLIError(.invalidArgument, message: "invalid scope `\(value)`.", remediation: "Use process, domain, ip, port, or any.")
                }
                scope = parsed
                scopeExplicit = true
            case "--priority":
                let value = try cursor.value(for: token)
                guard let parsed = Int(value), (Int.min...Int.max).contains(parsed) else {
                    throw CLIError(.invalidArgument, message: "invalid priority `\(value)`.", remediation: "Use an integer priority.")
                }
                priority = parsed
            case "--profile": profile = try cursor.value(for: token)
            case "--group": groupName = try cursor.value(for: token)
            case "--notes": notes = try cursor.value(for: token)
            case "--temporary": temporary = true
            case "--enabled": enabled = true
            case "--disabled": enabled = false
            case "--expires-at":
                let value = try cursor.value(for: token)
                guard let parsed = CLIJSON.date(value) else {
                    throw CLIError(.invalidArgument, message: "invalid expiration date `\(value)`.", remediation: "Use an ISO 8601 timestamp, for example 2026-08-13T12:00:00Z.")
                }
                expiresAt = parsed
            default:
                throw CLIError(.invalidArgument,
                               message: "unexpected argument `\(token)` for rules add.",
                               remediation: "Run `freesnitch rules add --help` for usage.")
            }
        }

        if !scopeExplicit {
            if remoteIP != nil { scope = .ip }
            else if remotePort != nil { scope = .port }
            else if processBundleId != nil || processPath != nil || processName != nil { scope = .process }
        }
        return Rule(id: id,
                    processBundleId: processBundleId,
                    processPath: processPath,
                    processName: processName,
                    remoteHost: remoteHost,
                    remoteIP: remoteIP,
                    remotePort: remotePort,
                    direction: direction,
                    action: action,
                    scope: scope,
                    priority: priority,
                    profile: profile.isEmpty ? "default" : profile,
                    groupName: groupName,
                    notes: notes,
                    enabled: enabled,
                    temporary: temporary,
                    expiresAt: expiresAt)
    }

    private static func parseUUID(_ value: String, context: String) throws -> UUID {
        guard let id = UUID(uuidString: value) else {
            throw CLIError(.invalidArgument, message: "`\(value)` is not a valid UUID.", remediation: "Use the rule ID printed by `freesnitch rules list`.")
        }
        return id
    }

    private static func parseUUIDs(_ tokens: [String], context: String) throws -> [UUID] {
        guard !tokens.isEmpty else {
            throw CLIError(.invalidArgument, message: "\(context) requires at least one rule ID.", remediation: "Use the IDs printed by `freesnitch rules list`. Multiple IDs are allowed.")
        }
        return try tokens.map { try parseUUID($0, context: context) }
    }

    private static func parseMonitor(_ tokens: [String]) throws -> MonitorCommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let subcommand = cursor.next() else {
            throw CLIError(.invalidArgument, message: "monitor requires a view.", remediation: "Use connections, traffic, processes, summary, blocked, or denied.")
        }
        let limit = try parseLimitOnly(cursor.remaining(), context: "monitor \(subcommand)", defaultLimit: subcommand == "summary" ? 5 : 100)
        switch subcommand {
        case "connections": return .connections(limit)
        case "traffic": return .traffic(limit)
        case "processes", "process-usage": return .processes(limit)
        case "summary": return .summary(limit)
        case "blocked": return .blocked(limit)
        case "denied": return .denied(limit)
        default: throw CLIError(.invalidArgument, message: "unknown monitor view `\(subcommand)`.", remediation: "Use connections, traffic, processes, summary, blocked, or denied.")
        }
    }

    private static func parseBlocklists(_ tokens: [String]) throws -> CLICommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let value = cursor.next() else {
            try cursor.requireEnd("blocklists")
            return .blocklists
        }
        guard value == "refresh" else {
            throw CLIError(.invalidArgument, message: "unknown blocklists subcommand `\(value)`.", remediation: "Use `blocklists` to list or `blocklists refresh` to refresh all.")
        }
        try cursor.requireEnd("blocklists refresh")
        return .refreshBlocklists
    }

    private static func parseBlocklist(_ tokens: [String]) throws -> CLICommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let id = cursor.next(), let value = cursor.next() else {
            throw CLIError(.invalidArgument, message: "blocklist requires an ID and on/off value.", remediation: "Use `blocklists` to find an ID, then `blocklist ID on` or `blocklist ID off`.")
        }
        try cursor.requireEnd("blocklist")
        guard let enabled = parseToggle(value) else {
            throw CLIError(.invalidArgument, message: "invalid blocklist state `\(value)`.", remediation: "Use on or off.")
        }
        return .blocklist(id: id, enabled: enabled)
    }

    private static func parsePF(_ tokens: [String]) throws -> PFCommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let value = cursor.next() else {
            throw CLIError(.invalidArgument, message: "pf requires install or uninstall.", remediation: "Use `pf install` or `pf uninstall --yes`.")
        }
        try cursor.requireEnd("pf")
        switch value {
        case "install": return .install
        case "uninstall": return .uninstall
        default: throw CLIError(.invalidArgument, message: "unknown pf operation `\(value)`.", remediation: "Use install or uninstall.")
        }
    }

    private static func parseSettings(_ tokens: [String]) throws -> SettingsCommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let subcommand = cursor.next() else {
            throw CLIError(.invalidArgument, message: "settings requires a setting or action.", remediation: "Use helper, speeds, launch-at-login, alerts-all-spaces, enforcement, mode, doh, dns, blocklists, or blocklist.")
        }
        switch subcommand {
        case "helper": return .helper(try parseHelperSettings(cursor.remaining()))
        case "speeds", "show-speeds": return try parseBooleanSetting(cursor.remaining(), key: AppPreferences.Key.showSpeeds, label: "show speeds")
        case "launch-at-login": return try parseBooleanSetting(cursor.remaining(), key: "launch-at-login", label: "launch at login")
        case "alerts-all-spaces": return try parseBooleanSetting(cursor.remaining(), key: AppPreferences.Key.alertsAllSpaces, label: "alerts on all Spaces")
        case "enforcement":
            if cursor.isAtEnd { return .enforcement(nil) }
            return .enforcement(try parseToggleCommand(cursor.remaining(), context: "settings enforcement"))
        case "mode": return .mode(try parseModeCommand(cursor.remaining(), context: "settings mode"))
        case "doh": return .doh(try parseSingleValue(cursor.remaining(), context: "settings doh"))
        case "dns":
            guard cursor.next() == "status", cursor.isAtEnd else {
                throw CLIError(.invalidArgument, message: "settings dns only supports status.", remediation: "Use `settings dns status`.")
            }
            return .dnsStatus
        case "blocklists":
            if cursor.isAtEnd { return .blocklists(refresh: false) }
            guard cursor.next() == "refresh", cursor.isAtEnd else {
                throw CLIError(.invalidArgument, message: "settings blocklists only supports list or refresh.", remediation: "Use `settings blocklists` or `settings blocklists refresh`.")
            }
            return .blocklists(refresh: true)
        case "blocklist":
            guard let id = cursor.next(), let value = cursor.next(), cursor.isAtEnd,
                  let enabled = parseToggle(value) else {
                throw CLIError(.invalidArgument, message: "settings blocklist requires an ID and on/off value.", remediation: "Use `settings blocklist ID on` or `settings blocklist ID off`.")
            }
            return .blocklist(id: id, enabled: enabled)
        default:
            throw CLIError(.invalidArgument, message: "unknown settings action `\(subcommand)`.", remediation: "Run `freesnitch settings --help` for the complete list.")
        }
    }

    private static func parseHelperSettings(_ tokens: [String]) throws -> HelperSettingsCommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let value = cursor.next() else { return .status }
        try cursor.requireEnd("helper \(value)")
        switch value {
        case "status": return .status
        case "recheck", "check": return .recheck
        case "open-login-items", "login-items": return .openLoginItems
        default: throw CLIError(.invalidArgument, message: "unknown helper action `\(value)`.", remediation: "Use status, recheck, or open-login-items.")
        }
    }

    private static func parseBooleanSetting(_ tokens: [String], key: String, label: String) throws -> SettingsCommand {
        var cursor = TokenCursor(tokens: tokens)
        guard let value = cursor.next() else { return .boolean(key: key, label: label, value: nil) }
        try cursor.requireEnd(label)
        guard let enabled = parseToggle(value) else {
            throw CLIError(.invalidArgument, message: "invalid state `\(value)` for \(label).", remediation: "Use on or off.")
        }
        return .boolean(key: key, label: label, value: enabled)
    }

    private static func helpName(_ topic: [String]) -> String {
        topic.isEmpty ? "help" : topic.joined(separator: " ")
    }

    private static func commandName(for command: CLICommand) -> String {
        switch command {
        case .help(let topic): return helpName(topic)
        case .version: return "version"
        case .status: return "status"
        case .doctor: return "doctor"
        case .mode: return "mode"
        case .rules(let value):
            switch value {
            case .list: return "rules list"
            case .show: return "rules show"
            case .add: return "rules add"
            case .setEnabled(_, let enabled): return enabled ? "rules enable" : "rules disable"
            case .remove: return "rules rm"
            case .importFile: return "rules import"
            case .exportFile: return "rules export"
            }
        case .monitor(let value):
            switch value {
            case .connections: return "monitor connections"
            case .traffic: return "monitor traffic"
            case .processes: return "monitor processes"
            case .summary: return "monitor summary"
            case .blocked: return "monitor blocked"
            case .denied: return "monitor denied"
            }
        case .connections: return "connections"
        case .traffic: return "traffic"
        case .processes: return "processes"
        case .blocked: return "blocked"
        case .denied: return "denied"
        case .blocklists: return "blocklists"
        case .refreshBlocklists: return "blocklists refresh"
        case .blocklist: return "blocklist"
        case .doh: return "doh"
        case .enforcement: return "enforcement"
        case .pf: return "pf"
        case .flush: return "flush"
        case .settings(let value):
            switch value {
            case .helper: return "settings helper"
            case .boolean(let key, _, _):
                switch key {
                case AppPreferences.Key.showSpeeds: return "settings speeds"
                case AppPreferences.Key.alertsAllSpaces: return "settings alerts-all-spaces"
                case "launch-at-login": return "settings launch-at-login"
                default: return "settings \(key)"
                }
            case .enforcement: return "settings enforcement"
            case .mode: return "settings mode"
            case .doh: return "settings doh"
            case .dnsStatus: return "settings dns status"
            case .blocklists(let refresh): return refresh ? "settings blocklists refresh" : "settings blocklists"
            case .blocklist: return "settings blocklist"
            }
        }
    }
}

private extension TokenCursor {
    func remaining() -> [String] {
        Array(tokens[index...])
    }
}
