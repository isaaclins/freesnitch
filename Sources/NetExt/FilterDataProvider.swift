//
//  FilterDataProvider.swift
//  PureSnitch Network System Extension
//
//  This target is DORMANT in v0.1.0. It compiles standalone for review
//  but is not part of the Xcode build because the
//  `com.apple.developer.networking.networkextension` entitlement with
//  `content-filter-provider-systemextension` value is Apple-gated.
//
//  Once you (or anyone forking this repo) obtains the entitlement from
//  Apple, add this folder as a target in project.yml with type
//  `app-extension` + `com.apple.security.application-groups` +
//  `com.apple.developer.networking.networkextension` entitlement and it
//  will compile and run as a true per-process firewall.
//

#if canImport(NetworkExtension)
import NetworkExtension
import Foundation

final class FilterDataProvider: NEFilterDataProvider {
    private var rules: [Rule] = []
    private var mode: AppMode = .alert
    private let matcher = RuleMatcher()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let allowAll = NEFilterRule(networkRule: NWHostEndpoint(hostname: "0.0.0.0", port: "0") as NWEndpoint as! NEFilterSocketRule.NWEndpoint, direction: .outbound, action: .filterData) as? NEFilterRule
        _ = allowAll
        let filter = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(filter) { error in
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow,
              let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            return .allow()
        }
        let pid = socketFlow.sourceAppAuditToken.flatMap { tokenToPID($0) } ?? 0
        let path = socketFlow.sourceAppIdentifier ?? ""
        let bundleId = socketFlow.sourceAppIdentifier
        let conn = Connection(
            pid: Int32(pid),
            processName: (path as NSString).lastPathComponent,
            processPath: path,
            processBundleId: bundleId,
            remoteHost: endpoint.hostname,
            remoteIP: endpoint.hostname,
            remotePort: Int(endpoint.port) ?? 0,
            direction: socketFlow.direction == .outbound ? .outgoing : .incoming
        )
        let decision = matcher.decision(for: conn, rules: rules, defaultMode: mode)
        switch decision {
        case .allow: return .allow()
        case .deny: return .drop()
        case .ask: return .pause()
        }
    }

    private func tokenToPID(_ data: Data) -> Int? {
        guard data.count >= MemoryLayout<audit_token_t>.size else { return nil }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { ptr in
            data.copyBytes(to: ptr, count: ptr.count)
        }
        return Int(token.val.5)
    }
}
#endif
