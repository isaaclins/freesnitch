import SwiftUI
import AppKit

/// What FreeSnitch knows about the destination selected in the Monitor (#194):
/// who runs the network, its AS number and range, and where the address is
/// estimated to be. All of it comes from offline databases on this Mac.
///
/// "Look Up Owner" is the only thing here that leaves the Mac, and only when
/// clicked: it asks the DNS server for the reverse name and a public RDAP
/// registry for the registration record of this one address.
struct EndpointDetailsSection: View {
    @EnvironmentObject var state: AppState
    let destination: MonitorDestinationNode

    var body: some View {
        Section("Selected Destination") {
            if let ip = destination.remoteIP {
                EndpointAddressDetails(ip: ip, name: nameShown(for: ip))
                    // A new address starts with no lookup result.
                    .id(ip)
            } else {
                LabeledContent("Name") { CopyableValue(value: destination.label) }
                Text("FreeSnitch has not seen the address for this destination yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func nameShown(for ip: String) -> String? {
        let label = destination.label
        return label == ip ? nil : label
    }
}

private struct EndpointAddressDetails: View {
    @EnvironmentObject var state: AppState
    let ip: String
    let name: String?

    @State private var lookup: LookupState = .idle

    enum LookupState {
        case idle
        case running
        case done(EndpointOwnerLookup.Result)
    }

    var body: some View {
        // Read on every render: both are a binary search in a mapped file.
        let network = IPASNCache.shared.lookup(ip)
        let location = IPGeoCache.shared.lookup(ip)
        let isPublic = EndpointOwnerLookup.isPublic(ip)

        LabeledContent("Address") { CopyableValue(value: ip) }
            .onAppear { runDemoLookupOnce() }
        if let name {
            LabeledContent("Name") { CopyableValue(value: name) }
        }

        if !isPublic {
            note("A local or private address. It belongs to your own network, not to anyone on the internet.")
        } else {
            if let network {
                if let organization = network.organization {
                    LabeledContent("Network") { CopyableValue(value: organization) }
                }
                LabeledContent("ASN") { CopyableValue(value: network.asnText) }
                LabeledContent("Address range") { CopyableValue(value: network.rangeText) }
            } else {
                note(networkMissingText)
            }

            if let location {
                LabeledContent("Location") { Text(locationText(location)).multilineTextAlignment(.trailing) }
            }
            note(locationNote(location))
            credit

            lookupRows
        }
    }

    /// `FREESNITCH_DEMO_MONITOR_LOOKUP=1` runs the lookup once by itself, so
    /// its result can be reviewed in a screenshot.
    private var demoRunsLookup: Bool {
        DemoMode.isOn && ProcessInfo.processInfo.environment["FREESNITCH_DEMO_MONITOR_LOOKUP"] == "1"
    }

    // MARK: Offline data

    private var networkMissingText: String {
        let status = state.asnStatus
        if !status.isLoaded {
            return String(localized: "Network owner data is still downloading.")
        }
        if !status.hasDatabase {
            return String(localized: "Network owner data could not be downloaded. FreeSnitch tries again on the next launch.")
        }
        return String(localized: "This address is not in the network owner data.")
    }

    private func locationText(_ entry: IPGeoCache.Entry) -> String {
        let country = entry.country ?? entry.countryCode ?? ""
        if let city = entry.city, !country.isEmpty { return "\(city), \(country)" }
        if !country.isEmpty { return String(localized: "\(country) (country only)") }
        return String(localized: "Unknown")
    }

    private func locationNote(_ entry: IPGeoCache.Entry?) -> String {
        guard entry != nil else {
            return state.geoStatus.isLoaded
                ? String(localized: "No location estimate for this address.")
                : String(localized: "Location data is still downloading.")
        }
        return String(localized: "The location is an estimate. Shared or anycast addresses can be served from many places.")
    }

    /// CC BY asks for a visible credit where the data is shown. The map
    /// carries one, but the map can be hidden (#473), so this section has its
    /// own, with the age of the data the reporter asked for.
    private var credit: some View {
        let built = [state.asnStatus.builtAt, state.geoStatus.builtAt].compactMap { $0 }.min()
        let text = built.map {
            String(localized: "Network and location data by DB-IP, updated \($0.formatted(date: .abbreviated, time: .omitted))")
        } ?? String(localized: "Network and location data by DB-IP")
        return Link(text, destination: URL(string: IPASNCache.attribution.linkURL) ?? URL(string: "https://db-ip.com/")!)
            .font(.caption)
            .help("\(IPASNCache.attribution.text), licensed \(IPASNCache.attribution.licenseName)")
    }

    // MARK: On-demand lookup

    @ViewBuilder
    private var lookupRows: some View {
        switch lookup {
        case .idle:
            Button("Look Up Owner…") { runLookup() }
                .help("Ask your DNS server for this address's name and a public registry (RDAP) for who registered it.")
            note("Sends this address to your DNS server and to rdap.org. Nothing is sent until you click.")
        case .running:
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Looking up…").foregroundStyle(.secondary)
            }
        case .done(let result):
            if let reverseName = result.reverseName {
                LabeledContent("Reverse DNS") { CopyableValue(value: reverseName) }
            } else {
                LabeledContent("Reverse DNS") { Text("None").foregroundStyle(.secondary) }
            }
            if let record = result.record {
                if let networkName = record.name {
                    LabeledContent("Registered as") {
                        CopyableValue(value: networkName)
                    }
                }
                if let owner = record.owner {
                    LabeledContent("Registered to") { CopyableValue(value: owner) }
                }
                if let range = record.rangeText {
                    LabeledContent("Registered range") { CopyableValue(value: range) }
                }
                if let country = record.country {
                    LabeledContent("Registry country") {
                        Text(Locale.current.localizedString(forRegionCode: country) ?? country)
                    }
                }
                if let handle = record.handle {
                    LabeledContent("Handle") { CopyableValue(value: handle) }
                }
            }
            if let failure = result.registryFailure {
                note(String(localized: "The registry lookup failed: \(failure)"))
            } else if let source = result.registryHost {
                note(String(localized: "Registration record from \(source). It says who registered the range, not where the server is."))
            }
            Button("Look Up Again") { runLookup() }
        }
    }

    private func runDemoLookupOnce() {
        if demoRunsLookup, case .idle = lookup { runLookup() }
    }

    private func runLookup() {
        lookup = .running
        let address = ip
        Task {
            let result = await EndpointOwnerLookup.run(ip: address)
            lookup = .done(result)
        }
    }

    private func note(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The click-only lookups. Each is bounded in time and size, and a failure is
/// reported, never retried behind the user's back.
enum EndpointOwnerLookup {
    struct Result: Sendable {
        var reverseName: String?
        var record: RDAPNetworkRecord?
        var registryHost: String?
        var registryFailure: String?
    }

    static func isPublic(_ ip: String) -> Bool {
        var text = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.withUTF8 { IPGeoCache.parseTarget($0) } != nil
    }

    static func run(ip: String) async -> Result {
        async let reverse = reverseName(for: ip)
        async let registry = registration(for: ip)
        let (name, (record, host, failure)) = await (reverse, registry)
        return Result(reverseName: name, record: record, registryHost: host, registryFailure: failure)
    }

    /// PTR through the system resolver, off the main thread.
    static func reverseName(for ip: String) async -> String? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: resolvePTR(ip))
            }
        }
    }

    private static func resolvePTR(_ ip: String) -> String? {
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST
        hints.ai_family = AF_UNSPEC
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(ip, nil, &hints, &info) == 0, let first = info else { return nil }
        defer { freeaddrinfo(info) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen,
                          &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) == 0 else { return nil }
        let name = String(cString: host)
        return name.isEmpty || name == ip ? nil : name
    }

    static func registration(for ip: String) async -> (RDAPNetworkRecord?, String?, String?) {
        guard let url = RDAPNetworkRecord.lookupURL(for: ip) else {
            return (nil, nil, String(localized: "not a public address"))
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let host = response.url?.host
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                return (nil, host, String(localized: "the registry answered with HTTP \(code)"))
            }
            guard let record = RDAPNetworkRecord.parse(data) else {
                return (nil, host, String(localized: "the registry's answer could not be read"))
            }
            return (record, host, nil)
        } catch {
            return (nil, nil, error.localizedDescription)
        }
    }
}
