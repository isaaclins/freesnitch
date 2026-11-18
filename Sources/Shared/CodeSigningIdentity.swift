import Foundation
import Security

/// The bundle id a rule may match a process by, taken from the process's code
/// signature rather than from an Info.plist (#351).
///
/// An Info.plist is an unsigned file anyone can write. Reading the bundle id
/// from it let any binary in a folder named `Something.app` claim another
/// app's id and inherit that app's rules, allow rules included. A signature's
/// identifier is only taken when the signature is valid and was issued by
/// Apple for distribution:
///
/// - Apple's own code (`anchor apple`)
/// - an app signed for the Mac App Store or the iOS App Store, where Apple
///   hands out each bundle id to one developer only
/// - a Developer ID application
///
/// Ad-hoc signatures, development certificates and unsigned code give no bundle
/// id: anyone can make one with any identifier, for free. Such a process is
/// still matched by its path. An identifier under `com.apple.` is taken only
/// from Apple's own code or the Mac App Store, so a Developer ID cannot claim
/// to be an Apple app.
///
/// A process that is not inside an .app bundle gets no bundle id, as before.
/// A process inside an .app (a helper tool, an XPC service) answers its own
/// signed identifier, never the enclosing app's: the app's seal of its nested
/// code is not checked here (that would hash the whole bundle), so any validly
/// signed binary, say Apple's curl, copied into a copy of Safari.app would
/// otherwise pass as Safari. Deny rules still reach such a tool through the
/// app's Info.plist id (`Connection.claimedBundleId`).
public enum CodeSigningIdentity {
    /// Who vouches for an identifier.
    enum Signer: Equatable {
        case apple
        case team(String)
    }

    struct Signed: Equatable {
        let identifier: String
        let signer: Signer
        let appStore: Bool
    }

    /// Outcome of one lookup. `unavailable` means the signature could not be
    /// read at all (the process exited and the file is gone, say), which a
    /// caller may retry; `untrusted` is a definite answer.
    enum Lookup: Equatable {
        case trusted(Signed)
        case untrusted
        case unavailable
    }

    /// Apple's own code, the Mac App Store, the iOS App Store, or a Developer
    /// ID application. The OIDs are the ones Apple's designated requirements
    /// use: 6.1.9 Mac App Store, 6.1.3 iPhone App Store, 6.2.6 Developer ID
    /// intermediate, 6.1.13 Developer ID application.
    static let distributionRequirementText =
        "anchor apple"
        + " or (anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists)"
        + " or (anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.3] exists)"
        + " or (anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
        + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists)"

    static let appStoreRequirementText =
        "anchor apple generic and (certificate leaf[field.1.2.840.113635.100.6.1.9] exists"
        + " or certificate leaf[field.1.2.840.113635.100.6.1.3] exists)"

    private static let distributionRequirement: SecRequirement? = requirement(distributionRequirementText)
    private static let appStoreRequirement: SecRequirement? = requirement(appStoreRequirementText)

    private static func requirement(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else { return nil }
        return requirement
    }

    /// Resources (images, nibs, localisations) are not hashed: that reads the
    /// whole bundle from disk on every lookup. The executable, its code
    /// directory and the Info.plist bound into the signature are still checked.
    private static let checkFlags = SecCSFlags(rawValue: kSecCSDoNotValidateResources)

    /// The bundle id rules may match the process by.
    ///
    /// `auditToken` (preferred) or `pid` names the running process. With
    /// `fileFallback` the executable file is checked when the process has
    /// already exited; the extension turns that off because it ties the answer
    /// to the code of the process it checked.
    /// Reads signatures from disk: never call it on a verdict path.
    static func resolve(executablePath: String, auditToken: Data?, pid: Int32, fileFallback: Bool = true) -> Resolution {
        guard enclosingAppPath(forExecutablePath: executablePath) != nil else { return .noBundle }
        let process: Lookup
        if let code = guestCode(auditToken: auditToken, pid: pid) {
            process = lookup(code: code)
        } else if fileFallback, let code = staticCode(atPath: executablePath) {
            process = lookup(staticCode: code)
        } else {
            process = .unavailable
        }
        return decide(process)
    }

    enum Resolution: Equatable {
        case noBundle
        case resolved(String?)
        case unavailable

        var bundleIdentifier: String? {
            if case .resolved(let id) = self { return id }
            return nil
        }
    }

    /// Pure decision, kept apart from the Security calls so it can be tested.
    static func decide(_ process: Lookup) -> Resolution {
        switch process {
        case .unavailable:
            return .unavailable
        case .untrusted:
            return .resolved(nil)
        case .trusted(let own):
            return .resolved(acceptable(own) ? own.identifier : nil)
        }
    }

    /// An Apple identifier comes only from Apple's code or the Mac App Store,
    /// where Apple decides who gets which bundle id.
    static func acceptable(_ signed: Signed) -> Bool {
        guard !signed.identifier.isEmpty else { return false }
        if signed.identifier.hasPrefix("com.apple.") {
            return signed.signer == .apple || signed.appStore
        }
        return true
    }

    /// The innermost .app the executable sits in, or nil.
    static func enclosingAppPath(forExecutablePath path: String) -> String? {
        guard !path.isEmpty, let r = path.range(of: ".app/", options: .backwards) else { return nil }
        return String(path[..<path.index(before: r.upperBound)])
    }

    private static func guestCode(auditToken: Data?, pid: Int32) -> SecCode? {
        let attributes: [String: Any]
        if let auditToken {
            attributes = [kSecGuestAttributeAudit as String: auditToken]
        } else if pid > 0 {
            attributes = [kSecGuestAttributePid as String: pid]
        } else {
            return nil
        }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    private static func staticCode(atPath path: String) -> SecStaticCode? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess else {
            return nil
        }
        return code
    }

    private static func lookup(code: SecCode) -> Lookup {
        guard let distribution = distributionRequirement else { return .untrusted }
        let status = SecCodeCheckValidity(code, checkFlags, distribution)
        guard status == errSecSuccess else { return failure(status) }
        let appStore = appStoreRequirement.map { SecCodeCheckValidity(code, checkFlags, $0) == errSecSuccess } ?? false
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return .unavailable }
        return signed(staticCode, appStore: appStore)
    }

    private static func lookup(staticCode: SecStaticCode) -> Lookup {
        guard let distribution = distributionRequirement else { return .untrusted }
        let status = SecStaticCodeCheckValidity(staticCode, checkFlags, distribution)
        guard status == errSecSuccess else { return failure(status) }
        let appStore = appStoreRequirement.map {
            SecStaticCodeCheckValidity(staticCode, checkFlags, $0) == errSecSuccess
        } ?? false
        return signed(staticCode, appStore: appStore)
    }

    /// Only an answer about the signature itself makes code untrusted: it is
    /// unsigned, its signature is broken, or the signer is not one rules may
    /// trust. Anything else (the process is gone, the app was updated on disk
    /// while running, the file could not be read) is no answer, so the caller
    /// checks again instead of turning every allow for that app into an alert.
    static func failure(_ status: OSStatus) -> Lookup {
        switch status {
        case errSecCSUnsigned, errSecCSReqFailed, errSecCSSignatureFailed, errSecCSSignatureInvalid,
             errSecCSSignatureUnsupported, errSecCSBadObjectFormat, errSecCSBadDictionaryFormat,
             errSecCSResourceDirectoryFailed, errSecCSInfoPlistFailed, errSecCSWeakResourceRules,
             errSecCSSignatureNotVerifiable, errSecCSHostReject, errSecCSInvalidPlatform:
            return .untrusted
        default:
            reportUnreadable(status)
            return .unavailable
        }
    }

    /// One unified log line per distinct status, so a check that keeps failing
    /// for a reason other than the signature (a sandbox refusal, say) shows up.
    private static let reportedLock = NSLock()
    nonisolated(unsafe) private static var reported: Set<OSStatus> = []
    private static func reportUnreadable(_ status: OSStatus) {
        guard status != errSecCSNoSuchCode, status != errSecCSStaticCodeChanged else { return }
        reportedLock.lock()
        let first = reported.insert(status).inserted
        reportedLock.unlock()
        guard first else { return }
        NSLog("FreeSnitch: could not read a code signature to verify a bundle id (OSStatus %d); it is checked again", status)
    }

    /// Only called once the signature passed `distributionRequirement`. Every
    /// certificate that passes it and is not Apple's own carries a team id, so
    /// a missing team id here means `anchor apple`.
    private static func signed(_ code: SecStaticCode, appStore: Bool) -> Lookup {
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let identifier = dict[kSecCodeInfoIdentifier as String] as? String else { return .untrusted }
        let team = (dict[kSecCodeInfoTeamIdentifier as String] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return .trusted(Signed(identifier: identifier, signer: team.map(Signer.team) ?? .apple, appStore: appStore))
    }
}
