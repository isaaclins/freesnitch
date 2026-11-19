import Foundation

/// What the failed-registration banner tells the user (#409).
///
/// The banner used to end every registration error with "Move FreeSnitch into
/// /Applications and try again", but registration is only attempted from
/// Applications, so that advice was wrong every time it showed. The message is
/// now built from what macOS actually said, and the move advice only appears
/// when the app really is outside Applications.
enum HelperRegistrationFailure {
    /// The older ServiceManagement API reports kSMError* codes in this domain.
    /// SMAppServiceErrorDomain mixes errno-style codes in, so there only the
    /// two failures whose text says what they are get specific advice.
    private static let frameworkDomain = "kSMErrorDomainFramework"
    private static let appServiceDomain = "SMAppServiceErrorDomain"

    static func message(for error: Error, inApplications: Bool) -> String {
        let ns = error as NSError
        return message(domain: ns.domain, code: ns.code,
                       description: ns.localizedDescription,
                       inApplications: inApplications)
    }

    /// Pure, so the test harness can check each case without SMAppService.
    static func message(domain: String, code: Int, description: String,
                        inApplications: Bool) -> String {
        // NSError's fallback text already names the domain and code.
        let text = sentence(description)
        let said: String
        if text.contains("\(domain) error \(code)") {
            said = text.hasSuffix(")")
                ? String(localized: "macOS said: \(text)")
                : String(localized: "macOS said: \(text).")
        } else {
            said = String(localized: "macOS said: \(text) (\(domain) \(code)).")
        }
        guard inApplications else {
            return String(localized: "\(said) macOS only installs background helpers for apps in Applications. Move FreeSnitch into /Applications, open it from there and try again.")
        }
        return "\(said) \(advice(domain: domain, code: code, description: description))"
    }

    private static let loginItems = String(localized: "FreeSnitch is switched off in the background items. Open System Settings under General > Login Items & Extensions, switch FreeSnitch on under \"Allow in the Background\", then retry.")
    private static let reinstall = String(localized: "The helper's declaration inside this copy of FreeSnitch is missing or unreadable. Download the signed release again and replace this copy.")
    private static let generic = String(localized: "Retry. If it keeps failing, restart the Mac and try again.")

    private static func advice(domain: String, code: Int, description: String) -> String {
        if domain == appServiceDomain {
            if code == 1, description.localizedCaseInsensitiveContains("not permitted") { return loginItems }
            if code == 108, description.localizedCaseInsensitiveContains("plist") { return reinstall }
            return generic
        }
        guard domain == frameworkDomain else { return generic }
        switch code {
        case 9, 11: // kSMErrorJobMustBeEnabled, kSMErrorLaunchDeniedByUser
            return loginItems
        case 3: // kSMErrorInvalidSignature
            return String(localized: "This copy of FreeSnitch isn't signed the way macOS requires for a helper. Download the signed release again and replace this copy.")
        case 8, 10: // kSMErrorJobPlistNotFound, kSMErrorInvalidPlist
            return reinstall
        case 4: // kSMErrorAuthorizationFailure
            return String(localized: "macOS didn't get the authorization it needed. Retry and approve the prompt if one appears.")
        default:
            return generic
        }
    }

    private static func sentence(_ text: String) -> String {
        var trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        while let last = trimmed.last, last == "." { trimmed.removeLast() }
        return trimmed.isEmpty ? String(localized: "registration failed", comment: "Stands in for an empty macOS error after \"macOS said:\"") : trimmed
    }
}
