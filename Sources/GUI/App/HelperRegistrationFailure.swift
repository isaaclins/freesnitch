import Foundation

/// What the failed-registration banner tells the user (#409).
///
/// The banner used to end every registration error with "Move FreeSnitch into
/// /Applications and try again", but registration is only attempted from
/// Applications, so that advice was wrong every time it showed. The message is
/// now built from what macOS actually said, and the move advice only appears
/// when the app really is outside Applications.
enum HelperRegistrationFailure {
    /// SMAppService reports its errors in this domain, and the framework domain
    /// of the older API uses the same kSMError* codes. The launchd and IPC
    /// domains carry errno-style codes, so they get the generic advice.
    private static let serviceManagementDomains: Set<String> = [
        "SMAppServiceErrorDomain",
        "kSMErrorDomainFramework",
    ]

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
        let said = text.contains("\(domain) error \(code)")
            ? "macOS said: \(text)."
            : "macOS said: \(text) (\(domain) \(code))."
        guard inApplications else {
            return "\(said) macOS only installs background helpers for apps in Applications. Move FreeSnitch into /Applications, open it from there and try again."
        }
        let advice: String
        if serviceManagementDomains.contains(domain) {
            switch code {
            case 1, 9, 11: // EPERM, kSMErrorJobMustBeEnabled, kSMErrorLaunchDeniedByUser
                advice = "FreeSnitch is switched off in the background items. Open System Settings under General > Login Items & Extensions, switch FreeSnitch on under \"Allow in the Background\", then retry."
            // kSMErrorInvalidSignature. Code 3 is also ESRCH ("No such
            // process"), so only take it as a signature problem when macOS
            // says so.
            case 3 where description.localizedCaseInsensitiveContains("sign"):
                advice = "This copy of FreeSnitch isn't signed the way macOS requires for a helper. Download the signed release again and replace this copy."
            case 8, 10, 108: // kSMErrorJobPlistNotFound, kSMErrorInvalidPlist, "Unable to read plist"
                advice = "The helper's declaration inside this copy of FreeSnitch is missing or unreadable. Download the signed release again and replace this copy."
            case 4: // kSMErrorAuthorizationFailure
                advice = "macOS didn't get the authorization it needed. Retry and approve the prompt if one appears."
            default:
                advice = "Retry. If it keeps failing, restart the Mac and try again."
            }
        } else {
            advice = "Retry. If it keeps failing, restart the Mac and try again."
        }
        return "\(said) \(advice)"
    }

    private static func sentence(_ text: String) -> String {
        var trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        while let last = trimmed.last, last == "." { trimmed.removeLast() }
        return trimmed.isEmpty ? "registration failed" : trimmed
    }
}
