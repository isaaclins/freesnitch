import Foundation
import NetworkExtension

// Entry point for the Network System Extension. The NetworkExtension framework
// instantiates FilterDataProvider (declared via NEProviderClasses in Info.plist)
// once the filter is started.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
