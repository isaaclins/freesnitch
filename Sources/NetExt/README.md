# NetExt (dormant)

This directory contains the Network System Extension code path used for true
per-process connection filtering. It is **not built** in v0.1.0 of PureSnitch
because shipping it requires:

1. The `com.apple.developer.networking.networkextension` entitlement with
   the `content-filter-provider-systemextension` value.
2. Apple's approval for that entitlement (granted via the Network Extension
   request form: https://developer.apple.com/contact/request/networking-entitlement).
3. A provisioning profile bundling that entitlement.

Without that entitlement, the system extension cannot be loaded — installing
it will fail with `OSSystemExtensionErrorAuthorizationRequired` or similar.

PureSnitch v0.1.0 ships with a **functional firewall** using pfctl + a local
DNS proxy that runs without this entitlement. Per-process IP-direct blocking
(traffic that doesn't go through DNS) requires this entitlement.

To activate this code path:
1. Apply for the entitlement from Apple.
2. Add this folder as a target in `project.yml` (type: `app-extension`).
3. Add the corresponding `com.apple.developer.networking.networkextension`
   entitlement to the system extension.
4. Update the GUI to call `OSSystemExtensionRequest.activationRequest(...)`
   instead of (or in addition to) the helper daemon path.

The Swift code in `FilterDataProvider.swift` shows the verdict path. It
reuses `RuleMatcher` from `Shared/`, so the rule semantics are identical.
