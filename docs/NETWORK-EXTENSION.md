# The Network System Extension and the two build flavours

`Sources/NetExt` implements a per-process content filter (`NEFilterDataProvider`).
It ships in the release DMG: releases are built from `project-netext.yml` by
`Scripts/release.sh`, which embeds `io.isaaclins.freesnitch.netext.systemextension`
and grants the app the two restricted entitlements:

- `com.apple.developer.networking.networkextension` (`content-filter-provider-systemextension`)
- `com.apple.developer.system-extension.install`

`project.yml`, the default contributor build, deliberately omits them.

## The reason

Both are *restricted* entitlements. A Developer ID signature does not grant
them. They have to be authorised by an Apple-issued provisioning profile
embedded in the bundle, and AMFI checks that at process creation. Ship a signed
app that requests them without the profile and the failure mode is not a
degraded feature - the process can be refused before `main()` runs, so the app
just never opens.

This is why the contributor build (`project.yml`) leaves out these entitlements.
The release build requires the Developer ID profiles that grant them.

Two concrete consequences we hit while building v0.2.0:

- `xcodebuild` refused outright: *"FreeSnitch requires a provisioning profile
  with the Network Extensions and System Extension features."* There was no way
  to produce a signed release with those entitlements and no profile.
- The 0.1.0 users in issue #5 already had an app that looked dead. Shipping a
  build that AMFI could kill at launch would have been a strictly worse bug.

v0.2.0 shipped as a monitor only: menu bar, traffic monitor, rules UI, and the
privileged helper. No system extension, no extension approval prompt. Current
releases are the firewall flavour built from `project-netext.yml`; the monitor
flavour (`project.yml`) is now only the contributor build.

## Building the release firewall flavour

`Scripts/release.sh` generates the release project with:

```bash
xcodegen generate --spec project-netext.yml
```

That spec re-adds the entitlements and embeds
`io.isaaclins.freesnitch.netext.systemextension`, whose filename matches the
system extension bundle identifier as required by sysextd. To build and sign
it, as `Scripts/release.sh` does, you need, from the Apple Developer portal,
under Team ID `BHAF4L4726`:

1. The **Network Extensions** capability enabled on App ID `io.isaaclins.freesnitch`
   (self-serve) and on `io.isaaclins.freesnitch.netext`.
2. The **System Extension** capability on the app's App ID.
3. Two Developer ID provisioning profiles - one per App ID - downloaded and
   embedded as `Contents/embedded.provisionprofile` in the respective bundles.
4. Inside-out signing is performed by `Scripts/release.sh` (helper, extension,
   then app), followed by notarization and stapling.
5. The app installed in `/Applications` and approved in
   System Settings › Privacy & Security. For local development only,
   `systemextensionsctl developer on` skips the notarization requirement.

Verify before releasing such a build: launch it on a clean machine from
`/Applications`, confirm the extension activates, and confirm nothing appears in
the log as an AMFI/taskgated rejection.

## Contributor build

Generated from `project.yml`:

```bash
xcodegen generate --spec project.yml
```

It has no extension and no per-process filtering. Use it to work on everything
except the firewall feature. It builds without provisioning profiles. It is not
what users receive; releases are built from `project-netext.yml`.
