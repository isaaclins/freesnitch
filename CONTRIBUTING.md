# Contributing to FreeSnitch

Thanks for considering a contribution. The bar is: ship working code, keep the diff small, leave the codebase clearer than you found it.

## Quick start

```bash
git clone https://github.com/isaaclins/freesnitch.git
cd freesnitch
brew install xcodegen
xcodegen generate --spec project.yml
open FreeSnitch.xcodeproj
```

The default `xcodegen generate` command uses `project.yml`, the contributor build. It omits the Network System Extension so it builds without this team's Developer ID provisioning profiles, which is why it is the default here. Users receive the firewall build instead, generated from `project-netext.yml` by `Scripts/release.sh`.

Build target: FreeSnitch. Hit ⌘R. A local contributor build may fail to install the helper daemon without Developer ID signing. That is expected for an unsigned development build. The GUI still launches against in-memory state, and per-process filtering is absent because the extension is not embedded.

## Conventions

- **Swift 5.10**, macOS 13+ deployment target.
- **No new dependencies** unless there's a load-bearing reason. SQLite via `import SQLite3` is fine; a third-party Swift package needs justification in the PR.
- **f-strings? no.** This is Swift. String interpolation, not Python.
- **No emoji in code or commits.** Yes, even there.
- **Match the existing style.** SwiftUI views split into small private computed properties. No mega-views.
- **Comments are for *why*, not *what*.** Identifier names should carry the *what*.

## Areas where help is most welcome

1. **Firewall build testing** (`project-netext.yml`). This is the build users get, and it is the hardest to test, since it needs the Developer ID profiles. Test the signed universal build, first-launch system extension approval, and per-process flow decisions.
2. **macOS compatibility**. Test on every macOS version you have, report breakage with a paste of the build error.
3. **Localization**. The strings are not yet `.strings`-extracted. Help wanted.
4. **Blocklist curation**. Add high-quality, low-false-positive sources; remove anything stale.
5. **UI polish**. Pixel-level fidelity to Little Snitch is the bar. Submit screenshots in the PR.

## Pull request checklist

- [ ] Monitor build is clean with `xcodegen generate --spec project.yml && xcodebuild -project FreeSnitch.xcodeproj -scheme FreeSnitch`
- [ ] If you touched the firewall flavour, generate it with `xcodegen generate --spec project-netext.yml` and verify the signed build with the required profiles
- [ ] No new warnings in your changed files
- [ ] Manual test pass: app launches, menubar popover appears, Network Monitor opens, and Rules Manager opens
- [ ] If you touched the helper: `sudo lsof -nP -iUDP:53` shows the proxy still binds, and `pfctl -a puresnitch -s rules` shows your rules
- [ ] If you touched the Network System Extension: verify first-launch approval and a new flow reaches the provider

## Reporting bugs

Open an issue. Include:
- macOS version
- FreeSnitch version from Settings under About
- Reproduction steps
- Console output from `log stream --predicate 'subsystem == "io.isaaclins.freesnitch"'`

## License

By contributing you agree your contributions are licensed under the MIT License.
