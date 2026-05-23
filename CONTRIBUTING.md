# Contributing to PureSnitch

Thanks for considering a contribution. The bar is: ship working code, keep the diff small, leave the codebase clearer than you found it.

## Quick start

```bash
git clone https://github.com/moamenbasel/puresnitch.git
cd puresnitch
brew install xcodegen
xcodegen generate
open PureSnitch.xcodeproj
```

Build target: PureSnitch. Hit ⌘R. The first run will fail to install the helper daemon if you're not signed with a Developer ID — that's expected for dev builds. The GUI still launches and is fully interactive against in-memory state.

## Conventions

- **Swift 5.10**, macOS 14+ deployment target.
- **No new dependencies** unless there's a load-bearing reason. SQLite via `import SQLite3` is fine; a third-party Swift package needs justification in the PR.
- **f-strings? no.** This is Swift. String interpolation, not Python.
- **No emoji in code or commits.** Yes, even there.
- **Match the existing style.** SwiftUI views split into small private computed properties. No mega-views.
- **Comments are for *why*, not *what*.** Identifier names should carry the *what*.

## Areas where help is most welcome

1. **Network Extension path** (Sources/NetExt/). If you have access to the `com.apple.developer.networking.networkextension` entitlement and want to wire up true per-process filtering, this is the highest-impact contribution.
2. **macOS 15 / 16 / 26 compatibility**. Test on every macOS you have, report breakage with a paste of the build error.
3. **Localization**. The strings are not yet `.strings`-extracted. Help wanted.
4. **Blocklist curation**. Add high-quality, low-false-positive lists; remove anything stale.
5. **UI polish**. Pixel-level fidelity to Little Snitch is the bar. Submit screenshots in the PR.

## Pull request checklist

- [ ] Builds clean with `xcodegen generate && xcodebuild -project PureSnitch.xcodeproj -scheme PureSnitch`
- [ ] No new warnings in your changed files
- [ ] Manual test pass: app launches, menubar popover appears, Network Monitor opens, Rules Manager opens
- [ ] If you touched the helper: `sudo lsof -nP -iUDP:53` shows the proxy still binds, `pfctl -a puresnitch -s rules` shows your rules

## Reporting bugs

Open an issue. Include:
- macOS version
- PureSnitch version (Settings → About)
- Reproduction steps
- Console output from `log stream --predicate 'subsystem == "io.moamenbasel.puresnitch"'`

## License

By contributing you agree your contributions are licensed under the MIT License.
