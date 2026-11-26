# CI and releases

## CI

The GitHub Actions workflow runs `Scripts/audit_firewall_safety.sh` on every
pull request and every push to `main`. The audit uses only Bash and `awk`
logic and runs on `ubuntu-latest`.

The macOS jobs (four groups of test harnesses and the monitor build) run on
every push to `main` and once per pull request, right before it merges: bring
the branch up to date with `main`, run `gh workflow run build.yml --ref
<branch>`, and merge when that run is green. They don't run on every push to a
pull request from this repo, because the macOS runners are few and shared and
a run takes five of them; a skipped job counts as passed in the check list, so
the manual run is the one to look at. Pull requests from forks run them right
away.

A newer run replaces an older one of the same kind on the same ref: a push to
`main` cancels the queued or running jobs of the previous `main` push, and a
new `gh workflow run` for a branch cancels the previous dispatch for it. So an
older `main` commit, including a release commit followed quickly by another
push, can show a cancelled run; the newest `main` commit always gets a full
one.

The monitor build job builds the monitor flavour from `project.yml`. It does not use
`project-netext.yml`, provisioning profiles, or a Developer ID signature. It
sets `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` and checks that restricted Network
Extension and System Extension entitlements are absent. The firewall flavour
is built only by the maintainer release command after the required profiles are
available.

## Website

The site is one self-contained page, `docs/index.html`, with its CSS and
JavaScript inline and the screenshots beside it in `docs/`. GitHub Pages serves
it as is: there is no build step. The page works without JavaScript; with it,
sections fade in as you scroll. Add `?shot` to the URL to show everything at
once, for full-page screenshots.

## Release command

When a maintainer says **release this**, the command is:

```sh
Scripts/release.sh VERSION BUILD NOTES_FILE
```

For example:

```sh
Scripts/release.sh 0.3.0 9 /tmp/freesnitch-v0.3.0.md
```

The notes file must be non-empty and may live outside the repository. The
script applies the version and build before running XcodeGen, generates the
firewall project from `project-netext.yml`, builds both architectures, signs,
notarizes, Gatekeeper-assesses, creates the Sparkle appcast, and only then
commits, tags, pushes, and creates the GitHub Release.

Once the GitHub Release exists, it also bumps the version and SHA-256 of the
FreeSnitch cask in [isaaclins/homebrew-tap](https://github.com/isaaclins/homebrew-tap),
using the checksum GitHub reports for the published disk image. The script
checks that it can push there before it publishes anything. If the bump fails
after the release is out, the release stays as it is and the script prints the
command that finishes it:

```sh
Scripts/release.sh --update-tap VERSION
```

Use these non-publishing checks before a real release:

```sh
Scripts/release.sh --dry-run VERSION BUILD
Scripts/release.sh --validate-only VERSION BUILD [NOTES_FILE]
```

`--dry-run` needs neither `main` nor release credentials. `--validate-only`
requires a clean, pushed `main` synchronized with its upstream and validates a
notes file only when one is supplied or the versioned notes file already exists.
Neither mode changes tracked files, tags, remotes, or GitHub Releases.

## After a release

`Scripts/release.sh` does not touch the website or the README. Both name the
current version and its download link, so update them by hand once the GitHub
Release is live:

- `docs/index.html`: every `releases/download/vX.Y.Z/FreeSnitch-X.Y.Z.dmg`
  link (navigation, hero, install), the version line under the hero buttons,
  the size on the install button, and `softwareVersion` and `downloadUrl` in
  the JSON-LD.
- `README.md`: the Install section and the Status paragraph.

Neither carries a checksum. The release script attaches `SHA256SUMS.txt`,
made from the files it uploads and checked before the release commit, so a
failure there stops the release before anything is tagged or pushed. GitHub
shows each asset's SHA-256 on the release page.

## Prerequisites

Run the real release on macOS with Xcode, XcodeGen, the Apple command-line
tools, Sparkle's `generate_appcast`, `gh`, and these exact signing credentials:

- Developer ID identity: `Developer ID Application: isaac lins (BHAF4L4726)`
- Team: `BHAF4L4726`
- App profile: `FreeSnitch App DeveloperID 2026-11` for
  `io.isaaclins.freesnitch`
- System extension profile: `FreeSnitch NetExt DeveloperID 2026-11` for
  `io.isaaclins.freesnitch.netext`
- Helper bundle identifier: `io.isaaclins.freesnitch.helper`
- System extension bundle filename:
  `io.isaaclins.freesnitch.netext.systemextension`
- Notarytool keychain profile: `puresnitch-dev` (set `NOTARY_PROFILE` for another name and
  `NOTARY_KEYCHAIN` when it lives in a keychain other than the default one)
- Sparkle 2.10.1 account: `puresnitch` (or `SPARKLE_EDDSA_PRIVATE_KEY_FILE`)
- Sparkle public key: `s19KDKXgrxZQgfYO2yymuly/OjXMOpCpwqsIvVebbfU=` (since 1.1.0, build 34; the 1.0.0 key
  `4tyy5OVCWUs8cUsqCW22ce2IxVmhNZbBxJkoBlftIz8=` was lost, so builds below 34
  get every newer update as informational only: Sparkle announces it and
  opens the releases page, and the user installs it by hand once)
- GitHub CLI authenticated with access to `isaaclins/freesnitch`

The release build always sets `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`. Do not
replace the profiles, bundle identifiers, system-extension filename, or
notarytool profile with values from another project.

## Pages and appcast setup

GitHub Pages should publish the repository's `docs/` directory from the
`main` branch. Keep `docs/.nojekyll` present so the XML feed is served as a
file. The custom-domain Pages setup must make this feed reachable at:

```text
https://isaaclins.com/freesnitch/appcast.xml
```

`docs/appcast.xml` starts as a valid RSS feed with no release items. A real
release replaces it with the signed feed produced by Sparkle. The release
script keeps the previous feed beside the downloaded archives so Sparkle can
preserve update history. Do not commit Sparkle private keys or generated
archives.

## Migrating the pre-FreeSnitch installation

The old and new content filters must not run together. FreeSnitch checks for
`/Applications/PureSnitch.app` and the old helper's LaunchDaemon every time it
opens and offers to remove both (`Sources/GUI/App/LegacyPureSnitch.swift`):
it stops the helper behind one password prompt (only when the helper is still
there), moves the app to the Trash, and keeps PureSnitch's user data. Since
macOS 15.3 the Trash may leave the old network extension running, and
FreeSnitch cannot remove another app's extension, so it also checks
`systemextensionsctl list` on every launch and, while PureSnitch's extension
is still active, says where to delete it in System Settings > General > Login
Items & Extensions, under Extensions. From a
source checkout the same can be done by hand:

```sh
Scripts/uninstall_puresnitch.sh
```

The migration script requests deactivation and uninstall of the legacy
system extension, unloads and removes the old helper LaunchDaemon, and removes
`/Applications/PureSnitch.app`. It reports the old
user Application Support directory and app-group container without deleting
them. Pass `--remove-user-data` only when intentionally resetting that legacy
state:

```sh
Scripts/uninstall_puresnitch.sh --remove-user-data
```

The script is idempotent, never touches FreeSnitch paths, and does not reboot
the Mac. `systemextensionsctl` may require a reboot to finish deactivation or
uninstall. The PF anchor keeps its established `puresnitch` name so renaming
the product cannot strand active firewall rules; FreeSnitch reuses that anchor.

## Failure recovery

Before committing or publishing, a failed release restores the tracked version
files so the next attempt can start from a clean tree. Check the result with:

```sh
git status --short
git log --oneline -3
git tag --list 'v*'
```

If failure happens after the release commit, inspect whether the tag or remote
push already completed before retrying. Do not reset or delete a remote commit
or tag blindly. Resolve the failing credential, build, notarization, appcast,
or GitHub operation, then continue from the repository state that actually
exists. A GitHub Release is considered published only after `gh release create`
succeeds.
