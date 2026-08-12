# CI and releases

## CI

The GitHub Actions workflow runs `Scripts/audit_firewall_safety.sh` on every
pull request and every push to `main`. The audit uses only Bash and `awk`
logic and runs on `ubuntu-latest`.

The macOS job builds the monitor flavour from `project.yml`. It does not use
`project-netext.yml`, provisioning profiles, or a Developer ID signature. It
sets `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` and checks that restricted Network
Extension and System Extension entitlements are absent. The firewall flavour
is built only by the maintainer release command after the required profiles are
available.

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

Use these non-publishing checks before a real release:

```sh
Scripts/release.sh --dry-run VERSION BUILD
Scripts/release.sh --validate-only VERSION BUILD [NOTES_FILE]
```

`--dry-run` needs neither `main` nor release credentials. `--validate-only`
requires a clean, pushed `main` synchronized with its upstream and validates a
notes file only when one is supplied or the versioned notes file already exists.
Neither mode changes tracked files, tags, remotes, or GitHub Releases.

## Prerequisites

Run the real release on macOS with Xcode, XcodeGen, the Apple command-line
tools, Sparkle's `generate_appcast`, `gh`, and these exact signing credentials:

- Developer ID identity: `Developer ID Application: isaac lins (BHAF4L4726)`
- Team: `BHAF4L4726`
- App profile: `FreeSnitch App DeveloperID` for
  `io.isaaclins.freesnitch`
- System extension profile: `FreeSnitch NetExt DeveloperID` for
  `io.isaaclins.freesnitch.netext`
- Helper bundle identifier: `io.isaaclins.freesnitch.helper`
- System extension bundle filename:
  `io.isaaclins.freesnitch.netext.systemextension`
- Notarytool keychain profile: `puresnitch-dev`
- Sparkle 2.7.1 account: `puresnitch`
- Sparkle public key: `4tyy5OVCWUs8cUsqCW22ce2IxVmhNZbBxJkoBlftIz8=`
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

The old and new content filters must not run together. Before installing a
signed FreeSnitch firewall build, run:

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
