Fixes #

## What changes for the user

<!-- One or two sentences, in plain words. What can someone do now, or what stops going wrong? -->

## How I tested it

<!-- What you ran or clicked, and on which macOS version. Say plainly what you could not test,
     for example the signed firewall build or a real network extension. -->

- [ ] `xcodegen generate --spec project.yml && xcodebuild -project FreeSnitch.xcodeproj -scheme FreeSnitch CODE_SIGNING_ALLOWED=NO build` is clean
- [ ] `bash Scripts/audit_firewall_safety.sh` passes
- [ ] The `Scripts/test_*.sh` that cover what I changed pass

## Screenshots

<!-- Anything visible: before and after, light and dark. `FREESNITCH_DEMO=1` fills the app with sample data.
     Delete this section if nothing visible changed. -->

| Before | After |
| --- | --- |
|  |  |
