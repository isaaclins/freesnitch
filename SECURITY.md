# Security policy

FreeSnitch sits between your Mac and the network. It runs a privileged helper as root, a Network System Extension that sees every new connection, a local DNS proxy and `pf` rules. A flaw in any of those matters more than a flaw in an ordinary app, so please report it privately first.

## Supported versions

| Version | Gets security fixes |
| --- | --- |
| 1.1.x (latest release) | Yes |
| 1.0.x and older | No. Please update. |

Fixes ship in the next release, through the built-in updater and the [releases page](https://github.com/isaaclins/freesnitch/releases). There are no backports to older versions.

FreeSnitch 1.0.0 cannot update itself to 1.1.0 or later, because the update signing key changed. If you still run 1.0.0, download the latest release by hand.

## How to report

Use GitHub's private vulnerability reporting: go to the [Security tab](https://github.com/isaaclins/freesnitch/security), choose **Report a vulnerability** and fill in the form. Only I see it until we publish an advisory together.

Please include:

- the FreeSnitch version (Settings > About) and your macOS version
- which part is affected (helper, network extension, DNS proxy, `pf` rules, updater, CLI, app)
- steps to reproduce, or a proof of concept
- what an attacker gains

Please don't open a public issue, discussion or pull request for a vulnerability before a fix is out.

What happens next: I confirm I got your report within a few days, tell you whether I see it as a vulnerability, and keep you updated while I fix it. Once the fix is released I publish an advisory and credit you, unless you'd rather stay anonymous.

## What counts as a security issue here

Report these privately:

- **Privilege escalation through the helper.** A local process that is not FreeSnitch gets the root helper to do something: talk to it over XPC, change rules, write files, run commands, or pass a request it should refuse.
- **Getting past rules on purpose.** A local process or a remote party can reliably make a connection that a rule the user set should have blocked, or make FreeSnitch treat one app as another (for example by faking a bundle id, path or code signature).
- **Tampering with rules, profiles or settings** from outside the app, or making an import file do more than add rules.
- **The DNS proxy or DNS over HTTPS** answering with something it shouldn't, leaking queries to a resolver the user didn't pick, or being reachable from other machines on the network.
- **The updater** accepting an update that isn't signed with the FreeSnitch key, or fetching it in a way that can be intercepted.
- **Leaking what FreeSnitch knows.** Connection history, host names or rules that another user or process on the Mac, or anything on the network, can read without permission.
- **Locking a user out of the network** in a way an attacker can trigger. FreeSnitch is built to fail open: if something goes wrong it stops filtering rather than blocking more than you asked.

These are normal bugs, so please open a [public issue](https://github.com/isaaclins/freesnitch/issues/new/choose):

- a rule that doesn't match what you expected, when nobody is exploiting it
- traffic that isn't filtered while the filter is off, the helper isn't approved, or Enforcement is off. That is how FreeSnitch fails open, by design.
- anything that already needs root or an administrator password on the Mac
- crashes and hangs that an outside party can't trigger
- the contributor build (unsigned, without the network extension) behaving differently from the release build

When you're unsure, report it privately. I'd rather get a report that turns out to be a normal bug than miss a real one.
