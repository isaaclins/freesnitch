# Accessibility

I want FreeSnitch to work for everyone who uses a Mac, including people who use VoiceOver or the keyboard instead of a pointer. This page says what works today, what doesn't yet, and how to tell me when something is in your way.

It describes FreeSnitch 1.1.0 and what is on `main`. It was last checked against the code on 18 November 2026.

## Supported macOS versions

FreeSnitch runs on macOS 13 Ventura and later, on Apple Silicon and Intel. The connection map on the Network Monitor needs macOS 14 Sonoma or later. On macOS 13 the rest of the app works the same, without the map.

## VoiceOver

FreeSnitch is built with standard SwiftUI and AppKit controls (lists, tables, buttons, toggles, sheets), so VoiceOver reads them the way it reads other Mac apps.

- Icon-only buttons have spoken names: allow, deny and remove-rule on each Network Monitor row (they name the app or host they act on), add, import and export rules, edit and search a blocklist, create and delete a profile, reload on Insights, and the close buttons on banners and the map.
- Buttons that can't be used right now are reported as dimmed, not just drawn faded.
- Each place on the connection map is a pin with its name. The pin's popover lists the apps that connected there.
- Traffic bars on the Network Monitor are read as "Sent ..., received ...".
- The three panes of the Rules page are named Categories, Rules and Information.
- The menu bar icon is named FreeSnitch.

## Keyboard

- **Command-1 to Command-5** switch between Network Monitor, Rules, Insights, Profiles and Settings, in the order of the sidebar.
- **Command-F** puts the cursor in the search field of the current page.
- **Tab** and **Shift-Tab** move between the category list, the rules table and the Information pane on the Rules page.
- **Delete** removes the selected rules or blocklist entries, and on the Network Monitor the rule on the selected row.
- **Command-C** copies the selected rows on the Network Monitor, Rules, Insights and blocklist pages.
- **Return** confirms and **Escape** cancels in connection alerts, sheets and confirmation dialogs.

## System settings FreeSnitch follows

FreeSnitch uses system colours and fonts, so it follows Light and Dark appearance, Increase Contrast, Reduce Transparency and your accent colour. Allow and deny don't rely on colour alone: each has its own symbol and spoken name.

## Known gaps

- Nobody has yet gone through the whole app with VoiceOver on and the keyboard only, so some barriers may still be unknown. That full check is [#394](https://github.com/isaaclins/freesnitch/issues/394).
- Whether a new connection alert is announced by VoiceOver when it appears has not been checked yet ([#394](https://github.com/isaaclins/freesnitch/issues/394)).
- The connection map is easier to use with a pointer than with the keyboard. The same connections are listed in the Network Monitor tree next to it.
- The app is only in English. The text is not yet set up for translation (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Report a barrier

If something in FreeSnitch is hard or impossible for you to use, please [open an issue](https://github.com/isaaclins/freesnitch/issues/new/choose) and start the title with "Accessibility:". Tell me what you tried to do, what assistive technology you use (VoiceOver, Full Keyboard Access, Voice Control, Zoom, ...), your macOS version and your FreeSnitch version (Settings > About).

If you'd rather not post in public, write to [freesnitch@isaaclins.com](mailto:freesnitch@isaaclins.com).

Barriers are treated as bugs, not as feature requests.
