# FreeSnitch brand

## The mark

Six bursts of concentric arcs radiating from a single dark core. The core is
your Mac; the arcs are the connections leaving it. The rings are what the app
actually shows you, a live radar of outbound traffic, so the icon describes the
product rather than decorating it.

Colour comes from overlap. Each burst is drawn with a multiply blend, so where
neighbouring bursts cross they produce a third hue, the same way the Photos icon
builds its palette. Nothing in the mark is a stock glyph.

## Reproducing it

    ./Scripts/make_icon.sh

`Scripts/render_icon.swift` draws every shape procedurally with AppKit. Swift and
`sips` are the only requirements, both of which ship with macOS. There is no
vector editor, no design tool, and no external asset to keep in sync.

That script writes:

- every size in `Resources/Assets.xcassets/AppIcon.appiconset/`
- `Resources/Branding/freesnitch-mark-1024.png`, the master render
- `docs/favicon.png` and `docs/icon-512.png`

## Why the shapes are hand-drawn

The composition was sketched using SF Symbols to test whether the idea held up.
Apple's SF Symbols licence does not permit shipping their glyphs inside an app
icon or logo, so the final artwork is built from our own arcs and circles. The
sketch informed the design; none of Apple's artwork is distributed here.

## Deliberately not inherited

FreeSnitch began as a fork of PureSnitch by Moamen Basel, which used an orange
shield containing linked nodes. None of that identity is reused: not the shield,
not the node motif, not the ember palette. The README credits the original
author; the brand is separate from that credit.
