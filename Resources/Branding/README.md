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
- the layer images in `Resources/AppIcon.icon/Assets/`

## Light, dark, clear and tinted

On macOS 26 and later the app icon comes from `Resources/AppIcon.icon`, an
Icon Composer document. The system draws its shape and switches between the
light and dark versions with the system appearance, and builds the clear and
tinted looks from the same layers. The colours for each appearance are in
`icon.json`: a light plate with blue rings and a dark core, or a dark plate with
brighter rings and a light core. In the clear and tinted looks the core stays
white so it doesn't disappear.

Xcode also renders a flat copy of the light version from that document for
macOS 13 to 15. `AppIcon.appiconset` stays for builds with an Xcode older than
26, which can't read Icon Composer documents. Open `AppIcon.icon` in Icon
Composer (it ships inside Xcode) to preview every look.

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
