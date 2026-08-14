import SwiftUI
import AppKit

/// A real `NSVisualEffectView`.
///
/// This is the thing that makes a Mac sidebar look like a Mac sidebar: it
/// samples what is behind the window and blurs it, and on macOS 26 and later
/// that same material is what the system renders as Liquid Glass. A flat fill,
/// however carefully chosen, can only ever be a screenshot of one appearance on
/// one wallpaper.
///
/// `.followsWindowActiveState` is deliberate: an inactive window's sidebar
/// desaturates, which is the cue that the window is not the one accepting keys.
struct VisualEffectView: NSViewRepresentable {
    var material: NSVisualEffectView.Material = .sidebar
    var blendingMode: NSVisualEffectView.BlendingMode = .behindWindow

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}
