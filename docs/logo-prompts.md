# Logo prompts

Generation prompts for a Binspector logo, written for Adobe Firefly but usable with any
text-to-image model. Kept in the repo so the branding rationale is recorded alongside the
tool rather than living in a chat log.

## Design rationale

The tool's identity is **looking inside a container to find what a surface scan misses**.
That is the thing worth encoding, and it is what separates Binspector from a generic
"magnifying glass over a file" icon.

Supporting inputs:

- The legacy banner's epigraph, which is the stated philosophy: *"Truth is confirmed by
  inspection and delay; falsehood by haste and uncertainly"* (Tacitus).
- A terminal-first Rust CLI, so a flat technical aesthetic rather than anything glossy.
- The palette already used by the tool's colorblind mode: Okabe-Ito amber `#E69F00` and
  slate blue `#0072B2`, which are chosen to avoid a red-green pairing.

## Primary: nested containers

Recommended. Encodes the differentiator instead of the category.

```
Flat vector app icon for a security tool called Binspector. A hexagonal outer
shell, partially cut away to reveal two smaller nested shells inside it, and at
the innermost core a glowing warning glyph. Thin geometric line work, 2px
uniform strokes, no gradients. Deep charcoal background, cool slate blue shells,
a single amber accent on the exposed core. Centered, symmetrical, generous
padding, legible at 64 pixels. Minimal, technical, modern developer-tool
branding. No text, no lettering.
```

## Alternative A: inspection instrument

More immediately readable as "inspector", less conceptually specific.

```
Minimal vector logo for a binary analysis tool. A precision caliper or lens
measuring a stack of data layers, rendered as clean concentric geometry. Flat
monoline style, uniform stroke weight, no gradients, no bevels. Palette limited
to dark slate, cool blue, and one amber highlight. Square canvas, centered,
strong silhouette, works as a small app icon. Technical and restrained, in the
style of modern open-source security tooling. No text.
```

## Alternative B: terminal wordmark

For a README header rather than an icon. Matches the ASCII banner aesthetic of the legacy
implementation.

```
Wide banner logo for a command-line security tool. A stylized terminal window
with a monospaced cursor, and inside it a faint grid of hexadecimal digits with
a handful highlighted in amber. Flat vector, dark charcoal, cool blue, single
amber accent, subtle scanline texture. Horizontal composition with clear space
on the left for a wordmark. Clean, technical, no clutter. No text.
```

## Notes on use

**Every prompt ends with "No text" on purpose.** Firefly and comparable models render
lettering unreliably. Set the wordmark in a real typeface afterward; a monospace face suits
the tool's aesthetic, and JetBrains Mono or IBM Plex Mono both work.

**To match the CLI output exactly**, append: `amber #E69F00 accent, slate blue #0072B2
shells`.

**No borrowed iconography.** These deliberately avoid motifs from any franchise. A public
repository's logo leaning on someone else's intellectual property is avoidable risk, and the
nested-shell idea fits what the tool does better anyway.

**Sizes worth exporting** once a direction is picked: 1024 and 512 for listings, 128 and 64
for an app icon, and a 1280x640 banner if Alternative B is used as a social preview.
