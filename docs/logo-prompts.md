# Logo prompts

Generation prompts for a Binspector logo, written for Adobe Firefly but usable with any
text-to-image model. Kept in the repo so the branding rationale is recorded alongside the
tool rather than living in a chat log.

## What the logo has to say

The tool's idea is **cracking a container open to find what a surface scan misses**. Every
prompt below encodes that literally: something sealed, opened, and a single dangerous thing
lit up inside it. That is the differentiator, and it is what separates this from a generic
magnifying glass over a file.

The aesthetic direction is steampunk, cyberpunk, comic-book heroic, and anime, which is a
richer register than a flat vector icon. Two practical consequences:

- **Two tiers.** A detailed illustration reads beautifully at 1024 and turns to mush at 64,
  so the badge prompts below are deliberately simpler than the key-visual prompts. Generate
  both. Use the illustration for the README header and social preview, the badge for the
  favicon and any app icon.
- **Palette holds across both.** Okabe-Ito amber `#E69F00` and slate blue `#0072B2`, the
  same pair the colorblind mode uses, over deep charcoal. Amber is always the discovered
  threat, blue is always the machinery. Keeping that consistent is what makes a detailed
  illustration and a flat badge look like one brand.

The legacy banner's epigraph is the tone to aim for: *"Truth is confirmed by inspection and
delay; falsehood by haste and uncertainly"* (Tacitus). Patient, methodical, slightly severe.
Not a hero mid-punch.

## Primary: cyberpunk anime key visual

Recommended for the README header. Most distinctive, and the composition leaves room for a
wordmark.

```
Anime key visual, cinematic cyberpunk illustration. A lone hooded technician
kneels in profile before a floating matte-black hexagonal container that has
split open along glowing seams, its inner shells peeled back in mid-air to
expose a single amber warning sigil burning at the core. Cel-shaded with hard
light, thick confident linework, dramatic rim lighting, volumetric haze, faint
scanlines. Deep charcoal and slate blue environment lit only by amber from the
opened core. Low camera angle, strong silhouette, negative space on the upper
left. Restrained and methodical rather than action-posed. Highly detailed, no
text, no lettering, no signature.
```

## Alternative A: steampunk inspection engine

Warmer and more mechanical. Reads as craft and patience, which suits the epigraph best.

```
Detailed steampunk illustration of a brass inspection engine. A riveted
spherical vessel clamped in an armature, its plating hinged open in overlapping
petals to reveal nested inner spheres, and at the center a single amber ember
held in a caliper. Fine copper piping, exposed gear trains, pressure gauges,
etched engraving detail, patinated brass and oxidised steel. Lit by the amber
core against a deep charcoal workshop, cool slate blue highlights on the metal.
Centered three-quarter view, symmetrical, ornate but legible. Ink and watercolor
rendering, visible line weight. No text, no lettering.
```

## Alternative B: heroic emblem badge

The app-icon tier. Comic-book chest-crest construction, which is exactly the shape language
that survives being shrunk to 64 pixels.

```
Bold comic-book emblem badge, chest-crest construction. A heavy-shouldered
hexagonal shield, cracked open down the center to reveal three receding inner
frames and a single amber diamond at the heart. Thick black keyline, flat bold
color fills, hard cel-shaded highlights, halftone dot texture in the shadows,
slight chromatic edge. Slate blue plating, amber core, deep charcoal ground.
Perfectly symmetrical, centered, generous padding, aggressive silhouette that
stays legible at 64 pixels. Modern superhero insignia design. No text, no
lettering, no franchise iconography.
```

## Alternative C: mecha inspector mascot

For a mascot or sticker rather than a logo. Use if a character is wanted.

```
Anime mecha character illustration, three-quarter view, full body. A compact
inspection drone the size of a person, matte charcoal armor with slate blue
accent panels, a single large amber optical lens, articulated multi-jointed
scanning arms folded at rest, one arm extended holding open a small cracked
container that glows amber. Cel-shaded, clean mechanical linework, panel lines
and visible fasteners, subtle wear. Neutral dark background with a soft amber
floor glow. Calm posture, not combat-ready. Detailed hard-surface design,
no text.
```

## Notes on use

**Every prompt ends with "no text" on purpose.** Firefly and comparable models render
lettering unreliably, and a misspelled logo is unusable. Set the wordmark in a real typeface
afterward. A monospace face suits the tool: JetBrains Mono or IBM Plex Mono for a restrained
look, or a heavier display face if the emblem direction wins.

**To pin the palette exactly**, append to any prompt: `amber #E69F00 core, slate blue #0072B2
plating, charcoal #1A1A1A ground`.

**No borrowed iconography, and this is a real constraint rather than a note.** The prompts
reach for the register of superhero and anime design without naming a franchise, a character,
a studio, or an artist. A public repository whose logo leans on someone else's intellectual
property is avoidable risk, and Firefly's commercial-use claim only holds while the output is
not derivative. If a generation comes back looking recognisably like a specific character,
discard it.

**Sizes worth exporting** once a direction is picked: 1280x640 for the social preview, 1024
and 512 for listings, 128 and 64 for the app icon and favicon. Check the 64 pixel render
before committing to a direction; that is where detailed illustration fails.

**Pairing that works:** Primary for the README header, Alternative B for the favicon. The
shared palette and the shared cracked-container motif carry the identity between them.
