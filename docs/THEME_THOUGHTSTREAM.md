# ThoughtStream theme

Status: working spec for the thin theme layer on Arctic Fuse 3. The font addon
is packaged and the setup service applies the accent and seeds the home menu
from this spec. The base palette and serif title wiring remain design intent
under the strict no-edit rule, as explained below.

ThoughtStream is a calm, editorial look that rides on top of Arctic Fuse 3
(AF3). The palette is warm stone neutrals with warm whites, hairline borders
instead of shadows, flat surfaces, and zero corner radius. Titles are set in a
serif (Libre Baskerville 700), UI text in a sans (Inter 400 and 600).

## Hard constraint that shapes this whole document: strict no-edit

We do not edit the AF3 addon in place. AF3 hardcodes its base colour palette
(in `colors/defaults.xml` and `1080i/Includes_Colors.xml`) and its font roles
(in `1080i/Font.xml` and `1080i/Includes_Font.xml`) inside its own addon
folder. Kodi has no supported way for a separate addon to override those at
install time without writing into the AF3 package.

So the three deliverables split into what can and cannot be applied cleanly:

| Deliverable | Applied cleanly under strict no-edit? |
| --- | --- |
| Home menu and widget rows (deliverable 3) | Yes. Stored in the user profile, not in AF3. Our setup service writes the shortcut and widget data the skin reads. |
| Accent colour (part of deliverable 2) | Yes. AF3 reads `Skin.String(focuscolor.name)`. The setup service sets it with `Skin.SetString(focuscolor.name,AARRGGBB)`. |
| Background image (part of deliverable 2) | Yes. `Skin.SetString(Background.Image,...)`. |
| Full stone base palette (rest of deliverable 2) | No. Lives in AF3 `colors/defaults.xml`. Cannot be applied without editing AF3. Documented here as design intent only. |
| Font role wiring, serif titles and sans UI (wiring half of deliverable 1) | No. Lives in AF3 `Font.xml` fontsets. The font ADDON ships cleanly, but AF3 will not use it for titles unless its fontset is edited. Documented here; needs the user to either relax the no-edit rule for a thin font patch, or accept fonts ship but stay inactive. |

The font addon itself (deliverable 1, packaging) ships cleanly because AF3
already imports an external `resource.font` addon and reads it over
`resource://`. We package ours the same way. Only the activation differs.

## Design tokens (warm stone)

Hex shown as RRGGBB. Kodi colours are AARRGGBB (alpha first). The applied
subset below restates the ones we can actually push.

| Token | Hex | Role intent |
| --- | --- | --- |
| stone.paper | FAF9F7 | Primary background, warm white |
| stone.surface | F4F2EF | Cards and panels, flat |
| stone.surface.alt | EDEAE4 | Secondary panels |
| stone.hairline | E2DED8 | Hairline borders, 1px, replaces shadows |
| stone.hairline.strong | D6D1C9 | Focused or active hairline |
| stone.ink | 2B2926 | Primary text, warm near black |
| stone.ink.soft | 4A453F | Headings on light |
| stone.muted | 6B655D | Secondary text |
| stone.faint | 9A938A | Tertiary text and disabled |
| stone.accent | 8A7B6B | Restrained warm accent for focus |
| stone.accent.alt | B08968 | Optional clay accent if more warmth wanted |

Accent is deliberately quiet. ThoughtStream avoids a saturated highlight. If
the focus state reads as too subtle on the ONN, bump to stone.accent.alt.

## Token to AF3 role mapping (full design intent)

This is the complete intent for when or if a thin AF3 colour patch is allowed.
Under strict no-edit only the rows marked APPLIED are pushed at runtime.

| AF3 role or skin string | Token | Applied now? |
| --- | --- | --- |
| focuscolor.name | stone.accent (ff8a7b6b) | APPLIED via Skin.SetString |
| Background.Image | warm white still background | APPLIED via Skin.SetString |
| main_fg_100 (primary text) | stone.ink | intent only, in defaults.xml |
| main_fg_90 | stone.ink.soft | intent only |
| main_fg_70 | stone.muted | intent only |
| main_fg_50 | stone.faint | intent only |
| panel and card fills | stone.surface | intent only |
| dialog_nib, dialog backgrounds | stone.paper | intent only |
| separators and borders | stone.hairline | intent only |

## Fonts

Sources, all OFL licensed, packaged into `resource.font.thoughtstream`:

- Libre Baskerville, weight 700 (Bold), for titles. File LibreBaskerville-Bold.ttf.
- Inter, weight 400 (Regular), for body UI. File Inter-Regular.ttf.
- Inter, weight 600 (SemiBold), for emphasis and labels. File Inter-SemiBold.ttf.

Packaging follows AF3's own pattern: a `resource.font.*` addon with
`<extension point="kodi.resource.fonts" />` and the .ttf files under
`resources/`, referenced as
`resource://resource.font.thoughtstream/LibreBaskerville-Bold.ttf`.

Activation note: AF3 declares its fontsets in `1080i/Font.xml`. To make AF3
render titles in Libre Baskerville and UI in Inter without editing AF3, there
is no supported hook. Options for review:

1. Relax the no-edit rule for a single small overlay of AF3 `Font.xml` that
   adds a "ThoughtStream" fontset pointing at our resource addon. Smallest
   change that actually delivers serif titles.
2. Keep strict no-edit. The font addon installs and is available to Kodi, but
   AF3 keeps its own fonts until the rule is relaxed.

Recommendation: ship the addon now under strict no-edit, revisit option 1 on a
later push once the menu and accent are confirmed on the ONN.

## Home menu and widgets

Driven by the rows in
`src/service.kodipersonal.setup/resources/config/lists.json`. The setup
service writes AF3's home shortcut and widget data into the user profile on
first run, so AF3 picks them up with no edit to the skin. Widgets use AF3's
on-focus lazy loading (`Container.IsUpdating`), so a row's widget loads only
when that row is focused, which matters on 2 to 3 GB hardware.

Two groups:

- For You: Up Next, Continue Watching, My Calendar, Recommended. Trakt backed
  through TMDb Helper.
- Five services, each with New, Trending, Top Rated: Netflix, Max, Apple TV+,
  Disney+, Prime Video. Discover queries filtered by TMDb watch provider and
  region US.

See lists.json for the exact plugin paths. Provider IDs are US values and are
flagged there for on-device verification.

## Open decisions for the user

1. Font activation: relax no-edit for a thin Font.xml overlay, or ship inactive.
2. Accent: stone.accent (ff8a7b6b) default, or warmer stone.accent.alt (ffb08968).
3. Provider IDs in lists.json: confirm on the ONN, especially Max and Prime.
