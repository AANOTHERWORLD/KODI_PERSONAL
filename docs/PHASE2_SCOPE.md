# Phase 2 scope: Arctic Fuse 3 fork sizing audit

Read-only audit of upstream `skin.arctic.fuse.3` to size a possible Phase 2 fork.
No changes were made to AF3. All references are to upstream
`github.com/jurialmunkey/skin.arctic.fuse.3` at the commit cloned for this audit
(full history, 315 commits). File paths are relative to the skin root. No em
dashes per repo convention.

Context: Phase 1 already took the no-fork performance headroom (texture caps in
advancedsettings.xml plus a one-time cache clear, shipped in
service.kodipersonal.setup 0.7.0). This audit sizes what still requires a fork.

---

## Q1: Home slot cap (supporting 8 or more top-level sections)

The build uses home plus four custom widget sections. That "five slot" cap is
not a single loop bound; it is baked into the skin in several places.

- Per-slot window files: `1080i/Custom_1101_Hub.xml` through
  `Custom_1104_Hub.xml`. Each is a thin 10-line window that wraps shared
  includes, parameterised by window id:
  ```
  <window type="window" id="1101">
      <include content="Hub_Onload"><param name="window_id">1101</param></include>
      <controls><include content="Hub_Window"><param name="window">1101</param></include></controls>
  </window>
  ```
- Window id space is already crowded: `Custom_1105_Search.xml`,
  `Custom_1106_NextAired.xml`, `Custom_1107_LiveTV.xml`,
  `Custom_1108_Addons.xml`, `Custom_1109_Settings.xml`. New widget slots need
  free ids (1110, 1112 and up; 1111 is the colour picker).
- The generator hardcodes exactly four widget lists:
  `shortcuts/generator/data/base/home_widgets.xml` lines 6 to 16 define
  `1101widgets` through `1104widgets` with explicit `window_id` values.
- The four-slot assumption is repeated as literal expressions
  `Window.IsVisible(1101) | ... | Window.IsVisible(1104)` across many includes:
  `Custom_1181_Dialog_Submenu.xml:9-10`,
  `Custom_1182_Dialog_Topmenu_Overlay.xml:3`,
  `Custom_1198_Dialog_Startup.xml:3`, `Includes_Background.xml:253`,
  `Includes_Furniture.xml:446`, `Dialog_DialogShortcuts.xml:513` and `:691`.
- The context menu that edits menu nodes hardcodes the slot list too:
  `Dialog_DialogContextMenu.xml:203`
  (`homewidgets||1101widgets||...||1104widgets||...`).

What must change for 8 or more sections: add new `Custom_11xx_Hub.xml` windows
(mechanical copies), add matching lists in `home_widgets.xml`, extend every
hardcoded `1101..1104` expression above, extend the context-menu node list, and
wire the HomeSwitcher settings and home menu bar for the new slots.

Verdict: HARD. This is structural layout XML plus repeated hardcoded slot lists
across roughly eight files, not a template loop bound. It is also the most
rebase-fragile change because those expressions live in files upstream touches.

---

## Q2: Font wiring (serif titles, sans UI from resource.font.thoughtstream)

- Fontsets are in `1080i/Font.xml`: `Default` (unicode false, includes
  `Font_Default`) and `Default (Unicode)` (unicode true, overrides to
  `resource://resource.font.robotocjksc/Inter-Unicode-*.ttf`, lines 8 to 21).
- UI and body fonts default in `1080i/Includes_Font.xml:105-108`
  (`<include name="Font_Default">`): `font_bold` Inter-Bold.ttf, `font_regular`
  Inter-Regular.ttf, `font_light` Inter-Light.ttf. So the UI is already Inter,
  from the skin's own bundled copies.
- Title and heading fonts in `Includes_Font.xml`: `font_title_huge` (line 139)
  and `font_title_midi` (line 144) use `<filename>$PARAM[font_bold]</filename>`,
  i.e. they inherit Inter Bold. `font_infotag_bold` (line 26) is
  LeagueSpartan-ExtraBold.ttf. Decorative variants `font_title_midi_1` through
  `_0` (lines 150 onward) point at `titles/*.ttf` and are not used by the build.

Minimal diff for the goal:
- Titles to Libre Baskerville 700: in `Includes_Font.xml`, change the
  `<filename>` of `font_title_huge` and `font_title_midi` (and optionally
  `font_infotag_bold`) to
  `resource://resource.font.thoughtstream/LibreBaskerville-Bold.ttf`. About 2 to
  3 lines.
- UI to our Inter 400/600: in the `Font_Default` include (lines 106 to 108),
  repoint `font_bold` to `resource://resource.font.thoughtstream/Inter-SemiBold.ttf`
  and `font_regular`/`font_light` to `.../Inter-Regular.ttf`. About 3 lines.
  Optional, since AF3 already renders UI in Inter; this only swaps to our
  packaged copies for exact parity.

Verdict: EASY. Contained to one file (`Includes_Font.xml`), about 2 to 5 lines.
This is the cleanest single win of the fork and delivers the serif-title look the
theme spec calls for, which cannot be done from settings alone.

---

## Q3: Corner radius (true 0 default)

The radius is not a user setting default; it is force-set on every home load:
`1080i/Home.xml:5` `<onload>Skin.SetString(TMDbHelper.Corner.Radius,20)</onload>`.

This is why the setup service cannot make it 0 from settings: Home.xml re-sets 20
each time Home loads, overriding the service.

Minimal diff: change `20` to `0` on that line, or remove the onload. One line in
`1080i/Home.xml`.

Verdict: EASY (one line), but it genuinely requires the fork because the value is
hardcoded in an onload, not exposed as a setting.

---

## Q4: First-run wizard / default config

Two upstream mechanisms apply the stock look on a fresh profile, both of which
the service currently suppresses by pre-setting their markers (Kodi skin settings
are case-insensitive, so our lowercase ids match):

- `1080i/Home.xml:14-17`, gated on `!Skin.HasSetting(Home.FirstRun)`: sets
  `Hub.Home.DisableSubmenu`, `Shortcuts.RebuildDateTime=FirstRun`,
  `Home.FirstRun`, and a reload alarm.
- `shortcuts/skinvariables-startup.json`, gated on
  `!Skin.HasSetting(DefaultConfig.InitDone)`: applies the stock default config
  then sets `DefaultConfig.InitDone`. This block turns on `TMDbHelper.EnableData`,
  `EnableCrop`, `EnableBlur`, `Service`, sets `Background.DialogImage=Adaptive`
  and a purple blur background, toggles `HomeSwitcher.1107`, and sets the Home
  spotlight to Random Movies. If not suppressed, it clobbers the ThoughtStream
  theme on first run.

Can a fork delete it outright: yes. Remove the `Home.FirstRun` onload block from
`Home.xml` and the `DefaultConfig.InitDone` action block from
`skinvariables-startup.json` (or replace that block with the ThoughtStream
defaults so the fork ships the right look with no service suppression needed).

Verdict: MEDIUM. Two files, one of which (`skinvariables-startup.json`) is skin
data upstream edits, so it needs re-checking on rebase. Removing it also lets us
drop the `defaultconfig.initdone` and `home.firstrun` entries from the service's
skin_settings, simplifying the runtime layer.

---

## Q5: Unused view types

View definitions live in `1080i/Includes_Views.xml` plus
`Includes_Views_List.xml`, `Includes_Views_Wall.xml`, `Includes_Views_Combined.xml`,
`Includes_Views_Row.xml`, `Includes_Views_PVR.xml`, and the generated
`script-skinviewtypes-includes.xml`. The deployed view map uses a small set of
ids (500, 501, 502, 508, 521).

Removing the unused view includes is possible but the payoff is negligible: view
includes are parsed once at skin load, the memory cost of an unreferenced view
definition is tiny, and pruning risks breaking cross-references (list and info
panels share view includes). Being honest per the brief: not worth doing.

Verdict: NEGLIGIBLE. Leave the view includes alone.

---

## Q6: Update surface (rebase burden)

Upstream AF3 is very actively developed.

- 315 commits to the skin in the last 6 months (roughly 52 per month).
- 10 commits in the last 6 months touched the specific files a fork would change
  (`Font.xml`, `Includes_Font.xml`, `Home.xml`, `Custom_1101_Hub.xml`,
  `home_widgets.xml`), roughly 2 per month on the fork surface.

Implication: a long-lived fork diverges quickly and must be rebased regularly.
The font and radius edits are small and localized, so they rebase cleanly. The
slot expansion (Q1) touches many files that upstream also edits, so it is the
part most likely to conflict on every rebase. A fork that takes only Q2, Q3, and
Q4 is low maintenance; a fork that also takes Q1 is a standing maintenance
commitment.

---

## Verdict table

| Phase 2 goal | Difficulty | Files touched | Risk / rebase burden |
| --- | --- | --- | --- |
| 8 or more home slots | Hard | New `Custom_11xx_Hub.xml` per slot, `generator/data/base/home_widgets.xml`, about 6 to 8 includes with hardcoded `1101..1104` lists, `Dialog_DialogContextMenu.xml` node list, HomeSwitcher wiring | High. Wide structural change over files upstream edits often. |
| Serif titles + Inter UI | Easy | `1080i/Includes_Font.xml` (2 to 5 lines) | Low. One file, rarely conflicting. |
| Corner radius 0 | Easy | `1080i/Home.xml` (1 line) | Low. |
| Remove first-run wizard | Medium | `1080i/Home.xml`, `shortcuts/skinvariables-startup.json` | Medium. startup.json is upstream data; re-check on rebase. |
| Texture load reduction | Done (no fork) | `advancedsettings.xml` (imageres/fanartres), shipped in 0.7.0 | Low. Already handled without a fork. |

Recommendation: the high-value, low-maintenance fork is Q2 plus Q3 plus Q4
(serif titles, radius 0, and shipping the ThoughtStream defaults so no runtime
suppression is needed). That is a handful of lines across three files and rebases
cleanly. Q1 (8+ slots) is a separate, larger commitment; only take it if more
than five top-level sections is a firm requirement, and budget for rebase
conflicts. Note the current build already nests extra providers under a More
Providers submenu, which sidesteps the slot cap without a fork.

### Phase 1 note on the per-row item cap (Task 3)

The menu generator supports only a single global per-row item cap
(`widget_limit` in the blueprint), not per-section caps. The plan asked to cap
Discover and For You rows at 15 specifically, which would require a small
generator change (per-section limits), so per the plan it was not built in Phase
1 and is recorded here. Multi-page fetch is already 1 everywhere (about 20 items
per row), so the remaining item-cap win is small; if wanted later, add optional
per-section `limit` support to `_tools/generate_menu.py`.

---

## Task 7: On-device validation checklist (for Jamel)

Run this after service 0.7.0 reaches the stick.

1. Let the stick pull the 0.7.0 service update, or install the zip manually.
2. Restart Kodi twice. The first restart deploys advancedsettings.xml and runs
   the one-time texture cache clear; the second restart runs with the caps
   active. Check `kodipersonal.log` for the line
   `Texture cache clear done for v0.7.0; N item(s) removed`.
3. Browse every section: Discover, For You, Netflix, Max, More Providers and all
   three provider sub-pages. The first pass will be slow while the cache
   rebuilds under the new caps. Then do a second full pass warm.
4. If adb is available: `adb shell dumpsys meminfo org.xbmc.kodi` before and
   after a full warm browse. Record PSS. Compare against a pre-update baseline if
   one exists; otherwise record this as the new baseline.
5. Stability bar: 15 minutes of continuous browsing across all sections with no
   OS kill.
6. Visual bar: posters in widget rows show no objectionable softness at couch
   distance. If they do, raise `imageres` from 405 to 450 (still below the 540
   default) and retest, rather than going back to 540.
7. If the stick still gets killed: drop `imageres` to 360, bump the service patch
   version (so the gate re-runs the cache clear once), and retest.

Note: changing `imageres` only affects art cached after the change, so any
`imageres` change must be paired with another one-time cache clear (a service
version bump triggers it), or a manual clear of Thumbnails and Textures*.db.
