# KODI_PERSONAL: complete build specification

Purpose of this document: capture the full, final functionality of the working
build so it can serve as the starting point for a completely custom
architecture. It records the intent (what the experience must do) and the
concrete reference implementation (exact values, add-ons, and queries), so a
rebuild can either reproduce it faithfully or swap the underlying tech while
keeping the behaviour.

Reference implementation at time of writing: setup service
`service.kodipersonal.setup` 0.6.7, repository `repository.aanotherworld` 1.2.0,
`resource.font.thoughtstream` 0.1.0, on Arctic Fuse 3 + TMDb Helper + Kodi 21
Omega. No em dashes are used in this repo's docs by convention.

---

## 1. Vision and guiding principles

A clean, lightweight, self-updating personal streaming front end that replaces a
bloated setup. It should feel intentional rather than default: a few curated
rows per service, a For You section driven by what you actually watch, and
nothing you do not use. Every add-on, row, and setting earns its place.

Principles that should carry into any custom build:

1. **Restraint.** If a feature is not used, it does not ship.
2. **Self-updating from one source.** All devices track one repo; you never
   hand-configure a box again.
3. **Not a frozen "magic build".** Customisations are reapplied by a small
   service on each start, not stamped over a device once. This avoids owning a
   skin fork and avoids wiping device state.
4. **Per-device identity.** Accounts (Trakt, debrid) are authenticated on each
   device and never stored in the repo.
5. **Public-safe repo.** Nothing secret is committed, so the repo can be public
   (required, because Kodi installs over raw URLs that cannot authenticate).

---

## 2. Target hardware and the constraint that follows

- Primary device: an ONN Google TV streamer, roughly 2 to 3 GB RAM. The stick
  variant is the weakest and is the binding constraint.
- Multiple home devices, all kept in sync from one repo.
- The build must survive upstream skin updates without reapplying customisations
  by hand.

Hard-won reality: a poster-rich home (a hero banner plus multiple artwork-heavy
widget rows) is inherently memory-heavy, because the cost is the artwork, not
the skin's code. On a 2 GB stick this can exceed Android's per-app memory limit
and the OS kills the app (a "crash" with no Python error in the log). The skin
choice is a minor lever next to "rich home on weak hardware." Design the UX with
a lite mode and a rich mode, and expect the richest layout to want a 3 to 4 GB
box.

---

## 3. Architecture

Two pieces, deliberately minimal:

1. **A repository add-on** that also aggregates the upstream repos the build
   depends on, so a clean device installs the whole stack in one pass from one
   source.
2. **A self-healing setup service add-on** that carries the customisations as its
   payload and reapplies them on every start. When the skin updates and
   overwrites its own folder, the service re-copies the theme, background, menu,
   and settings so they self-heal.

Why this shape: a magic build ships a frozen snapshot and stamps it over a
device, wiping state and needing a manual rebuild for every change. That was
rejected. The repo-plus-service model keeps the build self-updating, keeps
per-device accounts intact, and avoids maintaining a skin fork.

### What the setup service does on every start (reference implementation)

Runs about 20 seconds after startup, guarded so no step can crash the service,
logging verbosely to its own profile folder (`kodipersonal.log`):

1. **Verify dependencies.** Re-enable any disabled required add-on, best-effort
   install any missing one, notify only on a critical failure.
2. **Apply the colour set.** Copy the ThoughtStream colour file into the skin's
   `colors/` folder if missing or different.
3. **Apply the background.** Copy the background image into the skin, then point
   the skin at it (only when the skin is active).
4. **Apply skin settings.** Set the curated look and behaviour flags (bools and
   strings), and clear the settings marked for reset.
5. **Apply view types.** Deploy the list/poster view map for the widget engine.
6. **Deploy advancedsettings.xml** into the user profile for memory headroom
   (takes effect on the next restart).
7. **Deploy the home menu.** Write the menu node files, set the home section
   names and toggles, clear stale slots from old layouts, then force the menu
   engine to recompile its includes and reload the skin so rows appear without a
   cold restart.
8. **Apply source-and-behaviour settings** (TMDb Helper) once per version (the
   player slot, scrobbling, calendar behaviour, paging caps).

Key non-obvious mechanic: the home menu is compiled by the menu engine into a
generated includes file. Dropping menu JSON alone does not update the live menu;
the engine must be forced to recompile. Any custom architecture using a compiled
menu engine must trigger that rebuild after changing menu data.

---

## 4. The stack (add-ons and plug-ins)

| Add-on | Role | Source repo (aggregated) |
| --- | --- | --- |
| `skin.arctic.fuse.3` | Skin. Widget-driven home, TMDb Helper integrated. | jurialmunkey |
| `plugin.video.themoviedb.helper` (TMDb Helper) | The browsing engine. Builds all rows, holds the player slot. Not a scraper. | jurialmunkey |
| `script.skinvariables` | Drives the AF3 home menu and widgets. | jurialmunkey |
| `script.module.jurialmunkey` | Shared module for the above. | jurialmunkey |
| `script.trakt` | Watch history, progress, calendar, scrobbling. | Kodi official repo |
| `plugin.video.redlight` | The source layer. Plugs into TMDb Helper's player slot. | The Red Repo (redwizard.xyz) |
| `script.module.resolveurl` | Debrid resolving (Premiumize). | Gujal00 (smrzips) |
| `script.module.magneto` | Scraper module used by Red Light. | kodiyashimaru |
| `resource.font.thoughtstream` | Packaged fonts (see Aesthetics). | this repo |
| `service.kodipersonal.setup` | The self-healing setup service. | this repo |

Design rule inherited from the current build: **one browsing engine, one source
path.** TMDb Helper is the only browser; the source layer is Red Light in the
player slot, with debrid via ResolveURL and scraping via Magneto. Do not add a
second browser.

### Dependency install model

The setup service declares the whole stack as **required imports with 0.0.1
(presence-only) version floors**. Required (not optional) so Kodi auto-installs
the stack in one pass; 0.0.1 floors so no version pin can be "unsatisfiable".
Every id resolves through the aggregated repo or Kodi's official repo. A custom
architecture on Kodi should keep this pattern: hard imports, presence-only
floors, all sources reachable from one aggregated repo.

Aggregated sources (the repository add-on carries all of these as `<dir>`
blocks, so one install pulls everything):
- This build's own zips.
- jurialmunkey (base, nexus, omega variants for Kodi 20/21).
- The Red Repo (main, plus 21omega and 22piers variants).
- Gujal00 smrzips (ResolveURL).
- kodiyashimaru (Magneto).
- Kodi official repo (script.trakt, and Red Light's own requests/pil sub-deps).

---

## 5. UX and information architecture

The home is a set of sections (a horizontal or vertical menu). Focusing a
section reveals its stacked widget rows. Five top-level sections fit the skin's
render cap (home plus four custom slots); extra providers nest under a submenu.

### Sections and rows (reference content)

**Discover** (the default home section)
- Trending Series
- New Series (global calendar, new episodes, past 14 days)
- Recent Episodes (global calendar, premieres, past 7 days)
- Trending Movies
- New Movies (global movie calendar, past 14 days)
- Documentaries (movies, genre 99)

**For You** (Trakt-driven, personal)
- Up Next (next episodes of shows in progress)
- Continue Watching (on deck, movies and shows)
- My Calendar (see the dedicated spec below)
- Watchlist (combined movies and shows)
- Recommended Movies
- Recommended Shows

**Netflix** and **Max** (top-level per-service sections)
- New Movies, Latest Series, Trending Movies, Trending Series, Top Rated

**More Providers** (a submenu holding the services that do not fit as top-level
sections). The submenu lists each provider; selecting one reveals its rows.
- Apple TV+, Disney+, Prime Video
- Each provider sub-page: Latest Series, Trending Series, Latest Movies
- Section landing (before picking a provider): New Movies and New Series for each
  of the three providers

### My Calendar behaviour (explicit)

Requirement: show the latest episodes of my shows from the past two weeks,
ordered newest to oldest, with a roughly 24 hour delay after an episode airs so
it only appears once sources have had time to land.

Reference implementation (TMDb Helper Trakt calendar):
`info=trakt_calendar&tmdb_type=tv&startdate=-15&days=14&sort_by=released&sort_how=desc`
- `startdate=-15&days=14` gives a two-week window that ends about one day ago, so
  an episode surfaces roughly 24 hours after airing.
- `sort_by=released&sort_how=desc` orders by air date, newest first.
- Verify on device that the calendar honours the sort; if not, an `airing` sort
  option also exists.

### Playback flow

Browse in TMDb Helper, select an item, TMDb Helper hands off to its player slot,
which is Red Light. Red Light scrapes sources (Magneto and its own indexers) and
resolves playable links through ResolveURL and a debrid service (Premiumize).
Trakt scrobbles progress, which feeds Up Next, Continue Watching, and the
calendar.

---

## 6. Aesthetics: the ThoughtStream design language

A calm, editorial look: warm stone neutrals, warm whites, flat surfaces,
hairline separators rather than shadows. The intent is flat with zero corner
radius; note that the current build inherited a 20px thumb corner radius from the
source it was mined from, so a purist rebuild would set radius to 0.

### Palette

| Token | Hex (RRGGBB) | Role |
| --- | --- | --- |
| warm white | fafaf9 | primary background |
| surface | f5f5f4 | panels and dialogs |
| raised | efedeb | raised panels |
| stone | 78716c | accent |
| warm black | 1c1917 | text, emphasis, highlight |
| secondary | 57534e | metadata text |
| sage | a8a29e | dim labels and dividers |
| border | d6d3d1 | medium border |
| gold | ca8a04 | ratings |

Kodi colours are AARRGGBB (alpha first). Foreground tokens are warm black at
descending alpha (ff, e7, b3, 80, 4d, 1f, 0f); background tokens are warm white
at descending alpha; shadows are kept faint rather than removed so labels stay
legible over poster art on a TV. The reference file maps all 48 skin colour
tokens (main, dialog, panel, overlay, shadow, plus a ratings star colour).

### Typography

- Titles and headings: a serif, Libre Baskerville 700.
- UI and body: a sans, Inter 400 and Inter 600.
- Fonts are packaged as a resource add-on and referenced over `resource://`.

Open item: the fonts are packaged and available, but wiring the skin to actually
render titles in the serif and UI in the sans requires editing the skin's own
font definitions (its `Font.xml` fontset). That was not completed under the
"do not edit the skin" rule, so in the current build the fonts ship but the skin
still uses its own. A custom architecture should treat font-role assignment as a
first-class step, not an afterthought.

### Background

A flat, warm-white vertical gradient still image (top lighter, bottom slightly
warmer grey), 1920x1080. Applied as the static skin background, with the dialog
background set to the lightest option. No per-item fanart or blur background
(both are memory-heavy and are disabled).

### Hero / spotlight (optional)

A featured hero banner on the home is supported and was used in the rich
version (a Trending TV shows showcase). It is currently off because it is the
single largest home-screen memory cost on the 2 GB stick. Treat it as a
per-profile toggle: on for capable hardware, off for the lite profile.

### View types

List and poster views are mapped per content type. Poster walls are the
heaviest to render; a lite profile can switch the busy content types to list
views to cut simultaneous image loads.

---

## 7. Content query reference (skin-agnostic)

This is the functional heart and is independent of the skin. All rows are TMDb
Helper plugin paths. A custom front end that keeps TMDb Helper can reuse these
verbatim; one that replaces TMDb Helper must reproduce the same queries against
TMDb and Trakt.

Base: `plugin://plugin.video.themoviedb.helper/?`

Widget suffix appended to any row shown as a home widget:
`&reload=$INFO[Window(Home).Property(TMDbHelper.Widgets.Reload)]&widget=true`

**Per-provider discover** (streaming service rows):
`info=discover&tmdb_type={movie|tv}&with_watch_providers={id}&watch_region=US&with_watch_monetization_types=flatrate&sort_by={sort}`

Sort keys by row meaning:
- New / Latest movies: `primary_release_date.desc`
- Latest series: `first_air_date.desc`
- Trending (movies or series): `popularity.desc`
- Top Rated: `vote_average.desc`

**Trakt personal lists:**
- Up Next: `info=trakt_nextepisodes&tmdb_type=tv`
- Continue Watching: `info=trakt_ondeck&tmdb_type=both`
- Watchlist: `info=trakt_watchlist&tmdb_type=both&list_name=Combined+Watchlist&tmdb_id=None`
- Recommended: `info=trakt_recommendations&tmdb_type={movie|tv}`
- My Calendar: `info=trakt_calendar&tmdb_type=tv&startdate=-15&days=14&sort_by=released&sort_how=desc`

**Global discovery (Discover section):**
- Trending: `info=trending_week&tmdb_type={movie|tv}`
- New Series: `info=trakt_calendar&endpoint=new&user=false&tmdb_type=tv&startdate=-14&days=14`
- Recent Episodes: `info=trakt_calendar&endpoint=premieres&user=false&tmdb_type=tv&startdate=-7&days=7`
- New Movies: `info=trakt_moviecalendar&user=false&tmdb_type=movie&startdate=-14&days=14`
- Documentaries: `info=discover&tmdb_type=movie&with_genres=99&with_id=True&plugin_category=Documentary`

**Watch-provider IDs (US, TMDb):** Netflix 8, Max 1899, Apple TV+ 350,
Disney+ 337, Prime Video 9. Verify on device; provider IDs change over time
(Max in particular was formerly HBO Max 384).

The menu is generated from a single blueprint (a `lists.json` describing
sections, providers, and row templates). Editing intent lives in one file; the
menu files are generated. Keep this pattern in a custom build: one declarative
menu source of truth, everything else generated.

---

## 8. Behaviour and settings reference

### Source-and-behaviour settings (TMDb Helper)

- Player slot: Red Light auto player (`redlight.auto.json`), movies and episodes.
- Players list: bundled and combined players enabled, players list from the
  oldmanjax jsonplayers source.
- Trakt: scrobbling on, watched indicators on, in-progress indicators on, next
  episode sort by recently watched, cache own lists.
- Calendar: flattened; next-episodes not driven by the calendar; seasons show
  up-next, anticipated, and specials.
- Filtering: hide unaired movies, keep unaired episodes visible, MPAA prefix
  "Rated", ignore region release filter, widgets paginate.
- Paging: multi-page fetch set to 1 (about 20 items per row) to limit memory.
- Notifications: startup and sync notifications off, connection notifications on.

### Look and behaviour flags (skin settings)

Applied as booleans and strings on every start. Highlights:
- Disable the bottom tray, the home submenu, the home header and date.
- Disable extended widget properties, current-window images, blur, crop, extra
  data (all memory or CPU savers).
- Keep the local widget container (one reused container, lazy per focus).
- Disable director, writer, creator, crew, comments, and collection widgets on
  the info screen.
- Set `defaultconfig.initdone` and `home.firstrun` true so a fresh device does
  not run the skin's first-run wizard and clobber the layout.
- Ratings: custom rating sources Trakt then Metacritic; info actions Trailer,
  Trakt, Wikipedia.
- Corner radius 20 (see aesthetics note), settings level 3, back navigates to
  parent.
- Reset (clear) the home spotlight settings for the lite profile.

### Memory tuning (advancedsettings.xml)

Deployed to the user profile, applied on restart: modest streaming buffer,
dirty-region redraws to ease a weak GPU.

---

## 9. Deployment and cross-device model

- Install once per device: enable unknown sources, add the repo source URL,
  install the repository from zip, install the setup service. Required imports
  pull the whole stack in one pass. The one unavoidable manual step is
  installing the first zip.
- A clean install URL is provided so the first zip is a single direct link.
- Updates flow automatically: devices update add-ons from the repo on Kodi's
  schedule; the setup service reapplies theme, settings, and menu on each start,
  including migrating away from old menu slots.
- Maintainer flow: edit the menu blueprint or assets, run the two generators
  (one builds the menu files, one builds the repo index and zips), commit, push.
  Devices follow.

### Shared vs per-device

| Shared (from the repo) | Per-device (never in the repo) |
| --- | --- |
| Theme, fonts, background | Trakt authentication |
| Home menu and widgets | Debrid (Premiumize) authentication |
| Skin and behaviour settings | Skin selection if not auto |
| The add-on stack and versions | Any device-local tweaks |

---

## 10. Performance levers (rich vs lite)

Order of impact for reducing home-screen memory on weak hardware:

1. Remove the hero/spotlight (largest single always-on cost).
2. Fewer widget rows per section, and cap items per row.
3. Lighter views (list instead of poster wall) for busy content.
4. Disable blur, crop, extended data, and current-window images.
5. Lower the paging multiplier.
6. advancedsettings.xml cache caps.

The rich profile (hero on, full rows, no item cap) is what a capable box should
run. The lite profile (hero off, trimmed rows, item cap, lighter views) is what
keeps a 2 GB stick stable. Build both as toggles rather than as separate builds.

---

## 11. Skin options if rebuilding

- **Arctic Fuse 3 (current).** Rich, TMDb Helper native, widget home, hero,
  submenus via SkinVariables. Heavy on a 2 GB stick even when trimmed.
- **Copacetic.** Peer-class rich skin, also TMDb Helper native, has a
  Showcase hero and multi-row home, uses `script.skinshortcuts` (a different
  menu engine) and its own helper and colour and settings formats. Only modestly
  lighter than AF3, so not a guaranteed fix for the stick, and it is a large
  re-port because almost none of the AF3-specific plumbing carries over.
- **Estuary.** Genuinely light and rock solid on the stick, but a simpler skin:
  no hero, one widget row per menu item (no stacked multi-row provider pages),
  and only basic TMDb Helper widget support. Cannot reproduce the hero plus
  multi-row experience without forking it, which reintroduces the maintenance
  burden and the weight.

What is portable across skins vs skin-specific:
- Portable: the vision, the section and row structure, all the TMDb Helper and
  Trakt queries, the provider IDs, the palette values, the font choices, the
  behaviour settings intent, the deploy and sync model, the dependency stack.
- Skin-specific and needs re-authoring per skin: the menu engine and its data
  format (SkinVariables vs skinshortcuts vs Estuary's home menu), the colour
  file format and token names, the skin setting ids, the hero and view
  configuration, and the self-healing service's apply steps that write into that
  skin.

---

## 12. Security

- No secrets in the repo, ever. Trakt tokens, debrid keys, and any API keys are
  authenticated on each device. The repo stays public and safe because nothing
  secret is committed.
- A previously shared settings file once contained live Trakt, MDbList, Gemini,
  and OMDb credentials. Those were scrubbed and never propagated; treat all four
  as needing rotation if not already done. Keep the build holding no secrets.

---

## 13. Open items to resolve in a custom build

1. Font role wiring: make titles serif and UI sans at the skin level (packaged
   but not yet applied).
2. Corner radius: reconcile the flat/zero-radius intent with the inherited 20px
   setting.
3. Home-browse stability on the 2 GB stick with the rich profile; realistically
   a 3 to 4 GB box removes the constraint.
4. Verify on device: the My Calendar newest-first ordering and 24 hour delay,
   the More Providers submenu sub-pages, and the current US watch-provider IDs.
5. Decide hero on/off and rich/lite defaults per device class.
