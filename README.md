# KODI_PERSONAL

A lightweight, self-updating Kodi build for low-powered streamers (the target is
an ONN Google TV box, 2 to 3 GB RAM). It is a thin personal layer on top of
Arctic Fuse 3 + TMDb Helper + Trakt, installed and kept in sync from this one
repo. Nothing secret is stored here; accounts are authenticated on each device.

For the design and reasoning see the project notes; for the theme see
[docs/THEME_THOUGHTSTREAM.md](docs/THEME_THOUGHTSTREAM.md).

## Deploy to a new device

You only do this once per device. The single source is the repository addon; it
pulls in the whole stack, and the setup service applies the theme, menu, and
settings on every start.

1. Kodi: Settings > System > Add-ons > turn on **Unknown sources** and confirm.
2. Settings > File manager > **Add source** > `<None>` and enter, with the
   trailing slash:
   ```
   https://aanotherworld.github.io/KODI_PERSONAL/
   ```
   Name it `kodipersonal` and select OK.
3. Settings > Add-ons > **Install from zip file** > `kodipersonal` > `repo.zip`.
   This installs **KODI_PERSONAL Repository**.
4. Settings > Add-ons > **Install from repository** > KODI_PERSONAL Repository >
   Program add-ons (or Services) > install **KODI Personal Setup**.
   Installing it automatically pulls the rest of the stack from the aggregated
   repo: Arctic Fuse 3, TMDb Helper, SkinVariables, the jurialmunkey module,
   Trakt, Red Light, and ResolveURL. The setup service also re-checks the stack
   on every start and heals anything the installer missed.
5. Set the skin to **Arctic Fuse 3** if it did not switch automatically
   (Settings > Interface > Skin), then restart Kodi once. On that first start the
   setup service applies the ThoughtStream colours and background, the home menu
   (Discover, For You, Netflix, Max, More Providers), the skin settings, and the
   view types.

That is the whole bootstrap. The only unavoidable manual step is installing the
first zip in step 3; everything after it is automatic.

## Per-device sign-in (never stored in the repo)

Do these once on each device. They are personal credentials and are kept out of
the build on purpose.

- **Trakt**: authorize it in TMDb Helper (Settings > add-on settings for TMDb
  Helper > Trakt account), and in the Trakt service add-on if it prompts. This
  powers Up Next, Continue Watching, the calendar, the watchlist, and
  recommendations in For You.
- **Debrid (Premiumize)**: authorize it in ResolveURL settings (Universal
  Resolvers > Premiumize). Red Light is the source layer and plays through it.

## Updating devices

Nothing to do by hand. Devices update add-ons from the repo on Kodi's normal
schedule; to pull immediately use Settings > Add-ons > **Check for updates**.
When the setup service updates, it reapplies the theme and rebuilds the menu on
the next start, including migrating away from any old menu slots.

## Changing the build (maintainer workflow)

Edit once, push once, and every device follows.

1. Edit the blueprint or assets under `src/` (the menu lives in
   `src/service.kodipersonal.setup/resources/config/lists.json`).
2. Bump the `version` in that add-on's `addon.xml`.
3. Run the two generators (Python 3):
   ```
   python3 _tools/generate_menu.py
   python3 _tools/generate_repo.py
   ```
4. Commit and push to `main`. Devices pick it up on their next update check.

## Troubleshooting

- **Repo will not install in step 3**: use the folder URL with the trailing
  slash, and if Kodi shows the source empty, remove and re-add it (it caches the
  old listing), or restart Kodi.
- **Menu or theme did not change after an update**: make sure the add-on actually
  updated, then restart Kodi once. The setup service forces a SkinVariables
  rebuild only when something changed.
- **A required add-on is missing**: the setup service retries the dependency
  check on every start; you can also install it by hand from the repository.
- **Logs**: the setup service writes to its own profile folder,
  `addon_data/service.kodipersonal.setup/kodipersonal.log`. On Android that is
  under `Android/data/org.xbmc.kodi/files/.kodi/userdata/`. Look there to see
  what it applied, or for a dependency or copy warning.
