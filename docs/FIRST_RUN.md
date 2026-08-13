# First run: set up the build on a new device

The simple, do-it-once guide for putting this build on another device. Ten
minutes, mostly waiting. You install one thing; it pulls in everything else.

## Before you start

- The device should be running Kodi 21 (Omega). A fresh Kodi is easiest.
- You will sign into your own accounts (Trakt, Premiumize) at the end. Those are
  never stored in the build, so you do this once per device.

## Steps

1. Kodi: Settings (the gear) > System > Add-ons > turn on **Unknown sources**,
   and confirm the warning.

2. Settings > File manager > **Add source** > `<None>`, and type this exactly,
   including the slash at the end:
   ```
   https://aanotherworld.github.io/KODI_PERSONAL/
   ```
   Name it `kodipersonal` and select OK.

3. Settings > Add-ons > **Install from zip file** > `kodipersonal` > `repo.zip`.
   This installs the KODI_PERSONAL Repository.

4. Settings > Add-ons > **Install from repository** > KODI_PERSONAL Repository >
   install **KODI Personal Setup**. Say yes to the additional add-ons it asks
   for. This one install pulls the whole stack automatically (the skin, TMDb
   Helper, Trakt, Red Light, ResolveURL, Magneto, and the rest). Give it a minute
   or two.

5. If the skin did not switch on its own, set it: Settings > Interface > Skin >
   **Arctic Fuse 3**.

6. **Restart Kodi twice.**
   - First restart: the build copies in the theme, background, home menu, and
     settings, and does a one-time art-cache reset for the performance tuning.
   - Second restart: it runs with everything active.
   The first time you browse after this is slow while artwork re-caches. That is
   normal and only happens once.

## Sign in (once per device)

- **Trakt** (powers For You, Up Next, the calendar): open TMDb Helper's settings
  and authorize your Trakt account. This is what makes the personal rows work.
- **Premiumize / debrid** (for playback): open ResolveURL settings > Universal
  Resolvers > Premiumize, and authorize it. Red Light plays through this.

## Check it worked

- The home shows Discover, For You, Netflix, Max, and More Providers, with the
  warm ThoughtStream look.
- More Providers opens Apple TV+, Disney+, and Prime Video, each with their rows.
- Play something. If it finds sources and plays, the source and debrid side is
  good.

## If something is off

- **No sources found when you press play:** the scrapers may not have
  initialised. The build does this for you on the first start after installing,
  but if it did not take, open Settings > Add-ons > Program add-ons > **Magneto
  Module** once. Opening it prompts its scraper setup. Check
  `kodipersonal.log` for the line `Magneto scraper init done`.

- **Menu or theme looks wrong / did not appear:** restart Kodi once more. The
  build reapplies itself on every start.
- **An add-on seems missing:** Settings > Add-ons > Check for updates, then
  restart. On a truly clean device this fills any gap.
- **Repo would not install in step 3:** re-add the source in File manager (it can
  cache an empty listing), keep the trailing slash, then retry.
- **Details:** the build logs what it did to
  `addon_data/service.kodipersonal.setup/kodipersonal.log` (on Android, under
  `Android/data/org.xbmc.kodi/files/.kodi/userdata/`).

## Keeping devices in sync

You do not repeat this. After first run, every device updates itself from the one
repo on Kodi's normal schedule, and the build reapplies the theme and menu on
each start. To change the build for all devices, you edit and push once from the
repo; the devices follow.
