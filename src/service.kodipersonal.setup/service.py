# -*- coding: utf-8 -*-
# KODI Personal Setup service
# Applies the personal build defaults (TMDb Helper behavior + source-player slot)
# on first run and after each update, so every home device stays consistent.
# Copies the ThoughtStream colour set and background and deploys the home menu
# files into Arctic Fuse 3 on every start so the theme and menu self-heal after
# an AF3 update overwrites those files. Verifies required add-ons/repos on
# startup and silently heals what it can. Also runs a scheduled texture-cache
# prune (data efficiency) that drops textures unused for a while, on a timer so
# it does not run every start. Sets Trakt scrobble ownership (Red Light owns
# it, script.trakt scrobbling off). Hotfixes TMDb Helper's Trakt episode play
# params so calendar episodes play, and asserts Kodi's video cache settings.
# Logging is verbose by design.

import os
import json
import time
import shutil
import zipfile

import xbmc
import xbmcaddon
import xbmcgui
import xbmcvfs

ADDON = xbmcaddon.Addon()
ADDON_ID = ADDON.getAddonInfo('id')
ADDON_VERSION = ADDON.getAddonInfo('version')
ADDON_PATH = xbmcvfs.translatePath(ADDON.getAddonInfo('path'))
PROFILE = xbmcvfs.translatePath(ADDON.getAddonInfo('profile'))

CONFIG_DIR = os.path.join(ADDON_PATH, 'resources', 'config')
COLORS_DIR = os.path.join(ADDON_PATH, 'resources', 'colors')
BACKGROUNDS_DIR = os.path.join(ADDON_PATH, 'resources', 'backgrounds')
MENU_DIR = os.path.join(ADDON_PATH, 'resources', 'menu')
COLOUR_FILE = 'ThoughtStream.xml'
BACKGROUND_FILE = 'thoughtstream_bg.png'
AF3_ID = 'skin.arctic.fuse.3'
SKINVARS_NODES = 'special://profile/addon_data/script.skinvariables/nodes/skin.arctic.fuse.3/'
SKIN_SETTINGS_FILE = 'skin_settings.json'
VIEWTYPES_FILE = 'viewtypes.json'
VIEWTYPES_DEST = 'special://profile/addon_data/script.skinvariables/skin.arctic.fuse.3-viewtypes.json'
ADVANCEDSETTINGS_FILE = 'advancedsettings.xml'
ADVANCEDSETTINGS_DEST = 'special://profile/advancedsettings.xml'
LOG_TAG = '[KODIPERSONAL]'
LOGFILE = os.path.join(PROFILE, 'kodipersonal.log')

# Service version. addon.xml is authoritative (ADDON_VERSION above); this mirrors
# it for logging and is bumped alongside it.
SERVICE_VERSION = '0.8.7'

# Scheduled texture-cache prune (data efficiency). A texture unused for longer
# than the stale window is removed, and the prune itself runs at most once per
# interval, gated by the stored timestamp texturecache_pruned (epoch seconds).
# Arithmetic (seconds):
#   interval 7 days  = 7 * 24 * 60 * 60  = 604800
#   stale    30 days = 30 * 24 * 60 * 60 = 2592000
PRUNE_INTERVAL_SECONDS = 604800
PRUNE_STALE_SECONDS = 2592000

# Magneto scraper initialisation. Magneto installs as a module that registers
# under Program add-ons, so on a fresh device it stays uninitialised until its
# plugin endpoint is opened, which is what normally prompts the scraper setup.
# We fire that same action ourselves so a new device has working scrapers with
# no manual step. The builtin is Magneto's own "Enable Magneto Default
# Providers" action, taken from its settings schema.
MAGNETO_ID = 'script.module.magneto'
MAGNETO_DEFAULTS_BUILTIN = (
    'RunPlugin(plugin://script.module.magneto/?action=Defaults&setting=true)')
# Providers to assert on top of Magneto's stock defaults. Its defaults already
# cover piratebay, torrentio and aiostreams; zilean ships off (schema
# default="false") but is enabled on the reference device, so we turn it on
# after the defaults action runs.
MAGNETO_EXTRA_PROVIDERS = ('provider.zilean',)
# Seconds to let the asynchronous RunPlugin defaults action land before we
# assert the extra providers, so it cannot overwrite them.
MAGNETO_SETTLE_SECONDS = 5

# Addon package cache hygiene. Kodi keeps downloaded addon zips here and reuses a
# cached copy without a checksum when the repo gives none, so a corrupt cached zip
# would fail every install attempt. We purge corrupt zips once per version. Note
# this was NOT the cause of the InfoTagger 0.0.9 failure (see
# enforce_addon_update_policy for the real one); it stays as general hygiene.
PACKAGES_DIR = 'special://home/addons/packages/'
INFOTAGGER_ID = 'script.module.infotagger'

# Trakt sync repair. TMDb Helper's next-episodes sync persists an empty or
# truncated result as a successful sync (half day stamp), which is how Up Next
# ends up blank. Its own 'Clear sync data > Progress' action rebuilds watched,
# playback and next-episode data; we fire it once per version, after the
# max_threads cap has been applied so the rebuild itself does not trip the
# rate limit. The script router does not coerce booleans, so the dialog cannot
# be switched off from a builtin; it is a background progress bar, not modal.
TMDBHELPER_ID = 'plugin.video.themoviedb.helper'
# Both keys are passed on purpose. TMDb Helper 6.17 renamed the script method's
# required argument from invalidate_trakt_sync to invalidate_sync while keeping
# the legacy route key, and its router forwards every parameter as kwargs. So the
# legacy key alone raises TypeError on 6.17 (argument missing), and the new key
# alone is not a route on 6.16. With both present each version finds its
# argument and the extra key is harmlessly absorbed by **kwargs. 0.8.1 and 0.8.2
# shipped the legacy key only, so their repair never ran on 6.17.
TRAKTSYNC_REPAIR_BUILTIN = (
    'RunScript(plugin.video.themoviedb.helper,'
    'invalidate_sync=watchedprogress,invalidate_trakt_sync=watchedprogress)')
# Seconds to let TMDb Helper's own service settle after boot before asking it to
# rebuild sync data.
TRAKTSYNC_REPAIR_SETTLE_SECONDS = 15

# TMDb Helper's own window properties, as its get_property writes them (it
# prefixes every name with 'TMDbHelper.').
TRAKT_AUTH_PROPERTY = 'TMDbHelper.TraktIsAuth'
TRAKT_ATTEMPTS_PROPERTY = 'TMDbHelper.TraktRefreshAttempts'

# One-time maintenance revisions. Up to 0.8.5 these jobs were gated on the addon
# version, so EVERY service update re-ran them: a full texture cache wipe (all
# art re-downloaded, slow first browse, extra data), Magneto's defaults action
# (which can overwrite provider choices), and a full Trakt sync rebuild (a burst
# of Trakt calls and a blank Up Next while it rebuilds). Each job now runs once
# per revision. Bump a revision only when that job genuinely needs to run again.
# A device that already ran a job under the old per-version gate (any non-empty
# marker) is treated as done and its marker is rewritten to the revision.
TEXTURE_CLEAR_REVISION = 'caps-405-720'
MAGNETO_INIT_REVISION = 'magneto-1'
TRAKTSYNC_REPAIR_REVISION = 'traktsync-1'

# Kodi cache (video buffer) settings. Kodi 21 Omega moved these from
# advancedsettings.xml <cache> into the GUI and now ignores the XML tags, so the
# old <cache> block never applied. They are asserted here through JSON-RPC,
# read first and written only when different, like the update policy.
# Values come from Kodi's own option lists (ServicesSettings.cpp):
#   filecache.buffermode 4  = buffer all network filesystems, which includes
#                             internet streams (Kodi default)
#   filecache.memorysize 48 = 48 MB forward buffer (Kodi default 20). A 4K
#                             debrid stream around 60 Mbit/s is about 7.5 MB/s
#                             (60 / 8 = 7.5), so 20 MB holds under 3 seconds and
#                             48 MB about 6.4 seconds (48 / 7.5 = 6.4). Modest on
#                             a 2 GB device; drop to 32 if the GUI gets tight.
#   filecache.readfactor 0  = Adaptive: fills fast, then settles at 1.5x.
KODI_CACHE_SETTINGS = (
    ('filecache.buffermode', 4, 'Cache buffer mode', 'all network filesystems'),
    ('filecache.memorysize', 48, 'Cache memory size', '48 MB'),
    ('filecache.readfactor', 0, 'Cache read factor', 'adaptive'),
)

# Weather. AF3 already prints 'time • temperature' in its header whenever Kodi has
# a weather provider (Furniture_Header_Right, unless Header.DisableWeather is
# set), so all the build needs is a provider. Open-Meteo is in Kodi's official
# repository, needs no API key, and on first run locates the device by IP and
# fills its first location itself (its service.py geoip step), so nothing
# location specific is stored here. It only refreshes while it is Kodi's
# selected weather add-on, which is what weather.addon asserts.
WEATHER_ADDON_ID = 'weather.openmeteo'
WEATHER_KODI_SETTINGS = (
    ('weather.addon', WEATHER_ADDON_ID, 'Weather provider', 'Open-Meteo'),
    ('weather.currentlocation', 1, 'Weather location', 'first location'),
)
# One-time Open-Meteo preferences for a low-RAM stick: no radar map tiles (it
# downloads and stitches map images on every refresh) and no severe-weather
# popups over playback. Applied once per WEATHER_PREFS_REVISION so a later
# change made by hand in its settings sticks.
WEATHER_PREFS = (('loc1maps', 'false'), ('loc1alert', 'false'))
WEATHER_PREFS_REVISION = 'weather-1'

# Seconds to wait after a forced SkinVariables rebuild (which reloads the skin)
# before re-asserting skin settings. AF3's startup actions re-set some TMDb
# Helper bools on load (for example EnableCurrentWindowImages back to true), so
# without a second pass a menu change would silently undo those settings until
# the next boot.
SKIN_RELOAD_SETTLE_SECONDS = 10

# TMDb Helper episode play params hotfix. TMDb Helper's newer Trakt item mapper
# (resources/tmdbhelper/lib/items/directories/mapper_standard.py, used by the
# Trakt calendar and other standard Trakt lists) builds episode items whose play
# params carry only info, tmdb_type and tmdb_id. Season and episode live in the
# infolabels but never reach the params. Clicking such an episode therefore calls
# the player with season=None, TMDb Helper falls back to its movie dictionary,
# which has no season/episode keys and returns its '_' placeholder, and Red Light
# crashes on int('_') in sources.py playback_prep. That is the For You My Calendar
# play error. The legacy Trakt path (api/trakt/items.py EPISODE_PARAMS) and the
# stacked calendar path (specified_episodes) both include season and episode,
# which is why Up Next and multi-episode stacks still play.
# The patch adds a get_params override to EpisodeItemMapper that appends season
# and episode. It is applied on every start because a TMDb Helper update replaces
# the file, it is idempotent (marker line), and it stands down by itself if
# upstream adds its own get_params to EpisodeItemMapper or the anchor text changes.
TMDBH_MAPPER_RELPATH = os.path.join(
    'resources', 'tmdbhelper', 'lib', 'items', 'directories', 'mapper_standard.py')
TMDBH_PATCH_MARKER = '# KODIPERSONAL-PATCH episode-params'
TMDBH_PATCH_ANCHOR = (
    "        infolabels['episode'] = self.meta.get('number')\n"
    "        return infolabels\n")
TMDBH_PATCH_BLOCK = (
    "\n"
    "    def get_params(self):  " + TMDBH_PATCH_MARKER + "\n"
    "        params = super().get_params()\n"
    "        params['season'] = self.meta.get('season')\n"
    "        params['episode'] = self.meta.get('number')\n"
    "        return params\n")


def log(msg, level=xbmc.LOGINFO):
    line = '{} {}'.format(LOG_TAG, msg)
    xbmc.log(line, level)
    try:
        if not xbmcvfs.exists(PROFILE):
            xbmcvfs.mkdirs(PROFILE)
        stamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(LOGFILE, 'a', encoding='utf-8') as fh:
            fh.write('{} {}\n'.format(stamp, msg))
    except Exception as exc:  # never let logging crash the service
        xbmc.log('{} logfile write failed: {}'.format(LOG_TAG, exc), xbmc.LOGWARNING)


# kodipersonal.log is appended on every boot and had no size cap. Rotate it once
# per start when it passes 512 KB (512 * 1024 = 524288 bytes), keeping one
# previous file, so it cannot grow without bound on a low-storage stick.
LOGFILE_MAX_BYTES = 524288


def rotate_logfile():
    try:
        if os.path.isfile(LOGFILE) and os.path.getsize(LOGFILE) > LOGFILE_MAX_BYTES:
            os.replace(LOGFILE, LOGFILE + '.old')
            log('Rotated kodipersonal.log (previous run kept as kodipersonal.log.old).')
    except Exception as exc:
        xbmc.log('{} log rotation failed: {}'.format(LOG_TAG, exc), xbmc.LOGWARNING)


def notify(message):
    if ADDON.getSettingBool('show_notifications'):
        xbmcgui.Dialog().notification('KODI Personal', message,
                                      xbmcgui.NOTIFICATION_INFO, 4000)


def load_config(name):
    path = os.path.join(CONFIG_DIR, name)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        log('Loaded config {}'.format(name))
        return data
    except Exception as exc:
        log('Failed to load config {}: {}'.format(name, exc), xbmc.LOGERROR)
        return None


def verify_dependencies():
    # Auto-heal missing/disabled required add-ons and repos. Self-contained and
    # guarded so a failure here never crashes the service.
    try:
        from resources.lib.dependencies import verify_dependencies as _verify
        _verify(auto_install=True, notify_on_failure=True)
    except Exception as exc:
        log('Dependency check failed to run: {}'.format(exc), xbmc.LOGWARNING)


def _is_secret_key(key):
    # Setting ids that hold credentials (for example TMDb Helper mdblist_apikey).
    low = key.lower()
    return any(part in low for part in ('apikey', 'api_key', 'token', 'secret', 'password'))


def _apply_addon_settings_file(name, label):
    # Apply a settings map from resources/config/<name> to the addon it names
    # (target_addon). Shared by the TMDb Helper defaults and the scrobbler
    # ownership settings so both log the same way. Returns True only when every
    # key applied, so the version gate retries next start after any failure.
    cfg = load_config(name)
    if not cfg:
        return False
    target = cfg.get('target_addon')
    if not target:
        log('{} has no target_addon; skipping.'.format(name), xbmc.LOGERROR)
        return False
    try:
        addon = xbmcaddon.Addon(target)
    except Exception:
        log('{} is not installed yet; skipping settings apply this pass.'.format(target),
            xbmc.LOGWARNING)
        return False

    applied, failed = 0, 0
    for key, value in cfg.get('settings', {}).items():
        # Never write a credential value into kodi.log or kodipersonal.log.
        shown = '(hidden)' if _is_secret_key(key) else value
        try:
            addon.setSetting(key, str(value))
            applied += 1
            if _is_secret_key(key):
                log('{} {} applied (value hidden).'.format(label, key))
        except Exception as exc:
            failed += 1
            log('Could not set {}={} : {}'.format(key, shown, exc), xbmc.LOGWARNING)
    log('{} settings applied: {} ok, {} failed.'.format(label, applied, failed))
    return failed == 0


def apply_tmdbhelper_settings():
    return _apply_addon_settings_file('tmdbhelper_settings.json', 'TMDb Helper')


def apply_scrobbler_settings():
    # Trakt scrobble ownership. With the Red Light auto player TMDb Helper never
    # learns what is playing (its resolver takes the executebuiltin branch that
    # skips the playerstring), and Red Light steps aside whenever script.trakt is
    # authorised with scrobbling on, expecting script.trakt to do it. That
    # hand-off is what left nothing marking episodes watched. Switching
    # script.trakt scrobbling off makes Red Light the single owner: it scrobbles
    # start/stop with exact TMDb ids and writes watched history at 90 percent.
    return _apply_addon_settings_file('scrobbler_settings.json', 'script.trakt scrobble')


def _read_bytes(path):
    try:
        with open(path, 'rb') as fh:
            return fh.read()
    except Exception:
        return None


def resolve_af3_path():
    # Returns the on-disk path to the installed AF3 skin, or None if not present.
    try:
        af3 = xbmcaddon.Addon(AF3_ID)
    except Exception:
        return None
    return xbmcvfs.translatePath(af3.getAddonInfo('path'))


def _copy_if_different(src_data, dest_dir, dest, label):
    # Copy bytes to dest only if missing or different. Returns True when the file
    # ends up in place (copied or already current), False when the copy failed.
    if _read_bytes(dest) == src_data:
        log('{} already current at destination; nothing to copy.'.format(label))
        return True
    try:
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
        with open(dest, 'wb') as fh:
            fh.write(src_data)
        log('{} copied into AF3.'.format(label))
        return True
    except Exception as exc:
        log('Could not copy {} to {}: {}. The skin folder may be read only; '
            'place the file there manually.'.format(label, dest, exc), xbmc.LOGWARNING)
        return False


def _skin_string(sid):
    return xbmc.getInfoLabel('Skin.String({})'.format(sid)) or ''


def _skin_bool(sid):
    return bool(xbmc.getCondVisibility('Skin.HasSetting({})'.format(sid)))


def _set_skin_string(sid, value):
    # Write a skin string only when it differs. Every Skin.SetString is queued on
    # the GUI thread and re-evaluates skin conditions, so blindly re-setting about
    # 40 strings on every boot is avoidable startup work. Returns True if written.
    value = '' if value is None else str(value)
    if _skin_string(sid) == value:
        return False
    # Quote the value so paths with brackets, parentheses or commas pass through
    # the builtin parser intact.
    xbmc.executebuiltin('Skin.SetString({},"{}")'.format(sid, value))
    return True


def _set_skin_bool(sid, enabled):
    # Set or clear a skin bool only when it differs. Returns True if written.
    if _skin_bool(sid) == bool(enabled):
        return False
    if enabled:
        xbmc.executebuiltin('Skin.SetBool({})'.format(sid))
    else:
        xbmc.executebuiltin('Skin.Reset({})'.format(sid))
    return True


def _reset_skin_setting(sid):
    # Skin.Reset only when the setting holds something (string value or bool on).
    # Returns True if written.
    if not _skin_string(sid) and not _skin_bool(sid):
        return False
    xbmc.executebuiltin('Skin.Reset({})'.format(sid))
    return True


def apply_colour_theme():
    # Runs on EVERY start, not gated by the version check. AF3 owns its colors
    # folder, and an AF3 update can wipe our overlay, so we re-copy it whenever
    # it is missing or differs from our bundled copy. This self-heals the theme.
    src = os.path.join(COLORS_DIR, COLOUR_FILE)
    src_data = _read_bytes(src)
    if src_data is None:
        log('Colour set source missing at {}; skipping copy.'.format(src), xbmc.LOGERROR)
        return

    af3_path = resolve_af3_path()
    if not af3_path:
        log('{} is not installed; skipping colour set copy this pass.'.format(AF3_ID))
        return

    dest_dir = os.path.join(af3_path, 'colors')
    dest = os.path.join(dest_dir, COLOUR_FILE)
    log('Colour set source: {}'.format(src))
    log('Colour set destination: {}'.format(dest))
    _copy_if_different(src_data, dest_dir, dest, 'Colour set')


def apply_background():
    # Runs on EVERY start, same self-healing pattern as the colour set. After the
    # file is in place we point AF3 at it with a skin string, but only when AF3
    # is the active skin so we never change another skin's settings.
    src = os.path.join(BACKGROUNDS_DIR, BACKGROUND_FILE)
    src_data = _read_bytes(src)
    if src_data is None:
        log('Background source missing at {}; skipping copy.'.format(src), xbmc.LOGERROR)
        return

    af3_path = resolve_af3_path()
    if not af3_path:
        log('{} is not installed; skipping background copy this pass.'.format(AF3_ID))
        return

    dest_dir = os.path.join(af3_path, 'extras', 'backgrounds')
    dest = os.path.join(dest_dir, BACKGROUND_FILE)
    log('Background source: {}'.format(src))
    log('Background destination: {}'.format(dest))
    in_place = _copy_if_different(src_data, dest_dir, dest, 'Background image')
    if not in_place:
        return

    if xbmc.getSkinDir() == AF3_ID:
        image = 'special://skin/extras/backgrounds/{}'.format(BACKGROUND_FILE)
        if _set_skin_string('Background.Image', image):
            log('Set Background.Image to the ThoughtStream background.')
        else:
            log('Background.Image already the ThoughtStream background.')
        if _set_skin_string('Background.DialogImage', 'Chalk'):
            log('Set Background.DialogImage to Chalk.')
    else:
        log('Active skin is {}, not {}; left background skin strings unchanged.'.format(
            xbmc.getSkinDir(), AF3_ID))


def _read_slots_manifest():
    # Supports the new manifest {active_slots:[...], known_slots:[...]} and the
    # legacy flat list [...] for backward compatibility.
    path = os.path.join(MENU_DIR, 'slots.json')
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception as exc:
        log('Could not read slots.json: {}'.format(exc), xbmc.LOGWARNING)
        return [], []
    if isinstance(data, dict):
        return data.get('active_slots', []), data.get('known_slots', [])
    return data, []  # legacy flat list


def _is_managed_node(name):
    # Files this build owns and may retire on a device: the numbered home slots
    # (11xx widgets/submenu) and the old More Providers sub-page nodes from an
    # earlier version. Home, power and search nodes are left untouched so we
    # never clobber menus we do not manage.
    if not (name.startswith('skinvariables-shortcut-') and name.endswith('.json')):
        return False
    if 'moreprov-' in name:
        return True
    core = name[len('skinvariables-shortcut-'):-len('.json')]
    return core[:2] == '11' and core[:4].isdigit()


def deploy_menu():
    # Runs on EVERY start, not version-gated. Deploys all skinvariables menu
    # files into the AF3 node folder, sets the HomeSwitcher slot strings, clears
    # stale slots from previous versions, and asks SkinVariables to rebuild so
    # rows render without a cold restart. All ops are guarded.
    if not os.path.isdir(MENU_DIR):
        log('Menu source folder missing at {}; skipping menu deploy.'.format(MENU_DIR),
            xbmc.LOGERROR)
        return

    target_dir = xbmcvfs.translatePath(SKINVARS_NODES)
    try:
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            log('Created skinvariables node folder {}'.format(target_dir))
    except Exception as exc:
        log('Could not create menu target dir {}: {}'.format(target_dir, exc), xbmc.LOGWARNING)
        return

    try:
        names = sorted(n for n in os.listdir(MENU_DIR)
                       if n.startswith('skinvariables-shortcut-') and n.endswith('.json'))
    except Exception as exc:
        log('Could not list menu source folder {}: {}'.format(MENU_DIR, exc), xbmc.LOGWARNING)
        return

    deployed_names = set()
    changed = False
    for name in names:
        src = os.path.join(MENU_DIR, name)
        dest = os.path.join(target_dir, name)
        src_data = _read_bytes(src)
        if src_data is None:
            log('Could not read menu file {}; skipping.'.format(src), xbmc.LOGWARNING)
            continue
        deployed_names.add(name)
        if _read_bytes(dest) == src_data:
            log('Menu file {} already current.'.format(name))
            continue
        try:
            with open(dest, 'wb') as fh:
                fh.write(src_data)
            changed = True
            log('Menu file {} deployed.'.format(name))
        except Exception as exc:
            log('Could not deploy menu file {} to {}: {}'.format(name, dest, exc),
                xbmc.LOGWARNING)

    # Remove only the node files we manage and no longer ship (old 11xx slots
    # like 1105/1106, and the retired moreprov sub-page nodes). Home, power and
    # search nodes are deliberately left in place.
    try:
        for existing in os.listdir(target_dir):
            if existing not in deployed_names and _is_managed_node(existing):
                os.remove(os.path.join(target_dir, existing))
                changed = True
                log('Removed stale deployed node file {}'.format(existing))
    except Exception as exc:
        log('Could not prune stale node files: {}'.format(exc), xbmc.LOGWARNING)

    active = xbmc.getSkinDir()
    if active != AF3_ID:
        log('Active skin is {}, not {}; left HomeSwitcher slots unchanged and '
            'skipped skin reload.'.format(active, AF3_ID))
        return

    active_slots, known_slots = _read_slots_manifest()
    active_ids = {entry.get('slot') for entry in active_slots if entry.get('slot')}

    # Clear any known slot that is NOT in the active set (migrates away from old
    # layouts, e.g. the previous Disney+/Prime Video on 1105/1106).
    # Switch off inactive slots. Only the Toggle (which decides whether AF3 shows
    # the hub) and the Name are cleared. Mode is left alone on purpose: AF3's
    # startup refills an empty Mode on every load (for example 1107 and 1108 to
    # Wall), so clearing it would look like a change on every boot and force a
    # rebuild and skin reload each time. Up to 0.8.5 every inactive slot counted
    # as a change regardless, which is exactly what forced that per-boot reload.
    for slot in known_slots:
        if slot not in active_ids:
            cleared = False
            for sid in ('HomeSwitcher.{}.Name', 'homeswitcher.{}.toggle'):
                cleared = _reset_skin_setting(sid.format(slot)) or cleared
            if cleared:
                changed = True
                log('Switched off stale HomeSwitcher slot {}.'.format(slot))

    for entry in active_slots:
        slot = entry.get('slot')
        name = entry.get('name')
        toggle = str(entry.get('toggle', 'true')).lower()
        if not slot:
            continue
        written = _set_skin_string('HomeSwitcher.{}.Name'.format(slot), name)
        # The home slot is always present, so it carries no toggle; the custom
        # slots are toggled on.
        if toggle == 'true':
            written = _set_skin_string('homeswitcher.{}.toggle'.format(slot), 'true') or written
        written = _set_skin_string('homeswitcher.{}.mode'.format(slot), 'Standard') or written
        # Hub type: empty means Custom (widget rows). A slot repurposed from one
        # of AF3's prebuilt types (NextAired, LiveTV, Addons) must be reset or it
        # would render that hub instead of our rows.
        if slot != 'home' and _skin_string('HomeSwitcher.{}.Type'.format(slot)) not in ('', 'Custom'):
            written = _reset_skin_setting('HomeSwitcher.{}.Type'.format(slot)) or written
            log('Reset HomeSwitcher slot {} type to Custom.'.format(slot))
        if written:
            changed = True
            log('Set HomeSwitcher slot {} ({}): Name{}, mode.'.format(
                slot, name, ', toggle' if toggle == 'true' else ''))
        else:
            log('HomeSwitcher slot {} ({}) already current.'.format(slot, name))

    # The home menu is compiled by SkinVariables into a generator includes file
    # (script-skinvariables-generator-includes-.xml); dropping node JSON alone
    # does not update it, and the generator's own hash check ignores node-data
    # changes. So when anything changed we force a rebuild: action=buildtemplate
    # with force bypasses that gate, recompiles the includes from our nodes
    # (including any Custom_Submenu subgroups), and reloads the
    # skin itself, so the new rows actually appear without a cold restart.
    if changed:
        xbmc.executebuiltin('RunScript(script.skinvariables,action=buildtemplate,force=1)')
        log('Menu changed; forced SkinVariables template rebuild and skin reload.')
    else:
        log('No menu changes; SkinVariables rebuild not needed.')
    return changed


def apply_skin_settings():
    # Apply the curated, portable AF3 skin settings that define the ThoughtStream
    # look: bools via Skin.SetBool / Skin.Reset, strings via Skin.SetString. Runs
    # only when AF3 is the active skin, and self-heals the look on every start.
    if xbmc.getSkinDir() != AF3_ID:
        log('Active skin is not {}; skipping skin settings.'.format(AF3_ID))
        return
    cfg = load_config(SKIN_SETTINGS_FILE)
    if not cfg:
        return
    bools = cfg.get('bools', {})
    strings = cfg.get('strings', {})
    # Each setting is read first and written only when it differs, so a steady
    # state boot issues no skin builtins at all. Counts are of writes made.
    nb = 0
    for sid, val in bools.items():
        try:
            if _set_skin_bool(sid, val is True or str(val).lower() == 'true'):
                nb += 1
        except Exception as exc:
            log('Could not set bool {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    ns = 0
    for sid, val in strings.items():
        if val is None or val == '':
            continue
        try:
            if _set_skin_string(sid, val):
                ns += 1
        except Exception as exc:
            log('Could not set string {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    nr = 0
    for sid in cfg.get('reset', []):
        try:
            if _reset_skin_setting(sid):
                nr += 1
        except Exception as exc:
            log('Could not reset {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    log('Skin settings checked ({} bool(s), {} string(s), {} reset(s)); wrote {} bool(s), '
        '{} string(s), {} reset(s).'.format(len(bools), len(strings),
                                            len(cfg.get('reset', [])), nb, ns, nr))


def apply_viewtypes():
    # Deploy the SkinVariables view-type map so list and poster views match the
    # build. Self-healing copy, same pattern as the theme assets.
    src = os.path.join(CONFIG_DIR, VIEWTYPES_FILE)
    src_data = _read_bytes(src)
    if src_data is None:
        log('View types source missing at {}; skipping.'.format(src), xbmc.LOGERROR)
        return
    dest = xbmcvfs.translatePath(VIEWTYPES_DEST)
    dest_dir = os.path.dirname(dest)
    log('View types destination: {}'.format(dest))
    _copy_if_different(src_data, dest_dir, dest, 'View types')


def apply_advancedsettings():
    # Deploy advancedsettings.xml into the user profile to cap caches and give a
    # low-RAM device more headroom. Self-healing copy; only takes effect after a
    # Kodi restart, since Kodi reads advancedsettings.xml at startup.
    src = os.path.join(CONFIG_DIR, ADVANCEDSETTINGS_FILE)
    src_data = _read_bytes(src)
    if src_data is None:
        log('advancedsettings.xml source missing at {}; skipping.'.format(src), xbmc.LOGERROR)
        return
    dest = xbmcvfs.translatePath(ADVANCEDSETTINGS_DEST)
    dest_dir = os.path.dirname(dest)
    log('advancedsettings destination: {}'.format(dest))
    if _copy_if_different(src_data, dest_dir, dest, 'advancedsettings.xml'):
        log('advancedsettings.xml in place; takes effect on next Kodi restart.')


def _delete_dir_contents(path):
    # Remove everything inside a directory (files and subfolders), returning the
    # count removed. Guarded per entry so one failure does not stop the rest.
    if not os.path.isdir(path):
        log('Nothing to clear, folder not present: {}'.format(path))
        return 0
    count = 0
    for name in os.listdir(path):
        full = os.path.join(path, name)
        try:
            if os.path.isdir(full):
                shutil.rmtree(full, ignore_errors=True)
            else:
                os.remove(full)
            count += 1
            log('Deleted {}'.format(full))
        except Exception as exc:
            log('Could not delete {}: {}'.format(full, exc), xbmc.LOGWARNING)
    return count


def _revision_done(marker, revision, label):
    # True when a one-time job (see the *_REVISION constants) has already run.
    # A marker holding an old addon version means the job ran under the legacy
    # per-version gate; count that as done and rewrite it to the revision so the
    # next service update does not re-run the job.
    current = ADDON.getSetting(marker)
    if current == revision:
        log('{} already done for revision {}; skipping.'.format(label, revision))
        return True
    if current:
        ADDON.setSetting(marker, revision)
        log('{} already ran under the old per-version gate (marker {}); recorded '
            'revision {} so updates no longer re-run it.'.format(label, current, revision))
        return True
    return False


def clear_texture_cache_once():
    # One-time texture cache clear so the imageres/fanartres caps in
    # advancedsettings.xml actually take effect on an existing device. Kodi only
    # applies the caps to art cached AFTER the change, so already-cached art in
    # Thumbnails and Textures*.db keeps its old size until the cache is cleared
    # once. Version-gated the same way as the TMDb Helper setup (stored marker
    # texturecache_cleared), so it runs once per TEXTURE_CLEAR_REVISION (bump it
    # only when the caps change), never every start and no longer on every
    # service update. Fully guarded so nothing here can crash the service.
    if _revision_done('texturecache_cleared', TEXTURE_CLEAR_REVISION, 'Texture cache clear'):
        return

    log('===== Texture cache clear start (revision {}) ====='.format(TEXTURE_CLEAR_REVISION))
    deleted = 0
    try:
        # 1) Thumbnails folder: the hex subfolders 0-f and Video/ hold the cached
        #    image files. Clearing the contents forces Kodi to re-cache under the
        #    new caps.
        thumbs = xbmcvfs.translatePath('special://profile/Thumbnails/')
        log('Clearing Thumbnails at {}'.format(thumbs))
        deleted += _delete_dir_contents(thumbs)

        # 2) The texture database(s). Filename varies by Kodi version, so glob
        #    Textures*.db and log what is found. On the target (Android) the file
        #    is unlinked now and recreated empty on the next launch.
        dbdir = xbmcvfs.translatePath('special://database/')
        found_db = []
        try:
            for name in os.listdir(dbdir):
                low = name.lower()
                if low.startswith('textures') and low.endswith('.db'):
                    found_db.append(name)
        except Exception as exc:
            log('Could not list database dir {}: {}'.format(dbdir, exc), xbmc.LOGWARNING)
        log('Texture DB files found: {}'.format(', '.join(found_db) if found_db else 'none'))
        for name in found_db:
            full = os.path.join(dbdir, name)
            try:
                os.remove(full)
                deleted += 1
                log('Deleted texture DB {}'.format(full))
            except Exception as exc:
                log('Could not delete {}: {}'.format(full, exc), xbmc.LOGWARNING)

        ADDON.setSetting('texturecache_cleared', TEXTURE_CLEAR_REVISION)
        log('Texture cache clear done for revision {}; {} item(s) removed. The first '
            'browse after this will be slower while art re-caches under the new '
            'caps.'.format(TEXTURE_CLEAR_REVISION, deleted))
        notify('Art cache reset for the performance update.')
    except Exception as exc:
        log('Texture cache clear failed: {}'.format(exc), xbmc.LOGERROR)
    log('===== Texture cache clear end =====')


def _jsonrpc(method, params):
    # Minimal JSON-RPC helper. Returns the parsed response dict, or {} on error.
    request = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}
    try:
        return json.loads(xbmc.executeJSONRPC(json.dumps(request)))
    except Exception as exc:
        log('JSON-RPC {} failed: {}'.format(method, exc), xbmc.LOGWARNING)
        return {}


def _kodi_major():
    # Best-effort Kodi major version from System.BuildVersion, e.g. "21.2 (...)".
    build = xbmc.getInfoLabel('System.BuildVersion') or ''
    try:
        return int(build.split('.', 1)[0].strip())
    except Exception:
        return 0


def _texture_db_names():
    # Textures*.db filenames present, so we can confirm the expected name
    # (Textures13.db on Kodi 19-21) and log anything different on a newer Kodi.
    dbdir = xbmcvfs.translatePath('special://database/')
    names = []
    try:
        for name in os.listdir(dbdir):
            low = name.lower()
            if low.startswith('textures') and low.endswith('.db'):
                names.append(name)
    except Exception as exc:
        log('Could not list database dir {}: {}'.format(dbdir, exc), xbmc.LOGWARNING)
    return names


def _texture_lastused_epoch(value):
    # Parse a Textures.GetTextures lastused value ("YYYY-MM-DD HH:MM:SS", local
    # time) to epoch seconds. Returns None if empty or unparseable.
    if not value:
        return None
    try:
        return time.mktime(time.strptime(value, '%Y-%m-%d %H:%M:%S'))
    except Exception:
        return None


def prune_texture_cache():
    # Scheduled maintenance for data efficiency: remove cached textures not used
    # recently so the texture cache does not grow without bound on a low-storage
    # stick. Runs at most once per PRUNE_INTERVAL_SECONDS, tracked by the stored
    # timestamp texturecache_pruned so it does not run every start. Uses JSON-RPC
    # (Textures.GetTextures / Textures.RemoveTexture) so Kodi manages the locked
    # database and the cached files itself; we never touch the DB file directly
    # here. Fully guarded so nothing can crash the service.
    now = time.time()
    try:
        last = float(ADDON.getSetting('texturecache_pruned') or 0)
    except Exception:
        last = 0

    # Only run if at least the interval has elapsed. now - last must be
    # >= 604800 (7 days). On a fresh device last is 0, so it runs once and stamps.
    if last and (now - last) < PRUNE_INTERVAL_SECONDS:
        hours_left = int((PRUNE_INTERVAL_SECONDS - (now - last)) // 3600)
        log('Texture prune not due yet (about {} h remaining); skipping.'.format(hours_left))
        return

    log('===== Texture cache prune start ({}) ====='.format(
        time.strftime('%Y-%m-%d %H:%M:%S')))
    log('Kodi major version {}; texture DB present: {}'.format(
        _kodi_major(), ', '.join(_texture_db_names()) or 'none'))

    try:
        cutoff = now - PRUNE_STALE_SECONDS  # last used before this = stale
        # lastused is exposed inside each size entry, not at the texture level,
        # so request the sizes property and read lastused from it. sizes is the
        # smallest property set that carries lastused, keeping the response lean
        # on a low-RAM device; the textureid needed for removal is always given.
        resp = _jsonrpc('Textures.GetTextures', {'properties': ['sizes']})
        textures = resp.get('result', {}).get('textures', []) if resp else []
        examined = len(textures)
        removed = 0
        errors = 0
        for tex in textures:
            # Use the most recent lastused across the texture's size entries as
            # its freshness. Skip textures with no usable lastused (for example
            # just-cached art) or that are still within the stale window.
            epochs = [ep for ep in (
                _texture_lastused_epoch(s.get('lastused'))
                for s in (tex.get('sizes') or [])) if ep is not None]
            epoch = max(epochs) if epochs else None
            if epoch is None or epoch >= cutoff:
                continue
            tid = tex.get('textureid')
            if tid is None:
                continue
            result = _jsonrpc('Textures.RemoveTexture', {'textureid': tid})
            if result and 'error' not in result:
                removed += 1
            else:
                errors += 1
        ADDON.setSetting('texturecache_pruned', str(int(now)))
        # PRUNE_STALE_SECONDS // 86400 = 2592000 // 86400 = 30 (days), for the log.
        log('Texture prune done: examined {}, removed {} stale (unused > {} days), '
            '{} error(s).'.format(examined, removed, PRUNE_STALE_SECONDS // 86400, errors))
    except Exception as exc:
        log('Texture cache prune failed: {}'.format(exc), xbmc.LOGERROR)
    log('===== Texture cache prune end =====')


def initialise_magneto(monitor):
    # Trigger Magneto's scraper setup so a fresh device does not need the manual
    # step of opening Magneto under Program add-ons to prompt it. Gated by the
    # stored marker magneto_initialised so it runs once per MAGNETO_INIT_REVISION,
    # not on every service update (re-running the defaults action can overwrite
    # provider choices made since). Fully guarded so nothing here can crash the
    # service.
    if _revision_done('magneto_initialised', MAGNETO_INIT_REVISION, 'Magneto scraper init'):
        return

    try:
        xbmcaddon.Addon(MAGNETO_ID)
    except Exception:
        log('{} is not installed yet; skipping scraper init this pass.'.format(MAGNETO_ID),
            xbmc.LOGWARNING)
        return

    log('===== Magneto scraper init start (revision {}) ====='.format(MAGNETO_INIT_REVISION))
    try:
        xbmc.executebuiltin(MAGNETO_DEFAULTS_BUILTIN)
        log('Requested Magneto default providers via {}'.format(MAGNETO_DEFAULTS_BUILTIN))

        # RunPlugin is asynchronous, so wait before asserting the extra providers
        # or the defaults action could land afterwards and overwrite them.
        # waitForAbort returns True only if Kodi is shutting down.
        if monitor.waitForAbort(MAGNETO_SETTLE_SECONDS):
            log('Abort during Magneto init; leaving marker unset so it retries.',
                xbmc.LOGWARNING)
            return

        # Re-open the addon so we write against the settings the defaults action
        # just produced rather than a stale handle.
        magneto = xbmcaddon.Addon(MAGNETO_ID)
        enabled, failed = 0, 0
        for provider in MAGNETO_EXTRA_PROVIDERS:
            try:
                magneto.setSetting(provider, 'true')
                enabled += 1
                log('Enabled Magneto {}'.format(provider))
            except Exception as exc:
                failed += 1
                log('Could not enable Magneto {}: {}'.format(provider, exc), xbmc.LOGWARNING)

        ADDON.setSetting('magneto_initialised', MAGNETO_INIT_REVISION)
        log('Magneto scraper init done for revision {}: defaults requested, {} extra '
            'provider(s) enabled, {} failed.'.format(MAGNETO_INIT_REVISION, enabled, failed))
    except Exception as exc:
        log('Magneto scraper init failed: {}'.format(exc), xbmc.LOGERROR)
    log('===== Magneto scraper init end =====')


def enforce_addon_update_policy():
    # Two Kodi policies decide whether this build can update itself. They are
    # easy to confuse and 0.7.9 confused them, which caused a regression:
    #   general.addonupdates  Updates: 0 install automatically, 1 notify only,
    #                         2 never check. The build needs 0.
    #   addons.updatemode     Update official add-ons from: 0 official
    #                         repositories only, 1 any repositories. The build
    #                         needs 1.
    # Why 1 matters: script.module.infotagger is installed from Kodi's official
    # repository (origin repository.xbmc.org), and jurialmunkey ships newer
    # InfoTagger builds than the official repo carries. With the policy at 0,
    # Kodi's resolver (CAddonRepos::GetLatestAddonVersionFromAllRepos) only
    # considers the official version for an official-origin addon, so when TMDb
    # Helper requires a newer InfoTagger the update fails with 'The dependency on
    # script.module.infotagger version X could not be satisfied'. 0.7.9 forced
    # addons.updatemode to 0 by mistake; this asserts the correct values, reading
    # first and writing only what differs. Guarded and logged.
    _assert_kodi_settings((
        ('general.addonupdates', 0, 'Updates', 'install automatically'),
        ('addons.updatemode', 1, 'Update official add-ons from', 'any repositories'),
    ), 'Update policy')


def apply_cache_settings():
    # Video buffer settings (see KODI_CACHE_SETTINGS). Read first, written only
    # when different, so a steady state boot changes nothing.
    _assert_kodi_settings(KODI_CACHE_SETTINGS, 'Cache setting')


def _assert_kodi_settings(wanted, purpose):
    # Shared read-then-write helper for Kodi GUI settings via JSON-RPC.
    for setting, value, label, meaning in wanted:
        try:
            resp = _jsonrpc('Settings.GetSettingValue', {'setting': setting})
            if not resp or 'error' in resp:
                # For example the filecache.* settings do not exist before Kodi 21.
                log('{} {} is not available on this Kodi ({}); skipping.'.format(
                    purpose, setting, resp.get('error') if resp else 'no response'),
                    xbmc.LOGWARNING)
                continue
            current = resp.get('result', {}).get('value')
            if current == value:
                log('{} already {} ({}); nothing to change.'.format(label, value, meaning))
                continue
            log('{} is {}; setting {} to {} ({}).'.format(
                label, current, setting, value, meaning))
            result = _jsonrpc('Settings.SetSettingValue', {'setting': setting, 'value': value})
            if result and 'error' not in result:
                log('{} set to {} ({}).'.format(label, value, meaning))
            else:
                log('Could not set {}: {}'.format(setting, result), xbmc.LOGWARNING)
        except Exception as exc:
            log('{} check for {} failed to run: {}'.format(purpose, setting, exc),
                xbmc.LOGWARNING)


def apply_weather():
    # Point Kodi at Open-Meteo once it is installed (it arrives through this
    # addon's <requires>), then apply its lean preferences once. Guarded and
    # logged; nothing location specific is written.
    try:
        xbmcaddon.Addon(WEATHER_ADDON_ID)
    except Exception:
        log('{} is not installed yet; weather provider not set this pass.'.format(
            WEATHER_ADDON_ID), xbmc.LOGWARNING)
        return
    _assert_kodi_settings(WEATHER_KODI_SETTINGS, 'Weather setting')
    if _revision_done('weather_configured', WEATHER_PREFS_REVISION, 'Weather preferences'):
        return
    try:
        weather = xbmcaddon.Addon(WEATHER_ADDON_ID)
        for key, value in WEATHER_PREFS:
            weather.setSetting(key, value)
            log('Open-Meteo {} set to {}.'.format(key, value))
        ADDON.setSetting('weather_configured', WEATHER_PREFS_REVISION)
        log('Weather preferences applied for revision {}. Open-Meteo finds the '
            'location itself on its first run.'.format(WEATHER_PREFS_REVISION))
    except Exception as exc:
        log('Weather preferences failed: {}'.format(exc), xbmc.LOGWARNING)


def check_trakt_auth():
    # Diagnostic only, this changes nothing. TMDb Helper gates scrobbling on a
    # Home window property called TraktIsAuth, which holds the token expiry stamp
    # and is written by TMDb Helper's own service when the Trakt token refreshes
    # successfully (its lib/api/trakt/token.py). If that refresh fails the property
    # stays empty and scrobbling silently stops, while cached widget rows still
    # render, so the build looks fine but nothing gets marked watched. We only read
    # and log it so there is evidence in the log. Fully guarded.
    # The property names carry TMDb Helper's 'TMDbHelper.' prefix: its
    # get_property (script.module.jurialmunkey window.py) prepends it to every
    # name. Up to 0.8.5 this read the bare names, which never exist, so the log
    # always reported EMPTY even on a healthy device.
    try:
        window = xbmcgui.Window(10000)
        value = window.getProperty(TRAKT_AUTH_PROPERTY)
        attempts = window.getProperty(TRAKT_ATTEMPTS_PROPERTY) or '0'
        if not _tmdbhelper_has_trakt_token():
            log('Trakt auth: TMDb Helper has NO stored Trakt token. This is why Up '
                'Next is empty and why a Trakt login dialog appears on every launch '
                '(TMDb Helper drops the token after repeated refresh failures). '
                'Fix: TMDb Helper settings > Trakt > authorise, once.', xbmc.LOGWARNING)
            return
        if not value:
            log('Trakt auth: TraktIsAuth is EMPTY, so TMDb Helper will not scrobble '
                'and Trakt rows will go stale. Re-authorise Trakt in TMDb Helper '
                'settings. Failed refresh attempts: {}'.format(attempts), xbmc.LOGWARNING)
            return
        remaining = float(value) - time.time()
        if remaining <= 0:
            log('Trakt auth: token stamp {} has already expired; re-authorise Trakt '
                'in TMDb Helper settings. Failed refresh attempts: {}'.format(
                    value, attempts), xbmc.LOGWARNING)
            return
        # remaining is seconds; 86400 seconds = 1 day.
        log('Trakt auth OK: token valid for about {} day(s), {} failed refresh '
            'attempt(s).'.format(int(remaining // 86400), attempts))
    except Exception as exc:
        log('Trakt auth check failed to run: {}'.format(exc), xbmc.LOGWARNING)


def purge_addon_package_cache():
    # Remove corrupt cached addon zips, and any cached InfoTagger zip, so Kodi's
    # next dependency install downloads a fresh package instead of retrying a
    # broken cached one. Version-gated by packagecache_purged so it runs once per
    # version. Fully guarded so nothing here can crash the service.
    if ADDON.getSetting('packagecache_purged') == ADDON_VERSION:
        log('Package cache already purged for v{}; skipping.'.format(ADDON_VERSION))
        return
    log('===== Package cache purge start (v{}) ====='.format(ADDON_VERSION))
    removed = 0
    try:
        pkgdir = xbmcvfs.translatePath(PACKAGES_DIR)
        if not os.path.isdir(pkgdir):
            log('Package cache folder not present: {}'.format(pkgdir))
        else:
            for name in sorted(os.listdir(pkgdir)):
                if not name.lower().endswith('.zip'):
                    continue
                full = os.path.join(pkgdir, name)
                reason = None
                if name.startswith(INFOTAGGER_ID + '-'):
                    reason = 'cached InfoTagger package, forcing a fresh download'
                elif not zipfile.is_zipfile(full):
                    reason = 'not a valid zip'
                else:
                    try:
                        with zipfile.ZipFile(full) as zf:
                            bad = zf.testzip()
                        if bad:
                            reason = 'corrupt member {}'.format(bad)
                    except Exception as exc:
                        reason = 'unreadable ({})'.format(exc)
                if not reason:
                    continue
                try:
                    os.remove(full)
                    removed += 1
                    log('Removed cached package {}: {}'.format(name, reason))
                except Exception as exc:
                    log('Could not remove {}: {}'.format(full, exc), xbmc.LOGWARNING)
        xbmc.executebuiltin('UpdateAddonRepos')
        ADDON.setSetting('packagecache_purged', ADDON_VERSION)
        log('Package cache purge done for v{}: {} package(s) removed; repo refresh '
            'requested.'.format(ADDON_VERSION, removed))
    except Exception as exc:
        log('Package cache purge failed: {}'.format(exc), xbmc.LOGERROR)
    log('===== Package cache purge end =====')


def _tmdbhelper_has_trakt_token():
    # TMDb Helper's real auth state is its stored user token, not the
    # TraktIsAuth window property. That property is only a cached expiry stamp
    # and can survive while the token itself is gone: TMDb Helper deletes the
    # stored token after more than 3 failed refreshes (its token.py), and from
    # then on any Trakt sync calls is_authorized, which is authorize(forced=True),
    # which opens the device-code login dialog. Its only guard is per process, so
    # it prompts again on every launch. Reading the token here lets us avoid
    # triggering that prompt ourselves. Presence only; the value is never logged.
    try:
        helper = xbmcaddon.Addon(TMDBHELPER_ID)
    except Exception:
        return False
    for key in ('trakt_token', 'user_token'):
        try:
            if helper.getSetting(key).strip():
                return True
        except Exception:
            continue
    return False


def repair_trakt_sync(monitor):
    # One-time rebuild of TMDb Helper's watched, playback and next-episode sync
    # data through its own Clear sync data > Progress action, so a blank Up Next
    # recovers without waiting for the half day stamp. Gated by traktsync_repaired
    # so it runs once per TRAKTSYNC_REPAIR_REVISION, not on every service update
    # (each rebuild clears and refetches all watched data from Trakt). Skipped,
    # with the marker left unset so it retries, when TMDb Helper is missing or has
    # no stored Trakt token, because without a token the rebuild only produces an
    # empty table and forces a login prompt.
    if _revision_done('traktsync_repaired', TRAKTSYNC_REPAIR_REVISION, 'Trakt sync repair'):
        return
    try:
        xbmcaddon.Addon(TMDBHELPER_ID)
    except Exception:
        log('{} is not installed yet; skipping Trakt sync repair this pass.'.format(
            TMDBHELPER_ID), xbmc.LOGWARNING)
        return
    try:
        if not _tmdbhelper_has_trakt_token():
            log('Trakt sync repair deferred: TMDb Helper has NO stored Trakt token, so '
                'Up Next cannot fill and any sync would open the Trakt login dialog. '
                'Authorise Trakt in TMDb Helper settings once; the repair runs on the '
                'next start after that.', xbmc.LOGWARNING)
            return
        log('===== Trakt sync repair start (revision {}) ====='.format(TRAKTSYNC_REPAIR_REVISION))
        if monitor.waitForAbort(TRAKTSYNC_REPAIR_SETTLE_SECONDS):
            log('Abort during Trakt sync repair; leaving marker unset so it retries.',
                xbmc.LOGWARNING)
            return
        xbmc.executebuiltin(TRAKTSYNC_REPAIR_BUILTIN)
        ADDON.setSetting('traktsync_repaired', TRAKTSYNC_REPAIR_REVISION)
        log('Trakt sync repair requested via {}. A background progress bar shows '
            'while TMDb Helper rebuilds; Up Next fills in once it finishes.'.format(
                TRAKTSYNC_REPAIR_BUILTIN))
    except Exception as exc:
        log('Trakt sync repair failed: {}'.format(exc), xbmc.LOGERROR)
    log('===== Trakt sync repair end =====')


def _episode_mapper_block(text):
    # Return (start, end) of the EpisodeItemMapper class body in mapper_standard.py,
    # ending at the next top level class or def, or (-1, -1) if it is not found.
    start = text.find('\nclass EpisodeItemMapper(')
    if start == -1:
        return -1, -1
    ends = [i for i in (text.find('\nclass ', start + 1), text.find('\ndef ', start + 1))
            if i != -1]
    return start, (min(ends) if ends else len(text))


def patch_tmdbhelper_episode_params():
    # Hotfix for the calendar play error (see TMDBH_PATCH_* above). Runs on every
    # start because a TMDb Helper update overwrites the file. Fully guarded and
    # logged; any unexpected shape leaves the file untouched. Returns True only
    # when the file was changed in this pass, so the caller can refresh widgets.
    try:
        helper = xbmcaddon.Addon(TMDBHELPER_ID)
    except Exception:
        log('{} is not installed yet; skipping episode params patch.'.format(
            TMDBHELPER_ID), xbmc.LOGWARNING)
        return False
    try:
        helper_version = helper.getAddonInfo('version')
        helper_path = xbmcvfs.translatePath(helper.getAddonInfo('path'))
        target = os.path.join(helper_path, TMDBH_MAPPER_RELPATH)
        if not os.path.isfile(target):
            log('Episode params patch: {} not found in TMDb Helper v{}; layout changed, '
                'standing down.'.format(TMDBH_MAPPER_RELPATH, helper_version),
                xbmc.LOGWARNING)
            return False
        with open(target, 'r', encoding='utf-8') as fh:
            text = fh.read()

        if TMDBH_PATCH_MARKER in text:
            log('Episode params patch already present in TMDb Helper v{}.'.format(
                helper_version))
            return False

        start, end = _episode_mapper_block(text)
        if start == -1:
            log('Episode params patch: EpisodeItemMapper not found in TMDb Helper v{}; '
                'standing down.'.format(helper_version), xbmc.LOGWARNING)
            return False
        block = text[start:end]
        if 'def get_params' in block:
            log('Episode params patch not needed: TMDb Helper v{} defines its own '
                'EpisodeItemMapper.get_params (likely fixed upstream). Verify calendar '
                'episodes play, then this patch can be retired.'.format(helper_version))
            return False
        if block.count(TMDBH_PATCH_ANCHOR) != 1:
            log('Episode params patch: anchor text not found exactly once in '
                'EpisodeItemMapper (TMDb Helper v{}); standing down so nothing is '
                'corrupted.'.format(helper_version), xbmc.LOGWARNING)
            return False

        anchor_at = start + block.index(TMDBH_PATCH_ANCHOR) + len(TMDBH_PATCH_ANCHOR)
        patched = text[:anchor_at] + TMDBH_PATCH_BLOCK + text[anchor_at:]

        # Sanity check the result compiles before it replaces the original.
        compile(patched, target, 'exec')

        backup = target + '.kodipersonal.bak'
        shutil.copy2(target, backup)
        tmp = target + '.kodipersonal.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(patched)
        os.replace(tmp, target)

        # Drop the stale bytecode so the next plugin call compiles the patched file.
        cache_dir = os.path.join(os.path.dirname(target), '__pycache__')
        if os.path.isdir(cache_dir):
            for name in os.listdir(cache_dir):
                if name.startswith('mapper_standard.'):
                    try:
                        os.remove(os.path.join(cache_dir, name))
                        log('Removed stale bytecode {}'.format(name))
                    except Exception as exc:
                        log('Could not remove bytecode {}: {}'.format(name, exc),
                            xbmc.LOGWARNING)

        log('Episode params patch applied to TMDb Helper v{} ({}); backup at {}. '
            'Calendar episodes now pass season and episode to the player.'.format(
                helper_version, target, backup))
        return True
    except Exception as exc:
        log('Episode params patch failed: {}'.format(exc), xbmc.LOGERROR)
        return False


def refresh_tmdbhelper_widgets():
    # Bump TMDb Helper's widget reload property, which every For You widget path
    # includes, so Kodi re-requests the lists and picks up the patched params
    # instead of serving the listing it built before the patch.
    try:
        stamp = str(int(time.time()))
        xbmcgui.Window(10000).setProperty('TMDbHelper.Widgets.Reload', stamp)
        log('TMDb Helper widgets reload requested (stamp {}).'.format(stamp))
    except Exception as exc:
        log('Widget reload request failed: {}'.format(exc), xbmc.LOGWARNING)


def needs_apply():
    if not ADDON.getSettingBool('apply_on_update'):
        last = ADDON.getSetting('last_applied_version')
        return last == ''  # only ever run once if re-apply is disabled
    return ADDON.getSetting('last_applied_version') != ADDON_VERSION


def run_setup():
    log('===== Setup pass start (addon v{}) ====='.format(ADDON_VERSION))
    ok = apply_tmdbhelper_settings()
    ok = apply_scrobbler_settings() and ok
    if ok:
        ADDON.setSetting('last_applied_version', ADDON_VERSION)
        notify('Build defaults applied.')
        log('Setup pass complete; recorded version {}.'.format(ADDON_VERSION))
    else:
        log('Setup pass incomplete; will retry on next start.', xbmc.LOGWARNING)
    log('===== Setup pass end =====')


def main():
    monitor = xbmc.Monitor()
    rotate_logfile()
    log('Service started on {} (addon v{}, service v{})'.format(
        xbmc.getInfoLabel('System.BuildVersion'), ADDON_VERSION, SERVICE_VERSION))

    # Patch TMDb Helper's episode params before the 20 second settle, so the
    # home widgets that load during that window already get playable calendar
    # episodes. Only touches a file; if it changes anything, ask the widgets to
    # reload after the settle in case they were built from the old code.
    episode_patch_changed = patch_tmdbhelper_episode_params()

    # Give Kodi a moment to finish loading addons before we touch other addons.
    if monitor.waitForAbort(20):
        return

    if episode_patch_changed:
        refresh_tmdbhelper_widgets()

    # Clear corrupt cached addon packages first so any install the dependency
    # healer or Kodi's auto update does next fetches a fresh zip.
    purge_addon_package_cache()

    # Make sure the required stack is present/enabled before we depend on it.
    verify_dependencies()

    # Theme assets, skin settings, view types and the home menu self-heal on
    # every start, independent of the version gate.
    apply_colour_theme()
    apply_background()
    apply_skin_settings()
    apply_viewtypes()
    apply_advancedsettings()
    clear_texture_cache_once()
    prune_texture_cache()
    menu_changed = deploy_menu()

    # A menu change forces a SkinVariables rebuild, which reloads the skin, and
    # AF3's startup actions then re-set some TMDb Helper skin bools. Re-assert our
    # skin settings once the reload has settled so that change sticks.
    if menu_changed:
        if monitor.waitForAbort(SKIN_RELOAD_SETTLE_SECONDS):
            return
        log('Re-applying skin settings after the skin reload.')
        apply_skin_settings()

    # Scraper setup, version-gated, so a fresh device does not need the manual
    # step of opening Magneto to prompt it.
    initialise_magneto(monitor)

    # Assert Kodi's two update policies (install automatically, and accept
    # updates from any repository), then log TMDb Helper's Trakt auth health
    # (it drives the For You rows) so problems leave a trace.
    enforce_addon_update_policy()
    apply_cache_settings()
    apply_weather()
    check_trakt_auth()

    # TMDb Helper defaults stay version-gated so they only reapply after updates.
    if needs_apply():
        run_setup()
    else:
        log('Defaults already current for v{}; nothing to do.'.format(ADDON_VERSION))

    # After the settings pass (so the max_threads cap is live), rebuild TMDb
    # Helper's Trakt sync data once so a blank Up Next recovers.
    repair_trakt_sync(monitor)

    # Idle. The service exists mainly to run the setup pass after updates.
    while not monitor.abortRequested():
        if monitor.waitForAbort(3600):
            break
    log('Service stopping.')


if __name__ == '__main__':
    main()
