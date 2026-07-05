# -*- coding: utf-8 -*-
# KODI Personal Setup service
# Applies the personal build defaults (TMDb Helper behavior + source-player slot)
# on first run and after each update, so every home device stays consistent.
# Copies the ThoughtStream colour set and background and deploys the home menu
# files into Arctic Fuse 3 on every start so the theme and menu self-heal after
# an AF3 update overwrites those files. Verifies required add-ons/repos on
# startup and silently heals what it can. Also runs a scheduled texture-cache
# prune (data efficiency) that drops textures unused for a while, on a timer so
# it does not run every start. Logging is verbose by design.

import os
import json
import time
import shutil

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
SERVICE_VERSION = '0.7.2'

# Scheduled texture-cache prune (data efficiency). A texture unused for longer
# than the stale window is removed, and the prune itself runs at most once per
# interval, gated by the stored timestamp texturecache_pruned (epoch seconds).
# Arithmetic (seconds):
#   interval 7 days  = 7 * 24 * 60 * 60  = 604800
#   stale    30 days = 30 * 24 * 60 * 60 = 2592000
PRUNE_INTERVAL_SECONDS = 604800
PRUNE_STALE_SECONDS = 2592000


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


def apply_tmdbhelper_settings():
    cfg = load_config('tmdbhelper_settings.json')
    if not cfg:
        return False
    target = cfg.get('target_addon', 'plugin.video.themoviedb.helper')
    try:
        helper = xbmcaddon.Addon(target)
    except Exception:
        log('{} is not installed yet; skipping settings apply this pass.'.format(target),
            xbmc.LOGWARNING)
        return False

    applied, failed = 0, 0
    for key, value in cfg.get('settings', {}).items():
        try:
            helper.setSetting(key, str(value))
            applied += 1
        except Exception as exc:
            failed += 1
            log('Could not set {}={} : {}'.format(key, value, exc), xbmc.LOGWARNING)
    log('TMDb Helper settings applied: {} ok, {} failed.'.format(applied, failed))
    return failed == 0


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
        xbmc.executebuiltin(
            'Skin.SetString(Background.Image,'
            'special://skin/extras/backgrounds/{})'.format(BACKGROUND_FILE))
        log('Set Background.Image to the ThoughtStream background.')
        xbmc.executebuiltin('Skin.SetString(Background.DialogImage,Chalk)')
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
    for slot in known_slots:
        if slot not in active_ids:
            xbmc.executebuiltin('Skin.Reset(HomeSwitcher.{}.Name)'.format(slot))
            xbmc.executebuiltin('Skin.Reset(homeswitcher.{}.toggle)'.format(slot))
            xbmc.executebuiltin('Skin.Reset(homeswitcher.{}.mode)'.format(slot))
            changed = True
            log('Cleared stale HomeSwitcher slot {}.'.format(slot))

    for entry in active_slots:
        slot = entry.get('slot')
        name = entry.get('name')
        toggle = str(entry.get('toggle', 'true')).lower()
        if not slot:
            continue
        xbmc.executebuiltin('Skin.SetString(HomeSwitcher.{}.Name,{})'.format(slot, name))
        # The home slot is always present, so it carries no toggle; the custom
        # slots (1101-1104) are toggled on.
        if toggle == 'true':
            xbmc.executebuiltin('Skin.SetString(homeswitcher.{}.toggle,true)'.format(slot))
        xbmc.executebuiltin('Skin.SetString(homeswitcher.{}.mode,Standard)'.format(slot))
        log('Set HomeSwitcher slot {} ({}): Name{}, mode.'.format(
            slot, name, ', toggle' if toggle == 'true' else ''))

    # The home menu is compiled by SkinVariables into a generator includes file
    # (script-skinvariables-generator-includes-.xml); dropping node JSON alone
    # does not update it, and the generator's own hash check ignores node-data
    # changes. So when anything changed we force a rebuild: action=buildtemplate
    # with force bypasses that gate, recompiles the includes from our nodes
    # (including the More Providers Custom_Submenu subgroups), and reloads the
    # skin itself, so the new rows actually appear without a cold restart.
    if changed:
        xbmc.executebuiltin('RunScript(script.skinvariables,action=buildtemplate,force=1)')
        log('Menu changed; forced SkinVariables template rebuild and skin reload.')
    else:
        log('No menu changes; SkinVariables rebuild not needed.')


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
    nb = 0
    for sid, val in bools.items():
        try:
            if val is True or str(val).lower() == 'true':
                xbmc.executebuiltin('Skin.SetBool({})'.format(sid))
            else:
                xbmc.executebuiltin('Skin.Reset({})'.format(sid))
            nb += 1
        except Exception as exc:
            log('Could not set bool {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    ns = 0
    for sid, val in strings.items():
        if val is None or val == '':
            continue
        try:
            # Quote the value so paths with brackets, parentheses or commas pass
            # through the builtin parser intact.
            xbmc.executebuiltin('Skin.SetString({},"{}")'.format(sid, val))
            ns += 1
        except Exception as exc:
            log('Could not set string {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    nr = 0
    for sid in cfg.get('reset', []):
        try:
            xbmc.executebuiltin('Skin.Reset({})'.format(sid))
            nr += 1
        except Exception as exc:
            log('Could not reset {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    log('Applied skin settings: {} bool(s), {} string(s), {} reset.'.format(nb, ns, nr))


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


def clear_texture_cache_once():
    # One-time texture cache clear so the imageres/fanartres caps in
    # advancedsettings.xml actually take effect on an existing device. Kodi only
    # applies the caps to art cached AFTER the change, so already-cached art in
    # Thumbnails and Textures*.db keeps its old size until the cache is cleared
    # once. Version-gated the same way as the TMDb Helper setup (stored marker
    # texturecache_cleared), so it runs exactly once per version, never every
    # start. Fully guarded so nothing here can crash the service.
    if ADDON.getSetting('texturecache_cleared') == ADDON_VERSION:
        log('Texture cache already cleared for v{}; skipping.'.format(ADDON_VERSION))
        return

    log('===== Texture cache clear start (v{}) ====='.format(ADDON_VERSION))
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

        ADDON.setSetting('texturecache_cleared', ADDON_VERSION)
        log('Texture cache clear done for v{}; {} item(s) removed. The first '
            'browse after this will be slower while art re-caches under the new '
            'caps.'.format(ADDON_VERSION, deleted))
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


def needs_apply():
    if not ADDON.getSettingBool('apply_on_update'):
        last = ADDON.getSetting('last_applied_version')
        return last == ''  # only ever run once if re-apply is disabled
    return ADDON.getSetting('last_applied_version') != ADDON_VERSION


def run_setup():
    log('===== Setup pass start (addon v{}) ====='.format(ADDON_VERSION))
    ok = apply_tmdbhelper_settings()
    if ok:
        ADDON.setSetting('last_applied_version', ADDON_VERSION)
        notify('Build defaults applied.')
        log('Setup pass complete; recorded version {}.'.format(ADDON_VERSION))
    else:
        log('Setup pass incomplete; will retry on next start.', xbmc.LOGWARNING)
    log('===== Setup pass end =====')


def main():
    monitor = xbmc.Monitor()
    log('Service started on {} (addon v{}, service v{})'.format(
        xbmc.getInfoLabel('System.BuildVersion'), ADDON_VERSION, SERVICE_VERSION))

    # Give Kodi a moment to finish loading addons before we touch other addons.
    if monitor.waitForAbort(20):
        return

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
    deploy_menu()

    # TMDb Helper defaults stay version-gated so they only reapply after updates.
    if needs_apply():
        run_setup()
    else:
        log('Defaults already current for v{}; nothing to do.'.format(ADDON_VERSION))

    # Idle. The service exists mainly to run the setup pass after updates.
    while not monitor.abortRequested():
        if monitor.waitForAbort(3600):
            break
    log('Service stopping.')


if __name__ == '__main__':
    main()
