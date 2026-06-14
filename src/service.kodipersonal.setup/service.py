# -*- coding: utf-8 -*-
# KODI Personal Setup service
# Applies the personal build defaults (TMDb Helper behavior + source-player slot)
# on first run and after each update, so every home device stays consistent.
# Copies the ThoughtStream colour set and background and deploys the home menu
# files into Arctic Fuse 3 on every start so the theme and menu self-heal after
# an AF3 update overwrites those files. Verifies required add-ons/repos on
# startup and silently heals what it can. Logging is verbose by design.

import os
import json
import time

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
SKINVARS_RELOAD_PROP = 'SkinVariables.ShortcutsNode.Reload'
SKIN_SETTINGS_FILE = 'skin_settings.json'
VIEWTYPES_FILE = 'viewtypes.json'
VIEWTYPES_DEST = 'special://profile/addon_data/script.skinvariables/skin.arctic.fuse.3-viewtypes.json'
LOG_TAG = '[KODIPERSONAL]'
LOGFILE = os.path.join(PROFILE, 'kodipersonal.log')


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

    # Remove stale node files in the target that we no longer ship (e.g. an old
    # provider sub-page renamed, or a removed slot's widget file).
    try:
        for existing in os.listdir(target_dir):
            if (existing.startswith('skinvariables-shortcut-')
                    and existing.endswith('.json')
                    and existing not in deployed_names):
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

    # Tell SkinVariables to regenerate its node-driven includes, then reload the
    # skin. Setting the reload property is what makes new widget rows actually
    # appear without a cold restart.
    xbmc.executebuiltin('SetProperty({},{},Home)'.format(SKINVARS_RELOAD_PROP, time.time()))
    log('Signalled SkinVariables node reload.')

    if changed:
        xbmc.executebuiltin('ReloadSkin()')
        log('Menu files changed; reloaded skin so the menu appears.')
    else:
        log('No menu file changes; skin reload not needed.')


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
            # through the builtin parser intact (e.g. the spotlight $INFO path).
            xbmc.executebuiltin('Skin.SetString({},"{}")'.format(sid, val))
            ns += 1
        except Exception as exc:
            log('Could not set string {}: {}'.format(sid, exc), xbmc.LOGWARNING)
    log('Applied skin settings: {} bool(s), {} string(s).'.format(nb, ns))


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
    log('Service started on {} (addon v{})'.format(
        xbmc.getInfoLabel('System.BuildVersion'), ADDON_VERSION))

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
