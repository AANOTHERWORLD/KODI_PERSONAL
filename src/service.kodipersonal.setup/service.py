# -*- coding: utf-8 -*-
# KODI Personal Setup service
# Applies the personal build defaults (TMDb Helper behavior + source-player slot)
# on first run and after each update, so every home device stays consistent.
# Also copies the ThoughtStream colour set and background, and deploys the home
# menu widget files, into Arctic Fuse 3 on every start so the theme and menu
# self-heal after an AF3 update overwrites those files.
# Logging is verbose by design to support later monitoring.

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


def deploy_menu():
    # Runs on EVERY start, not version-gated. Deploys the home menu widget files
    # into the script.skinvariables node folder for AF3 and sets the HomeSwitcher
    # slot strings, self-healing like the colour set and background. All file ops
    # are guarded so a failure here never crashes the service.
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

    changed = False
    for name in names:
        src = os.path.join(MENU_DIR, name)
        dest = os.path.join(target_dir, name)
        src_data = _read_bytes(src)
        if src_data is None:
            log('Could not read menu file {}; skipping.'.format(src), xbmc.LOGWARNING)
            continue
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

    active = xbmc.getSkinDir()
    if active != AF3_ID:
        log('Active skin is {}, not {}; left HomeSwitcher slots unchanged and '
            'skipped skin reload.'.format(active, AF3_ID))
        return

    slots = []
    try:
        with open(os.path.join(MENU_DIR, 'slots.json'), 'r', encoding='utf-8') as fh:
            slots = json.load(fh)
    except Exception as exc:
        log('Could not read slots.json: {}'.format(exc), xbmc.LOGWARNING)

    for entry in slots:
        slot = entry.get('slot')
        name = entry.get('name')
        if not slot:
            continue
        xbmc.executebuiltin('Skin.SetString(HomeSwitcher.{}.Name,{})'.format(slot, name))
        xbmc.executebuiltin('Skin.SetString(homeswitcher.{}.toggle,true)'.format(slot))
        xbmc.executebuiltin('Skin.SetString(homeswitcher.{}.mode,Standard)'.format(slot))
        log('Set HomeSwitcher slot {} ({}): Name, toggle, mode.'.format(slot, name))

    if changed:
        xbmc.executebuiltin('ReloadSkin()')
        log('Menu files changed; reloaded skin so the menu appears.')
    else:
        log('No menu file changes; skin reload not needed.')


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
    log('Service started on {} (Kodi build: {})'.format(
        xbmc.getInfoLabel('System.BuildVersion'), ADDON_VERSION))

    # Give Kodi a moment to finish loading addons before we touch other addons.
    if monitor.waitForAbort(20):
        return

    # Theme assets and the home menu self-heal on every start, independent of the
    # version gate.
    apply_colour_theme()
    apply_background()
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
