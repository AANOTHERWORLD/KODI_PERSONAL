# -*- coding: utf-8 -*-
# KODI Personal Setup service
# Applies the personal build defaults (TMDb Helper behavior + source-player slot)
# on first run and after each update, so every home device stays consistent.
# Also copies the ThoughtStream colour set into Arctic Fuse 3 on every start so
# the theme self-heals after an AF3 update overwrites its colors folder.
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
COLOUR_FILE = 'ThoughtStream.xml'
AF3_ID = 'skin.arctic.fuse.3'
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


def apply_colour_theme():
    # Runs on EVERY start, not gated by the version check. AF3 owns its colors
    # folder, and an AF3 update can wipe our overlay, so we re-copy it whenever
    # it is missing or differs from our bundled copy. This self-heals the theme.
    src = os.path.join(COLORS_DIR, COLOUR_FILE)
    src_data = _read_bytes(src)
    if src_data is None:
        log('Colour set source missing at {}; skipping copy.'.format(src), xbmc.LOGERROR)
        return

    try:
        af3 = xbmcaddon.Addon(AF3_ID)
    except Exception:
        log('{} is not installed; skipping colour set copy this pass.'.format(AF3_ID))
        return

    af3_path = xbmcvfs.translatePath(af3.getAddonInfo('path'))
    dest_dir = os.path.join(af3_path, 'colors')
    dest = os.path.join(dest_dir, COLOUR_FILE)
    log('Colour set source: {}'.format(src))
    log('Colour set destination: {}'.format(dest))

    if _read_bytes(dest) == src_data:
        log('Colour set already current at destination; nothing to copy.')
        return

    try:
        if not os.path.isdir(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
        with open(dest, 'wb') as fh:
            fh.write(src_data)
        log('Colour set copied into AF3 colors folder.')
    except Exception as exc:
        log('Could not copy colour set to {}: {}. The skin folder may be read '
            'only; place {} in that colors folder manually.'.format(dest, exc, COLOUR_FILE),
            xbmc.LOGWARNING)


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

    # Colour set self-heals on every start, independent of the version gate.
    apply_colour_theme()

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
