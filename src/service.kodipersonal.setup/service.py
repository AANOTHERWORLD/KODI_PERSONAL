# Setup service for the ThoughtStream layer on Arctic Fuse 3 (AF3).
#
# Strict no-edit design. This service never writes into the AF3 addon. It only
# touches the user profile and the running skin's settings, both of which are
# reversible by the user from the skin settings screen.
#
# What it does on start:
#   1. Logs to setup.log in this addon's own profile folder, matching the
#      existing setup service pattern.
#   2. Applies the ThoughtStream accent to AF3 with Skin.SetString, which AF3
#      reads as focuscolor.name. No skin edit needed.
#   3. Reads resources/config/lists.json and seeds the home menu and widget
#      rows into the script.skinvariables profile data so AF3 can pick them up.
#      AF3 drives its home menu through script.skinvariables, and that addon
#      keeps user data under special://profile/addon_data/script.skinvariables/.
#      The exact node layout is confirmed on the ONN during the first push and
#      check pass, so this writes a clearly named seed file and logs every
#      intended binding rather than guessing a format silently.
#
# No secrets are read or written. No em dashes.

import json
import os
import time

import xbmc
import xbmcaddon
import xbmcvfs

ADDON = xbmcaddon.Addon()
ADDON_ID = ADDON.getAddonId()
PROFILE = xbmcvfs.translatePath(ADDON.getAddonInfo("profile"))
CONFIG = xbmcvfs.translatePath(
    os.path.join(ADDON.getAddonInfo("path"), "resources", "config", "lists.json")
)

# Where script.skinvariables keeps its user data. Confirmed from the addon
# source: resources/lib/method.py uses special://profile/addon_data/script.skinvariables/.
SKINVARS_DATA = xbmcvfs.translatePath(
    "special://profile/addon_data/script.skinvariables/kodipersonal/"
)

# ThoughtStream accent, AARRGGBB. stone.accent from THEME_THOUGHTSTREAM.md.
ACCENT = "ff8a7b6b"
AF3_ID = "skin.arctic.fuse.3"


def _ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)


def log(message, level=xbmc.LOGINFO):
    # Log to the Kodi log and to our own profile log file.
    xbmc.log("[%s] %s" % (ADDON_ID, message), level)
    try:
        _ensure_dir(PROFILE)
        line = "%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
        with open(os.path.join(PROFILE, "setup.log"), "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as exc:
        xbmc.log("[%s] could not write profile log: %s" % (ADDON_ID, exc), xbmc.LOGWARNING)


def current_skin():
    return xbmc.getSkinDir()


def apply_accent():
    if current_skin() != AF3_ID:
        log("skin is %s, not %s, skipping accent" % (current_skin(), AF3_ID))
        return
    xbmc.executebuiltin("Skin.SetString(focuscolor.name,%s)" % ACCENT)
    log("applied accent focuscolor.name %s" % ACCENT)


def load_lists():
    try:
        with open(CONFIG, "r", encoding="utf-8") as f:
            data = json.load(f)
        rows = data.get("rows", [])
        log("loaded %d rows from lists.json" % len(rows))
        return data
    except Exception as exc:
        log("could not read lists.json: %s" % exc, xbmc.LOGERROR)
        return {"rows": []}


def seed_home_menu(data):
    # Write the rows as a seed file into the skinvariables profile data and log
    # every intended binding. The first ONN pass confirms the exact node layout
    # AF3 expects, after which the copy target here is finalised.
    rows = data.get("rows", [])
    try:
        _ensure_dir(SKINVARS_DATA)
        seed_path = os.path.join(SKINVARS_DATA, "thoughtstream_home_rows.json")
        with open(seed_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log("seeded %d rows to %s" % (len(rows), seed_path))
    except Exception as exc:
        log("could not seed home rows: %s" % exc, xbmc.LOGERROR)

    for row in rows:
        log("intended binding group=%s id=%s target=%s path=%s"
            % (row.get("group"), row.get("id"), row.get("target"), row.get("path")))
    log("home menu seed written, confirm node layout on device")


def run_once():
    log("setup service start, skin=%s" % current_skin())
    apply_accent()
    seed_home_menu(load_lists())
    log("setup service done")


if __name__ == "__main__":
    # Wait briefly for the GUI so getSkinDir and Skin.SetString are meaningful,
    # then run once. waitForAbort returns True if Kodi is shutting down.
    monitor = xbmc.Monitor()
    if not monitor.waitForAbort(5):
        run_once()
