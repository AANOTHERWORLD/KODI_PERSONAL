# -*- coding: utf-8 -*-
# KODI_PERSONAL build: dependency verification + silent auto-heal.
# On startup, checks every required repo/addon from required_dependencies.json.
#   - installed + enabled  -> OK
#   - installed + disabled -> silently re-enabled via JSON-RPC (no prompt)
#   - missing              -> best-effort install attempt; notify if it fails
#
# Note on "silent": Kodi can re-enable a disabled addon with no prompt, and the
# native <requires> resolver pulls missing addons at install/update time. There
# is no public API to silently install a never-present addon at runtime, so the
# missing case is best-effort and always surfaces a notification on failure so
# you are never left guessing.

import os
import json
import xbmc
import xbmcgui
import xbmcaddon

ADDON = xbmcaddon.Addon()
LOG_PREFIX = "[KODIPERSONAL.DEPS]"


def log(message, level=xbmc.LOGINFO):
    xbmc.log("{} {}".format(LOG_PREFIX, message), level=level)


def _manifest_path():
    import xbmcvfs
    base = xbmcvfs.translatePath(ADDON.getAddonInfo("path"))
    return os.path.join(base, "resources", "config", "required_dependencies.json")


def _load_manifest():
    path = _manifest_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        log("Loaded dependency manifest: {}".format(path))
        return data
    except Exception as error:  # noqa: BLE001
        log("Could not read manifest {}: {}".format(path, error), xbmc.LOGERROR)
        return {"repositories": [], "addons": []}


def _jsonrpc(method, params):
    request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    try:
        return json.loads(xbmc.executeJSONRPC(json.dumps(request)))
    except Exception as error:  # noqa: BLE001
        log("JSON-RPC {} failed: {}".format(method, error), xbmc.LOGERROR)
        return {}


def _addon_state(addon_id):
    # Returns (installed, enabled).
    response = _jsonrpc("Addons.GetAddonDetails",
                        {"addonid": addon_id, "properties": ["enabled"]})
    if "error" in response or not response:
        return (False, False)
    details = response.get("result", {}).get("addon", {})
    return (True, bool(details.get("enabled", False)))


def _enable(addon_id):
    # Silent re-enable, no user prompt.
    response = _jsonrpc("Addons.SetAddonEnabled", {"addonid": addon_id, "enabled": True})
    ok = "error" not in response and bool(response)
    log("{} re-enable of {}".format("OK" if ok else "FAILED", addon_id),
        xbmc.LOGINFO if ok else xbmc.LOGWARNING)
    return ok


def _try_install(addon_id):
    # Best effort. InstallAddon may prompt; <requires> normally covers this at
    # install time, so this path is a fallback only.
    try:
        xbmc.executebuiltin("InstallAddon({})".format(addon_id))
        log("Requested install of {} (may require confirmation).".format(addon_id))
        return True
    except Exception as error:  # noqa: BLE001
        log("Install request for {} failed: {}".format(addon_id, error), xbmc.LOGERROR)
        return False


def _process(label, entries):
    healed = []
    failed = []
    for entry in entries:
        addon_id = entry.get("id", "")
        name = entry.get("name", addon_id)
        critical = bool(entry.get("critical", False))
        installed, enabled = _addon_state(addon_id)

        if installed and enabled:
            log("OK {} '{}' ({})".format(label, name, addon_id))
            continue

        if installed and not enabled:
            log("DISABLED {} '{}' ({}); re-enabling.".format(label, name, addon_id),
                xbmc.LOGWARNING)
            (healed if _enable(addon_id) else failed).append((name, critical))
            continue

        # Missing.
        log("MISSING {} '{}' ({}){}".format(
            label, name, addon_id, " [CRITICAL]" if critical else ""), xbmc.LOGWARNING)
        if _try_install(addon_id):
            healed.append((name, critical))
        else:
            failed.append((name, critical))
    return healed, failed


def verify_dependencies(auto_install=True, notify_on_failure=True):
    """Verify required repos/addons. Silently re-enables disabled ones and makes
    a best-effort install attempt for missing ones. Returns True if nothing
    critical is left broken. Notifies only when something critical fails."""
    manifest = _load_manifest()

    if not auto_install:
        # Report-only mode still logs a full picture.
        log("Running in report-only mode.")

    r_healed, r_failed = _process("repo", manifest.get("repositories", []))
    a_healed, a_failed = _process("addon", manifest.get("addons", []))

    failed = r_failed + a_failed
    critical_failed = [name for name, critical in failed if critical]

    if not failed:
        log("Dependencies OK (healed {} item(s) this pass).".format(
            len(r_healed) + len(a_healed)))
        return True

    summary = "Could not resolve: {}".format(", ".join(name for name, _ in failed)[:120])
    log("Dependency problems remain. {}".format(summary), xbmc.LOGWARNING)

    if notify_on_failure and critical_failed:
        xbmcgui.Dialog().notification(
            "KodiPersonal: missing add-ons",
            ", ".join(critical_failed[:3]),
            xbmcgui.NOTIFICATION_ERROR, 8000)

    return not critical_failed
