# -*- coding: utf-8 -*-
# KODI_PERSONAL build: menu generator.
# Reads service.kodipersonal.setup/resources/config/lists.json and writes the
# AF3 skinvariables files into service.kodipersonal.setup/resources/menu/:
#   - the home (Discover) widget file (rows shown on the home section)
#   - one widget file per home slot (rows shown on that section)
#   - a 1104 submenu file (More Providers -> Apple TV+ / Disney+ / Prime Video)
#   - one sub-page node file per submenu provider (Latest Series / Latest Movies)
#   - slots.json (the slot manifest the setup service applies)
#
# AF3 only renders widget rows on home + slots 1101-1104 (the 5-slot cap, taken
# from the skin's own generator). Extra providers therefore live under the 1104
# submenu, each opening its own sub-page rather than a home row.
#
# A widget row may define its TMDb Helper query in one of three ways:
#   - "params": an ordered map of query keys to values (used for the bespoke
#               Discover and For You rows, e.g. trakt calendars with date ranges)
#   - "info" + "tmdb_type": the lean Trakt list form
#   - neither: a provider discover row, built from the section provider_id
#
# Run:  python3 _tools/generate_menu.py
# Verbose logging by design so a later monitoring agent can parse the output.

import os
import sys
import json
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ADDON = os.path.join(REPO, "src", "service.kodipersonal.setup")
# Fall back to a flat layout (addon at repo root) if src/ is not present.
if not os.path.isdir(ADDON):
    ADDON = os.path.join(REPO, "service.kodipersonal.setup")
CONFIG_DIR = os.path.join(ADDON, "resources", "config")
MENU_DIR = os.path.join(ADDON, "resources", "menu")
LISTS_FILE = os.path.join(CONFIG_DIR, "lists.json")

SKIN_ID = "skin.arctic.fuse.3"
FILE_PREFIX = "skinvariables-shortcut-"


def log(message):
    print("[generate_menu] {}".format(message))


def guid_for(*parts):
    # Deterministic so regenerating does not churn guids in git.
    raw = "|".join(str(p) for p in parts)
    return "guid-{}".format(hashlib.md5(raw.encode("utf-8")).hexdigest()[:8])


def load_lists():
    with open(LISTS_FILE, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    log("Loaded blueprint {}".format(LISTS_FILE))
    return data


def params_path(cfg, params, as_widget):
    # Build a TMDb Helper query from an ordered params map. Insertion order is
    # preserved so the generated path reads the same way every run.
    query = "&".join("{}={}".format(k, v) for k, v in params.items())
    url = "{tmdbh}?{query}".format(tmdbh=cfg["tmdbh"], query=query)
    return url + cfg["widget_suffix"] if as_widget else url


def discover_path(cfg, tmdb_type, provider_id, sort_by, as_widget):
    # Standard TMDb Helper discover URL for a watch provider. as_widget adds the
    # widget reload token + widget=true for home rows; navigation items omit it.
    url = (
        "{tmdbh}?info=discover&tmdb_type={t}&with_watch_providers={pid}"
        "&watch_region={region}&with_watch_monetization_types={monet}"
        "&sort_by={sort}"
    ).format(
        tmdbh=cfg["tmdbh"], t=tmdb_type, pid=provider_id,
        region=cfg["watch_region"], monet=cfg["monetization"], sort=sort_by,
    )
    return url + cfg["widget_suffix"] if as_widget else url


def info_path(cfg, info, tmdb_type, as_widget):
    # TMDb Helper info list (the lean Trakt row form).
    url = "{tmdbh}?info={info}&tmdb_type={t}".format(
        tmdbh=cfg["tmdbh"], info=info, t=tmdb_type)
    return url + cfg["widget_suffix"] if as_widget else url


def widget_path(cfg, w, section, as_widget=True):
    # Resolve a single widget row's path from params, info/tmdb_type, or a
    # provider discover fallback.
    if "params" in w:
        return params_path(cfg, w["params"], as_widget)
    if "info" in w:
        return info_path(cfg, w["info"], w["tmdb_type"], as_widget)
    return discover_path(cfg, w["tmdb_type"], section.get("provider_id", ""),
                         w.get("sort_by", "popularity.desc"), as_widget)


def node_url(provider_key):
    # Opens a skinvariables node as a browsable folder (the provider sub-page).
    return (
        "plugin://script.skinvariables/?info=get_shortcuts_node"
        "&menu={menu}&skin={skin}"
    ).format(menu=provider_key, skin=SKIN_ID)


def row(label, path, guid, target="videos", icon=""):
    return {"label": label, "icon": icon, "path": path, "target": target, "guid": guid}


def write_menu(name, items):
    path = os.path.join(MENU_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(items, handle, indent=4)
    log("Wrote {} ({} item(s))".format(name, len(items)))


def provider_key(name):
    # apple tv+ -> appletv ; prime video -> primevideo
    key = "".join(ch for ch in name.lower() if ch.isalnum())
    return "moreprov-{}".format(key)


def build():
    if not os.path.isdir(MENU_DIR):
        os.makedirs(MENU_DIR, exist_ok=True)
        log("Created menu output folder {}".format(MENU_DIR))

    cfg = load_lists()
    slots = []
    written = set()

    for section in cfg["sections"]:
        slot = section["slot"]
        name = section["name"]
        kind = section.get("type", "provider")
        # The home slot is always present in AF3, so it is never toggled. The
        # custom slots (1101-1104) are toggled on.
        slots.append({
            "slot": slot,
            "name": name,
            "toggle": "" if slot == "home" else "true",
        })

        if kind == "widgets":
            items = []
            for w in section["widgets"]:
                p = widget_path(cfg, w, section, as_widget=True)
                items.append(row(w["label"], p, guid_for(slot, w["label"])))
            fname = "{}{}widgets.json".format(FILE_PREFIX, slot)
            write_menu(fname, items)
            written.add(fname)

        elif kind == "provider":
            pid = section["provider_id"]
            items = []
            for r in cfg["full_provider_rows"]:
                p = discover_path(cfg, r["tmdb_type"], pid, r["sort_by"], as_widget=True)
                items.append(row(r["label"], p, guid_for(slot, r["label"])))
            fname = "{}{}widgets.json".format(FILE_PREFIX, slot)
            write_menu(fname, items)
            written.add(fname)

        elif kind == "submenu":
            # 1) Landing rows for the slot itself: one "New on <provider>" movie
            #    row per provider, so the section is never empty.
            landing = []
            for prov in section["submenu"]:
                p = discover_path(cfg, "movie", prov["provider_id"],
                                  "primary_release_date.desc", as_widget=True)
                landing.append(row("New on {}".format(prov["name"]), p,
                                   guid_for(slot, "landing", prov["name"])))
            fname = "{}{}widgets.json".format(FILE_PREFIX, slot)
            write_menu(fname, landing)
            written.add(fname)

            # 2) Submenu entries: each opens that provider's sub-page node.
            submenu = []
            for prov in section["submenu"]:
                pkey = provider_key(prov["name"])
                submenu.append(row(prov["name"], node_url(pkey),
                                   guid_for(slot, "submenu", prov["name"])))
            sname = "{}{}submenu.json".format(FILE_PREFIX, slot)
            write_menu(sname, submenu)
            written.add(sname)

            # 3) One sub-page node per provider: Latest Series + Latest Movies,
            #    as browsable folders (navigation, so no widget suffix).
            for prov in section["submenu"]:
                pkey = provider_key(prov["name"])
                page = []
                for r in cfg["provider_rows"]:
                    p = discover_path(cfg, r["tmdb_type"], prov["provider_id"],
                                      r["sort_by"], as_widget=False)
                    page.append(row("{} {}".format(prov["name"], r["label"]), p,
                                    guid_for(pkey, r["label"])))
                pfname = "{}{}.json".format(FILE_PREFIX, pkey)
                write_menu(pfname, page)
                written.add(pfname)
        else:
            log("WARNING: unknown section type '{}' for slot {}".format(kind, slot))

    # Slot manifest the setup service consumes. Recording the full known slot
    # range lets the service clear any stale slots (e.g. old 1105/1106) that a
    # previous version may have set.
    manifest = {
        "active_slots": slots,
        "known_slots": ["1101", "1102", "1103", "1104", "1105", "1106", "1107", "1108"],
    }
    with open(os.path.join(MENU_DIR, "slots.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=4)
    log("Wrote slots.json ({} active slot(s))".format(len(slots)))

    # Remove any stale generated menu files no longer in the blueprint.
    for existing in os.listdir(MENU_DIR):
        if existing.startswith(FILE_PREFIX) and existing.endswith(".json"):
            if existing not in written:
                os.remove(os.path.join(MENU_DIR, existing))
                log("Removed stale menu file {}".format(existing))

    log("Done. {} menu file(s) + slots.json written.".format(len(written)))


if __name__ == "__main__":
    try:
        build()
    except Exception as error:  # noqa: BLE001
        log("FAILED: {}".format(error))
        sys.exit(1)
