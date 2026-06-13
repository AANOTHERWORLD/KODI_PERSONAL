#!/usr/bin/env python3
# Build step for the thin personal layer.
#
# Walks every addon under src/, zips each into zips/<addon.id>/<addon.id>-<version>.zip,
# copies the addon.xml next to the zip, and regenerates the repo addons.xml plus its
# md5. This is intentionally the only build step, per the project rules.
#
# No secrets are read or written here. No em dashes used anywhere. Logging goes to
# stdout so the run is visible in CI or a terminal.

import hashlib
import os
import sys
import xml.etree.ElementTree as ET
import zipfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")
ZIPS_DIR = os.path.join(REPO_ROOT, "zips")


def log(message):
    print("[generate_repo] " + message)


def find_addons(src_dir):
    # An addon is any immediate subfolder of src/ that has an addon.xml.
    addons = []
    if not os.path.isdir(src_dir):
        log("no src directory at " + src_dir)
        return addons
    for name in sorted(os.listdir(src_dir)):
        path = os.path.join(src_dir, name)
        if os.path.isdir(path) and os.path.isfile(os.path.join(path, "addon.xml")):
            addons.append(path)
    return addons


def read_addon_meta(addon_path):
    addon_xml = os.path.join(addon_path, "addon.xml")
    tree = ET.parse(addon_xml)
    root = tree.getroot()
    addon_id = root.get("id")
    version = root.get("version")
    if not addon_id or not version:
        raise ValueError("addon.xml missing id or version at " + addon_xml)
    return addon_id, version, addon_xml


def zip_addon(addon_path, addon_id, version):
    out_dir = os.path.join(ZIPS_DIR, addon_id)
    os.makedirs(out_dir, exist_ok=True)
    zip_path = os.path.join(out_dir, addon_id + "-" + version + ".zip")

    # The zip must contain a top level folder named after the addon id, which is
    # what Kodi expects when installing from a zip.
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for base, _dirs, files in os.walk(addon_path):
            for fname in files:
                full = os.path.join(base, fname)
                rel = os.path.relpath(full, addon_path)
                arc = os.path.join(addon_id, rel)
                zf.write(full, arc)
    log("wrote " + os.path.relpath(zip_path, REPO_ROOT))

    # Copy addon.xml next to the zip so a repository can serve metadata directly.
    src_xml = os.path.join(addon_path, "addon.xml")
    dst_xml = os.path.join(out_dir, "addon.xml")
    with open(src_xml, "rb") as r, open(dst_xml, "wb") as w:
        w.write(r.read())
    return zip_path


def build_addons_xml(addons):
    root = ET.Element("addons")
    for addon_path in addons:
        tree = ET.parse(os.path.join(addon_path, "addon.xml"))
        root.append(tree.getroot())
    return root


def write_addons_xml(root):
    os.makedirs(ZIPS_DIR, exist_ok=True)
    addons_xml_path = os.path.join(ZIPS_DIR, "addons.xml")
    data = ET.tostring(root, encoding="utf-8")
    with open(addons_xml_path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write(data)
    md5 = hashlib.md5(open(addons_xml_path, "rb").read()).hexdigest()
    with open(addons_xml_path + ".md5", "w") as f:
        f.write(md5)
    log("wrote zips/addons.xml and addons.xml.md5")


def write_repo_alias(repo_zip_path):
    # Copy the repository addon zip to a stable short name at the repo root so it
    # can be installed in Kodi from one clean URL, for example
    # https://<user>.github.io/<repo>/repo.zip, without a versioned path.
    alias = os.path.join(REPO_ROOT, "repo.zip")
    with open(repo_zip_path, "rb") as r, open(alias, "wb") as w:
        w.write(r.read())
    log("wrote repo.zip alias from " + os.path.relpath(repo_zip_path, REPO_ROOT))


def _write_index(dir_path, entries, title):
    rows = "\n".join(
        '    <li><a href="{0}">{0}</a></li>'.format(name) for name in entries
    )
    html = (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8" />\n'
        "<title>{title}</title>\n</head>\n<body>\n"
        "<h1>{title}</h1>\n<ul>\n{rows}\n</ul>\n</body>\n</html>\n"
    ).format(title=title, rows=rows)
    with open(os.path.join(dir_path, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)


def write_html_indexes():
    # GitHub Pages and raw.githubusercontent do not serve browsable directory
    # listings, which Kodi needs to locate a zip in Install from zip file. We
    # emit simple HTML index pages whose <a href> links Kodi parses as a
    # directory listing. This makes the folder URLs browsable on device.

    # Root landing page: the clean repo install entry point.
    _write_index(REPO_ROOT, ["repo.zip", "zips/"], "KODI_PERSONAL")
    log("wrote index.html (root)")

    if not os.path.isdir(ZIPS_DIR):
        return

    # zips listing: addons.xml, checksum, and one folder per addon.
    top = []
    for name in sorted(os.listdir(ZIPS_DIR)):
        if name == "index.html":
            continue
        full = os.path.join(ZIPS_DIR, name)
        top.append(name + "/" if os.path.isdir(full) else name)
    _write_index(ZIPS_DIR, top, "KODI_PERSONAL zips")
    log("wrote zips/index.html")

    # Per addon folder listing so each zip is browsable too.
    for name in sorted(os.listdir(ZIPS_DIR)):
        full = os.path.join(ZIPS_DIR, name)
        if not os.path.isdir(full):
            continue
        files = [f for f in sorted(os.listdir(full)) if f != "index.html"]
        _write_index(full, files, "KODI_PERSONAL " + name)
    log("wrote per addon index.html files")


def main():
    log("repo root " + REPO_ROOT)
    addons = find_addons(SRC_DIR)
    if not addons:
        log("nothing to build, exiting")
        return 0
    repo_zip_path = None
    for addon_path in addons:
        addon_id, version, _xml = read_addon_meta(addon_path)
        log("packaging " + addon_id + " " + version)
        zpath = zip_addon(addon_path, addon_id, version)
        if addon_id.startswith("repository."):
            repo_zip_path = zpath
    root = build_addons_xml(addons)
    write_addons_xml(root)
    if repo_zip_path:
        write_repo_alias(repo_zip_path)
    else:
        log("no repository addon found, skipping repo.zip alias")
    write_html_indexes()
    log("done, " + str(len(addons)) + " addon(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
