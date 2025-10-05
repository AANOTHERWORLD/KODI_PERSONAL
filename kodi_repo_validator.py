#!/usr/bin/env python3
"""
Kodi GitHub Repository Validator
--------------------------------
Validates a GitHub-hosted Kodi repository folder (e.g., Repository/) by checking:
  1) addons.xml is reachable
  2) addons.xml.md5 exactly matches the MD5 of addons.xml (content)
  3) For each <addon> entry, tries to locate a corresponding ZIP under:
       <datadir>/<addon_id>/<addon_id>-<version>.zip
     and confirms the file is reachable (HTTP 200).

No external deps. Uses urllib, hashlib, and xml.etree.ElementTree.

USAGE EXAMPLES
--------------
# Validate your repo (AANOTHERWORLD / KODI_PERSONAL on branch main, path "Repository"):
python3 kodi_repo_validator.py \
  --owner AANOTHERWORLD \
  --repo KODI_PERSONAL \
  --branch main \
  --base-path Repository

# If your repo used a different folder (e.g., Build):
python3 kodi_repo_validator.py \
  --owner AANOTHERWORLD \
  --repo KODI_PERSONAL \
  --branch main \
  --base-path Build
"""
import argparse
import hashlib
import sys
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

RAW_BASE = "https://raw.githubusercontent.com"
GITHUB_RAW_BASE = "https://github.com"  # we'll also test the /raw/ form if needed

def http_head_or_range(url: str) -> (int, str):
    """
    Try a HEAD request first; if not allowed, try a byte-range GET to minimize traffic.
    Returns (status_code, reason)
    """
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), resp.reason
    except Exception as e:
        # Try a tiny GET
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("Range", "bytes=0-1")
            with urllib.request.urlopen(req) as resp:
                return resp.getcode(), resp.reason
        except Exception as e2:
            return 0, str(e2)

def http_get(url: str) -> bytes:
    with urllib.request.urlopen(url) as resp:
        return resp.read()

def compute_md5(data: bytes) -> str:
    h = hashlib.md5()
    h.update(data)
    return h.hexdigest()

def build_raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    """
    Return the canonical raw.githubusercontent.com URL:
      https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>
    """
    return f"{RAW_BASE}/{owner}/{repo}/{branch}/{path}".replace("\\", "/")

def build_github_raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    """
    Alternate raw URL (often bypasses networks that block raw.githubusercontent):
      https://github.com/<owner>/<repo>/raw/<branch>/<path>
    """
    return f"{GITHUB_RAW_BASE}/{owner}/{repo}/raw/{branch}/{path}".replace("\\", "/")

def fetch_with_fallbacks(owner: str, repo: str, branch: str, path: str) -> (bytes, str):
    """
    Try raw.githubusercontent first, then github.com/raw as fallback.
    Returns (content_bytes, url_used)
    """
    urls = [
        build_raw_url(owner, repo, branch, path),
        build_github_raw_url(owner, repo, branch, path),
    ]
    last_err = None
    for u in urls:
        try:
            data = http_get(u)
            return data, u
        except Exception as e:
            last_err = e
    raise last_err

def main():
    ap = argparse.ArgumentParser(description="Validate a GitHub-hosted Kodi repository folder (addons.xml, MD5, zips).")
    ap.add_argument("--owner", required=True, help="GitHub owner/org (case-sensitive)")
    ap.add_argument("--repo", required=True, help="GitHub repository name (case-sensitive)")
    ap.add_argument("--branch", default="main", help="Branch name (default: main)")
    ap.add_argument("--base-path", default="Repository", help="Folder that contains addons.xml and zips/")
    args = ap.parse_args()

    print("== Kodi GitHub Repository Validator ==")
    print(f"Owner   : {args.owner}")
    print(f"Repo    : {args.repo}")
    print(f"Branch  : {args.branch}")
    print(f"Base dir: {args.base_path}")
    print()

    # 1) Fetch addons.xml
    addons_xml_path = f"{args.base_path}/addons.xml"
    md5_path = f"{args.base_path}/addons.xml.md5"
    print("[1/4] Fetching addons.xml ...")
    try:
        addons_xml_bytes, addons_xml_url = fetch_with_fallbacks(args.owner, args.repo, args.branch, addons_xml_path)
        print(f"  OK: {addons_xml_url}")
    except Exception as e:
        print("  ERROR: Could not fetch addons.xml:", e)
        print("  HINT: Check case-sensitive path, branch name, and whether the file is committed & public.")
        sys.exit(1)

    # 2) Fetch addons.xml.md5 and compare
    print("[2/4] Fetching addons.xml.md5 and verifying MD5 ...")
    try:
        md5_bytes, md5_url = fetch_with_fallbacks(args.owner, args.repo, args.branch, md5_path)
        md5_text = md5_bytes.decode("utf-8").strip()
        calc_md5 = compute_md5(addons_xml_bytes)
        print(f"  MD5 in file : {md5_text}")
        print(f"  MD5 computed: {calc_md5}")
        if md5_text.lower() != calc_md5.lower():
            print("  ERROR: MD5 mismatch. Update addons.xml.md5 to contain ONLY the MD5 of addons.xml content.")
        else:
            print("  OK: MD5 matches addons.xml.")
    except Exception as e:
        print("  ERROR: Could not fetch addons.xml.md5:", e)
        print("  HINT: Ensure addons.xml.md5 exists next to addons.xml and contains ONLY the 32-char hash.")
        # continue; not fatal for zip existence tests

    # 3) Parse addons.xml
    print("[3/4] Parsing addons.xml ...")
    try:
        root = ET.fromstring(addons_xml_bytes)
    except Exception as e:
        print("  ERROR: addons.xml is not valid XML:", e)
        sys.exit(1)

    # Try to detect datadir from the repository addon entry
    datadir_base = None
    for addon_el in root.findall("addon"):
        for ext in addon_el.findall("extension"):
            if ext.attrib.get("point") == "xbmc.addon.repository":
                datadir_base = ext.findtext("datadir")
                if datadir_base:
                    datadir_base = datadir_base.strip()
                break
        if datadir_base:
            break

    if not datadir_base:
        # fallback to GitHub path under base-path/zips
        datadir_base = build_github_raw_url(args.owner, args.repo, args.branch, f"{args.base_path}/zips/")
        print(f"  INFO: No <datadir> found; using default: {datadir_base}")
    else:
        print(f"  Using <datadir>: {datadir_base}")

    # 4) For each addon entry, verify expected ZIP exists
    print("[4/4] Checking addon ZIPs ...")
    problems = 0
    for addon_el in root.findall("addon"):
        addon_id = addon_el.attrib.get("id")
        addon_ver = addon_el.attrib.get("version")
        if not addon_id or not addon_ver:
            print("  WARN: Skipping addon without id/version.")
            continue
        if not datadir_base.endswith("/"):
            datadir_base += "/"
        zip_url = f"{datadir_base}{addon_id}/{addon_id}-{addon_ver}.zip"
        code, reason = http_head_or_range(zip_url)
        status = "OK" if code in (200, 206) else "MISSING"
        if status != "OK":
            problems += 1
        print(f"  {status}: {addon_id} v{addon_ver} -> {zip_url} (HTTP {code} {reason})")

    if problems == 0:
        print("\nAll checks passed ✔")
        sys.exit(0)
    else:
        print(f"\nFound {problems} problem(s). See lines above for the first failing URL(s).")
        print("Fix the filename/path/version to match the expected pattern or update <datadir> accordingly.")
        sys.exit(2)

if __name__ == "__main__":
    main()
