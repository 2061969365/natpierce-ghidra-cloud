"""Resolve a Ghidra release asset URL by version prefix.
Usage: python3 resolve_ghidra.py 12.1.2
Prints the browser_download_url of the first asset named ghidra_<ver>_PUBLIC_*.zip
in the matching release (uses GitHub API, works with GITHUB_TOKEN or anonymously).
"""
import json
import sys
import urllib.request

ver = sys.argv[1] if len(sys.argv) > 1 else "12.1.2"
repo = "NationalSecurityAgency/ghidra"


def api(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    import os
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


releases = api("https://api.github.com/repos/%s/releases?per_page=100" % repo)
for rel in releases:
    for a in rel.get("assets", []):
        name = a.get("name", "")
        if name.startswith("ghidra_%s_PUBLIC_" % ver) and name.endswith(".zip"):
            print(a["browser_download_url"])
            sys.exit(0)
print("no asset for ghidra %s" % ver, file=sys.stderr)
sys.exit(1)
