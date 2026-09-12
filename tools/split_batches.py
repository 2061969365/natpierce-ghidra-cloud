"""Filter ghidra-funcs.csv and split into batch lists for DecompileBatch.java.
Usage: python3 split_batches.py funcs.csv outdir batch_size scope
  scope=app  : only natpierce business packages (same regex as local triage)
  scope=full : everything except FUN_ unnamed stubs and entry
  scope=all  : literally everything (for stripped Delphi binaries)
Writes outdir/batch1.lst ... (lines: addr:name)
"""
import csv
import os
import re
import sys

APP = re.compile(
    r",(nat11|nat1x|nat22|natlan|socket|run|mapping|json|AES|encode|"
    r"TCPTools|UDPTools|node|server|upnpCon|values|myfmt|main)[.:]"
)

funcs_csv, outdir, size, scope = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
os.makedirs(outdir, exist_ok=True)

rows = []
with open(funcs_csv, newline="") as f:
    for i, line in enumerate(f):
        line = line.rstrip("\r\n")
        if i == 0 and line == "addr,name":
            continue
        if "," not in line:
            continue
        addr, name = line.split(",", 1)  # names may contain commas (C++/thunks)
        if not addr:
            continue
        if scope == "app":
            if not APP.search("," + name):
                continue
        elif scope == "all":
            pass
        else:
            if name.startswith("FUN_") or name in ("entry",):
                continue
        rows.append("%s:%s" % (addr, name))

n = 0
for i in range(0, len(rows), size):
    n += 1
    with open(os.path.join(outdir, "batch%d.lst" % n), "w") as f:
        f.write("\n".join(rows[i:i + size]) + "\n")
print("funcs=%d batches=%d scope=%s" % (len(rows), n, scope))
