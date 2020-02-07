#!/usr/bin/env python3

import sys
from cvss import CVSS3
from db import *


sys.stderr.write("Creating a CVE list of all CVEs from database where integrity=none and confidentiality=none and output to stdout.")

metrics = [(e["cve_id"],CVSS3(e["vector"]).metrics) 
    for e in cve_db._execute("SELECT * FROM cve").fetchall()]
cves = [id_ for id_, metric in metrics if metric["I"] == "N" and metric["C"] == "N"]]
for cve in cves: print(cve)

