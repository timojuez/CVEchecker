#!/usr/bin/env python3

import argparse,csv,sys
from db import *


class Main(object):

    def __init__(self):
        parser = argparse.ArgumentParser(description="Create cve table from list")
        parser.add_argument('path', metavar="PATH", help="List of CVEs (format: 'CVE-2018-10546')")
        parser.add_argument('--csv', metavar="PATH", help='File name where results shall be stored.')
        #parser.add_argument('--reason', metavar="TEXT", help='Reason table column text.')
        self.args = parser.parse_args()

    def __call__(self):
        with open(self.args.path) as fp:
            blacklist = [line_strip for line in fp for line_strip in [line.strip()] if line_strip]
        rows = list(cve_db.get_cves_by_ids(ids=blacklist))
        if len(rows) == 0: 
            sys.sterr.write("No CVEs found.\n")
            exit(1)
        with open(self.args.csv,"w") as fp:
                writer=csv.DictWriter(fp, fieldnames=rows[0].keys())
                writer.writeheader()
                for data in rows: writer.writerow(data)
                
if __name__ == '__main__':
    Main()()

