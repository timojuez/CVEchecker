#!/usr/bin/env python3

import argparse,csv,sys
from db import *


class Main(object):

    def __init__(self):
        parser = argparse.ArgumentParser(description="Filter cve_id col in csv file by cve_id col in other csv file")
        parser.add_argument('csv', metavar="CSV", help="Read and modify this file")
        parser.add_argument('--blacklist', nargs="+", metavar="PATH", help='CVE list with CVEs to be removed')
        parser.add_argument('--whitelist', nargs="+", metavar="PATH", help='CVE list with CVEs to make an intersection with')
        #parser.add_argument('--reason', metavar="TEXT", help='Reason table column text.')
        self.args = parser.parse_args()

    def readf(self,f):
        with open(f) as fp:
            return fp.readlines()
    
    def loadCVElist(self, paths):
        if not paths: return None
        def readcsv(path):
            with open(path,"r") as fp:
                csvfile = csv.DictReader(fp)
                return [e["cve_id"] for e in csvfile]
        return [x for path in paths for x in readcsv(path)]
            
    def __call__(self):
        blacklist = self.loadCVElist(self.args.blacklist)
        whitelist = self.loadCVElist(self.args.whitelist)
        with open(self.args.csv,"r") as fp:
            csvfile = csv.DictReader(fp)
            csvfile = [e for e in csvfile 
                if (not whitelist or e["cve_id"] in whitelist)
                and (not blacklist or e["cve_id"] not in blacklist)]
        if len(csvfile) == 0:
            sys.stderr.write("WARNING: Filter result is empty\n")
            return
        writer=csv.DictWriter(sys.stdout, fieldnames=csvfile[0].keys())
        writer.writeheader()
        for data in csvfile: writer.writerow(data)


if __name__ == '__main__':
    Main()()

