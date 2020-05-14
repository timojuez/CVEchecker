#!/usr/bin/env python3

import argparse,csv,sys
from db import *


class Main(object):

    def __init__(self):
        parser = argparse.ArgumentParser(description="Count amount of CVEs in one or more CSV files")
        parser.add_argument('csv', nargs="+", metavar="CSV", help="Read and modify this file")
        self.args = parser.parse_args()

    def readcsv(self,path):
        with open(path,"r") as fp:
            dr = csv.DictReader(fp)
            rows = [1 for r in dr if r["cve_id"]]
            return len(rows)

    def __call__(self):
        amount = sum([self.readcsv(f) for f in self.args.csv])
        print("%d rows."%amount)


if __name__ == '__main__':
    Main()()

