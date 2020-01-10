#!/usr/bin/env python3
import json, sys, csv
import pugsql
from pprint import pprint
import argparse
import os
import zipfile
import io
import datetime
import requests


cve_db = pugsql.module("queries/")
cve_db.connect("sqlite:///cve_db.db")

        
class PackageLoader(object):
    """ Reads the list of the customer's packages in use """
  
    @classmethod
    def create_packages_file(self):
        apps=os.popen("apt list --installed").readlines()
        p_file = open("./packages.txt", 'w')
        
        for app in apps:
            if ("/") in app:
                name=app.split("/")[0]
                version = app.split()[1]
                p_file.write("{0} {1}\n".format(name,version))
        p_file.close
        
    def __init__(self,f):
        with open(f, encoding='utf-8') as p_file:
            p=[line.strip().rsplit(" ",1) for line in p_file if line.strip()]
        p = [(name.replace(" ","_"),self._sanitize_version(version)) for name,version in p]
        p = sorted(p,key=lambda e:e[0].upper())
        print("\n[*] {0} packages to check:".format(len(p)))
        for name,version in p:
            print ("[*] {0} {1}".format(name,version))
        self.packages = p

    def _sanitize_version(self,version):
        # splitting app version examples:
        # 2.0.4~r204
        if version[0]=="v": version = version[1:]
        version = version.split("~")[0]
        # 2.0.26-1ubuntu2
        version = version.split("-")[0]
        # 3.113+nmu3ubuntu4
        version = version.split("+")[0]
        # 4:15.1
        if ":" in version:
            version = version.split(":")[1]
        return version

    
class CVE_DB_Installer(object):
    """ Read CVE as JSON from the internet and create local database """

    def __init__(self,json_db_paths=None):
        if not json_db_paths:
            json_db_paths = self._download_cve_dbs()
        cve_db.create_source()
        cve_db.create_cve()
        cve_db.create_product()
        cve_dbs = self._convert_cve_dbs(json_db_paths)
        print ("\n[*] {0} CVE databases loaded:".format(len(json_db_paths)))
        for db_path in json_db_paths:
            print ("[*] {0}".format(db_path))

    def _download_cve_dbs(self):
        current_year=datetime.datetime.now().year
        years=range(2002, current_year + 1)
        print ("\n[*] download CVEs from {0}-{1}".format("2002", current_year))
        #years=[] # TODO: skipping
        for year in years:
            zip_file_url = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-{0}.json.zip".format(year)
            print ("[*] download and extract {0}".format(zip_file_url))
            r = requests.get("" + zip_file_url)
            if r.ok:
                z = zipfile.ZipFile(io.BytesIO(r.content))
                z.extractall()
            else:
                print ("[!] download failed")

        cve_db_paths = []
        for f in os.listdir("./"):
            if f.startswith('nvdcve-1.0-') and f.endswith('.json'):
                cve_db_paths.append(f)
        return cve_db_paths

    def _convert_cve_dbs(self,cve_db_paths):
        sys.stderr.write("[*] Converting database")
        for cve_db_path in cve_db_paths:
            with open(cve_db_path, encoding='utf-8') as fp:
                self._parseJSON(cve_db_path,json.load(fp))
            sys.stderr.write(".");sys.stderr.flush()
        sys.stderr.write("\n")
        
    def _parseImpact(self,cve):
        if 'baseMetricV3' in cve['impact']:
            base_metric='cvssV3'
            impact_score=cve['impact']['baseMetricV3']['cvssV3']['baseScore']
            impact_severity=cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        elif 'baseMetricV2' in cve['impact']:
            base_metric='cvssV2'
            impact_score=cve['impact']['baseMetricV2']['cvssV2']['baseScore']
            impact_severity=cve['impact']['baseMetricV2']['severity']  
        else: raise
        return base_metric,impact_score,impact_severity
    
    def _parseJSON(self,path,json_d):
        source_id = cve_db.insert_source(filename=path,added_on=str(datetime.datetime.now()))
        
        for cve in json_d["CVE_Items"]:
            if len(cve["cve"]["affects"]["vendor"]["vendor_data"]) == 0: continue
            base_metric,impact_score,impact_severity = self._parseImpact(cve)
            cve_id = cve_db.insert_cve(
                source=source_id,
                cve_id=cve['cve']['CVE_data_meta']['ID'],
                cve_description=cve['cve']['description']['description_data'][0]['value'],
                base_metric=base_metric,
                impact_score=impact_score,
                impact_severity=impact_severity,
            )
            cve_db.insert_product(*tuple([dict(
                            cve=cve_id,
                            product_name=product_data['product_name'],
                            product_version=version_data['version_value'],
                )
                for vendor in cve['cve']['affects']['vendor']['vendor_data']
                for product_data in vendor['product']['product_data']
                for version_data in product_data['version']['version_data']
            ]))


class CVE_Finder(object):
    
    def __init__(self,packages, blacklist):
        """
        @packages: [(name,version)]
        """
        try:
            cve_db._execute("DROP TABLE packages")
        except Exception as e: pass
        
        with cve_db.transaction() as t:
            try:
                cve_db.create_packages()
                for name,version in packages: 
                    cve_db.insert_package(product_name=name,product_version=version)
                self.cves = list(cve_db.get_cves(blacklist=blacklist))
                print("Vulnerability List\n")
                for d in self.cves:
                    print(("%(product_name)s %(product_version)s\t"
                        "%(cve_id)s\t%(base_metric)s: %(impact_score)s, %(impact_severity)s")%d)
                print()
                self.unmatched = list(cve_db.get_unmatched())
                if self.unmatched:
                    print("[!] %d of %d packages not found in DB:"%(len(self.unmatched),len(packages)))
                    for d in self.unmatched: print("[*] %s"%d["product_name"])
            finally: 
                t.rollback()
        

class Main(object):

    def __init__(self):
        parser = argparse.ArgumentParser(description="This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. Once after initialising the database with parameter init, you can feed it with the package list file.")
        subparsers = parser.add_subparsers(dest="command")
        subparsers.required = True

        init = subparsers.add_parser('init', help='Download and extract all CVE databases since 2002 from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED). More than 1 GB of free harddrive space is needed.')
        init.set_defaults(func=self.init_db)
        init.add_argument('--cve-dbs', metavar="PATH", nargs="+", help='Instead of downloading, use a local path to CVE database file(s). The json content must follow the NVD JSON 0.1 beta Schema (https://nvd.nist.gov/vuln/data-feeds#JSON_FEED).')

        create_package_file = subparsers.add_parser('create-packages-file', help='Create a list of locally installed packages and corresponding versions. Just works for packages installed with APT.')
        create_package_file.set_defaults(func=PackageLoader.create_packages_file)

        find_cve = subparsers.add_parser('find-cve')
        find_cve.add_argument("packages_file",metavar="packages-file",help='A whitespace seperated list with software name and version.')
        find_cve.add_argument('--blacklist', metavar="PATH", help="A list of CVEs (format: 'CVE-2018-10546') which will not show up in the result. Can be used to exclude false-positives.")
        find_cve.add_argument('--csv', metavar="PATH", help='File name where results shall be stored.')
        find_cve.set_defaults(func=self.find_cve)
        
        self.args = parser.parse_args()
        self.args.func()

    def init_db(self):
        CVE_DB_Installer(self.args.cve_dbs)

    def find_cve(self):
        packages_file = self.args.packages_file or './packages.txt'
        packages = PackageLoader(packages_file).packages

        cve_blacklist=self._load_cve_blacklist(self.args.blacklist) \
            if self.args.blacklist else []
        print("\n")
        finder = CVE_Finder(packages, cve_blacklist)
        if self.args.csv and len(finder.cves)>0:
            with open(self.args.csv, 'w') as fp:
                writer=csv.DictWriter(fp, fieldnames=finder.cves[0].keys())
                writer.writeheader()
                for data in finder.cves: writer.writerow(data)

    def _load_cve_blacklist(self,f):
        with open(f, encoding='utf-8') as p_file:
            cves = sorted([line_stripped for line in p_file 
                for line_stripped in [line.strip()] if line_stripped])
        print ("\n[*] {0} CVEs blacklisted:".format(len(cves)))
        for cve_id in cves:
            print ("[*] {0}".format(cve_id)) 
        return cves    


if __name__ == '__main__':
    Main()

