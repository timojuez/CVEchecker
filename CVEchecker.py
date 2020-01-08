#!/usr/bin/env python3
import json, sys
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

        
def load_cve_whitelist(f):
    cves = []
    with open(f, encoding='utf-8') as p_file:
        for line in p_file:
            cves.append(line.replace("\n", "").replace("\r", ""))
    return cves    


def sanitize_version(version):
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
    
def create_packages_file():
    apps=os.popen("apt list --installed").readlines()
    p_file = open("./packages.txt", 'w')
    for app in apps:
        if ("/") in app:
            name=app.split("/")[0]
            version = app.split()[1]
            p_file.write("{0} {1}\n".format(name,version))
    p_file.close
    
    
def load_packages(f):
    with open(f, encoding='utf-8') as p_file:
        p=[line.split(" ",1) for line in p_file]
    p = [(name,sanitize_version(version)) for name,version in p]
    return p

    
class CVE_Parser(object):

    @classmethod
    def install_cve_from_web(self):
        if args.cve_dbs:
            cve_db_paths = args.cve_dbs.split(",")
        else:
            cve_db_paths = self._download_cve_dbs()
        cve_db.create_source()
        cve_db.create_cve()
        cve_db.create_product()
        cve_dbs = CVE_Parser._convert_cve_dbs(cve_db_paths)
        print ("\n[*] {0} CVE databases loaded:".format(len(cve_db_paths)))
        for db_path in cve_db_paths:
            print ("[*] {0}".format(db_path))
        return cve_dbs

    @classmethod
    def _download_cve_dbs(self):
        current_year=datetime.datetime.now().year
        years=range(2002, current_year + 1)
        print ("\n[*] download CVEs from {0}-{1}".format("2002", current_year))
        years=[] # TODO: skipping
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

    @classmethod
    def _convert_cve_dbs(self,cve_db_paths):
        sys.stderr.write("[*] Converting database")
        for cve_db_path in cve_db_paths:
            with open(cve_db_path, encoding='utf-8') as fp:
                self._parseDB(cve_db_path,json.load(fp))
            sys.stderr.write(".");sys.stderr.flush()
        sys.stderr.write("\n")
        #cve_db.session.commit()
        
    @classmethod
    def load_cve_db(self):
        #return pd.read_pickle("csv_db.pkl")
        pass

    @classmethod
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
    
    @classmethod
    def _parseDB(self,path,cve_db_):
        source_id = cve_db.insert_source(filename=path,added_on=str(datetime.datetime.now()))
        
        for cve in cve_db_["CVE_Items"]:
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
        """
        return [db.insert(cve_db.cve).values(
                product_name=product_data['product_name'],
                product_version=version_data['version_value'],
                cve_id=cve['cve']['CVE_data_meta']['ID'],
                cve_description=cve['cve']['description']['description_data'][0]['value'],
                base_metric=base_metric,
                impact_score=impact_score,
                impact_severity=impact_severity,
            )
            for cve in cve_db_["CVE_Items"] for vendor in cve['cve']['affects']['vendor']['vendor_data'] for product_data in vendor['product']['product_data']
            for version_data in product_data['version']['version_data'] for base_metric,impact_score,impact_severity in [self._parseImpact(cve)] ]
        """


def check_packages(packages, cve_dbs, whitelist):
    """
    @packages: [(name,version)]
    @cve_dbs: see CVE_Parser.parseDB
    """
    try:
        cve_db._execute("DROP TABLE packages")
    except Exception as e: pass
    
    with cve_db.transaction() as t:
        try:
            cve_db.create_packages()
            for name,version in packages: 
                cve_db.insert_package(product_name=name,product_version=version)
            rows = cve_db.get_cves()
        finally: 
            t.rollback()
    for d in rows:
        print(("%(product_name)s %(product_version)s\t"
            "%(cve_id)s (%(base_metric)s: %(impact_score)s, %(impact_severity)s)")%d)
    
    
def check_package (package, cve_dbs, whitelist):
    """
    packages: (name, version)
    cves: product_data['product_name'], product_data['version']['version_data'][['version_value']]
    """
    
    name,version = package.split(" ",1)
    print ("\n[*] lookup \"{0} {1}\"".format(name, version))
    
    for cve_db in cve_dbs:
        for cve in cve_db["CVE_Items"]:
            for vendor in cve['cve']['affects']['vendor']['vendor_data']:
                for product_data in vendor['product']['product_data']:
                    if name not in product_data['product_name']: continue
                    for version_data in product_data['version']['version_data']:
                        if version != version_data['version_value']: continue
                        product_name=product_data['product_name']
                        product_version=version_data['version_value']
                        cve_id=cve['cve']['CVE_data_meta']['ID']
                        base_metric=''
                        impact_score=''
                        impact_severity=''
                        if 'baseMetricV3' in cve['impact']:
                            base_metric='cvssV3'
                            impact_score=cve['impact']['baseMetricV3']['cvssV3']['baseScore']
                            impact_severity=cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        else:
                            base_metric='cvssV2'
                            impact_score=cve['impact']['baseMetricV2']['cvssV2']['baseScore']
                            impact_severity=cve['impact']['baseMetricV2']['severity']  
                        cve_description=cve['cve']['description']['description_data'][0]['value'] # should only be english description
                        if cve_id in whitelist:
                            continue
                        print ("[+] {0} {1} is affected by {2}, {3}-score {4} ({5})".format(product_name, product_version, cve_id, base_metric, impact_score, impact_severity))
                        if args.csv:
                            csv_file.write("{0};{1};{2};{3};{4};{5};{6};{7}\n".format(name, product_name, version, cve_id, base_metric, impact_score, impact_severity, cve_description))
                                

def check():
    cve_whitelist=[]
    if args.csv:
        csv_file = open(args.csv, 'w')
    packages = load_packages(packages_file)
    print ("\n[*] {0} packages to check:".format(len(packages)))
    for name,version in packages:
        print ("[*] {0} {1}".format(name,version))
    if args.whitelist_file:
        cve_whitelist=load_cve_whitelist(args.whitelist_file)
        print ("\n[*] {0} CVEs whitelisted:".format(len(cve_whitelist)))
        for cve_id in cve_whitelist:
            print ("[*] {0}".format(cve_id)) 
    cve_dbs=CVE_Parser.load_cve_db()
    if args.csv:
        csv_file.write("Name;Matching Name;Version;CVE;Metric;Score;Severity;Description\n")
    check_packages(packages, cve_dbs, cve_whitelist)
    if args.csv:
        csv_file.close   
        
def parseArgs():
    global args
    parser = argparse.ArgumentParser(description="This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. It gets fed with two files, the package list file and a cve database file(s). These can be obtained manually or by using the paramaters --download-cve-dbs and --create-packages-file.")

    parser.add_argument('--download-cve-dbs', action="store_true", help='Download and extract all CVE databases since 2002 from https://nvd.nist.gov/vuln/data-feeds#JSON_FEED). More than 1 GB of free harddrive space is needed.')
    parser.add_argument('--create-packages-file', action="store_true", help='Create a list of installed packages and corresponding versions. Just works for packages installed with APT.')
    parser.add_argument('--packages-file', help='A whitespace seperated list with software name and version. If parameter is not set, the file ./packages.txt will be loaded by default.')
    parser.add_argument('--cve-dbs', help='Path to CVE database file(s). Multiple paths must be seperated by a comma. The json content must follow the NVD JSON 0.1 beta Schema (https://nvd.nist.gov/vuln/data-feeds#JSON_FEED). If parameter is not set, all files with the name \"nvdcve-1.0-YYYY.json\" will be loaded by default.')
    parser.add_argument('--whitelist-file', help="A list of CVEs (format: 'CVE-2018-10546') which won't show up in the result. Can be used to exclude false-positives.")
    parser.add_argument('--no-check', action="store_true", help='Use it together with --download-cve-db or --create-packages-file to skip the cve checking process afterwards.')
    parser.add_argument('--csv', help='File name where results shall be stored.')

    args = parser.parse_args()




# defaults
packages_file=""
cve_db_paths=[]


if __name__ == '__main__':
    parseArgs()
    if args.download_cve_dbs:
        CVE_Parser.install_cve_from_web()

    if args.create_packages_file:
        create_packages_file()

    if args.packages_file:
        packages_file = args.packages_file
    else:
        packages_file = './packages.txt'

    if not args.no_check: check()

