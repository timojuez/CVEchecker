# CVEC - CVE checking tools
A simple but powerful offline checker to lookup CVEs for software packages.

## Description 
This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. Once after initialising the database with parameter init, you can feed it with the package list file.

## Features
* Download CVE databases
* Create list of installed applications
* Lookup corresponding CVEs to applications+version
* CVE lookup works offline
* CSV output
* CVE blacklist management - Blacklist CVEs in various custom files
* Get a report about different results from different runs

## Install
`$ git clone https://github.com/timojuez/CVEchecker.git && pip3 install --user ./CVEchecker`

## Usage
The program consists of many small tools that find CVEs for a given software version.

* The program downloads files and creates a database of CVEs
`cvec_checker init`
* Reads program names and version from a text input file and writes CVEs in csv format 
`cvec_checker find-cve --output cves.csv input_file`
* Blacklist CVE ids
    * Create blacklist with all CVEs that do not affect confidentiality or integrity 
  `cvec_find_availability_cves > blacklist`
    * Convert CVE ids list to csv containing CVE description etc `cvec_cvelist2csv --output blacklist.csv blacklist`
    * Remove CVEs that are not in cves.csv: ` cvec_filter_cve_list.py --whitelist cves.csv -- blacklist.csv > blacklist_filtered.csv`
    * Remove CVEs that are already in other_blacklist1.csv and other_blacklist2.csv: `cvec_filter_cve_list --blacklist other_blacklist1.csv other_blacklist2.csv -- blacklist.csv > blacklist_filtered.csv`
    * Remove CVEs from blacklist1.csv and blacklist2.csv in cves.csv: `cvec_filter_cve_list --blacklist blacklist1.csv blacklist2.csv -- cves.csv > cves_filtered.csv`
* Print a report comparing all csv files with the same name in dir1 and dir2: `cvec_summary dir1 dir2`



## Missing Features
* Show only --criticality findigs (LOW,MEDIUM,HIGH,...)
* show exact reason for matching (name + version, fuzzy/exact,...)

# References
* See also https://github.com/intel/cve-bin-tool#csv2cve

