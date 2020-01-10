# CVEchecker
A simple but powerful offline checker to lookup CVEs for software packages.

## Description 
This little tool helps you to identify vulnerable software packages, by looking them up in the CVE (Common Vulnerabilities and Exposure) databases from the NVD. CVEchecker is designed to work offline. Once after initialising the database with parameter init, you can feed it with the package list file.

## Features
* Download CVE databases
* Create list of installed applications
* Lookup corresponding CVEs to applications+version
* CVE lookup works offline
* CSV output

## Dependencies
   ```Python 3.4```
   ```pugsql```

## Quickstart
1. Download CVE databases. Don't run the check afterwards.

   ``` ~# python CVEchecker.py init ```

2. Run CVEchecker against all packages in the "package.txt" file.

   ``` ~# python CVEchecker.py find-cve ./package.txt```

3. Like #2 but exclude some CVEs from the result and save results as csv.

   ``` ~# python CVEchecker.py --blacklist /some/blacklisted_csvs.txt --csv output.csv ./package.txt ```
    

## Missing Features
* Show only --criticality findigs (LOW,MEDIUM,HIGH,...)
* disable fuzzy search to avoid false positives
* show exact reason for matching (name + version, fuzzy/exact,...)
