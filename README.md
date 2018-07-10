# Subdomain searcher
This script accepts a domain name and queries multiple sources to gather subdomains. The script includes an additional option, -s (--scan), which will attempt to connect on ports 80, 443, 8080, and 8443 to check connectivity to the system. 

This script is an excellent way to map the Internet presence or an organization, and the checkweb option.

Requirements: This script requires the requests module and Python3:

Usage:
```
Python subdomain_searcher.py -d domainname.com -s
```
Will lookup subdomains from multiple sources and then scan the returned subdomains to check connectivity.
