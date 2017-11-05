# subdomain_searcher
This script accepts a domain name and queries two sources (censys.io and crt.sh) to gather subdomains. The script includes an additional option, -cw (--checkweb), which will then sending an web request to each domain enumerated, and will return the HTTP response code as well as the title of the website (if possible). 

This script is an excellent way to map the Internet presence or an organization, and the checkweb option gives you a good idea of some of the web apps that are out there.

There is also a an option that is still under development, -cc (--checkcreds), that will attempt guessing default credentials against the sites returned from the checkweb option.

Installation: This script requires a few several modules that you may have to install, including:

requests – pip install requests

requests_ntlm – pip install requests_ntlm

selenium – pip install selenium

The script also uses PhantomJS with the -cw (--checkweb) option for use with selenium for a headless browser experience. It will run without PhantomJS, however the results will be less accurate. I recommend using a package manager (yum, brew, choco, etc.) for installation, as it will install the executable in your PATH.

Usage:
Python subdomain_searcher.py –domain domainname.com

C:\Tools>python subdomain_searcher.py -d github.com

 [+]    Getting subdomains for github.com from censys.io


 [+]    Getting subdomains for github.com from crt.sh


 [+]    Domains found for github.com:

        offer.github.com
        visualstudio.github.com
        *.registry.github.com
        id.github.com
        atom-installer.github.com
        
        <snip>

To print the list of domains to a file, use the -o (--outfile) option.
To visit each domain name and grab the title, use the -cw (--checkweb) option:

C:\Tools>python subdomain_searcher.py -d github.com -cw

 [+]    Getting subdomains for github.com from censys.io


 [+]    Getting subdomains for github.com from crt.sh


 [+]    Domains found for github.com:

        <snip>

 [+]    Checking each domain to see if it is accessible...

 [+]    Site: vpn-ca.iad.github.com 
        Response Code: 200
        Title: Unable to parse title
        
 [+]    Site: community.github.com
        Response Code: 200
        Title: GitHub Sponsorships
 [+]    Site: www.github.com
        Response Code: 200
        Title: The world&#39;s leading software development platform · GitHub', '1clr-code-hosting
 [+]    Site: maintainers.github.com
        Response Code: 200
        Title: Sign in to GitHub · GitHub

The script will save the checkweb results to a file by default. A -i (--infile) option is included in case you want to submit a list of domain names to use the checkweb option against. Just do:

python subdomain_searcher.py -i domain_file.txt -cw

The checkcreds portion of the script will be updated as I continue development. Other options include a -v (--verbose) option which will print more message to the console.
