try:
    import argparse
    import requests
    import re
    from requests.auth import HTTPBasicAuth
    from requests.auth import HTTPDigestAuth
    from requests_ntlm import HttpNtlmAuth
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from selenium import webdriver
    from selenium.webdriver.support.ui import WebDriverWait
except ImportError as error:
    missing_module = str(error).split(' ')[-1]
    print('\nThis script requires several modules that you may not have.')
    print('Missing module: {}'.format(missing_module))
    print('Try running "pip install {}", or do an Internet search for installation instructions.'.format(missing_module.strip("'")))
    exit()
    

__author__ = 'Jake Miller'
__date__ = '20171019'
__version__ = '0.01'
__description__ = 'Accepts a domain name and queries multiple sources to return subdomains.'


def get_censys_report(domain):
    """Navigates to the censys site and looks up subdomains.
    
    Args:
        domain: An domain name to look up subdomains
        
    Returns:
        A list object containing the the subdomains returned from censys.
    """
    url = "https://censys.io/certificates/report?q=%28.{}%29+AND+tags.raw%3A+%22unexpired%22&field=parsed.names.raw&max_buckets=".format(domain)
    print("\n [+]\tGetting subdomains for {} from censys.io\n".format(domain))
    resp = requests.get(url)
    data = re.findall(r'names%3A\+%22(.*?)%22', resp.text)
    subs = []
    for item in data:
        if domain in item:
            subs.append(item)
            
    return subs

    
def get_crt_report(domain):
    """Navigates to the crt site and looks up subdomains.
    
    Args:
        domain: An domain name to look up subdomains
        
    Returns:
        A list object containing the the subdomains returned from crt.
    """
    url = "https://crt.sh/?q=%25.{}".format(domain)
    print("\n [+]\tGetting subdomains for {} from crt.sh\n".format(domain))
    resp = requests.get(url)
    data = re.findall(r'<TD>(.*?)</TD>', resp.text)
    subs = []
    for item in data:
        if domain in item:
            subs.append(item
            
    return subs

    
def checkweb(domain_names):
    """Sends a web request to each site in a provided list.
    
    Args:
        domain_names: A list object containing domains to 
        send HTTP requests to. Will print the HTTP respoonse
        code and site title if reachable.
        
    Returns:
        web_ident, non_ident_basic_auth.
    """
    print('\n [+]\tChecking each domain to see if it is accessible...\n')
    if not type(domain_names) == list:
        domain_names = list(domain_names)
    filename = domain_names[0].split(".")[-2] + '_checkweb_out.txt'
    file = open(filename,'a')
    web_ident = {}
    non_ident_basic_auth = []
    for domain in domain_names:
        if '*' in domain:
            domain = domain.strip('*')[1:]
        url = "https://{}".format(domain)
        if args.verbose:
            print("\n [+]\tChecking {}...".format(url))
        try:
            resp = requests.get(url, headers=headers, verify=False, timeout=2)
        except:
            if args.verbose:
                print(' [-]\tUnable to connect to site: {}'.format(domain))
            continue
        title = re.findall(r'<title[^>]*>([^<]+)</title>',resp.text, re.IGNORECASE)
        title = str(title).strip("[,],'")
        if title == "":
            if args.verbose:
                print(' [-]\tThe title returned empty. Using browser emulation to get site title...')
                print('    \tThis could take ~10 seconds...')
            try:
                browser = webdriver.PhantomJS()
                browser.get(url)
                WebDriverWait(browser, 2)
                title = browser.title
                browser.close()
            except:
                pass
        print(' [+]\tSite: {}'.format(domain))
        print('    \tResponse Code: {}'.format(resp.status_code))
        if title == "":
            print('    \tTitle: Unable to parse title')
        else:
            try:
                print('    \tTitle: {}'.format(title))
            except UnicodeEncodeError:
                print('    \tTitle: {}'.format(title.encode('utf-8')))
        try:
            file.write('Site: {}\tResponse Code: {}\tTitle: {}\n'.format(domain, resp.status_code, title))
        except UnicodeEncodeError:
            file.write('Site: {}\tResponse Code: {}\tTitle: {}\n'.format(domain, resp.status_code, title.encode('utf-8')))
        if resp.status_code == 401 and title == "":
            non_ident_basic_auth.append(domain)
        if str(resp.status_code).startswith('2') or str(resp.status_code).startswith('3') or resp.status_code == 401 and title != "":
            web_ident[domain] = title
            
    return web_ident#, non_ident_basic_auth


def check_creds(sites):
    '''Sends a web request attempting to login to each site using 
    the domain and parameters in a provided dictionary.
    
    Args:
        sites: A dictionary object containing domain login path with
        parameters and default credentials.
        
    Returns:
        Nothing.
    '''
    creds = credfile()
    for item in sites:
        if sites[item].lower() in creds:
            s = requests.Session()
            site_title = sites[item].lower()
            data = creds[site_title]
            post_data = data[1]
            url = "https://{}{}".format(item, data[0])
            print('\n [+]\tTrying default credentials on {} at {}.'.format(site_title.title(), url))
            resp = s.post(url, post_data)
            
            print(" [+]\tThe application responded with a code of {}.".format(str(resp.status_code)))
            print(" [+]\tThe current URL is {}.".format(resp.url))
            if resp.url != url:
                print(' [+]\tPossible successful login due to redirect after login.')

    
def main():
    """Main function of the script.
    """
    subdomains = []
    if args.domain:
        subdomains = get_censys_report(domain)
        subdomains += get_crt_report(domain)
        uniq_subdomains = set(subdomains)
        print("\n [+]\tDomains found for {}:\n".format(domain))
        for sub in uniq_subdomains:
            print("    \t{}".format(sub))
            if args.outfile:
                file.write(sub + '\n')
    if args.checkweb and args.domain:
        websites = checkweb(uniq_subdomains)
    if args.checkweb and not args.domain:
        subdomains = open(infile).read().splitlines()
        websites = checkweb(subdomains)
    if args.checkcreds:
        check_creds(websites)

        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    parser.add_argument("-d", "--domain", help="specify the domain name to query subdomain for. Example: ./subdomain_searcher.py -d example.com")
    parser.add_argument("-i", "--infile", help="specify name of the infile to check for domain name connectivity.")
    parser.add_argument("-o", "--outfile", help="specify name of outfile.")
    parser.add_argument("-cw", "--checkweb", help="check websites and return site info.", action="store_true")
    parser.add_argument("-cc", "--checkcreds", help="attempts to login with default credentials if website is known. Must be used with --checkweb", action="store_true")
    args = parser.parse_args()
	
    if not args.domain and not args.infile:
        print('\n [-]\tYou must specify a domain name!\n')
        parser.print_help()
        exit()
    else:
        domain = args.domain
    
    if args.infile and not args.checkweb:
        print("\n [-]\tOnly use an infile if you want to check connectivity to those domain names (the --checkweb option)\n")
        parser.print_help()
        exit()
    
    if args.checkcreds and not args.checkweb:
        print('\n [-]\tYou must specify also --checkweb to use --checkcreds!\n')
        parser.print_help()
        exit()
    
    if args.infile:
        infile = args.infile
    
    if args.outfile:		
        outfile = args.outfile
        file = open(outfile,'a')
        
    if args.checkcreds:
        try:
            from default_credentials import form_auth_creds, header_auth_creds
        except ImportError:
            print("\n [-]\tThe -cc (--checkcreds) option requires a file containing default credentials. See example at https://github.com/laconicwolf/subdomain_searcher\n")
            parser.print_help()
            exit()
            
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36'} 
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    main()
