def form_auth_creds():
    '''A dictionary of credentials, where the key is the site title, and
    the value is a list that contains the path where the POST request 
    should be submitted and the 0 index, and login parameters at index 
    1 in the form of a dictionary. If a site has multiple default
    credentials that you would like to submit, add them as separate
    dictionaries in the same list (at index 2, 3, etc.) For example the
    for the first title 'aris connect', will use the login path 
    '/copernicus/default/service/login', and will then attempt two logins
    the first using superuser:superuser and the second using
    system:manager    
    '''
    creds = {'aris connect': ['/copernicus/default/service/login',
                             {'schema': '0', 'alias': 'superuser', 'password': 'superuser'},
                             {'schema': '0', 'alias': 'system', 'password': 'manager'}],
             'lan': ['/goform/home_loggedout',
                    {'loginUsername': 'admin', 'loginPassword': 'password'},
                    {'loginUsername': 'admin', 'loginPassword': 'admin'}]
            }
    
    return creds
   

def header_auth_creds():
    '''A list of dictionaries, where each dictionarie contains a username
    as a key and password as a value.
    '''
    creds = [{'admin': 'admin'},
             {'admin': 'password'}]
    
    return creds

    
def main():
    print(form_auth_creds())
    print(header_auth_creds())

    
if __name__ == '__main__':
    main()
