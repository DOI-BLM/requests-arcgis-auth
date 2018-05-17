
import sys,os
try:
    import ConfigParser
except:
    import configparser as ConfigParser
import requests
from getpass import getpass

import warnings
warnings.filterwarnings("ignore")
print ("ATTN!!! Warnings are being filtered !!!")

if __name__ == '__main__' and __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from arcgis_token_auth import ArcGISServerTokenAuth, ArcGISPortalTokenAuth
from arcgis_auth import ArcGISPortalAuth, ArcGISServerAuth
from arcgis_saml_auth import ArcGISPortalSAMLAuth

try:
    from colorama import init
    init(autoreset=True)
except:
    sys.path.append(os.path.join(os.getcwd(),"packages","colorama-0.3.9"))
    from colorama import init
    init(autoreset=True)

from colorama import Fore,Back

def print_color(color,*objs):
    # color = foreground colors from colorama.Fore.  EX: Fore.GREEN
    # *objs = Objects to print that color
    print (color+" ".join([str(x) for x in objs]))

def print_green(*objs):
    #print (Fore.GREEN+" ".join([str(x) for x in objs]))
    print_color(Fore.GREEN,*objs)

def print_red(*objs):
    print_color(Fore.RED,*objs)

def print_yellow(*objs):
    print_color(Fore.YELLOW,*objs)

def print_cyan(*objs):
    print_color(Fore.CYAN,*objs)


TOOL_INFO = """
This test harness will execute HTTP requests to Esri ArcGIS for Server and Portal (including ArcGIS Online)
using custom authenticaiton handlers for the python requests API.

Optional Input -
    CONFIG_FILE (defaults to test.cfg).

Usage:
        python.exe test_arcgis_auth.py <PATH_TO_CONFIG_FILE>
"""

SAMPLE_CONFIG_FILE = """
    [General Settings]
    verify_certs = False

    # URL's with different security postures.  Passwords will be prompted (except for 'duplicate' usernames, the previous password promt will be re-used)
    [ArcGIS Server Token Auth]
    url = https://gis.dev.blm.doi.net/arcgispub/admin/?f=json
    expected_output = {"resources":["machines","clusters","system","services","security","data","uploads","logs","mode","usagereports"],"currentVersion":10.41,"fullVersion":"10.4.1","acceptLanguage":null}
    auth_handler = ArcGISServerTokenAuth
    username = blm\pfoppe

    [ArcGIS Server Kerberos Auth]
    url = https://gis.dev.blm.doi.net/arcgisauthpub/admin/?f=json
    expected_output={"resources":["machines","clusters","system","services","security","data","uploads","logs","mode","usagereports"],"currentVersion":10.41,"fullVersion":"10.4.1","acceptLanguage":null}
    auth_handler = ArcGISServerAuth

    [ArcGIS Server NTLM Auth]
    url = https://gis.blm.doi.net/arcgisauthpub/admin/?f=json
    username = blm\pfoppe
    expected_output={"resources":["machines","clusters","system","services","security","data","uploads","logs","mode","usagereports"],"currentVersion":10.41,"fullVersion":"10.4.1","acceptLanguage":null}
    auth_handler = ArcGISServerAuth

    [Portal Token Auth]
    url = https://blm-egis.maps.arcgis.com/sharing/rest?f=json
    username = pfoppe_BLM
    expected_output = {"currentVersion":"5.1"}
    auth_handler = ArcGISPortalTokenAuth

    [Portal Kerberos Auth]
    url = https://ilmocop3ap60.blm.doi.net/portal/sharing/rest?f=json
    expected_output = {"currentVersion":"3.10"}
    auth_handler = ArcGISPortalAuth

    [Portal NTLM Auth]
    url = https://egisportal.blm.doi.net/portal/sharing/rest?f=json
    username = blm\pfoppe
    expected_output = {"currentVersion":"3.10"}
    auth_handler = ArcGISPortalAuth
\n\n\n"""


def get_inputs():
    if len(sys.argv) == 2:
        cfg_file = sys.argv[1]
        if os.path.exists(cfg_file):
            return cfg_file
        else:
            print ("!!! ERROR !!! Could not find CONFIG file %s"%cfg_file)
    elif len(sys.argv) == 1:
        cfg_file = "test.cfg"
        print (TOOL_INFO)
        print_yellow ("!!! WARNING !!!  No Config File Supplied.  \nUsing default config file %s"%cfg_file)
        print (SAMPLE_CONFIG_FILE)
        return cfg_file

    print (TOOL_INFO)
    print (SAMPLE_CONFIG_FILE)
    sys.exit()

def get_configs(cfg_file):
    config = ConfigParser.RawConfigParser()
    config.read(cfg_file)
    return config

def get_password(username):
    return getpass("Enter password for %s:"%username)

def get_credentials(config):
    print ("Obtaining ALL User Credentials...")
    credentials={}
    for s in config.sections():
        if config.has_option(s,"username"):
            username=config.get(s,"username")
            if username == "":
                continue
            if credentials.get(username) is None:
                credentials.update({username:get_password(username)})
    return credentials

def process_sections(config,credentials,verify):

    for s in config.sections():

        # Skip the "General Settings" section
        if s == "General Settings":
            continue

        # Get Configs
        print ("--------------------------------------\nGETTING CONFIGS TO TEST '%s'"%s)
        try:
            url=config.get(s,"url")
            expected_output=config.get(s,"expected_output")
            auth_handler=config.get(s,"auth_handler")
        except:
            print(Back.RED + "ERROR - Failed to acquire configs for %s.  Not executing Test"%s)
            continue
        username=config.get(s,"username") if config.has_option(s,"username") else ""

        # Setup Auth Handler
        # print ("Setting Auth Handler...")
        auth = None
        if auth_handler == "ArcGISServerTokenAuth":
            if username == "":
                print_red ("ERROR - %s requires credentials.  Not executing Test"%auth_handler)
                continue
            auth=ArcGISServerTokenAuth(username,credentials[username],verify=verify)
        elif auth_handler == "ArcGISPortalTokenAuth":
            if username == "":
                print_red ("ERROR - %s requires credentials.  Not executing Test"%auth_handler)
                continue
            auth=ArcGISPortalTokenAuth(username,credentials[username],verify=verify)
        elif auth_handler == "ArcGISServerAuth":
            if username == "":
                auth=ArcGISServerAuth(verify=verify)
            else:
                auth=ArcGISServerAuth(username,credentials[username],verify=verify)
        elif auth_handler == "ArcGISPortalAuth":
            if username == "":
                auth=ArcGISPortalAuth(verify=verify)
            else:
                auth=ArcGISPortalAuth(username,credentials[username],verify=verify)
        elif auth_handler == "ArcGISPortalSAMLAuth":
            client_id=config.get(s,"client_id")
            auth = ArcGISPortalSAMLAuth(client_id)

        #Make Requests
        print ("Executing test...")
        result=test_auth(auth,url,verify,expected_output)
        if result:
            print (Back.GREEN + "%s tests passed"%s)
        else:
            print (Back.RED + "%s tests failed"%s)

def test_auth(auth,url,verify,expected_output):

    # auth = authenticaiton handler (session().auth = auth)
    # url = (str)
    # verify = (Bool) Verify the SSL certificates?
    # Expected Output = (STR)

    output=True
    s = requests.Session()
    s.auth=auth
    r=s.get(url,verify=verify)

    # Check Status Code
    if r.status_code == 200:
        print_green("Status Code: ",r.status_code)
    else:
        print_red("Status Code: ",r.status_code)
        output=False

    # Check Expected Output
    if r.text == expected_output:
        print_green('Expected Output Matches!')
    else:
        print_red("Expected Output Does Not Match!  Output:\n%s"%r.text.encode("UTF-8"))
        output=False

    # Check for existance of token
    if type(auth) == ArcGISPortalSAMLAuth:
        if auth._token_data is not None:
            print_green("Access Token is present! %s..."%auth._token_data.get("access_token")[0:10])
            print_green("Refresh Token is present! %s..."%auth._token_data.get("refresh_token")[0:10])
    elif type(auth) == ArcGISPortalTokenAuth or type(auth) == ArcGISServerTokenAuth:
        if auth._token.get("token") is not None:
            print_green("Token is present!  %s..."%auth._token.get("token")[0:10])
        else:
            print_red("Token is NOT PRESENT!  %s"%str(auth._token))
            output=False
    elif auth._instanceof == ArcGISPortalTokenAuth or auth._instanceof == ArcGISServerTokenAuth:
        if auth._token.get("token") is not None:
            print_green("Token is present!  %s..."%auth._token.get("token")[0:10])
        else:
            print_red("Token is NOT PRESENT!  %s"%str(auth._token))
            output=False

    return output


def main():

    # Get Configs...
    cfg_file = get_inputs()
    # GET RID OF GLOBAL REFERENCE WHEN NOT DEBUGGING
    global config,credentials
    config=get_configs(cfg_file)
    credentials=get_credentials(config)
    verify=config.getboolean("General Settings","verify_certs")

    print_cyan("==== STARTING TESTS ====")
    process_sections(config,credentials,verify)

    # Start Tests
    """section="ArcGIS Server Token Auth"
    url=config.get(section,"url")
    username=config.get(section,"username")
    expected_output=config.get(section,"expected_output")
    auth=ArcGISServerTokenAuth(username,credentials[username],verify=verify)
    test_auth(auth,url,verify,expected_output)

    section = "Portal Token Auth"
    url=config.get(section,"url")
    username=config.get(section,"username")
    expected_output=config.get(section,"expected_output")
    auth=ArcGISPortalTokenAuth(username,credentials[username],verify=verify)
    test_auth(auth,url,verify,expected_output)
    """


if __name__ == '__main__':
    main()
