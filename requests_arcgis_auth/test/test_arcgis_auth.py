
import sys,os
import ConfigParser
import requests
from getpass import getpass

import warnings
warnings.filterwarnings("ignore")
print "ATTN!!! Warnings are being filtered !!!"

# Had to do this to run interactivly from PyScripter
try:
    from ..arcgis_token_auth import ArcGISServerTokenAuth, ArcGISPortalTokenAuth
except:
    import sys
    from os import path
    sys.path.append( path.dirname( path.dirname( path.abspath(__file__) ) ) )
    from arcgis_token_auth import ArcGISServerTokenAuth, ArcGISPortalTokenAuth


# Adjust terminal colors (pass/fail)
try:
    from colorama import init
    init(autoreset=True)
except:
    sys.path.append(os.path.join(os.getcwd(),"packages","colorama-0.3.9"))
    from colorama import init
    init(autoreset=True)

from colorama import Fore

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

def print_blue(*objs):
    print_color(Fore.BLUE,*objs)


TOOL_INFO = """
This test harness will execute HTTP requests to Esri ArcGIS for Server and Portal (including ArcGIS Online)
using custom authenticaiton handlers for the python requests API.

Optional Input -
    CONFIG_FILE (defaults to test.cfg).

Usage:
        python.exe test_arcgis_auth.py <PATH_TO_CONFIG_FILE>
"""

SAMPLE_CONFIG_FILE = """
=============================
SAMPLE CONFIG FILE
=============================

[General Settings]

# Verbose Logging?  True/False
verbose = True

# URL's with different security postures.  Ensure to add f=json parameter to parse...
[ArcGIS Server Token Auth]
url = https://gis.dev.blm.doi.net/arcgispub/admin/?f=json
username = blm\pfoppe

[ArcGIS Server Kerberos Auth]
url = https://gis.dev.blm.doi.net/arcgisauthpub/admin/?f=json
username =

[ArcGIS Server NTLM Auth]
url = https://gis.blm.doi.net/arcgisauthpub/admin/?f=json
username = blm\pfoppe

[Portal Token Auth]
url = https://blm-egis.maps.arcgis.com/sharing/rest?f=json
username = pfoppe_BLM

[Portal Kerberos Auth]
url = https://ilmocop3ap60.blm.doi.net/portal/sharing/rest?f=json
username =

[Portal NTLM Auth]
url = https://egisportal.blm.doi.net/portal/sharing/rest?f=json
username = blm\pfoppe"""


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

"""def test_ags_token(url,username,pwd,verify):
    s=requests.session()
    s.auth=ArcGISServerTokenAuth(username,pwd,verify=verify)
"""

def get_password(username):
    return getpass("Enter password for %s:"%username)

def get_credentials(config):
    credentials={}
    for s in config.sections():
        if config.has_option(s,"username"):
            username=config.get(s,"username")
            if username == "":
                continue
            if credentials.get(username) is None:
                credentials.update({username:get_password(username)})
    return credentials

def test_auth(auth,url,verify,expected_output):
    # auth = authenticaiton handler (session().auth = auth)
    # url = (str)
    # verify = (Bool) Verify the SSL certificates?
    # Expected Output = (STR)
    s = requests.Session()
    s.auth=auth
    r=s.get(url,verify=verify)
    if r.status_code == 200:
        print_green("Status Code: ",r.status_code)
    else:
        print_red("Status Code: ",r.status_code)

    if r.text == expected_output:
        print_green('Expected Output Matches!')
    else:
        print_red("Expected Output Does Not Match!  Output:\n%s"%r.text.decode("UTF-8"))


def main():

    # Get Configs...
    cfg_file = get_inputs()
    # GET RID OF GLOBAL REFERENCE WHEN NOT DEBUGGING
    global config,credentials
    config=get_configs(cfg_file)
    credentials=get_credentials(config)
    verify=config.getboolean("General Settings","verify_certs")

    print_blue("==== STARTING TESTS ====")

    # Start Tests
    section="ArcGIS Server Token Auth"
    url=config.get(section,"url")
    username=config.get(section,"username")
    expected_output=config.get(section,"expected_output")
    test_auth(ArcGISServerTokenAuth(username,credentials[username]),url,verify,expected_output)

    section = "Portal Token Auth"
    url=config.get(section,"url")
    username=config.get(section,"username")
    expected_output=config.get(section,"expected_output")
    test_auth(ArcGISPortalTokenAuth(username,credentials[username]),url,verify,expected_output)


if __name__ == '__main__':
    main()
