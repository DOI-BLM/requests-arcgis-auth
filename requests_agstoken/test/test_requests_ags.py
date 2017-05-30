
import sys,os
import requests
import getpass

sys.path.append(os.path.split(os.path.split(os.getcwd())[0])[0])
from requests_agstoken import ArcGISServerAuth

print "This will test out the Token or 'Web-Tier' (kerberos or NTLM) security"
url=raw_input('Enter ArcGIS for Server "Token Auth" URL: ')
username="BLM\\"+getpass.getuser()
password=getpass.getpass("Enter Password for %s: "%username)


auth_obj=ArcGISServerAuth(username,password,verify=False)

print("Instance",auth_obj)
r=requests.get(url,verify=False,auth=auth_obj)


print ("Instance Of: %s"%str(auth_obj._instanceof))
print ("Auth Instance: ",auth_obj.instance)
print ("Status Code: ",r.status_code)
print ("Response Data: ",r.text)
print ("Request Method: ",r.request.method)
print ("Request body: ",r.request.body)