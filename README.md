# Esri ArcGIS Authentication for Requests

**Authentication handler for using Esri ArcGIS for Server and Portal (ArcGIS Online) Authentication with Python Requests**

----------

This module provides a python requests authentication handler for the propriatery Esri ArcGIS for Server and Portal Token Authentication.  This also supports 'web-tier' authentication using Kerberos or NTLM (Microsoft Integrated Windows Authentication).  


ArcGIS for Server "Token Authentication" Usage (Non-Session Based): 
```python
import requests
from requests_arcgis_auth import ArcGISServerTokenAuth
r = requests.get(r'https://host/arcgis/rest/services?f=json', auth=ArcGISServerTokenAuth(username,password))
```

ArcGIS for Server "Token" Authentication Usage (Session Based):
```python
import requests
from requests_arcgis_auth import ArcGISServerTokenAuth
s = requests.Session()
s.auth=ArcGISServerTokenAuth(username,password)
r = s.get(r'https://host/arcgis/rest/services?f=json')
```

ArcGIS Online and Portal for ArcGIS "Token" Authentication Usage:
```python
import requests
from requests_arcgis_auth import ArcGISPortalTokenAuth
s=requests.Session()
s.auth = ArcGISPortalTokenAuth(username,password)
r = s.get(r'https://host/sharing/rest?f=json')
```

More information and examples can be found on the WIKI Pages - https://github.com/DOI-BLM/requests-arcgis-auth/wiki
