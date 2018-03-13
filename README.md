# Esri ArcGIS Authentication Handlers for Python Requests API

**Authenticate to Esri ArcGIS for Server, Portal and ArcGIS Online (AGOL) using Python Requests**

----------

This module provides python requests authentication handlers for the Esri ArcGIS Server and Portal products. The purpose is to authenticate a user to obtain authorized access to protected data and functions in the Esri REST API.  There are endless use cases to automate business or IT administrative workflows... here are a few examples: 
1) Automate user management (creating/removing users or modifying users roles/permissions)  
2) Automate service publishing
3) Completing geospatial data analysis (for protected services)

The authentication handlers support the following deployment models:

* Propritery ‘Token-Based’ Authentication
* Web-Tier security using NTLM or Kerberos (Microsoft Integrated Windows Authentication)
* SAML based ‘enterprise logins’ (OAuth2)\*

*Only supports SAML services with Kerberos authentication (no forms based login)

More information and examples can be found at - https://doi-blm.github.io/requests-arcgis-auth/

## Basic Usage Examples:

ArcGIS for Server "Token Authentication" Usage (Non-Session Based): 
```python
import requests
from requests_arcgis_auth import ArcGISServerTokenAuth
r = requests.get(r'https://host/arcgis/rest/services?f=json', auth=ArcGISServerTokenAuth(username,password))
```

ArcGIS Online and Portal for ArcGIS "Token" Authentication Usage:
```python
import requests
from requests_arcgis_auth import ArcGISPortalTokenAuth
s=requests.Session()
s.auth = ArcGISPortalTokenAuth(username,password)
r = s.get(r'https://host/sharing/rest?f=json')
```

ArcGIS Online and Portal for ArcGIS "Enterprise Logins via SAML" Authentication Usage:
```python
import requests
from requests_arcgis_auth import ArcGISPortalSAMLAuth

client_id = "123456789"                 # This client_id is that of a registered 'application' in the portal.  
auth = ArcGISPortalSAMLAuth(client_id)

s = requests.session()
s.auth = auth
s.get("https://org.maps.arcgis.com/sharing/rest/portals/self?f=json")
```


