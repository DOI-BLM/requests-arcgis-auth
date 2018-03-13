
Welcome to requests_arcgis_auth's documentation!
================================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   Documentation & Code Samples
   ArcGISPortalSAMLAuth
   ArcGISServerAuth
   ArcGISPortalTokenAuth
   ArcGISServerTokenAuth


A python :mod:`requests` API authentication handler for the Esri ArcGIS Server, Portal, and ArcGIS Online (AGOL) products

**requests_arcgis_auth** allows you to authenticate to Esri ArcGIS for Server,
Portal for ArcGIS and ArcGIS Online (AGOL).  The authentication handlers support the
following deployment models:

* Propritery 'Token-Based' Authentication
* Web-Tier security using NTLM or Kerberos (Microsoft Integrated Windows Authentication)
* SAML based 'enterprise logins' (OAuth2)\*

\*Only supports SAML services with Kerberos authentication (no forms based login)


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Documentation & Code Samples
============================

ArcGISPortalSAMLAuth
--------------------
.. autoclass:: requests_arcgis_auth.ArcGISPortalSAMLAuth

The ArcGISPortalSAMLAuth authentication handler was developed to work with Portal
and ArcGIS Online (AGOL) solutions (refereed to an 'Esri portal' from here on)
that are federated to the Department of Interior (DOI) Security Assertion Markup
Language (SAML) service. This is an implementation of the Esri "Enterprise Logins"
feature of an Esri portal solution. The authentication to the DOI SAML service is
setup to use requests-kerberos authentication with OPTIONAL Mutual Authentication.
This handler could theoretically support other 3rd party SAML services, but has
not been developed or tested for that purpose.

The authentication handler was developed as an Authorization Code Grant 'User Login'
and will require a *Client ID* of an Esri portal registered application. Further
information of this login workflow can be found at http://resources.arcgis.com/en/help/arcgis-rest-api/index.html#/Authentication/02r30000009z000000/

Code Sample (Session Based):

    >>> import requests
    >>> from requests_arcgis_auth import ArcGISPortalSAMLAuth
    >>> s = requests.session()
    >>> s.auth = ArcGISPortalSAMLAuth(client_id)
    >>> r = s.get("https://org.maps.arcgis.com/sharing/rest/portals/self?f=json")
    >>> print ("logged in as {}".format(r.json().get('user').get('username')))
    logged in as <USERNAME>

.. note:: The ArcGISPortalSAMLAuth handler requires the requests_kerberos, requests_ntlm and BeautifulSoup4 modules.

ArcGISServerAuth
----------------
.. autoclass:: requests_arcgis_auth.ArcGISServerAuth

**Token OR Web-tier (Kerberos/NTLM) Authentication Example ("General Handler")**---
The following will attempt to acquire a token and in the event of an HTTP Status
Code 401 (un-authorized) it will inspect HTTP www-authenticate response headers
for Kerberos and/or NTLM support. If the server supports Kerberos or NTLM the
auth handler will attempt authentication with the appropriate security provider.

    >>> from requests_arcgis_auth import ArcGISServerAuth
    >>>auth = ArcGISServerAuth(username,password)

**Kerberos Web-Tier Authentication Example**---
The users logged in identity can be leverated if the client, server, and
underlying domain all support Kerberos single-sign-on. The advantage of
this approach is that the user credentials do not need to be stored in memory.
The example can be used if the underlying site is known to support Kerberos.

    >>> from requests_arcgis_auth import ArcGISServerAuth
    >>> auth = ArcGISServerAuth()


ArcGISPortalTokenAuth
---------------------
.. autoclass:: requests_arcgis_auth.ArcGISPortalTokenAuth

**Kerberos Web-Tier Authentication Example** ---
The users logged in identity can be leveraged if the client, server, and
underlying domain all support Kerberos single-sign-on. The advantage of this
approach is that the user credentials do not need to be stored in memory.
The example can be used if the underlying site is known to support Kerberos.

    >>> from requests_arcgis_auth import ArcGISPortalAuth
    >>> auth = ArcGISPortalAuth()

**Token OR Web-tier (Kerberos/NTLM) Authentication Example ("General Handler")**---
The following will attempt to acquire a token and in the event of an HTTP Status
Code 401 (un-authorized) it will inspect HTTP www-authenticate response headers
for Kerberos and/or NTLM support. If the server supports Kerberos or NTLM the
auth handler will attempt authentication with the appropriate security provider.

    >>> from requests_arcgis_auth import ArcGISPortalAuth
    >>> auth = ArcGISPortalAuth(username,password)

ArcGISServerTokenAuth
---------------------
.. autoclass:: requests_arcgis_auth.ArcGISServerTokenAuth


Exceptions
----------
.. autoexception:: requests_arcgis_auth.TokenAuthenticationError
.. autoexception:: requests_arcgis_auth.TokenAuthenticationWarning



References
===================
Information about the Esri ArcGIS for Server Token authentication can be found
at: http://server.arcgis.com/en/server/latest/administer/windows/about-arcgis-tokens.htm

Information about the Esri Portal for ArcGIS Token Authentication can be found
at: http://resources.arcgis.com/en/help/arcgis-rest-api/index.html#/Generate_Token/02r3000000m5000000/

Information on python requests can be found at: http://docs.python-requests.org/en/master/

OAuth2 via SAML authentication was developed based on https://www.prowestgis.com/there-and-back-again/

The authentication handlers were developed and tested using the standard python installation bundled with Esri ArcGIS for Desktop 10.3.1 (2.7.8) and the requests API.