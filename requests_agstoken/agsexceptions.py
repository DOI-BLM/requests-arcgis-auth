from requests.exceptions import RequestException,RequestsWarning

class TokenAuthenticationError(RequestException):
    """Site Does Not Support Token Authentication"""
    pass

class TokenAuthenticationWarning(RequestsWarning):
    """Site Does Not Support Token Authentication"""
    pass
