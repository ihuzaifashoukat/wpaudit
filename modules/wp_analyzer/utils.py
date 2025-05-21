import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress InsecureRequestWarning if verify=False is used often
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def make_request(url, config, method="GET", data=None, allow_redirects=True, timeout=None):
    """Helper to make HTTP requests with consistent settings."""
    try:
        request_timeout = timeout if timeout is not None else config.get("requests_timeout", 15)
        return requests.request(
            method, url, data=data,
            timeout=request_timeout,
            headers={"User-Agent": config.get("default_user_agent")},
            verify=False, # Common setting in security tools, but be aware of risks
            allow_redirects=allow_redirects
        )
    except requests.exceptions.RequestException as e:
        # Log or print the error more visibly, perhaps based on a verbosity setting
        print(f"      [-] Request error for {url}: {e}")
        return None
