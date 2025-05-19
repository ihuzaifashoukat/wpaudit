# Module for WordPress Admin Area Security Checks
import requests
from urllib.parse import urljoin
from core.utils import make_request # Assuming a utility for requests exists

def analyze_admin_area_security(state, config, target_url):
    """
    Checks for common admin area hardening techniques like non-standard URLs
    or additional access controls (e.g., HTTP Auth).
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "admin_area_security"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Checking standard admin paths and HTTP authentication.",
        "standard_login_accessible": None, # True/False/None
        "standard_admin_accessible": None, # True/False/None
        "http_auth_detected_login": False,
        "http_auth_detected_admin": False
    })

    login_url = urljoin(target_url, 'wp-login.php')
    admin_url = urljoin(target_url, 'wp-admin/') # Trailing slash is important for directory access check

    print(f"    Checking standard login path: {login_url}")
    try:
        # Check wp-login.php without allowing redirects initially to detect HTTP Auth
        response_login = make_request(login_url, config, method="GET", allow_redirects=False, timeout=10)
        if response_login:
            if response_login.status_code == 401:
                findings["http_auth_detected_login"] = True
                findings["standard_login_accessible"] = True # Accessible, but protected
                print("      [+] HTTP Authentication detected on wp-login.php")
            elif 200 <= response_login.status_code < 400:
                 # If it's a redirect or success, it's likely accessible (might redirect to login form or dashboard)
                 findings["standard_login_accessible"] = True
                 print("      [+] Standard wp-login.php path seems accessible.")
            else:
                 # 404 or other errors suggest it might be moved or blocked
                 findings["standard_login_accessible"] = False
                 print("      [-] Standard wp-login.php path does not seem accessible (Status: {}).".format(response_login.status_code))
        else:
            findings["standard_login_accessible"] = None # Request failed
            print("      [-] Request failed for wp-login.php.")

    except requests.exceptions.RequestException as e:
        print(f"      [-] Error checking {login_url}: {e}")
        findings["standard_login_accessible"] = None

    print(f"    Checking standard admin path: {admin_url}")
    try:
        # Check wp-admin/ without allowing redirects initially
        response_admin = make_request(admin_url, config, method="GET", allow_redirects=False, timeout=10)
        if response_admin:
            if response_admin.status_code == 401:
                findings["http_auth_detected_admin"] = True
                findings["standard_admin_accessible"] = True # Accessible, but protected
                print("      [+] HTTP Authentication detected on wp-admin/")
            # wp-admin often redirects to wp-login.php if not logged in
            elif response_admin.status_code in [301, 302, 303, 307, 308]:
                 # Check if redirect location contains wp-login.php
                 redirect_location = response_admin.headers.get('Location', '')
                 if 'wp-login.php' in redirect_location:
                     findings["standard_admin_accessible"] = True # Redirects to login, so path exists
                     print("      [+] Standard wp-admin/ path redirects to login, seems accessible.")
                 else:
                     # Redirects elsewhere, might be accessible but custom setup
                     findings["standard_admin_accessible"] = True
                     print(f"      [?] Standard wp-admin/ path redirects elsewhere ({redirect_location}), seems accessible.")
            elif 200 <= response_admin.status_code < 300:
                 # Direct 200 might happen in some edge cases or if already logged in via cookies? Unlikely without cookies.
                 findings["standard_admin_accessible"] = True
                 print("      [+] Standard wp-admin/ path returned 2xx status, seems accessible.")
            else:
                 # 404 or other errors
                 findings["standard_admin_accessible"] = False
                 print("      [-] Standard wp-admin/ path does not seem accessible (Status: {}).".format(response_admin.status_code))
        else:
            findings["standard_admin_accessible"] = None # Request failed
            print("      [-] Request failed for wp-admin/.")

    except requests.exceptions.RequestException as e:
        print(f"      [-] Error checking {admin_url}: {e}")
        findings["standard_admin_accessible"] = None


    # Finalize details
    details_parts = []
    if findings["http_auth_detected_login"] or findings["http_auth_detected_admin"]:
        details_parts.append("HTTP Authentication detected on standard admin paths.")
        state.add_remediation_suggestion("admin_http_auth_info", {
            "source": "WP Analyzer",
            "description": "HTTP Authentication (e.g., Basic/Digest) is used on admin paths, adding a layer of security.",
            "severity": "Info",
            "remediation": "Ensure strong credentials are used for HTTP Authentication. This is generally a good security practice."
        })

    if findings["standard_login_accessible"] is False or findings["standard_admin_accessible"] is False:
        details_parts.append("Standard admin paths (/wp-login.php or /wp-admin/) might be moved or blocked.")
        state.add_remediation_suggestion("admin_path_moved_info", {
            "source": "WP Analyzer",
            "description": "Standard admin paths (/wp-login.php, /wp-admin/) appear inaccessible. They might be moved or protected by security plugins.",
            "severity": "Info",
            "remediation": "Obscuring admin paths can deter simple bots, but is not a substitute for strong passwords and other security measures. Ensure the new paths are not easily guessable if custom ones are used."
        })
    elif findings["standard_login_accessible"] is True and findings["standard_admin_accessible"] is True:
         details_parts.append("Standard admin paths (/wp-login.php, /wp-admin/) appear accessible.")
         # No specific remediation needed unless HTTP auth wasn't detected and user wants more security.

    if not details_parts:
         details_parts.append("Could not definitively determine status of standard admin paths.")


    findings["status"] = "Completed"
    findings["details"] = " ".join(details_parts)
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Admin area security check finished. Details: {findings['details']}")
