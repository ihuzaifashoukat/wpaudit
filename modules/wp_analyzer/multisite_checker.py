# Module for WordPress Multisite Specific Security Checks
import requests
from urllib.parse import urljoin
from core.utils import make_request # Assuming a utility for requests exists

def analyze_multisite(state, config, target_url):
    """
    Performs security checks specific to WordPress Multisite installations.
    Attempts detection by checking for /wp-signup.php.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "multisite_analysis"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Checking for signs of Multisite installation.",
        "is_multisite_detected": False, # Default to false
        "detection_method": None,
        "user_signup_accessible": None, # Check if /wp-signup.php is accessible
        "network_settings_check": {"status": "Not Implemented"} # Placeholder
    })

    signup_url = urljoin(target_url, 'wp-signup.php')
    print(f"    Checking for Multisite indicator: {signup_url}")
    is_multisite = False
    signup_accessible = None

    try:
        response = make_request(signup_url, config, method="GET", timeout=10)
        if response:
            # If wp-signup.php exists (status 200), it's a strong indicator of Multisite
            if response.status_code == 200:
                 is_multisite = True
                 signup_accessible = True
                 findings["detection_method"] = "/wp-signup.php accessible (200 OK)"
                 print("      [+] Found accessible /wp-signup.php - Strong indicator of Multisite.")
                 # Check if registration is actually enabled within the page content
                 if "registration disabled" in response.text.lower():
                     findings["details"] = "Multisite detected (via /wp-signup.php). User/site registration appears disabled on the signup page."
                     print("        [i] Registration appears disabled on signup page.")
                 else:
                     findings["details"] = "Multisite detected (via /wp-signup.php). User/site registration may be open."
                     print("        [!] /wp-signup.php is accessible and registration does not appear explicitly disabled. Manual verification needed.")
                     state.add_remediation_suggestion("multisite_open_signup", {
                         "source": "WP Analyzer",
                         "description": "WordPress Multisite detected and the signup page (/wp-signup.php) is accessible and doesn't explicitly state registration is disabled.",
                         "severity": "Medium",
                         "remediation": "If public user/site registration is not intended, ensure it is disabled in the Network Admin settings (Settings -> Network Settings -> Allow new registrations). Open registration can lead to spam or abuse."
                     })

            elif response.status_code == 404:
                 print("      [-] /wp-signup.php not found (404). Likely not Multisite or path is changed.")
                 findings["details"] = "Standard Multisite signup page (/wp-signup.php) not found."
            else:
                 # Other status codes might indicate it exists but is blocked (e.g., 403)
                 signup_accessible = False
                 findings["details"] = f"Standard Multisite signup page (/wp-signup.php) returned status {response.status_code}."
                 print(f"      [?] /wp-signup.php returned status {response.status_code}.")

        else:
            findings["details"] = "Request to /wp-signup.php failed."
            print("      [-] Request failed for /wp-signup.php.")

    except requests.exceptions.RequestException as e:
        print(f"      [-] Error checking {signup_url}: {e}")
        findings["details"] = f"Error during request to /wp-signup.php: {e}"

    findings["is_multisite_detected"] = is_multisite
    findings["user_signup_accessible"] = signup_accessible
    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Multisite analysis finished. Detected: {is_multisite}. Details: {findings['details']}")
