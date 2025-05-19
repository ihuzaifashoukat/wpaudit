# Module for WordPress Multisite Specific Security Checks
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.utils import make_request

def analyze_multisite(state, config, target_url):
    """
    Performs security checks specific to WordPress Multisite installations.
    Attempts detection via /wp-signup.php, HTML footprints, and sunrise.php.
    Analyzes wp-signup.php if found.
    """
    module_key = "wp_analyzer"
    findings_key = "multisite_analysis"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Checking for signs of Multisite installation and specific configurations.",
        "is_multisite_detected": False,
        "detection_methods": [], # List of methods that indicated multisite
        "wp_signup_status": {"accessible": None, "status_code": None, "registration_disabled_msg": False, "allows_user_reg": None, "allows_site_reg": None},
        "sunrise_php_present": None, # True, False, "Error"
        "html_footprints": {"body_class_multisite": False, "blogs_dir_or_sites_in_assets": False},
        "network_settings_check": {"status": "Informational", "details": "Network settings like default site quotas, upload filetypes, etc., require authenticated access to check."}
    })
    print("    [i] Analyzing WordPress Multisite Configuration...")

    is_multisite_by_any_method = False
    detection_methods_list = []

    # 1. Check for /wp-signup.php
    signup_url = urljoin(target_url, 'wp-signup.php')
    print(f"      Checking for Multisite indicator: {signup_url}")
    try:
        response_signup = make_request(signup_url, config, method="GET", timeout=10)
        if response_signup:
            findings["wp_signup_status"]["status_code"] = response_signup.status_code
            if response_signup.status_code == 200:
                is_multisite_by_any_method = True
                detection_methods_list.append("/wp-signup.php accessible (200 OK)")
                findings["wp_signup_status"]["accessible"] = True
                print("        [+] Found accessible /wp-signup.php - Strong indicator of Multisite.")
                
                signup_html_lower = response_signup.text.lower()
                if "registration disabled" in signup_html_lower or "registrations are not allowed" in signup_html_lower :
                    findings["wp_signup_status"]["registration_disabled_msg"] = True
                    print("          [i] Registration appears explicitly disabled on signup page.")
                else:
                    # Check for forms indicating user or site registration
                    # These are heuristics based on common form field names
                    if 'name="user_name"' in signup_html_lower or 'name="user_email"' in signup_html_lower:
                        findings["wp_signup_status"]["allows_user_reg"] = True
                        print("          [i] Signup page seems to allow USER registration.")
                    if 'name="blogname"' in signup_html_lower or 'name="blog_title"' in signup_html_lower : # blog_title for older versions
                        findings["wp_signup_status"]["allows_site_reg"] = True
                        print("          [i] Signup page seems to allow SITE registration.")
                    
                    if findings["wp_signup_status"]["allows_user_reg"] or findings["wp_signup_status"]["allows_site_reg"]:
                         state.add_remediation_suggestion("multisite_open_signup_v2", { # new key
                            "source": "WP Analyzer (Multisite)",
                            "description": "WordPress Multisite detected and /wp-signup.php is accessible, potentially allowing open user and/or site registration.",
                            "severity": "Medium",
                            "remediation": "If public user/site registration is not intended, ensure it is disabled in Network Admin settings (Settings -> Network Settings -> Allow new registrations). Open registration can lead to spam, resource abuse, or security risks if not properly managed."
                        })
            elif response_signup.status_code == 404:
                findings["wp_signup_status"]["accessible"] = False
                print("        [-] /wp-signup.php not found (404).")
            else:
                findings["wp_signup_status"]["accessible"] = "Blocked/Redirected"
                print(f"        [?] /wp-signup.php returned status {response_signup.status_code}.")
        else:
            findings["wp_signup_status"]["accessible"] = "Error (No Response)"
            print("        [-] Request failed for /wp-signup.php.")
    except Exception as e:
        print(f"      [-] Error checking {signup_url}: {e}")
        findings["wp_signup_status"]["accessible"] = f"Error ({type(e).__name__})"

    # 2. Check HTML Footprints on main target_url
    print(f"      Checking HTML footprints for Multisite on {target_url}...")
    try:
        response_main = make_request(target_url, config, method="GET", timeout=7)
        if response_main and response_main.text:
            soup_main = BeautifulSoup(response_main.text, 'html.parser')
            body_tag = soup_main.find('body')
            if body_tag and body_tag.has_attr('class') and 'multisite' in body_tag['class']:
                findings["html_footprints"]["body_class_multisite"] = True
                is_multisite_by_any_method = True
                detection_methods_list.append("Body class 'multisite' found")
                print("        [+] Found 'multisite' in body class.")

            # Check for /blogs.dir/ or /sites/ in asset URLs (img, link, script src)
            asset_pattern = re.compile(r"""['"](https?://[^"']+?/wp-content/(?:blogs\.dir/\d+/|uploads/sites/\d+/)[^"']+)['"]""", re.IGNORECASE)
            if asset_pattern.search(response_main.text):
                findings["html_footprints"]["blogs_dir_or_sites_in_assets"] = True
                is_multisite_by_any_method = True
                detection_methods_list.append("Asset path with /blogs.dir/ or /uploads/sites/ found")
                print("        [+] Found asset path indicative of Multisite (blogs.dir or uploads/sites).")
        else:
            print("        [-] Could not fetch main page HTML for footprint check.")
    except Exception as e:
        print(f"      [-] Error checking HTML footprints: {e}")

    # 3. Check for wp-content/sunrise.php
    sunrise_url = urljoin(target_url, 'wp-content/sunrise.php')
    print(f"      Checking for sunrise.php: {sunrise_url}")
    try:
        response_sunrise = make_request(sunrise_url, config, method="GET", timeout=5)
        if response_sunrise and response_sunrise.status_code == 200:
            # Even a blank 200 or one with errors indicates presence
            findings["sunrise_php_present"] = True
            is_multisite_by_any_method = True # Presence of sunrise.php is a very strong indicator
            detection_methods_list.append("wp-content/sunrise.php accessible (200 OK)")
            print("        [+] wp-content/sunrise.php found. Strong indicator of Multisite, likely with domain mapping.")
        elif response_sunrise and response_sunrise.status_code == 404:
            findings["sunrise_php_present"] = False
            print("        [-] wp-content/sunrise.php not found (404).")
        elif response_sunrise:
            findings["sunrise_php_present"] = "Blocked/Error" # Exists but not 200 or 404
            print(f"        [?] wp-content/sunrise.php returned status {response_sunrise.status_code}.")
        else:
            findings["sunrise_php_present"] = "Error (No Response)"
            print(f"        [-] Request for wp-content/sunrise.php failed.")
    except Exception as e:
        print(f"      [-] Error checking for sunrise.php: {e}")
        findings["sunrise_php_present"] = f"Error ({type(e).__name__})"


    findings["is_multisite_detected"] = is_multisite_by_any_method
    findings["detection_methods"] = list(set(detection_methods_list)) # Unique methods

    if is_multisite_by_any_method:
        findings["details"] = f"WordPress Multisite detected. Detection methods: {', '.join(findings['detection_methods'])}."
        state.add_remediation_suggestion("multisite_general_review", {
            "source": "WP Analyzer (Multisite)",
            "description": "This WordPress installation appears to be a Multisite network.",
            "severity": "Info",
            "remediation": "Multisite installations have unique security considerations. Ensure network settings, user roles, plugin/theme compatibility, and site registration policies are configured securely. Regularly audit individual sites within the network."
        })
    else:
        findings["details"] = "No clear indicators of a WordPress Multisite installation found through common checks."

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Multisite analysis finished. Detected: {is_multisite_by_any_method}. Details: {findings['details']}")
