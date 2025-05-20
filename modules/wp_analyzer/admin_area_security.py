# Module for WordPress Admin Area Security Checks
import requests
import re # For plugin footprint detection
from urllib.parse import urljoin
from .utils import make_request # Assuming a utility for requests exists

# Common alternative admin paths (non-exhaustive)
COMMON_ALT_ADMIN_PATHS = [
    "login", "admin", "dashboard", "wp-admin-hidden", "my-admin", "secret-admin",
    "control-panel", "cpanel", "admin-login", "member-login", "site-admin",
    "backend", "manage", "webadmin", "admin123", "adm"
]

# Footprints for admin protection plugins (simple examples)
ADMIN_PLUGIN_FOOTPRINTS = {
    "WPS Hide Login": [
        re.compile(r"<!-- WPS Hide Login"), # HTML Comment
        re.compile(r"/wp-content/plugins/wps-hide-login/", re.IGNORECASE) # Asset path
    ],
    "Protect Your Admin": [ # Fictional example, replace with real plugin footprints
        re.compile(r"Protect Your Admin - Active", re.IGNORECASE)
    ],
    "Limit Login Attempts Reloaded": [
        re.compile(r"limit-login-attempts-reloaded", re.IGNORECASE), # Asset path or class name
        re.compile(r"llar_protect_script", re.IGNORECASE) # JS variable or script ID
    ]
    # Add more plugins and their footprints
}


def _check_path_accessibility(url, config, path_description):
    """Helper to check accessibility and HTTP Auth for a given path."""
    is_accessible = None
    http_auth = False
    status_code = None
    content_snippet = ""
    redirect_location = None

    print(f"      Checking {path_description}: {url}")
    try:
        response = make_request(url, config, method="GET", allow_redirects=False, timeout=7)
        if response:
            status_code = response.status_code
            content_snippet = response.text[:200] if response.text else "" # Get a snippet for footprint analysis
            redirect_location = response.headers.get('Location')

            if status_code == 401:
                http_auth = True
                is_accessible = True # Path exists but is protected by HTTP Auth
                print(f"        [+] HTTP Authentication detected on {path_description}.")
            elif 200 <= status_code < 300:
                is_accessible = True
                print(f"        [+] {path_description} directly accessible (Status: {status_code}).")
            elif 300 <= status_code < 400 and redirect_location:
                is_accessible = True # Path exists, redirects
                print(f"        [+] {path_description} redirects to {redirect_location} (Status: {status_code}).")
            else: # 404, 403 (other than 401), 5xx etc.
                is_accessible = False
                print(f"        [-] {path_description} not accessible or blocked (Status: {status_code}).")
        else:
            print(f"        [-] Request failed for {path_description}.")
    except requests.exceptions.RequestException as e:
        print(f"        [-] Error checking {path_description} at {url}: {e}")
    
    return is_accessible, http_auth, status_code, content_snippet, redirect_location


def analyze_admin_area_security(state, config, target_url):
    """
    Enhanced checks for admin area security: standard paths, HTTP Auth,
    common alternative paths, and footprints of protection plugins.
    """
    module_key = "wp_analyzer"
    findings_key = "admin_area_security"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Checking admin area security aspects...",
        "standard_login_status": {"accessible": None, "http_auth": False, "status_code": None, "redirect_url": None},
        "standard_admin_dir_status": {"accessible": None, "http_auth": False, "status_code": None, "redirect_url": None},
        "alternative_admin_paths_found": [],
        "detected_protection_plugins": [],
        "htaccess_protection_wp_admin": "Unknown" # Could be True, False, Heuristic
    })

    print("    [i] Analyzing Admin Area Security...")

    # 1. Check standard wp-login.php
    login_url = urljoin(target_url, 'wp-login.php')
    is_acc, http_auth, sc, content, redir = _check_path_accessibility(login_url, config, "standard wp-login.php")
    findings["standard_login_status"] = {"accessible": is_acc, "http_auth": http_auth, "status_code": sc, "content_snippet": content, "redirect_url": redir}
    login_page_content_for_plugins = content if is_acc else "" # Use content if accessible for plugin checks

    # 2. Check standard wp-admin/
    admin_dir_url = urljoin(target_url, 'wp-admin/')
    is_acc, http_auth, sc, content, redir = _check_path_accessibility(admin_dir_url, config, "standard wp-admin directory")
    findings["standard_admin_dir_status"] = {"accessible": is_acc, "http_auth": http_auth, "status_code": sc, "content_snippet": content, "redirect_url": redir}
    
    # If wp-admin redirects to wp-login.php and wp-login.php was found, that's normal.
    if findings["standard_admin_dir_status"]["redirect_url"] and \
       'wp-login.php' in findings["standard_admin_dir_status"]["redirect_url"] and \
       findings["standard_login_status"]["accessible"]:
        print("        [i] wp-admin correctly redirects to wp-login.php.")


    # 3. Check for common alternative admin paths (only if standard login seems inaccessible)
    if findings["standard_login_status"]["accessible"] is False:
        print("    [i] Standard wp-login.php seems inaccessible, checking common alternative admin paths...")
        for alt_path in COMMON_ALT_ADMIN_PATHS:
            alt_url = urljoin(target_url, alt_path)
            # Avoid re-checking if it's essentially the same as target_url (e.g. alt_path is empty or just '/')
            if alt_url == target_url or alt_url == target_url + "/": 
                continue

            is_acc, http_auth, sc, content, redir = _check_path_accessibility(alt_url, config, f"alternative path '{alt_path}'")
            if is_acc:
                # Heuristic: if it looks like a login page (contains "log in", "username", "password")
                login_keywords = ["log in", "username", "password", "user name", "pass word", "forgot password"]
                is_likely_login = any(kw in content.lower() for kw in login_keywords) if content else False
                
                path_info = {"path": alt_path, "url": alt_url, "status_code": sc, "http_auth": http_auth, "is_likely_login_page": is_likely_login, "redirect_url": redir}
                findings["alternative_admin_paths_found"].append(path_info)
                print(f"        [+] Found potentially active alternative admin path: {alt_url} (Likely Login: {is_likely_login})")
                if not login_page_content_for_plugins and is_likely_login: # If standard login failed, use this for plugin checks
                    login_page_content_for_plugins = content


    # 4. Detect Admin Protection / Login Security Plugins via footprints
    # Use content from accessible login page (standard or alternative)
    if login_page_content_for_plugins:
        print("    [i] Checking for footprints of admin protection plugins on login page content...")
        for plugin_name, patterns in ADMIN_PLUGIN_FOOTPRINTS.items():
            for pattern in patterns:
                if pattern.search(login_page_content_for_plugins):
                    if plugin_name not in findings["detected_protection_plugins"]:
                        findings["detected_protection_plugins"].append(plugin_name)
                        print(f"        [+] Detected potential footprint for plugin: {plugin_name}")
                        break # Found this plugin, move to next plugin
    else:
        print("    [i] No accessible login page content to check for plugin footprints.")

    # 5. Check for wp-admin/.htaccess (heuristic)
    htaccess_url = urljoin(target_url, 'wp-admin/.htaccess')
    print(f"    [i] Heuristically checking for wp-admin/.htaccess protection at {htaccess_url}")
    try:
        # We don't expect to fetch it (200), but 403 might indicate it's present and protected.
        # 404 means it's not directly accessible (could be due to server config or not present).
        response_htaccess = make_request(htaccess_url, config, method="GET", timeout=5)
        if response_htaccess and response_htaccess.status_code == 403:
            findings["htaccess_protection_wp_admin"] = "Heuristic (403 Forbidden on .htaccess)"
            print("        [+] Received 403 Forbidden for wp-admin/.htaccess, suggesting it might be present and protected.")
        elif response_htaccess and response_htaccess.status_code == 404:
            findings["htaccess_protection_wp_admin"] = "Not Directly Accessible (404)"
            print("        [-] wp-admin/.htaccess not directly accessible (404).")
        elif response_htaccess:
            findings["htaccess_protection_wp_admin"] = f"Unexpected Status ({response_htaccess.status_code})"
            print(f"        [?] Unexpected status {response_htaccess.status_code} for wp-admin/.htaccess.")
        else:
            print("        [-] Request failed for wp-admin/.htaccess check.")
    except requests.exceptions.RequestException as e:
        print(f"        [-] Error checking {htaccess_url}: {e}")


    # Finalize details for reporting
    details_parts = []
    if findings["standard_login_status"]["http_auth"] or findings["standard_admin_dir_status"]["http_auth"]:
        details_parts.append("HTTP Authentication detected on standard admin paths.")
        state.add_remediation_suggestion("admin_http_auth_info_v2", { # new key
            "source": "WP Analyzer (Admin Security)",
            "description": "HTTP Authentication (e.g., Basic/Digest) is used on standard admin paths (/wp-login.php or /wp-admin/), adding a layer of security.",
            "severity": "Info",
            "remediation": "Ensure strong credentials are used for HTTP Authentication. This is generally a good security practice."
        })

    if findings["standard_login_status"]["accessible"] is False:
        details_parts.append("Standard wp-login.php path appears inaccessible or blocked.")
    elif findings["standard_login_status"]["accessible"] is True:
        details_parts.append("Standard wp-login.php path appears accessible.")

    if findings["standard_admin_dir_status"]["accessible"] is False:
        details_parts.append("Standard wp-admin/ directory appears inaccessible or blocked.")
    elif findings["standard_admin_dir_status"]["accessible"] is True:
        details_parts.append("Standard wp-admin/ directory appears accessible.")
    
    if findings["alternative_admin_paths_found"]:
        alt_paths_str = ", ".join([p["path"] for p in findings["alternative_admin_paths_found"]])
        details_parts.append(f"Found {len(findings['alternative_admin_paths_found'])} potential alternative admin path(s): {alt_paths_str}.")
        state.add_remediation_suggestion("admin_alt_paths_found", {
            "source": "WP Analyzer (Admin Security)",
            "description": f"Potential alternative admin path(s) found: {alt_paths_str}. If these are active login pages, ensure they are adequately secured.",
            "severity": "Medium" if any(p["is_likely_login_page"] for p in findings["alternative_admin_paths_found"]) else "Low",
            "remediation": "If standard admin paths are intentionally hidden, ensure the new paths are not easily guessable and are protected by strong passwords, 2FA, and rate limiting. Verify if these alternative paths are legitimate."
        })

    if findings["detected_protection_plugins"]:
        plugins_str = ", ".join(findings["detected_protection_plugins"])
        details_parts.append(f"Detected footprints of protection plugin(s): {plugins_str}.")
        state.add_remediation_suggestion("admin_protection_plugins_detected", {
            "source": "WP Analyzer (Admin Security)",
            "description": f"Footprints suggest the use of admin/login protection plugin(s): {plugins_str}. This is generally a good security measure.",
            "severity": "Info",
            "remediation": "Ensure any security plugins are kept up-to-date and configured correctly according to best practices."
        })
    
    if findings["htaccess_protection_wp_admin"] not in ["Unknown", "Not Directly Accessible (404)"]:
        details_parts.append(f"wp-admin/.htaccess protection status: {findings['htaccess_protection_wp_admin']}.")


    if not details_parts:
         details_parts.append("Admin area security checks run. Review specific findings for details.")

    findings["status"] = "Completed"
    findings["details"] = " ".join(filter(None, details_parts)) # Filter out empty strings
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Admin area security advanced check finished. Details: {findings['details']}")
