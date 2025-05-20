# Module for WordPress Authentication Hardening Checks
import requests # Retained for context
import re # Added import for re module
from .utils import make_request

from bs4 import BeautifulSoup

# Footprints for CAPTCHA plugins (expanded)
CAPTCHA_FOOTPRINTS_AUTH = {
    "Google reCAPTCHA": [re.compile(r"google.com/recaptcha|grecaptcha|recaptcha-keys", re.IGNORECASE)],
    "hCaptcha": [re.compile(r"hcaptcha.com|h-captcha-response", re.IGNORECASE)],
    "Cloudflare Turnstile": [re.compile(r"challenges.cloudflare.com/turnstile|cf-turnstile", re.IGNORECASE)],
    "Really Simple CAPTCHA": [re.compile(r"really-simple-captcha", re.IGNORECASE)],
    "Math Captcha": [re.compile(r"math-captcha|wpcf7-math-captcha-form-control", re.IGNORECASE)],
    "Login No Captcha reCAPTCHA": [re.compile(r"login-nocaptcha", re.IGNORECASE)],
}

# Footprints for 2FA plugins (expanded)
TFA_PLUGIN_FOOTPRINTS_AUTH = {
    "Wordfence Login Security": [re.compile(r"wordfence-ls-|wf-ls-|wf_scan", re.IGNORECASE)], # wf_scan is more general Wordfence
    "Google Authenticator (WordPress Plugin by MiniOrange)": [re.compile(r"miniorange-2-factor|mo_2fa", re.IGNORECASE)],
    "Two Factor (Official Plugin by WordPress Core Team)": [re.compile(r"Two Factor Authentication|#two-factor-backup-codes|#configure-two-factor", re.IGNORECASE)],
    "WP 2FA": [re.compile(r"wp-2fa-|wp2fa_", re.IGNORECASE)],
    "iThemes Security (formerly Better WP Security)": [re.compile(r"it-security|itsec_", re.IGNORECASE)], # General iThemes
    "All In One WP Security & Firewall": [re.compile(r"aiowps_|wp-security-నోటిసు", re.IGNORECASE)], # General AIOWPS
}

# Footprints for general Login Security / Hardening plugins
LOGIN_SECURITY_PLUGIN_FOOTPRINTS = {
    "Wordfence Security": [re.compile(r"wordfence", re.IGNORECASE)], # General
    "iThemes Security": [re.compile(r"ithemes-security|itsec_", re.IGNORECASE)], # General
    "Sucuri Security": [re.compile(r"sucuri-scanner", re.IGNORECASE)], # General
    "All In One WP Security & Firewall": [re.compile(r"aiowpsec|aiowps_", re.IGNORECASE)], # General
    "Limit Login Attempts Reloaded": [re.compile(r"limit-login-attempts-reloaded|llar_", re.IGNORECASE)],
    "WPS Hide Login": [re.compile(r"wps-hide-login", re.IGNORECASE)], # If login page is custom
    # Add more general login security plugin footprints
}


def _check_footprints(html_content, footprints_dict, category_name):
    """Helper to check for multiple footprints in HTML content."""
    detected = []
    if not html_content:
        return detected
    for name, patterns in footprints_dict.items():
        for pattern in patterns:
            if pattern.search(html_content):
                if name not in detected:
                    detected.append(name)
                    print(f"        [+] Detected {category_name} footprint: {name}")
                break # Found this specific plugin/type
    return detected


def analyze_auth_hardening(state, config, target_url):
    """
    Analyzes login page and related authentication hardening measures.
    Checks for CAPTCHA, 2FA, HTTP Auth, general security plugins, and clickjacking protection.
    """
    module_key = "wp_analyzer"
    findings_key = "auth_hardening"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Performing authentication hardening checks...",
        "login_page_url": None,
        "login_page_accessible": None,
        "http_auth_on_login": False,
        "captcha_details": {"detected_types": [], "on_login_page": False, "on_lost_password_page": False},
        "tfa_plugin_footprints": [],
        "login_security_plugin_footprints": [],
        "clickjacking_protection_login": {"x_frame_options": None, "csp_frame_ancestors": None},
        "lost_password_page_accessible": None,
        # Placeholders for checks difficult to do remotely without being disruptive
        "password_policy_strength": {"status": "Informational", "details": "Password policy strength is best assessed through configuration review or authenticated testing."},
        "account_lockout_mechanism": {"status": "Informational", "details": "Account lockout mechanisms are difficult to confirm reliably without potentially disruptive active login attempts."}
    })

    print("    [i] Analyzing Authentication Hardening...")
    login_url = urljoin(target_url, 'wp-login.php')
    findings["login_page_url"] = login_url
    login_page_html = None
    login_page_headers = {}

    # 1. Check wp-login.php accessibility and HTTP Auth
    print(f"      Checking accessibility and HTTP Auth for: {login_url}")
    try:
        # Check without redirects first for HTTP Auth
        response_no_redirect = make_request(login_url, config, method="GET", allow_redirects=False, timeout=7)
        if response_no_redirect:
            findings["login_page_status_code_initial"] = response_no_redirect.status_code
            if response_no_redirect.status_code == 401:
                findings["http_auth_on_login"] = True
                print("        [+] HTTP Authentication detected on wp-login.php.")
                # If HTTP auth, still try to get content if a subsequent request (e.g. by a browser with creds) would work
                # For this script, we assume if 401, we can't proceed to get HTML content easily.
            elif 200 <= response_no_redirect.status_code < 400 : # Includes 200 OK or redirects
                 # Now fetch with redirects to get the final login page content
                response_final = make_request(login_url, config, method="GET", allow_redirects=True, timeout=10)
                if response_final and response_final.status_code == 200:
                    if "user_login" in response_final.text and "user_pass" in response_final.text:
                        findings["login_page_accessible"] = True
                        login_page_html = response_final.text
                        login_page_headers = response_final.headers
                        print(f"        [+] Login page accessible at {response_final.url}.")
                    else:
                        findings["login_page_accessible"] = "Partial (Content Mismatch)"
                        print(f"        [?] Login page at {response_final.url} returned 200 but content doesn't match standard form.")
                elif response_final:
                    findings["login_page_accessible"] = False
                    print(f"        [-] Login page final request failed or non-200: Status {response_final.status_code} at {response_final.url}")
                else:
                    findings["login_page_accessible"] = False; print("        [-] Failed to fetch final login page after initial check.")
            else: # 403, 404, 5xx on initial request
                findings["login_page_accessible"] = False
                print(f"        [-] wp-login.php not accessible or blocked (Initial Status: {response_no_redirect.status_code}).")
        else:
            findings["login_page_accessible"] = False; print("        [-] Request to wp-login.php failed (no initial response).")
    except Exception as e:
        print(f"      [-] Error checking login page: {e}")
        findings["login_page_accessible"] = "Error"
        findings["login_page_status_code_initial"] = f"Error: {type(e).__name__}"

    # 2. Analyze Login Page HTML if fetched
    if login_page_html:
        findings["captcha_details"]["on_login_page"] = True # Assume we are checking login page if HTML is present
        detected_captcha_types = _check_footprints(login_page_html, CAPTCHA_FOOTPRINTS_AUTH, "CAPTCHA")
        if detected_captcha_types:
            findings["captcha_details"]["detected_types"].extend(dt for dt in detected_captcha_types if dt not in findings["captcha_details"]["detected_types"])
        
        detected_tfa_plugins = _check_footprints(login_page_html, TFA_PLUGIN_FOOTPRINTS_AUTH, "2FA Plugin")
        findings["tfa_plugin_footprints"].extend(dt for dt in detected_tfa_plugins if dt not in findings["tfa_plugin_footprints"])

        detected_sec_plugins = _check_footprints(login_page_html, LOGIN_SECURITY_PLUGIN_FOOTPRINTS, "Login Security Plugin")
        findings["login_security_plugin_footprints"].extend(dt for dt in detected_sec_plugins if dt not in findings["login_security_plugin_footprints"])

        # Clickjacking Protection
        findings["clickjacking_protection_login"]["x_frame_options"] = login_page_headers.get('X-Frame-Options', 'Not Set')
        findings["clickjacking_protection_login"]["csp_frame_ancestors"] = login_page_headers.get('Content-Security-Policy', 'Not Set') # Basic check, full CSP parsing is complex
        if 'frame-ancestors' in findings["clickjacking_protection_login"]["csp_frame_ancestors"]:
             print(f"        [+] CSP frame-ancestors found: {findings['clickjacking_protection_login']['csp_frame_ancestors']}")
        elif findings["clickjacking_protection_login"]["x_frame_options"] != 'Not Set':
             print(f"        [+] X-Frame-Options found: {findings['clickjacking_protection_login']['x_frame_options']}")
        else:
             print("        [-] No X-Frame-Options or CSP frame-ancestors found on login page headers.")


    # 3. Password Reset Page Analysis (wp-login.php?action=lostpassword)
    lostpassword_url = urljoin(target_url, 'wp-login.php?action=lostpassword')
    print(f"      Checking password reset page: {lostpassword_url}")
    lostpassword_page_html = None
    try:
        response_lp = make_request(lostpassword_url, config, method="GET", timeout=7)
        if response_lp and response_lp.status_code == 200:
            findings["lost_password_page_accessible"] = True
            lostpassword_page_html = response_lp.text
            print(f"        [+] Password reset page accessible at {lostpassword_url}.")
            # Check for CAPTCHA on lost password page
            if lostpassword_page_html:
                findings["captcha_details"]["on_lost_password_page"] = True
                detected_lp_captcha_types = _check_footprints(lostpassword_page_html, CAPTCHA_FOOTPRINTS_AUTH, "CAPTCHA on Lost Password Page")
                if detected_lp_captcha_types: # Add to overall list, avoid duplicates
                    for dt in detected_lp_captcha_types:
                        if dt not in findings["captcha_details"]["detected_types"]:
                             findings["captcha_details"]["detected_types"].append(dt)
        elif response_lp:
            findings["lost_password_page_accessible"] = False
            print(f"        [-] Password reset page not accessible or error (Status: {response_lp.status_code}).")
        else:
            findings["lost_password_page_accessible"] = False; print("        [-] Request to password reset page failed.")
    except Exception as e:
        print(f"      [-] Error checking password reset page: {e}")
        findings["lost_password_page_accessible"] = "Error"

    # Consolidate details and add remediations
    summary = []
    if findings["http_auth_on_login"]:
        summary.append("HTTP Authentication is enabled on wp-login.php.")
        state.add_remediation_suggestion("auth_http_login", {"source":"AuthHardening", "description":"HTTP Auth on login page.", "severity":"Info", "remediation":"Good practice. Ensure strong credentials."})
    
    if findings["captcha_details"]["detected_types"]:
        types = ", ".join(findings["captcha_details"]["detected_types"])
        summary.append(f"CAPTCHA ({types}) detected.")
        state.add_remediation_suggestion("auth_captcha_present", {"source":"AuthHardening", "description":f"CAPTCHA ({types}) detected.", "severity":"Info", "remediation":"Good. Ensure it's effective and up-to-date."})
    else:
        summary.append("No common CAPTCHA detected on login/lost password pages.")
        state.add_remediation_suggestion("auth_captcha_missing", {"source":"AuthHardening", "description":"No CAPTCHA detected.", "severity":"Low", "remediation":"Consider adding CAPTCHA to login and password reset forms."})

    if findings["tfa_plugin_footprints"]:
        summary.append(f"2FA plugin footprints detected: {', '.join(findings['tfa_plugin_footprints'])}.")
        state.add_remediation_suggestion("auth_tfa_plugins", {"source":"AuthHardening", "description":"2FA plugin footprints detected.", "severity":"Info", "remediation":"Good. Ensure 2FA is enforced for privileged users."})

    if findings["login_security_plugin_footprints"]:
        summary.append(f"General login security plugin footprints: {', '.join(findings['login_security_plugin_footprints'])}.")
    
    if findings["clickjacking_protection_login"]["x_frame_options"] == 'Not Set' and 'frame-ancestors' not in findings["clickjacking_protection_login"]["csp_frame_ancestors"]:
        summary.append("Login page may be vulnerable to clickjacking (Missing X-Frame-Options/CSP frame-ancestors).")
        state.add_remediation_suggestion("auth_clickjacking_login", {"source":"AuthHardening", "description":"Login page clickjacking protection missing.", "severity":"Medium", "remediation":"Implement X-Frame-Options or CSP frame-ancestors headers on the login page."})

    findings["details"] = " ".join(summary) if summary else "Auth hardening checks performed. See specific findings."
    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Authentication hardening checks finished. Details: {findings['details']}")
