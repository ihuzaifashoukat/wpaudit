import time
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.utils import user_confirm
from .utils import make_request, sanitize_filename

# Common CAPTCHA footprints (keywords, script sources, class names)
CAPTCHA_FOOTPRINTS = {
    "Google reCAPTCHA": [re.compile(r"google.com/recaptcha|grecaptcha", re.IGNORECASE)],
    "hCaptcha": [re.compile(r"hcaptcha.com|h-captcha", re.IGNORECASE)],
    "Really Simple CAPTCHA": [re.compile(r"really-simple-captcha", re.IGNORECASE)],
    "Math Captcha": [re.compile(r"math-captcha|wpcf7-math-captcha", re.IGNORECASE)],
    # Add more specific footprints for other CAPTCHA plugins
}

# Common 2FA plugin footprints
TFA_PLUGIN_FOOTPRINTS = {
    "Wordfence Login Security": [re.compile(r"wordfence-ls-|wf-ls-", re.IGNORECASE)],
    "Google Authenticator (WordPress Plugin)": [re.compile(r"ga_google_authenticator|google-authenticator", re.IGNORECASE)],
    "Two Factor (Official Plugin)": [re.compile(r"Two Factor Authentication|#two-factor-backup-codes", re.IGNORECASE)],
    "WP 2FA": [re.compile(r"wp-2fa-|wp2fa_", re.IGNORECASE)],
    # Add more
}


def _analyze_login_form_html(html_content, login_url_base, findings_details):
    """Analyzes HTML content of the login page for CAPTCHA, 2FA, links."""
    if not html_content:
        return

    soup = BeautifulSoup(html_content, 'html.parser')
    text_lower = html_content.lower() # For string searching

    # CAPTCHA Detection
    detected_captchas = []
    for name, patterns in CAPTCHA_FOOTPRINTS.items():
        for pattern in patterns:
            if pattern.search(html_content): # Search raw HTML for script sources etc.
                if name not in detected_captchas:
                    detected_captchas.append(name)
                    print(f"        [+] Detected CAPTCHA footprint: {name}")
                break
    findings_details["captcha_detected"] = detected_captchas if detected_captchas else False

    # 2FA Plugin Footprint Detection
    detected_2fa_plugins = []
    for name, patterns in TFA_PLUGIN_FOOTPRINTS.items():
        for pattern in patterns:
            if pattern.search(html_content):
                if name not in detected_2fa_plugins:
                    detected_2fa_plugins.append(name)
                    print(f"        [+] Detected 2FA plugin footprint: {name}")
                break
    findings_details["2fa_plugin_footprints"] = detected_2fa_plugins if detected_2fa_plugins else False

    # "Lost your password?" Link
    lost_password_link = soup.find('a', href=re.compile(r"wp-login\.php\?action=lostpassword", re.IGNORECASE))
    if lost_password_link:
        findings_details["lost_password_link_present"] = True
        findings_details["lost_password_link_url"] = urljoin(login_url_base, lost_password_link.get('href', ''))
        print(f"        [+] Standard 'Lost your password?' link found: {findings_details['lost_password_link_url']}")
    else:
        findings_details["lost_password_link_present"] = False
        print("        [-] Standard 'Lost your password?' link not found or modified.")

    # "Register" Link
    register_link = soup.find('a', href=re.compile(r"wp-login\.php\?action=register", re.IGNORECASE))
    if register_link:
        findings_details["register_link_present"] = True
        findings_details["register_link_url"] = urljoin(login_url_base, register_link.get('href', ''))
        print(f"        [+] 'Register' link found: {findings_details['register_link_url']}")
    else:
        findings_details["register_link_present"] = False
        print("        [-] 'Register' link not found on login page.")
    
    # Password Policy Hints (very basic)
    password_input = soup.find('input', attrs={'type': 'password', 'name': re.compile(r'pwd|user_pass', re.I)})
    if password_input:
        if password_input.get('pattern'):
            findings_details["password_policy_hint_pattern"] = password_input['pattern']
            print(f"        [i] Password input has HTML5 pattern attribute: {password_input['pattern']}")
        if password_input.get('minlength'):
            findings_details["password_policy_hint_minlength"] = password_input['minlength']
            print(f"        [i] Password input has HTML5 minlength attribute: {password_input['minlength']}")
        # Could also search for JS related to password strength meters by class/ID


def analyze_login_page(state, config, target_url):
    """Analyzes the WordPress login page for accessibility, protections, and potential information leakage."""
    module_key = "wp_analyzer" # Part of main wp_analyzer findings
    analyzer_findings = state.get_module_findings(module_key, {})
    
    # Initialize login_page_analysis structure if it doesn't exist
    if "login_page_analysis" not in analyzer_findings:
        analyzer_findings["login_page_analysis"] = {} # Will be populated by this function

    # Use a clear sub-dictionary for this module's specific findings
    login_analysis_results = analyzer_findings.setdefault("login_page_analysis", {})
    login_analysis_results.update({ # Default structure for this run
        "status": "Running",
        "details": {}, # General details will be built here
        "standard_login_url_checked": None,
        "standard_login_accessible": None,
        "standard_login_status_code": None,
        "standard_login_redirects_to": None,
        "captcha_detected": False,
        "2fa_plugin_footprints": False,
        "lost_password_link_present": None,
        "register_link_present": None,
        "login_error_leakage_status": "Not Tested"
    })


    login_path = "/wp-login.php"
    login_url = urljoin(target_url, login_path)
    login_analysis_results["standard_login_url_checked"] = login_url
    print(f"    [i] Analyzing WordPress Login Page: {login_url}")

    # Initial request to get login page HTML and check accessibility
    # We need allow_redirects=True here to get the final login page content if it redirects (e.g. http to https)
    # but for the initial check of "is /wp-login.php itself 200 or a redirect", we might do allow_redirects=False first.
    # Let's try allow_redirects=False first to see the immediate status of /wp-login.php
    
    initial_response = make_request(login_url, config, allow_redirects=False, timeout=10)
    login_page_html_content = None

    if initial_response:
        login_analysis_results["standard_login_status_code"] = initial_response.status_code
        if initial_response.status_code == 200:
            if "user_login" in initial_response.text and "user_pass" in initial_response.text:
                print(f"    [+] Standard login page ({login_url}) directly accessible (200 OK).")
                login_analysis_results["standard_login_accessible"] = True
                login_page_html_content = initial_response.text
            else:
                print(f"    [?] Standard login page ({login_url}) returned 200 OK but doesn't look like a standard WP login form.")
                login_analysis_results["standard_login_accessible"] = "Partial (200 OK, Content Mismatch)"
                login_page_html_content = initial_response.text # Still try to parse
        
        elif 300 <= initial_response.status_code < 400 and initial_response.headers.get("Location"):
            redirect_loc = initial_response.headers["Location"]
            login_analysis_results["standard_login_redirects_to"] = redirect_loc
            print(f"    [i] Standard login page ({login_url}) redirects to: {redirect_loc}.")
            
            # If it redirects, make another request to the redirect location to get its content
            # Only if it's on the same primary domain or a known related domain (e.g. www. subdomain)
            parsed_target_netloc = urlparse(target_url).netloc
            parsed_redirect_netloc = urlparse(redirect_loc).netloc
            if parsed_redirect_netloc == parsed_target_netloc or \
               parsed_redirect_netloc.endswith("." + parsed_target_netloc) or \
               parsed_target_netloc.endswith("." + parsed_redirect_netloc):
                print(f"      Following redirect to analyze login page content at: {redirect_loc}")
                final_login_page_response = make_request(redirect_loc, config, allow_redirects=True, timeout=10)
                if final_login_page_response and final_login_page_response.status_code == 200 and \
                   "user_login" in final_login_page_response.text and "user_pass" in final_login_page_response.text:
                    login_page_html_content = final_login_page_response.text
                    login_analysis_results["standard_login_accessible"] = True # Considered accessible if redirect leads to valid form
                    login_analysis_results["final_login_page_url"] = final_login_page_response.url # Store the final URL
                    print(f"    [+] Successfully fetched login page content from redirected URL: {final_login_page_response.url}")
                elif final_login_page_response:
                    login_analysis_results["standard_login_accessible"] = "Partial (Redirected, Final Content Mismatch or Error)"
                    print(f"    [-] Redirected login page at {redirect_loc} did not appear to be a standard WP login form (Status: {final_login_page_response.status_code}).")
                else:
                    login_analysis_results["standard_login_accessible"] = "Error (Redirect Fetch Failed)"
                    print(f"    [-] Failed to fetch redirected login page at {redirect_loc}.")
            else:
                login_analysis_results["standard_login_accessible"] = "Redirected Externally"
                print(f"    [i] Standard login page redirects to an external domain: {redirect_loc}. Not analyzing further.")

        else: # 4xx, 5xx errors for initial /wp-login.php
            print(f"    [-] Standard login page ({login_url}) not accessible (Status: {initial_response.status_code}).")
            login_analysis_results["standard_login_accessible"] = False
    else:
        print(f"    [-] Request to standard login page ({login_url}) failed.")
        login_analysis_results["standard_login_accessible"] = False
        login_analysis_results["standard_login_status_code"] = "Request Failed"

    # Analyze HTML content if we successfully fetched it
    if login_page_html_content:
        print("      Analyzing fetched login page HTML for protections and links...")
        _analyze_login_form_html(login_page_html_content, login_analysis_results.get("final_login_page_url", login_url), login_analysis_results)
    else:
        print("      No login page HTML content to analyze for CAPTCHA, 2FA, or links.")


    # Test error message leakage (username enumeration) if login page seems somewhat accessible
    # This part remains largely the same but uses the login_analysis_results dictionary
    if login_analysis_results["standard_login_accessible"] is True or \
       login_analysis_results["standard_login_accessible"] == "Partial (200 OK, Content Mismatch)" or \
       login_analysis_results["standard_login_accessible"] == "Partial (Redirected, Final Content Mismatch or Error)":
        
        effective_login_url_for_post = login_analysis_results.get("final_login_page_url", login_url) # Use final URL if redirected

        if config.get("analyzer_login_enumeration_test", True):
            if user_confirm(f"Perform login error message leakage test on {effective_login_url_for_post}? (Submits invalid credentials)", config):
                test_user = f"nonexistentuser_{int(time.time())}"
                test_pass = "invalidpassword"
                post_data = {"log": test_user, "pwd": test_pass, "wp-submit": "Log In", "testcookie": "1"}
                
                print(f"      Submitting invalid credentials (user: '{test_user}') to {effective_login_url_for_post} for error message analysis...")
                login_post_response = make_request(effective_login_url_for_post, config, method="POST", data=post_data, allow_redirects=True)

                if login_post_response and login_post_response.text:
                    text_lower = login_post_response.text.lower()
                    user_does_not_exist_msgs = ["unknown username", "invalid username", "no account found with that username"]
                    password_is_incorrect_msgs = [
                        f"the password you entered for the username {test_user.lower()}", # Check lowercased test_user
                        f"password you entered for the username <strong>{test_user}</strong>", # Check with strong tags
                        "error: incorrect password", "the password you entered is incorrect"
                    ]
                    generic_error_msgs = [
                        "the username or password you entered is incorrect", "your username and password don't match",
                        "invalid login credentials"
                    ]

                    found_user_does_not_exist = any(msg in text_lower for msg in user_does_not_exist_msgs)
                    found_password_is_incorrect = any(msg in text_lower for msg in password_is_incorrect_msgs)
                    found_generic_error = any(msg in text_lower for msg in generic_error_msgs)

                    if found_password_is_incorrect and not found_user_does_not_exist: # Key condition: implies user exists
                        print(f"        [!!!] Login error message potentially leaks user existence! Non-existent user '{test_user}' triggered a 'password incorrect' type error.")
                        login_analysis_results["login_error_leakage_status"] = "Leaks User Existence (High Confidence)"
                        state.add_critical_alert(f"Login page error messages may leak username existence at {effective_login_url_for_post}")
                        state.add_remediation_suggestion("login_username_enum_v2", {
                            "source": "WP Analyzer (Login Page)",
                            "description": f"Login error messages at {effective_login_url_for_post} appear to differentiate between invalid usernames and incorrect passwords for valid usernames, potentially allowing username enumeration.",
                            "severity": "Medium",
                            "remediation": "Configure WordPress or use a security plugin to display generic error messages for all failed login attempts, regardless of whether the username exists or not (e.g., 'Invalid username or password.')."
                        })
                    elif found_user_does_not_exist:
                        print(f"        [+] Login error message correctly indicates non-existent user '{test_user}'. This is better, but ensure it's identical to 'wrong password' message for true non-leakage.")
                        login_analysis_results["login_error_leakage_status"] = "Likely Differentiates User (Moderate Confidence)"
                    elif found_generic_error:
                         print(f"        [+] Login error message appears generic. Good.")
                         login_analysis_results["login_error_leakage_status"] = "Likely Generic (Good)"
                    else:
                        print(f"        [i] Login error message analysis inconclusive. Response snippet: {login_post_response.text[:250]}")
                        login_analysis_results["login_error_leakage_status"] = "Inconclusive"
                else:
                    print(f"        [-] Failed to get a response from login POST for error message check.")
                    login_analysis_results["login_error_leakage_status"] = "Test Failed (No Response)"
            else:
                login_analysis_results["login_error_leakage_status"] = "Skipped (User Declined)"
        else:
             login_analysis_results["login_error_leakage_status"] = "Skipped (Disabled in Config)"
    else: # Login page not accessible enough for error message test
        login_analysis_results["login_error_leakage_status"] = "Skipped (Login Page Not Accessible)"


    # Consolidate details for the main "details" field
    summary_details = []
    if login_analysis_results["standard_login_accessible"] is True: summary_details.append("Standard login page accessible.")
    elif login_analysis_results["standard_login_accessible"] is False: summary_details.append("Standard login page not accessible.")
    elif login_analysis_results["standard_login_redirects_to"]: summary_details.append(f"Standard login redirects to {login_analysis_results['standard_login_redirects_to']}.")
    
    if login_analysis_results.get("captcha_detected"): summary_details.append(f"CAPTCHA detected: {', '.join(login_analysis_results['captcha_detected'])}.")
    if login_analysis_results.get("2fa_plugin_footprints"): summary_details.append(f"2FA plugin footprints: {', '.join(login_analysis_results['2fa_plugin_footprints'])}.")
    if login_analysis_results.get("lost_password_link_present") is True: summary_details.append("'Lost password' link present.")
    if login_analysis_results.get("register_link_present") is True: summary_details.append("'Register' link present.")
    
    leak_status = login_analysis_results.get("login_error_leakage_status", "Not Tested")
    if leak_status not in ["Not Tested", "Skipped (User Declined)", "Skipped (Disabled in Config)", "Skipped (Login Page Not Accessible)", "Likely Generic (Good)"]:
        summary_details.append(f"Login error leakage: {leak_status}.")

    login_analysis_results["details"] = " ".join(summary_details) if summary_details else "Login page checks performed. See specific findings."
    login_analysis_results["status"] = "Completed"
    
    # Update the main analyzer_findings with the modified login_analysis_results
    analyzer_findings["login_page_analysis"] = login_analysis_results
    state.update_module_findings(module_key, analyzer_findings)
    print(f"    [+] Login page analysis finished. Status: {login_analysis_results['status']}")
