# Module for WordPress Authentication Hardening Checks
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.utils import make_request # Assuming a utility for requests exists

def analyze_auth_hardening(state, config, target_url):
    """
    Analyzes login page security, focusing on CAPTCHA detection.
    Password policy and lockout checks are difficult externally and remain placeholders.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "auth_hardening"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Checking login page for CAPTCHA.",
        "password_policy_check": {"status": "Not Implemented", "details": "Difficult to check externally"},
        "lockout_mechanism_check": {"status": "Not Implemented", "details": "Requires failed login attempts, potentially disruptive."},
        "captcha_check": {"status": "Running", "detected": False, "type_hint": None},
        "two_factor_auth_check": {"status": "Not Implemented", "details": "Difficult to check externally"}
    })

    login_url = urljoin(target_url, 'wp-login.php')
    print(f"    Checking login page for CAPTCHA: {login_url}")

    try:
        response = make_request(login_url, config, method="GET", timeout=15)
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'lxml')
            login_form = soup.find('form', id='loginform')

            if login_form:
                form_html = str(login_form).lower()
                captcha_detected = False
                captcha_type = None

                # Check for common CAPTCHA indicators
                if 'class="g-recaptcha"' in form_html or 'google.com/recaptcha' in form_html:
                    captcha_detected = True
                    captcha_type = "Google reCAPTCHA"
                    print("      [+] Google reCAPTCHA detected.")
                elif 'class="cf-turnstile"' in form_html or 'challenges.cloudflare.com/turnstile' in form_html:
                     captcha_detected = True
                     captcha_type = "Cloudflare Turnstile"
                     print("      [+] Cloudflare Turnstile detected.")
                elif 'id="captcha_image"' in form_html or 'name="captcha_code"' in form_html:
                     # Basic image/text captcha
                     captcha_detected = True
                     captcha_type = "Basic Image/Text CAPTCHA"
                     print("      [+] Basic Image/Text CAPTCHA detected.")
                # Add more checks for other CAPTCHA providers if needed

                findings["captcha_check"]["detected"] = captcha_detected
                findings["captcha_check"]["type_hint"] = captcha_type
                findings["captcha_check"]["status"] = "Completed"
                if captcha_detected:
                    findings["details"] = f"CAPTCHA ({captcha_type}) detected on login page."
                    state.add_remediation_suggestion("login_captcha_info", {
                        "source": "WP Analyzer",
                        "description": f"A CAPTCHA ({captcha_type}) is present on the login page, helping to mitigate automated brute-force attacks.",
                        "severity": "Info",
                        "remediation": "Ensure the CAPTCHA implementation is up-to-date and properly configured. This is a good security measure."
                    })
                else:
                    findings["details"] = "No common CAPTCHA indicators found on the login page form."
                    print("      [-] No obvious CAPTCHA detected on login form.")
                    state.add_remediation_suggestion("login_captcha_missing", {
                        "source": "WP Analyzer",
                        "description": "No CAPTCHA was detected on the login page.",
                        "severity": "Low",
                        "remediation": "Consider adding CAPTCHA (like reCAPTCHA, hCaptcha, or Cloudflare Turnstile) to the login page to protect against automated brute-force attacks."
                    })

            else:
                findings["captcha_check"]["status"] = "Error"
                findings["details"] = "Could not find login form (#loginform) on wp-login.php to check for CAPTCHA."
                print("      [-] Could not find #loginform on wp-login.php.")

        elif response:
            findings["captcha_check"]["status"] = "Error"
            findings["details"] = f"Could not fetch wp-login.php (Status: {response.status_code}) to check for CAPTCHA."
            print(f"      [-] Failed to fetch wp-login.php (Status: {response.status_code}).")
        else:
            findings["captcha_check"]["status"] = "Error"
            findings["details"] = "Request to wp-login.php failed."
            print("      [-] Request failed for wp-login.php.")

    except Exception as e:
        print(f"      [-] Error checking login page for CAPTCHA: {e}")
        findings["captcha_check"]["status"] = "Error"
        findings["details"] = f"Error during CAPTCHA check: {e}"

    # Final status update
    findings["status"] = "Completed" # Mark module as completed even if sub-checks failed/skipped
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Authentication hardening check (CAPTCHA) finished. Details: {findings['details']}")
