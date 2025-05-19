import re
from urllib.parse import urljoin
from .utils import make_request # Import the helper function

def analyze_user_registration(state, config, target_url):
    """Analyzes user registration status and common paths."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "user_registration" not in analyzer_findings:
        analyzer_findings["user_registration"] = {"status": "Running", "details": {}}
    reg_details = analyzer_findings["user_registration"]

    # Common registration paths
    reg_paths = ["/wp-login.php?action=register", "/wp-signup.php", "/register"]
    registration_open = False
    registration_url_found = None

    for path in reg_paths:
        test_url = urljoin(target_url, path)
        print(f"    Checking registration page: {test_url}")
        response = make_request(test_url, config)

        # Check for status 200 and common registration form indicators
        if response and response.status_code == 200:
            text_lower = response.text.lower()
            # Keywords indicating a registration page
            keywords_present = any(kw in text_lower for kw in [
                "register for this site", "create an account", "registration form",
                "complete signup", "choose a username"
            ])
            # Form elements indicating a registration form
            form_present = (
                re.search(r'<form[^>]+(id="registerform"|name="registerform")[^>]*>', response.text, re.IGNORECASE) or
                (re.search(r'input[^>]+name=["\']user_login["\']', response.text, re.IGNORECASE) and
                 re.search(r'input[^>]+name=["\']user_email["\']', response.text, re.IGNORECASE))
            )
            # Avoid matching login forms that might contain "register" links
            is_login_form = "log in" in text_lower and "user_pass" in text_lower

            if keywords_present and form_present and not is_login_form:
                registration_open = True
                registration_url_found = test_url
                print(f"    [!] User registration appears to be OPEN at: {test_url}")
                break # Found an open registration page

    reg_details["open"] = registration_open
    reg_details["url_checked"] = registration_url_found if registration_url_found else reg_paths[0] # Report the URL found or the first one checked

    if registration_open:
        reg_details["status"] = "Open"
        state.add_critical_alert(f"User registration is open at {registration_url_found}.")
        state.add_remediation_suggestion("user_registration_open", {
            "source": "WP Analyzer",
            "description": f"User registration is open at {registration_url_found}. This can be a security risk if not properly managed.",
            "severity": "Medium",
            "remediation": "Disable user registration if not required (Settings > General > Membership). If required, ensure new users get the 'Subscriber' role by default and use strong captchas/verification."
        })
        # Note: Checking default role automatically is complex and often requires creating a test user.
        reg_details["default_role_check"] = "Manual check recommended if registration is open."
    else:
        reg_details["status"] = "Likely Closed or Not Found"
        print("    [+] User registration seems closed or not found at common paths.")

    # Update the specific sub-key within the module's findings
    analyzer_findings["user_registration"] = reg_details
    state.update_module_findings(module_key, analyzer_findings)
