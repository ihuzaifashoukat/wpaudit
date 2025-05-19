import time
from urllib.parse import urljoin
from core.utils import user_confirm # Core utils needed here
from .utils import make_request # Local utils for requests

def analyze_login_page(state, config, target_url):
    """Analyzes the WordPress login page for accessibility and potential information leakage."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "login_page_analysis" not in analyzer_findings:
        analyzer_findings["login_page_analysis"] = {"status": "Running", "details": {}}
    login_details = analyzer_findings["login_page_analysis"]

    login_path = "/wp-login.php" # Standard login path
    login_url = urljoin(target_url, login_path)
    login_details["details"]["standard_login_url_checked"] = login_url
    print(f"    Checking standard login page: {login_url}")

    # First request: Check accessibility without redirects
    response = make_request(login_url, config, allow_redirects=False)

    if response and response.status_code == 200 and "user_login" in response.text and "user_pass" in response.text:
        print(f"    [+] Standard login page found at {login_url}.")
        login_details["details"]["standard_login_accessible"] = True

        # Test error message leakage (username enumeration) if login page is accessible
        # This is an active test that submits invalid credentials.
        if config.get("analyzer_login_enumeration_test", True): # Add config flag
            if user_confirm("Perform login error message leakage test (username enumeration)? This submits invalid credentials.", config):
                test_user = f"nonexistentuser_{int(time.time())}"
                test_pass = "invalidpassword"
                # Data for the login POST request
                post_data = {"log": test_user, "pwd": test_pass, "wp-submit": "Log In", "testcookie": "1"}

                # Make the POST request, allowing redirects to see the final error page
                print(f"      Submitting invalid credentials for user '{test_user}' to test error messages...")
                login_post_response = make_request(login_url, config, method="POST", data=post_data, allow_redirects=True)

                if login_post_response and login_post_response.text:
                    text_lower = login_post_response.text.lower()
                    # Check for specific error messages that differentiate between invalid user and invalid password
                    # WordPress messages can vary slightly by version/language, but these are common patterns.
                    user_does_not_exist_msgs = ["unknown username", "invalid username"]
                    password_is_incorrect_msgs = [
                        f"the password you entered for the username {test_user}", # Explicitly mentions the username
                        "error: incorrect password", # Sometimes combined with other hints
                        "the password you entered is incorrect" # Generic but implies user exists
                    ]
                    generic_error_msgs = [
                        "the username or password you entered is incorrect", # Good, generic message
                        "your username and password don't match"
                    ]

                    found_user_does_not_exist = any(msg in text_lower for msg in user_does_not_exist_msgs)
                    found_password_is_incorrect = any(msg in text_lower for msg in password_is_incorrect_msgs)
                    found_generic_error = any(msg in text_lower for msg in generic_error_msgs)

                    if found_password_is_incorrect:
                        # This is bad - the error implies the non-existent user actually exists.
                        print(f"    [!!!] Login error message leaks user existence! Non-existent user '{test_user}' triggered a 'password incorrect' type error.")
                        login_details["details"]["login_error_leakage_status"] = "Leaks User Existence"
                        state.add_critical_alert(f"Login page error messages leak username existence at {login_url}")
                        state.add_remediation_suggestion("login_username_enum", {
                            "source": "WP Analyzer",
                            "description": f"Login error messages at {login_url} differentiate between invalid usernames and incorrect passwords, allowing username enumeration.",
                            "severity": "Medium",
                            "remediation": "Configure WordPress or use a plugin to display generic error messages for failed login attempts, regardless of whether the username exists or not."
                        })
                    elif found_user_does_not_exist:
                        # This is expected for a non-existent user. Check if it's distinct from password errors.
                        print(f"    [+] Login error message correctly indicates non-existent user '{test_user}'.")
                        login_details["details"]["login_error_leakage_status"] = "Likely Not Leaking (Differentiates User)"
                        # Note: This is still a form of leakage if it's different from the password error message.
                        # A truly non-leaking system uses the same generic message for both cases.
                        # We flag it as "Likely Not Leaking" in the sense of *confirming* existence, but it's not ideal.
                    elif found_generic_error:
                         print(f"    [+] Login error message appears generic (good). Does not seem to leak user existence.")
                         login_details["details"]["login_error_leakage_status"] = "Likely Generic (Good)"
                    else:
                        print(f"    [i] Login error message analysis inconclusive. Response snippet: {login_post_response.text[:250]}")
                        login_details["details"]["login_error_leakage_status"] = "Inconclusive"
                else:
                    print(f"    [-] Failed to get a response from login POST for error message check.")
                    login_details["details"]["login_error_leakage_status"] = "Test Failed (No Response)"
            else:
                login_details["details"]["login_error_leakage_status"] = "Skipped (User Declined)"
        else:
             login_details["details"]["login_error_leakage_status"] = "Skipped (Disabled in Config)"

    elif response and 300 <= response.status_code < 400 and response.headers.get("Location"):
        # Handle redirects (e.g., custom login page)
        redirect_loc = response.headers["Location"]
        print(f"    [i] Standard login page ({login_url}) redirects to: {redirect_loc}. This might indicate a custom login URL (security by obscurity).")
        login_details["details"]["standard_login_redirects_to"] = redirect_loc
        login_details["details"]["standard_login_accessible"] = False
        state.add_summary_point(f"Standard login page redirects, potentially custom login URL in use: {redirect_loc}")
        # Optionally, try analyzing the redirected URL if it's on the same domain?
        # if urlparse(redirect_loc).netloc == urlparse(target_url).netloc:
        #     print(f"    Attempting to analyze redirected login page: {redirect_loc}")
        #     # Recursive call or separate logic for custom login URLs
    elif response:
        # Handle other non-200 responses
        print(f"    [-] Standard login page not accessible as expected (Status: {response.status_code}).")
        login_details["details"]["standard_login_accessible"] = False
        login_details["details"]["standard_login_status"] = response.status_code
    else:
        # Handle request failure
        print(f"    [-] Request to standard login page failed.")
        login_details["details"]["standard_login_accessible"] = False
        login_details["details"]["standard_login_status"] = "Request Failed"

    login_details["status"] = "Checked"
    analyzer_findings["login_page_analysis"] = login_details
    state.update_module_findings(module_key, analyzer_findings)
