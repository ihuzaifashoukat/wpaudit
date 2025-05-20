# Module for WordPress Cron Job (wp-cron.php) Analysis
import requests
from urllib.parse import urljoin
from .utils import make_request # Assuming a utility for requests exists

def analyze_cron(state, config, target_url):
    """
    Analyzes the accessibility and potential issues related to wp-cron.php.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "cron_analysis"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Analyzing wp-cron.php accessibility and configuration hints.",
        "wp_cron_url": None,
        "wp_cron_accessible": None, # True, False, "Error"
        "wp_cron_status_code": None,
        "potential_dos_risk": False,
        "disable_wp_cron_hint": None, # True (hinted), False (not hinted), "Unknown"
        "alternate_wp_cron_info": "Not actively checked. If used, ensure it's intentional.",
        "x_robots_tag_present": None # True, False, "Not Applicable"
    })
    print("    [i] Analyzing WordPress Cron (wp-cron.php)...")

    cron_url = urljoin(target_url, 'wp-cron.php')
    findings["wp_cron_url"] = cron_url
    print(f"      Checking cron path: {cron_url}")

    response_text_snippet = ""
    response_headers = {}

    try:
        # Prefer GET for wp-cron.php as HEAD might not always behave identically or reveal headers like X-Robots-Tag
        # Adding a doing_wp_cron query param can sometimes elicit a more standard response or bypass caches.
        cron_test_url = f"{cron_url}?doing_wp_cron&{requests.utils.quote(str(requests.compat.urlparse(target_url).netloc))}" # Mimic WP's own call
        
        response = make_request(cron_test_url, config, method="GET", timeout=15)

        if response:
            findings["wp_cron_status_code"] = response.status_code
            response_headers = response.headers
            response_text_snippet = response.text[:250] if response.text else "" # Get a snippet

            if response.status_code == 404:
                findings["wp_cron_accessible"] = False
                findings["details"] = "wp-cron.php returned 404 Not Found. It might be deleted or blocked at the server level."
                print(f"      [-] {cron_url} not found (404).")
            elif response.status_code == 403:
                findings["wp_cron_accessible"] = False # Blocked
                findings["details"] = f"wp-cron.php is forbidden (Status: {response.status_code}). Access is likely blocked."
                print(f"      [+] {cron_url} access forbidden (403). Good if server cron is used.")
            elif 200 <= response.status_code < 300: # Typically 200
                findings["wp_cron_accessible"] = True
                findings["potential_dos_risk"] = True # Always a potential if directly accessible
                findings["details"] = f"wp-cron.php is accessible (Status: {response.status_code})."
                print(f"      [+] {cron_url} is accessible (Status: {response.status_code}).")

                # Heuristic for DISABLE_WP_CRON:
                # If wp-cron.php returns 200 OK but is completely empty or very minimal,
                # it *might* hint at DISABLE_WP_CRON, but this is weak.
                # WordPress core wp-cron.php, even when DISABLE_WP_CRON is true, will still execute
                # and exit early. It usually returns a blank page.
                # If it's accessible, the main concern is DoS regardless of DISABLE_WP_CRON.
                # The constant itself prevents WP from *spawning* cron, not direct access.
                if not response.text or len(response.text.strip()) < 10: # Arbitrary small length
                    findings["disable_wp_cron_hint"] = "Possible (Minimal Response)"
                    findings["details"] += " Response was minimal, DISABLE_WP_CRON might be true, but file is still accessible."
                    print("        [i] Response from wp-cron.php was minimal. DISABLE_WP_CRON might be true, but file remains accessible.")
                else:
                    findings["disable_wp_cron_hint"] = "Not Evident from Response"
                
                state.add_remediation_suggestion("wp_cron_dos_risk_v2", { # Updated key
                    "source": "WP Analyzer (Cron Check)",
                    "description": f"wp-cron.php is publicly accessible ({cron_url}). While necessary for scheduled tasks if server-side cron isn't used, it can be abused for DoS attacks by overwhelming the server with requests.",
                    "severity": "Low",
                    "remediation": "If using a real server-side cron job, define('DISABLE_WP_CRON', true); in wp-config.php AND block direct web access to wp-cron.php (e.g., via .htaccess/Nginx rules). If relying on built-in WP-Cron, ensure adequate server resources or consider solutions like Action Scheduler for more robust background processing, and implement rate limiting if possible."
                })
            elif 500 <= response.status_code < 600:
                findings["wp_cron_accessible"] = True # It exists but is erroring
                findings["potential_dos_risk"] = True # Can still be hit repeatedly
                findings["details"] = f"wp-cron.php returned a server error (Status: {response.status_code}). It exists but is misconfigured or causing load."
                print(f"      [!] {cron_url} returned server error {response.status_code}. Potential issue or DoS vector.")
            else: # Other codes (e.g. 401, 405)
                findings["wp_cron_accessible"] = True # Exists, but access is modified/restricted
                findings["potential_dos_risk"] = True # Still potentially hittable
                findings["details"] = f"wp-cron.php returned status {response.status_code}. Access is modified."
                print(f"      [?] {cron_url} returned status {response.status_code}. Access seems modified (e.g., auth, method block).")
        else:
            findings["wp_cron_accessible"] = "Error (No Response)"
            findings["details"] = "Request to wp-cron.php failed (no response object)."
            print(f"      [-] Request failed for {cron_url} (no response object).")

        # Check X-Robots-Tag
        x_robots_tag = response_headers.get('X-Robots-Tag', response_headers.get('x-robots-tag'))
        if x_robots_tag:
            if "noindex" in x_robots_tag.lower():
                findings["x_robots_tag_present"] = True
                print(f"        [+] X-Robots-Tag: '{x_robots_tag}' found (good).")
            else:
                findings["x_robots_tag_present"] = "Present but not 'noindex'"
                print(f"        [?] X-Robots-Tag: '{x_robots_tag}' found but doesn't explicitly contain 'noindex'.")
        elif findings["wp_cron_accessible"] is True: # Only relevant if accessible
            findings["x_robots_tag_present"] = False
            print("        [-] X-Robots-Tag with 'noindex' not found for wp-cron.php.")
            state.add_remediation_suggestion("wp_cron_xrobots", {
                "source": "WP Analyzer (Cron Check)",
                "description": "The X-Robots-Tag: noindex, nofollow header was not detected for wp-cron.php.",
                "severity": "Info",
                "remediation": "Consider adding an X-Robots-Tag HTTP header with 'noindex, nofollow' for wp-cron.php via server configuration to prevent search engines from attempting to index it."
            })
        else:
            findings["x_robots_tag_present"] = "Not Applicable (File Not Accessible)"


    except requests.exceptions.RequestException as e:
        print(f"      [-] Error during wp-cron.php check: {e}")
        findings["wp_cron_accessible"] = "Error (Request Exception)"
        findings["details"] = f"Request exception for wp-cron.php: {type(e).__name__}"

    # Add informational note about ALTERNATE_WP_CRON
    if findings["alternate_wp_cron_info"] == "Not actively checked. If used, ensure it's intentional.": # Only if not overridden
        findings["alternate_wp_cron_info"] = "ALTERNATE_WP_CRON is a WordPress constant that, if true, uses a redirect-based mechanism to trigger cron. This is generally less reliable and not commonly used. Its status cannot be easily determined remotely."


    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] WordPress Cron (wp-cron.php) analysis finished. Overall status: {findings.get('details', 'See specific findings.')}")
