# Module for WordPress Cron Job (wp-cron.php) Analysis
import requests
from urllib.parse import urljoin
from core.utils import make_request # Assuming a utility for requests exists

def analyze_cron(state, config, target_url):
    """
    Analyzes the accessibility and potential issues related to wp-cron.php.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "cron_analysis"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Checking wp-cron.php accessibility.",
        "wp_cron_accessible": None, # True/False/None
        "potential_dos_risk": False # If accessible
    })

    cron_url = urljoin(target_url, 'wp-cron.php')
    print(f"    Checking cron path: {cron_url}")

    try:
        # Make a HEAD request first to be less intrusive, fallback to GET if needed
        response = make_request(cron_url, config, method="HEAD", timeout=10)
        if not response: # If HEAD fails, try GET
             print(f"      HEAD request failed for {cron_url}, trying GET...")
             response = make_request(cron_url, config, method="GET", timeout=15)

        if response:
            # Consider any 2xx or 4xx (except 404) as potentially accessible or blocked, but existing
            # 5xx might indicate it exists but is erroring (could still be a DoS vector)
            if response.status_code == 404:
                findings["wp_cron_accessible"] = False
                findings["details"] = "wp-cron.php returned 404 Not Found."
                print(f"      [-] {cron_url} not found (404).")
            elif 200 <= response.status_code < 500:
                 findings["wp_cron_accessible"] = True
                 findings["potential_dos_risk"] = True # Mark potential risk if accessible
                 findings["details"] = f"wp-cron.php is accessible (Status: {response.status_code}). This might pose a DoS risk if not rate-limited or if disabled in wp-config but still reachable."
                 print(f"      [+] {cron_url} is accessible (Status: {response.status_code}). Potential DoS vector.")
                 state.add_remediation_suggestion("wp_cron_dos_risk", {
                     "source": "WP Analyzer",
                     "description": f"wp-cron.php is publicly accessible ({cron_url}). While necessary for scheduled tasks if server-side cron isn't used, it can sometimes be abused for DoS attacks.",
                     "severity": "Low",
                     "remediation": "If using a real server-side cron job, consider disabling the default WP-Cron behavior by adding `define('DISABLE_WP_CRON', true);` to wp-config.php and blocking direct access to wp-cron.php via web server rules (e.g., .htaccess/Nginx). If relying on WP-Cron, ensure adequate server resources or implement rate limiting."
                 })
            else: # 5xx errors or unexpected codes
                 findings["wp_cron_accessible"] = True # It exists but is erroring
                 findings["potential_dos_risk"] = True
                 findings["details"] = f"wp-cron.php returned an error status ({response.status_code}). It exists but may be misconfigured or causing server load."
                 print(f"      [?] {cron_url} returned status {response.status_code}. Might indicate issues.")

        else:
            findings["wp_cron_accessible"] = None # Request failed
            findings["details"] = "Request to wp-cron.php failed."
            print(f"      [-] Request failed for {cron_url}.")

    except requests.exceptions.RequestException as e:
        print(f"      [-] Error checking {cron_url}: {e}")
        findings["wp_cron_accessible"] = None
        findings["details"] = f"Error during request to wp-cron.php: {e}"

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Cron job analysis finished. Details: {findings['details']}")
