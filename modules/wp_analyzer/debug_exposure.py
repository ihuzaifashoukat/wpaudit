import re
import time
from urllib.parse import urljoin
from core.utils import sanitize_filename # Core utils needed here
from .utils import make_request # Local utils for requests

def check_wp_debug_exposure(state, config, target_url):
    """Checks for signs of WP_DEBUG being enabled and exposing errors on pages."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "wp_debug_exposure" not in analyzer_findings:
        analyzer_findings["wp_debug_exposure"] = {"status": "Running", "exposed_on_pages": []}
    debug_exposure_details = analyzer_findings["wp_debug_exposure"]

    # Check config flag first
    if not config.get("analyzer_check_wp_debug", True):
        print("    [i] WP_DEBUG exposure check disabled in configuration.")
        debug_exposure_details["status"] = "Disabled in Config"
        analyzer_findings["wp_debug_exposure"] = debug_exposure_details
        state.update_module_findings(module_key, analyzer_findings)
        return # Exit if disabled

    # Common PHP error strings that might appear if WP_DEBUG is on and errors are displayed
    # Using raw strings (r"...") for regex patterns
    debug_error_patterns = [
        r"<b>Notice</b>:", r"<b>Warning</b>:", r"<b>Fatal error</b>:",
        r"<b>Parse error</b>:", r"<b>Deprecated</b>:",
        r"Call Stack", r"Stack trace",
        r"in\s+.+?\s+on\s+line\s+\d+", # Matches "in /path/to/file.php on line 123"
        r"WordPress\s+database\s+error" # Matches common WP DB error message
    ]
    # Compile patterns for efficiency
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in debug_error_patterns]

    # Pages to check (can be expanded based on findings from other modules)
    pages_to_check = [
        target_url, # Check homepage
        urljoin(target_url, "/wp-login.php"), # Check login page
        # Check a non-existent page which might trigger 404-related errors if debug is on
        urljoin(target_url, "/nonexistent-page-for-debug-test-" + sanitize_filename(str(time.time())) + ".php")
    ]
    # Future enhancement: Add paths discovered by directory bruteforcer or sitemap scanner

    # Ensure exposed_on_pages list exists
    if "exposed_on_pages" not in debug_exposure_details:
        debug_exposure_details["exposed_on_pages"] = []
    exposed_pages_list = debug_exposure_details["exposed_on_pages"]

    found_exposure = False # Flag to track if any exposure was found

    for page_url in pages_to_check:
        print(f"    Checking WP_DEBUG exposure on: {page_url}")
        response = make_request(page_url, config, method="GET")
        if response and response.text:
            page_found_exposure = False
            for pattern in compiled_patterns:
                # Search for any of the debug patterns in the response body
                if pattern.search(response.text):
                    print(f"    [!!!] Potential WP_DEBUG error exposure found on: {page_url}")
                    # Avoid adding duplicate URLs
                    if page_url not in exposed_pages_list:
                        exposed_pages_list.append(page_url)
                    found_exposure = True
                    page_found_exposure = True
                    # Add remediation suggestion only once per finding type, but alert for each page
                    state.add_critical_alert(f"WP_DEBUG errors potentially exposed on {page_url}")
                    state.add_remediation_suggestion(f"wp_debug_exposed", { # Use a general key for the suggestion
                        "source": "WP Analyzer",
                        "description": f"PHP error messages (indicative of WP_DEBUG=true and display_errors=On) found on one or more pages (e.g., {page_url}). This can leak sensitive information like file paths or database query details.",
                        "severity": "Medium",
                        "remediation": "Ensure WP_DEBUG, WP_DEBUG_LOG, and WP_DEBUG_DISPLAY are set to false on production sites. Configure PHP to log errors to a file instead of displaying them publicly (log_errors = On, display_errors = Off)."
                    })
                    break # Found an error on this page, no need to check other patterns for it
            # if not page_found_exposure:
            #     print(f"      [+] No obvious WP_DEBUG errors found on {page_url}") # Optional positive confirmation

    debug_exposure_details["exposed_on_pages"] = exposed_pages_list
    if found_exposure:
        debug_exposure_details["status"] = "Potentially Exposed"
    else:
        debug_exposure_details["status"] = "Likely Not Exposed"
        print("    [+] No obvious signs of WP_DEBUG error exposure found on checked pages.")

    analyzer_findings["wp_debug_exposure"] = debug_exposure_details
    state.update_module_findings(module_key, analyzer_findings)
