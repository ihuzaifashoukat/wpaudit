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
    if "exposed_on_pages" not in debug_exposure_details: # For PHP error messages
        debug_exposure_details["exposed_on_pages"] = []
    if "exposed_debug_log_url" not in debug_exposure_details: # For debug.log
        debug_exposure_details["exposed_debug_log_url"] = None
    if "query_monitor_footprints" not in debug_exposure_details: # For Query Monitor
        debug_exposure_details["query_monitor_footprints"] = {"detected_on_pages": [], "details": []}

    exposed_php_error_pages = debug_exposure_details["exposed_on_pages"]
    found_php_error_exposure = False

    print("    [i] Checking for PHP error message exposure (WP_DEBUG)...")
    for page_url in pages_to_check:
        print(f"      Checking for PHP errors on: {page_url}")
        try:
            response = make_request(page_url, config, method="GET", timeout=7)
            if response and response.text:
                page_found_php_error = False
                for pattern in compiled_patterns:
                    if pattern.search(response.text):
                        print(f"        [!!!] Potential PHP error (WP_DEBUG) exposure found on: {page_url}")
                        if page_url not in exposed_php_error_pages:
                            exposed_php_error_pages.append(page_url)
                        found_php_error_exposure = True
                        page_found_php_error = True
                        # Remediation suggestion added once later if found_php_error_exposure is true
                        break 
                # Query Monitor check on this page's content
                qm_comments = re.findall(r"<!-- Query Monitor.*?-->|<!-- QM.*?-->", response.text, re.DOTALL)
                qm_ids_classes = re.findall(r"id=['\"]query-monitor(-.+)?['\"]|class=['\"]qm(-.+)?['\"]", response.text)
                if qm_comments or qm_ids_classes:
                    print(f"        [!] Query Monitor footprints detected on: {page_url}")
                    if page_url not in debug_exposure_details["query_monitor_footprints"]["detected_on_pages"]:
                        debug_exposure_details["query_monitor_footprints"]["detected_on_pages"].append(page_url)
                    if qm_comments and "Query Monitor HTML output" not in debug_exposure_details["query_monitor_footprints"]["details"]:
                         debug_exposure_details["query_monitor_footprints"]["details"].append("Query Monitor HTML output (comments) found.")
                    if qm_ids_classes and "Query Monitor CSS IDs/classes found." not in debug_exposure_details["query_monitor_footprints"]["details"]:
                         debug_exposure_details["query_monitor_footprints"]["details"].append("Query Monitor CSS IDs/classes found.")
        except Exception as e:
            print(f"        [-] Error checking page {page_url} for debug exposure: {e}")

    debug_exposure_details["exposed_on_pages"] = exposed_php_error_pages
    if found_php_error_exposure:
        state.add_critical_alert(f"WP_DEBUG errors potentially exposed on one or more pages.")
        state.add_remediation_suggestion("wp_debug_php_errors_exposed", {
            "source": "WP Analyzer (Debug Exposure)",
            "description": f"PHP error messages (indicative of WP_DEBUG=true and display_errors=On) found on pages like: {', '.join(exposed_php_error_pages[:2])}{'...' if len(exposed_php_error_pages)>2 else ''}. This can leak sensitive information.",
            "severity": "Medium",
            "remediation": "Ensure WP_DEBUG and WP_DEBUG_DISPLAY are false on production. Log errors to a private file (WP_DEBUG_LOG true, but ensure log file is not web accessible)."
        })

    # Check for publicly accessible debug.log
    print("    [i] Checking for publicly accessible wp-content/debug.log...")
    debug_log_url = urljoin(target_url, "wp-content/debug.log")
    try:
        log_response = make_request(debug_log_url, config, method="GET", timeout=7)
        if log_response and log_response.status_code == 200 and log_response.text:
            # Check if it looks like a log file (e.g., contains timestamps, PHP errors)
            if re.search(r"\[\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}(?: UTC)?\] PHP", log_response.text):
                print(f"    [!!!] Publicly accessible debug.log found and contains data: {debug_log_url}")
                debug_exposure_details["exposed_debug_log_url"] = debug_log_url
                state.add_critical_alert(f"Publicly accessible debug.log found: {debug_log_url}")
                state.add_remediation_suggestion("wp_debug_log_exposed", {
                    "source": "WP Analyzer (Debug Exposure)",
                    "description": f"The WordPress debug log file (wp-content/debug.log) is publicly accessible at {debug_log_url} and contains debug information. This is a critical information leak.",
                    "severity": "High",
                    "remediation": "Ensure WP_DEBUG_LOG is true ONLY for debugging, and if so, protect the debug.log file from public web access (e.g., via .htaccess or server configuration). Delete old log files if not needed. Ideally, disable WP_DEBUG_LOG on production."
                })
            else:
                print(f"      [?] {debug_log_url} is accessible but doesn't look like a typical debug.log or is empty.")
        elif log_response and log_response.status_code != 404:
             print(f"      [i] {debug_log_url} returned status {log_response.status_code} (not 200 or 404).")
        else: # 404 or request failed
            print(f"      [+] No publicly accessible debug.log found at {debug_log_url} (or request failed).")
    except Exception as e:
        print(f"      [-] Error checking for debug.log: {e}")


    # Consolidate status
    final_details_parts = []
    if found_php_error_exposure:
        final_details_parts.append(f"PHP errors exposed on {len(exposed_php_error_pages)} page(s).")
    if debug_exposure_details["exposed_debug_log_url"]:
        final_details_parts.append("Public debug.log found.")
    if debug_exposure_details["query_monitor_footprints"]["detected_on_pages"]:
        final_details_parts.append(f"Query Monitor footprints on {len(debug_exposure_details['query_monitor_footprints']['detected_on_pages'])} page(s).")
        state.add_remediation_suggestion("query_monitor_exposed", {
            "source": "WP Analyzer (Debug Exposure)",
            "description": f"Query Monitor plugin footprints detected. If its output is visible to unauthenticated users or on production, it can leak sensitive information.",
            "severity": "Low", # Can be higher if actual data is shown
            "remediation": "Ensure Query Monitor (or similar debugging plugins) are configured to only display output to authenticated administrators, or are disabled on production sites."
        })


    if not final_details_parts:
        debug_exposure_details["status"] = "Likely Not Exposed"
        print("    [+] No obvious signs of common debug information exposure found.")
    else:
        debug_exposure_details["status"] = "Potential Exposure Found"
    
    debug_exposure_details["details_summary"] = " ".join(final_details_parts) if final_details_parts else "No specific debug exposures identified by these checks."

    analyzer_findings["wp_debug_exposure"] = debug_exposure_details
    state.update_module_findings(module_key, analyzer_findings)
