import json
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup # For parsing HTML to find actions
from .utils import make_request, sanitize_filename # Assuming utils.py is in the same wp_analyzer package

# Basic XSS and SQLi payloads for AJAX parameter fuzzing (keep small and targeted)
# These should be distinct from the main XSS/SQLi checkers' payloads
AJAX_FUZZ_PAYLOADS = {
    "xss_basic": ["<script>alert('AJAX_XSS')</script>", "\"'><svg/onload=alert`1`>"],
    "sqli_basic": ["'", " OR 1=1 --", "SLEEP(5)"]
}

DEFAULT_AJAX_ACTIONS_TO_TEST = [
    {"action_name": "heartbeat", "method": "POST", "params": {"data[screen_id]": "front"}, "requires_nonce": False, "is_nopriv": True},
    # Add more known WordPress core or popular plugin 'nopriv' actions that are safe to call
    # Example: {"action_name": "some_plugin_public_info", "method": "GET", "params": {}, "requires_nonce": False, "is_nopriv": True},
]

def _discover_actions_from_html(html_content, target_url):
    """Rudimentary discovery of AJAX actions from HTML source."""
    discovered = []
    if not html_content:
        return discovered
    
    # Regex for common patterns like:
    # data-action="my_action"
    # 'action': 'my_action' (in JS objects)
    # action: "my_action"
    # jQuery.post(ajaxurl, { action: 'my_action_name' ... })
    # wp.ajax.send('my_action_name', { ... })
    
    # Simple regex for action names in JS-like structures or data attributes
    # This is very basic and can have false positives/negatives.
    # Looking for 'action': 'value' or "action": "value" or data-action="value"
    patterns = [
        re.compile(r"data-action\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        re.compile(r"['\"]action['\"]\s*:\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    ]
    
    for pattern in patterns:
        for match in pattern.finditer(html_content):
            action_name = match.group(1)
            if action_name and action_name not in discovered:
                # Assume GET/POST and no specific params for discovered actions initially
                discovered.append({"action_name": action_name, "method": "BOTH", "params": {}, "source": "HTML_Discovery"})
                print(f"        [d] Discovered potential AJAX action from HTML: '{action_name}'")
    return discovered


def _test_single_ajax_action(ajax_url, action_item, state, config):
    """Tests a single AJAX action and returns results."""
    action_value = action_item.get("action_name")
    methods_to_test_str = action_item.get("method", "BOTH").upper()
    base_params = action_item.get("params", {})
    # requires_nonce = action_item.get("requires_nonce", True) # Placeholder for future nonce checks
    # is_nopriv = action_item.get("is_nopriv", False) # If true, expect it to work without auth

    action_test_summary = {"action": action_value, "results": [], "fuzz_results": []}
    potential_issues_for_action = []

    print(f"      Testing AJAX action: '{action_value}'")

    methods_to_run = []
    if methods_to_test_str == "GET": methods_to_run.append("GET")
    elif methods_to_test_str == "POST": methods_to_run.append("POST")
    elif methods_to_test_str == "BOTH": methods_to_run.extend(["GET", "POST"])

    for method in methods_to_run:
        current_params = {"action": action_value, **base_params}
        response_data_parsed = None
        response_text_raw = ""
        response_status_code = None
        error_message = None
        
        try:
            response = make_request(ajax_url, config, method=method, data=current_params) # data works for GET/POST in make_request
            if response:
                response_status_code = response.status_code
                response_text_raw = response.text.strip() if response.text else ""
                try:
                    response_data_parsed = response.json()
                except json.JSONDecodeError:
                    # If not JSON, use raw text for analysis, unless it's common WP "error" strings
                    if response_text_raw not in ["0", "-1"]:
                        response_data_parsed = response_text_raw 
                    else: # It's "0" or "-1", common for errors/nonce failures
                        response_data_parsed = {"wp_ajax_error": response_text_raw} 
            else:
                error_message = "Request failed (no response)"
        except Exception as e:
            error_message = f"Request exception: {str(e)}"
            print(f"        [-] Error testing action '{action_value}' ({method}): {e}")

        result_entry = {
            "method": method, "status_code": response_status_code,
            "response_snippet": response_text_raw[:250] + "..." if len(response_text_raw) > 250 else response_text_raw,
            "error": error_message
        }
        action_test_summary["results"].append(result_entry)

        # Heuristic issue detection
        is_potential_issue = False
        issue_details = ""
        severity_guess = "Low"

        if response_status_code == 200:
            if isinstance(response_data_parsed, dict):
                if response_data_parsed.get("success") is True and response_data_parsed.get("data"):
                    is_potential_issue = True; issue_details = "Reported success with data."; severity_guess = "Medium"
                elif response_data_parsed.get("success") is True and not response_data_parsed.get("data"):
                    issue_details = "Reported success with no specific data (Info)." # Less likely an issue
                elif response_data_parsed.get("success") is False:
                    issue_details = f"Reported failure. Data: {str(response_data_parsed.get('data'))[:100]}"
                elif response_data_parsed.get("wp_ajax_error"): # Our custom key for "0" or "-1"
                     issue_details = f"Returned '{response_data_parsed['wp_ajax_error']}' (common error/auth/nonce failure)."
                else: # Other JSON structure
                    sensitive_keys = ["users", "config", "settings", "debug", "path", "key", "secret", "password", "token", "id", "name", "email"]
                    if any(s_key in response_data_parsed for s_key in sensitive_keys) and len(response_data_parsed) > 0:
                        is_potential_issue = True; issue_details = "JSON response contains potentially sensitive keys/structure."; severity_guess = "Medium"
            elif isinstance(response_data_parsed, str) and response_data_parsed: # Non-empty string, not "0" or "-1"
                is_potential_issue = True; issue_details = "Returned non-standard string response."; severity_guess = "Low"
                if "<!DOCTYPE html>" in response_data_parsed.lower() or "<html" in response_data_parsed.lower():
                    issue_details += " Contains HTML."; severity_guess = "Medium"
                elif len(response_data_parsed) > 200:
                    issue_details += " Response is lengthy."
            
        if is_potential_issue:
            issue_desc = f"AJAX action '{action_value}' ({method}) - {issue_details} Review manually."
            print(f"        [!] Potential Issue: {issue_desc} Snippet: {result_entry['response_snippet'][:100]}...")
            potential_issues_for_action.append({
                "action": action_value, "method": method, "description": issue_desc,
                "response_snippet": result_entry['response_snippet'], "params_tested": current_params, "severity_guess": severity_guess
            })
        elif issue_details: # Log non-issue findings too for verbosity
             print(f"        [i] AJAX action '{action_value}' ({method}): {issue_details} Snippet: {result_entry['response_snippet'][:100]}...")


        # Basic Parameter Fuzzing (Placeholder - can be expanded significantly)
        # Only fuzz if the initial call didn't clearly fail (e.g. not 400/500, or not "0" / "-1" if that means auth fail)
        # And if the action has parameters to fuzz.
        if config.get("analyzer_enable_ajax_fuzzing", False) and base_params and response_status_code == 200 and response_text_raw not in ["0", "-1"]:
            print(f"          Fuzzing parameters for action '{action_value}' ({method})...")
            for param_to_fuzz in base_params.keys(): # Only fuzz known/default params for now
                for fuzz_type, payloads in AJAX_FUZZ_PAYLOADS.items():
                    for payload in payloads:
                        fuzzed_params = {"action": action_value, **base_params}
                        fuzzed_params[param_to_fuzz] = payload
                        fuzz_response_text = ""
                        fuzz_status = None
                        try:
                            fuzz_resp = make_request(ajax_url, config, method=method, data=fuzzed_params, timeout=5)
                            if fuzz_resp:
                                fuzz_status = fuzz_resp.status_code
                                fuzz_response_text = fuzz_resp.text.strip() if fuzz_resp.text else ""
                                
                                # Basic check for XSS reflection or SQL error
                                if fuzz_type == "xss_basic" and payload in fuzz_response_text:
                                    fuzz_issue = f"Potential XSS in param '{param_to_fuzz}' with payload '{payload}'. Reflected."
                                    action_test_summary["fuzz_results"].append({"param": param_to_fuzz, "type": "XSS", "payload": payload, "details": fuzz_issue})
                                    potential_issues_for_action.append({
                                        "action": action_value, "method": method, "description": fuzz_issue, "is_fuzzing_finding": True,
                                        "response_snippet": fuzz_response_text[:150], "params_tested": fuzzed_params, "severity_guess": "High"
                                    })
                                    print(f"            [!!!] Fuzzing: {fuzz_issue}")
                                # Add basic SQL error check if desired (very heuristic)
                                # elif fuzz_type == "sqli_basic" and any(err in fuzz_response_text.lower() for err in ["syntax error", "mysql", "unclosed quotation"]):
                                #     fuzz_issue = f"Potential SQLi in param '{param_to_fuzz}' with payload '{payload}'. Error-like response."
                                #     ... add to fuzz_results and potential_issues ...
                        except Exception as e_fuzz:
                            print(f"            [-] Error fuzzing param '{param_to_fuzz}' for action '{action_value}': {e_fuzz}")
    
    return action_test_summary, potential_issues_for_action


def analyze_ajax_actions(state, config, target_url):
    """
    Analyzes WordPress AJAX actions: default, configured, discovered from HTML.
    Includes basic parameter fuzzing if enabled.
    """
    module_key = "wp_analyzer" # Part of the main wp_analyzer findings
    # Ensure the top-level key for this specific analysis exists
    analyzer_findings = state.get_module_findings(module_key, {})
    if "ajax_action_analysis" not in analyzer_findings: # Initialize if not present
        analyzer_findings["ajax_action_analysis"] = {
            "status": "Not Checked", 
            "tested_actions_summary": [], 
            "potential_issues": [],
            "discovered_actions_from_html": []
        }
    ajax_analysis_results = analyzer_findings["ajax_action_analysis"]


    if not config.get("analyzer_check_ajax_actions", True):
        print("    [i] AJAX action analysis disabled in configuration.")
        ajax_analysis_results["status"] = "Disabled in Config"
        state.update_module_findings(module_key, analyzer_findings)
        return

    ajax_url = urljoin(target_url.rstrip('/'), "/wp-admin/admin-ajax.php")
    print(f"    [i] Analyzing AJAX actions via: {ajax_url}")
    ajax_analysis_results["status"] = "Running"
    ajax_analysis_results["ajax_endpoint_url"] = ajax_url

    # 1. Discover actions from target_url's HTML content
    discovered_actions = []
    if config.get("analyzer_discover_ajax_from_html", True):
        print("      Attempting to discover AJAX actions from page HTML...")
        try:
            main_page_resp = make_request(target_url, config, method="GET", timeout=7)
            if main_page_resp and main_page_resp.text:
                discovered_actions = _discover_actions_from_html(main_page_resp.text, target_url)
                ajax_analysis_results["discovered_actions_from_html"] = [d["action_name"] for d in discovered_actions]
            else:
                print("        [-] Could not fetch main page content for AJAX action discovery.")
        except Exception as e:
            print(f"        [-] Error during HTML-based AJAX action discovery: {e}")
    
    # 2. Get actions from config or use defaults, then merge with discovered
    configured_actions = config.get("analyzer_ajax_actions_list", DEFAULT_AJAX_ACTIONS_TO_TEST)
    
    # Combine and de-duplicate actions (preferring configured if names clash)
    final_actions_to_test_map = {item['action_name']: item for item in configured_actions}
    for disc_item in discovered_actions:
        if disc_item['action_name'] not in final_actions_to_test_map:
            final_actions_to_test_map[disc_item['action_name']] = disc_item
    
    final_actions_to_test = list(final_actions_to_test_map.values())

    if not final_actions_to_test:
        print("    [i] No AJAX actions configured or discovered for testing.")
        ajax_analysis_results["status"] = "Skipped (No Actions To Test)"
        state.update_module_findings(module_key, analyzer_findings)
        return
    
    print(f"    [i] Will test a total of {len(final_actions_to_test)} unique AJAX action(s).")

    all_potential_issues = []
    all_tested_actions_summary = []

    for action_item_to_test in final_actions_to_test:
        action_summary, issues_for_this_action = _test_single_ajax_action(ajax_url, action_item_to_test, state, config)
        all_tested_actions_summary.append(action_summary)
        all_potential_issues.extend(issues_for_this_action)

    ajax_analysis_results["tested_actions_summary"] = all_tested_actions_summary
    ajax_analysis_results["potential_issues"] = all_potential_issues
    
    if all_potential_issues:
        ajax_analysis_results["status"] = "Completed (Potential Issues Found)"
        # Create remediation suggestions for unique issues
        unique_remediation_keys = set()
        for issue in all_potential_issues:
            action_name = issue.get("action", "unknown_action")
            method = issue.get("method", "unknown_method")
            severity = issue.get("severity_guess", "Medium")
            description = issue.get("description", "Potential AJAX security issue.")
            
            remediation_key_base = f"ajax_vuln_{sanitize_filename(action_name)}_{method.lower()}"
            remediation_key = remediation_key_base
            counter = 1
            while remediation_key in unique_remediation_keys: # Ensure unique key for multiple issues on same action/method
                remediation_key = f"{remediation_key_base}_{counter}"
                counter += 1
            unique_remediation_keys.add(remediation_key)

            state.add_remediation_suggestion(remediation_key, {
                "source": "WP Analyzer (AJAX Check - Advanced)",
                "description": f"AJAX action '{action_name}' ({method}) may be insecure. Finding: {description}",
                "severity": severity,
                "remediation": f"Ensure the AJAX action '{action_name}' correctly implements nonce checks and capability/permission checks for all operations. Only expose data or allow actions to appropriately authenticated and authorized users. Validate all input parameters. Review server-side logic for this action."
            })
        state.add_critical_alert(f"Potential insecure AJAX actions found ({len(all_potential_issues)}). Review needed.")
    else:
        ajax_analysis_results["status"] = "Completed (No Obvious Issues)"

    state.update_module_findings(module_key, analyzer_findings) # Save all ajax_action_analysis back
    print(f"    [+] Advanced AJAX action analysis finished. Status: {ajax_analysis_results['status']}")
