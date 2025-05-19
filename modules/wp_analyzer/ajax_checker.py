import json
from urllib.parse import urljoin
from .utils import make_request # Assuming utils.py is in the same wp_analyzer package

# List of common/interesting AJAX actions to test.
# This list can be expanded or moved to config for more flexibility.
# Format: {"action_name": "action_value", "method": "GET|POST|BOTH", "params": {}}
# 'params' are additional parameters that might be required or useful for the test.
DEFAULT_AJAX_ACTIONS_TO_TEST = [
    # Example: Some plugins might have actions that disclose info or perform operations without auth
    {"action_name": "heartbeat", "method": "POST", "params": {"data[screen_id]": "front"}}, # WordPress Heartbeat
    {"action_name": "nopriv_example_action", "method": "GET", "params": {}}, # Placeholder for a common 'nopriv' action
    # Common actions from popular plugins (examples, actual actions vary)
    # {"action_name": "some_plugin_get_data", "method": "GET", "params": {"item_id": "1"}},
    # {"action_name": "some_plugin_perform_task", "method": "POST", "params": {"task_id": "abc"}},
    # WooCommerce (examples, actual actions are more complex and often require nonces)
    # {"action_name": "woocommerce_get_refreshed_fragments", "method": "GET", "params": {}},
    # {"action_name": "woocommerce_add_to_cart", "method": "POST", "params": {"product_id": "1", "quantity": "1"}},
]

def analyze_ajax_actions(state, config, target_url):
    """
    Analyzes common and configured WordPress AJAX actions for potential vulnerabilities.
    """
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    if "ajax_action_analysis" not in analyzer_findings:
        analyzer_findings["ajax_action_analysis"] = {"status": "Not Checked", "tested_actions": [], "potential_issues": []}
    ajax_analysis_details = analyzer_findings["ajax_action_analysis"]

    if not config.get("analyzer_check_ajax_actions", True): # Config flag to enable/disable
        print("    [i] AJAX action analysis disabled in configuration.")
        ajax_analysis_details["status"] = "Disabled in Config"
        state.update_module_findings(module_key, analyzer_findings)
        return

    ajax_url = urljoin(target_url.rstrip('/'), "/wp-admin/admin-ajax.php")
    print(f"    Analyzing AJAX actions via: {ajax_url}")
    ajax_analysis_details["status"] = "Running"
    ajax_analysis_details["ajax_endpoint_url"] = ajax_url

    # Get actions from config or use defaults
    actions_to_test = config.get("analyzer_ajax_actions_list", DEFAULT_AJAX_ACTIONS_TO_TEST)
    if not actions_to_test:
        print("    [i] No AJAX actions configured for testing.")
        ajax_analysis_details["status"] = "Skipped (No Actions Configured)"
        state.update_module_findings(module_key, analyzer_findings)
        return

    potential_issues_found = []
    tested_actions_summary = []

    for action_item in actions_to_test:
        action_value = action_item.get("action_name")
        methods_to_test = action_item.get("method", "BOTH").upper()
        custom_params = action_item.get("params", {})

        if not action_value:
            continue

        action_summary = {"action": action_value, "results": []}
        print(f"      Testing AJAX action: '{action_value}'")

        test_methods = []
        if methods_to_test == "GET":
            test_methods.append("GET")
        elif methods_to_test == "POST":
            test_methods.append("POST")
        elif methods_to_test == "BOTH":
            test_methods.extend(["GET", "POST"])

        for method in test_methods:
            request_params = {"action": action_value, **custom_params}
            response_data = None
            response_status_code = None
            error_message = None
            
            try:
                if method == "GET":
                    # For GET, params are URL-encoded
                    response = make_request(ajax_url, config, method="GET", data=request_params) # requests lib handles params for GET
                else: # POST
                    response = make_request(ajax_url, config, method="POST", data=request_params)

                if response:
                    response_status_code = response.status_code
                    # Try to parse as JSON, otherwise take text.
                    try:
                        response_data_json = response.json()
                        response_data = response_data_json # Store parsed JSON
                        
                        # Detailed check for success patterns
                        if isinstance(response_data_json, dict):
                            if response_data_json.get("success") == True and response_data_json.get("data"):
                                print(f"        [+] AJAX action '{action_value}' ({method}) reported success with data.")
                            elif response_data_json.get("success") == True and not response_data_json.get("data"):
                                print(f"        [i] AJAX action '{action_value}' ({method}) reported success with no specific data.")
                            elif response_data_json.get("success") == False:
                                print(f"        [i] AJAX action '{action_value}' ({method}) reported failure. Data: {str(response_data_json.get('data'))[:100]}")
                            # else: other JSON structure, will be caught by general checks below
                        
                    except json.JSONDecodeError:
                        response_data = response.text.strip() # Store raw text
                        if response_data not in ["0", "-1", ""]:
                            print(f"        [i] AJAX action '{action_value}' ({method}) returned non-standard text: {response_data[:100]}...")
                        elif response_data == "0":
                            print(f"        [i] AJAX action '{action_value}' ({method}) returned '0' (common for failed auth/nonce or error).")
                        elif response_data == "-1":
                            print(f"        [i] AJAX action '{action_value}' ({method}) returned '-1' (common for errors).")
                            
                else: # No response object
                    error_message = "Request failed (no response)"
                    response_data = "No response" # Ensure response_data has a value

            except Exception as e:
                error_message = f"Request exception: {str(e)}"
                response_data = f"Error: {error_message}"
                print(f"        [-] Error testing action '{action_value}' ({method}): {e}")

            result_entry = {
                "method": method,
                "status_code": response_status_code,
                "response_snippet": response_data if isinstance(response_data, str) else json.dumps(response_data), # Ensure snippet is string
                "error": error_message
            }
            action_summary["results"].append(result_entry)

            # Enhanced heuristic for potential issue:
            is_potential_issue = False
            issue_details = ""

            if response_status_code == 200:
                if isinstance(response_data, dict):
                    # Case 1: Explicit success with non-empty data
                    if response_data.get("success") == True and response_data.get("data"):
                        is_potential_issue = True
                        issue_details = "Reported success with data."
                    # Case 2: No explicit success field, but contains potentially sensitive keys in data
                    elif not response_data.get("success") and isinstance(response_data.get("data"), dict):
                        sensitive_keys = ["users", "config", "settings", "debug", "path", "key", "secret", "password", "token"]
                        if any(s_key in (response_data.get("data") or {}) for s_key in sensitive_keys):
                            is_potential_issue = True
                            issue_details = "Contains potentially sensitive keys in data."
                    # Case 3: The response itself (if not 'success' field) contains sensitive keys
                    elif not response_data.get("success"):
                         sensitive_keys_in_root = ["users", "config", "settings", "debug", "path", "key", "secret", "password", "token", "id", "name", "email"]
                         if any(s_key in response_data for s_key in sensitive_keys_in_root) and len(response_data) > 1: # more than just one key
                            is_potential_issue = True
                            issue_details = "Root of JSON response contains potentially sensitive keys or structure."


                elif isinstance(response_data, str) and response_data not in ["0", "-1", ""]:
                    # Case 4: Non-standard string response (not "0" or "-1")
                    is_potential_issue = True
                    issue_details = "Returned non-standard string response (not '0' or '-1')."
                    # Further checks for HTML or specific error patterns could be added here
                    if "<!DOCTYPE html>" in response_data.lower() or "<html" in response_data.lower():
                        issue_details += " Contains HTML."
                    elif len(response_data) > 200: # Arbitrary length for "significant data"
                        issue_details += " Response is lengthy."
                
            if is_potential_issue:
                issue_desc = f"AJAX action '{action_value}' ({method}) - {issue_details} Review manually."
                print(f"        [!] Potential Issue: {issue_desc} Response Snippet: {str(response_data)[:150]}...")
                potential_issues_found.append({
                    "action": action_value,
                    "method": method,
                    "description": issue_desc,
                    "response_snippet": result_entry["response_snippet"], # Use the stringified snippet
                    "params_tested": request_params
                })
                # Add remediation suggestion (can be made more specific based on issue_details)
                state.add_remediation_suggestion(f"ajax_vuln_{sanitize_filename(action_value)}_{method.lower()}", {
                    "source": "WP Analyzer (AJAX Check)",
                    "description": f"AJAX action '{action_value}' ({method}) may be insecure ({issue_details}). This could lead to information disclosure or unauthorized actions if nonces/permissions are not properly checked server-side.",
                    "severity": "Medium", # Default, could be adjusted based on issue_details
                    "remediation": f"Ensure the AJAX action '{action_value}' correctly implements nonce checks and capability/permission checks for all operations. Only expose data or allow actions to appropriately authenticated and authorized users. Validate all input parameters."
                })
        
        tested_actions_summary.append(action_summary)

    ajax_analysis_details["tested_actions"] = tested_actions_summary
    ajax_analysis_details["potential_issues"] = potential_issues_found
    if potential_issues_found:
        ajax_analysis_details["status"] = "Completed (Potential Issues Found)"
        state.add_critical_alert(f"Potential insecure AJAX actions found ({len(potential_issues_found)}). Review needed.")
    else:
        ajax_analysis_details["status"] = "Completed (No Obvious Issues)"

    state.update_module_findings(module_key, analyzer_findings)
