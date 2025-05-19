# Module for Fuzzing Custom WordPress REST/AJAX Endpoints
import requests
import json
import re
import time # For time-based SQLi
from urllib.parse import urljoin, urlencode, quote_plus
from core.utils import make_request, sanitize_filename

# Known core WordPress REST API namespaces (non-exhaustive, can be expanded)
CORE_REST_NAMESPACES = [
    "wp/v2", "oembed/1.0", "wc/v1", "wc/v2", "wc/v3", "wc-blocks", "wc-store-api",
    "contact-form-7/v1", "jetpack/v4", "yoast/v1", "buddypress/v1", "regenerate-thumbnails/v1"
]

# Payloads for lightweight fuzzing
XSS_FUZZ_MARKER = "cefpXSSmarker99" # Custom Endpoint Fuzz Probe Marker
CUSTOM_ENDPOINT_FUZZ_PAYLOADS = {
    "xss_light": [
        f"\"'><script>{XSS_FUZZ_MARKER}();</script>",
        f"<img src=x onerror=alert('{XSS_FUZZ_MARKER}')>",
        f"javascript:alert('{XSS_FUZZ_MARKER}')"
    ],
    "sqli_light": [
        "'", "\"", "`",
        "' OR '1'='1", "\" OR \"1\"=\"1",
        f"' AND SLEEP(3)-- ", # Time-based, 3 seconds for MySQL
        f"\" AND SLEEP(3)-- ",
        f"pg_sleep(3)--", # For PostgreSQL
        f"WAITFOR DELAY '00:00:03'--" # For SQL Server
    ]
}
SQL_ERROR_PATTERNS_FUZZ = [ # Simplified list
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning: mysql_", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"supplied argument is not a valid (mysql|pg|oci)_result", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE)
]
# Common parameter names to guess if none are known from schema/defaults
GUESSED_PARAM_NAMES = ["id", "item_id", "user_id", "post_id", "s", "search", "query", "data", "value", "name", "email", "param", "input", "page", "action", "cmd", "exec", "payload", "url", "file", "path"]


def _fuzz_endpoint(endpoint_url, http_method, parameters_to_fuzz, base_data, state, config, findings_list, endpoint_type="Unknown"):
    """
    Fuzzes identified parameters of a given endpoint.
    parameters_to_fuzz: list of parameter names.
    base_data: dict of original parameters for the request (used for POST or to fill non-fuzzed GET params).
    """
    if not config.get("analyzer_enable_custom_endpoint_fuzzing", False):
        return

    print(f"          Fuzzing {http_method} {endpoint_url} with params: {', '.join(parameters_to_fuzz) if parameters_to_fuzz else 'No specific params, trying guessed.'}")

    params_to_try_fuzzing = list(set(parameters_to_fuzz + GUESSED_PARAM_NAMES[:5])) # Fuzz known/schema params + a few common guesses

    for param_name in params_to_try_fuzzing:
        for fuzz_category, payloads in CUSTOM_ENDPOINT_FUZZ_PAYLOADS.items():
            for payload_str in payloads:
                fuzzed_request_data = base_data.copy() if base_data else {}
                fuzzed_request_params_get = base_data.copy() if base_data else {} # For GET, start with base if any

                if http_method == "POST":
                    fuzzed_request_data[param_name] = payload_str
                else: # GET
                    fuzzed_request_params_get[param_name] = payload_str
                
                fuzz_url = endpoint_url
                if http_method == "GET" and fuzzed_request_params_get:
                    # Ensure action param is present for AJAX if it's a GET fuzz
                    if endpoint_type == "AJAX" and "action" not in fuzzed_request_params_get and "action" in base_data:
                         fuzzed_request_params_get["action"] = base_data["action"]
                    fuzz_url += "?" + urlencode(fuzzed_request_params_get, quote_via=quote_plus)

                time_based_sqli_expected_delay = 0
                if fuzz_category == "sqli_light" and ("SLEEP(" in payload_str.upper() or "PG_SLEEP(" in payload_str.upper() or "WAITFOR DELAY" in payload_str.upper()):
                    time_based_sqli_expected_delay = 3 # Matches payloads

                start_time = time.time()
                fuzz_response = make_request(fuzz_url, config, method=http_method, data=fuzzed_request_data if http_method=="POST" else None, timeout=7 + time_based_sqli_expected_delay)
                duration = time.time() - start_time

                if fuzz_response:
                    # XSS Check
                    if fuzz_category == "xss_light" and XSS_FUZZ_MARKER in fuzz_response.text:
                        vuln = {
                            "type": "FUZZ_XSS_REFLECTED", "endpoint_type": endpoint_type, "url": endpoint_url,
                            "method": http_method, "parameter_fuzzed": param_name, "payload_used": payload_str,
                            "observation": f"XSS marker '{XSS_FUZZ_MARKER}' reflected in response.",
                            "response_snippet_fuzzed": fuzz_response.text[:200]
                        }
                        findings_list.append(vuln)
                        print(f"            [!!!] Potential XSS: {param_name} on {endpoint_url} with '{payload_str}'")
                    
                    # SQLi Checks
                    if fuzz_category == "sqli_light":
                        # Error-based
                        for err_pattern in SQL_ERROR_PATTERNS_FUZZ:
                            if err_pattern.search(fuzz_response.text):
                                vuln = {
                                    "type": "FUZZ_SQLI_ERROR", "endpoint_type": endpoint_type, "url": endpoint_url,
                                    "method": http_method, "parameter_fuzzed": param_name, "payload_used": payload_str,
                                    "observation": f"SQL error pattern '{err_pattern.pattern}' matched.",
                                    "response_snippet_fuzzed": fuzz_response.text[:200]
                                }
                                findings_list.append(vuln)
                                print(f"            [!!!] Potential SQLi (Error-based): {param_name} on {endpoint_url} with '{payload_str}'")
                                break # Found one error, enough for this payload
                        # Time-based
                        if time_based_sqli_expected_delay > 0 and duration >= time_based_sqli_expected_delay * 0.9: # Allow 10% margin
                            vuln = {
                                "type": "FUZZ_SQLI_TIMEBASED", "endpoint_type": endpoint_type, "url": endpoint_url,
                                "method": http_method, "parameter_fuzzed": param_name, "payload_used": payload_str,
                                "observation": f"Response delayed by {duration:.2f}s (expected ~{time_based_sqli_expected_delay}s).",
                                "response_snippet_fuzzed": "" # Not relevant for time-based
                            }
                            findings_list.append(vuln)
                            print(f"            [!!!] Potential SQLi (Time-based): {param_name} on {endpoint_url} with '{payload_str}'")
def analyze_custom_endpoints(state, config, target_url):
    """
    Discovers custom REST API and AJAX endpoints, probes them unauthenticated,
    and performs lightweight fuzzing if enabled.
    """
    module_key = "wp_analyzer"
    findings_key = "custom_endpoint_analysis" # Renamed key for clarity
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Discovering, probing, and fuzzing custom REST API and AJAX endpoints.",
        "discovered_rest_namespaces": [],
        "custom_rest_endpoints_details": [], # Changed from custom_rest_namespaces_details
        "probed_ajax_actions_details": [], # Changed from probed_ajax_actions
        "fuzzing_results": [], # Consolidated fuzzing results here
        "recommendation": "Identified custom endpoints should be manually reviewed. Any fuzzing findings require careful verification."
    })
    print("    [i] Custom Endpoint Discovery, Probing, and Fuzzing...")
    enable_fuzzing = config.get("analyzer_enable_custom_endpoint_fuzzing", False)
    if enable_fuzzing:
        print("      Lightweight fuzzing of custom endpoints is ENABLED.")

    # --- REST API Custom Endpoint Discovery, Probing & Fuzzing ---
    print("      Discovering REST API namespaces and endpoints...")
    wp_json_url = urljoin(target_url, 'wp-json/')
    
    try:
        response_base = make_request(wp_json_url, config, method="GET", timeout=10)
        if response_base and response_base.status_code == 200:
            try:
                data_base = response_base.json()
                if "namespaces" in data_base and isinstance(data_base["namespaces"], list):
                    findings["discovered_rest_namespaces"] = data_base["namespaces"]
                    print(f"        Found {len(data_base['namespaces'])} total REST namespaces.")

                    for ns in data_base["namespaces"]:
                        is_core_or_common = any(ns.startswith(core_ns) for core_ns in CORE_REST_NAMESPACES)
                        if not is_core_or_common:
                            print(f"          [+] Potential custom REST namespace: {ns}. Discovering its routes...")
                            namespace_url = urljoin(wp_json_url, ns.lstrip('/')) # Ensure ns is path component
                            ns_detail_entry = {"namespace": ns, "routes": [], "unauth_probe_results": [], "fuzzable_params": {}}
                            try:
                                response_ns = make_request(namespace_url, config, method="GET", timeout=7)
                                if response_ns and response_ns.status_code == 200:
                                    data_ns = response_ns.json()
                                    if "routes" in data_ns and isinstance(data_ns["routes"], dict):
                                        for route_path, route_data in data_ns["routes"].items():
                                            full_route_url = urljoin(namespace_url + ("/" if not namespace_url.endswith("/") else ""), route_path.lstrip('/'))
                                            
                                            methods = []
                                            if isinstance(route_data, dict) and "methods" in route_data:
                                                methods = route_data.get("methods", [])
                                            elif isinstance(route_data, list): # Older WP REST API format?
                                                 for endpoint_details in route_data:
                                                      if "methods" in endpoint_details: methods.extend(endpoint_details["methods"])
                                                 methods = list(set(methods))


                                            route_info = {"path": route_path, "url": full_route_url, "methods": methods, "args": {}}
                                            if isinstance(route_data, dict) and "endpoints" in route_data:
                                                # Try to get args from the first endpoint definition
                                                first_endpoint = route_data["endpoints"][0] if route_data["endpoints"] else {}
                                                route_info["args"] = first_endpoint.get("args", {})
                                            
                                            ns_detail_entry["routes"].append(route_info)
                                            print(f"            Route: {route_path} (Methods: {', '.join(methods)}) Args: {list(route_info['args'].keys()) if route_info['args'] else 'None'}")
                                            
                                            # Basic Unauthenticated Probing
                                            for http_method in methods:
                                                if http_method in ["GET", "POST", "PUT", "DELETE"]: # Probe common methods
                                                    probe_resp = make_request(full_route_url, config, method=http_method, timeout=5)
                                                    probe_result = {"method": http_method, "url": full_route_url, "status": probe_resp.status_code if probe_resp else None, "response_snippet": probe_resp.text[:100] if probe_resp and probe_resp.text else ""}
                                                    ns_detail_entry["unauth_probe_results"].append(probe_result)
                                                    if probe_resp and probe_resp.status_code == 200 and probe_resp.text:
                                                        findings["fuzzing_results"].append({ # Using fuzzing_results for consistency
                                                            "type": "REST_Unauth_Access", "endpoint_type": "REST", "url": full_route_url, "method": http_method,
                                                            "observation": "Responded 200 OK to unauthenticated request with data.", "response_snippet_fuzzed": probe_result["response_snippet"]
                                                        })
                                                        print(f"                [!!!] Unauth {http_method} to {full_route_url} -> 200 OK")
                                            
                                            # Fuzzing if enabled
                                            if enable_fuzzing:
                                                param_names_from_schema = list(route_info["args"].keys())
                                                for http_method in methods: # Fuzz all supported methods
                                                     _fuzz_endpoint(full_route_url, http_method, param_names_from_schema, {}, state, config, findings["fuzzing_results"], "REST")
                                    findings["custom_rest_endpoints_details"].append(ns_detail_entry)
                            except Exception as e_ns: print(f"            Error processing namespace {ns}: {e_ns}")
            except Exception as e_base: print(f"        Error processing {wp_json_url}: {e_base}")
        elif response_base: print(f"      [-] {wp_json_url} returned {response_base.status_code}")
        else: print(f"      [-] Request to {wp_json_url} failed.")
    except Exception as e_main_rest: print(f"    [-] Error during REST API discovery: {e_main_rest}")

    # --- AJAX Action Probing & Fuzzing (Consume from ajax_checker.py) ---
    print("      Probing and Fuzzing discovered/configured AJAX actions (unauthenticated)...")
    ajax_checker_findings = state.get_specific_finding(module_key, "ajax_action_analysis", {})
    
    # ajax_checker stores results in "tested_actions_summary"
    # Each item in tested_actions_summary is like: {"action": action_value, "results": [...], "fuzz_results": []}
    # We need the original action_item structure that had "params" if available.
    # The ajax_checker.py itself combines default/configured and discovered.
    # Let's assume ajax_checker.py's "potential_issues" or "tested_actions_summary" can give us action names and their original params.
    # For simplicity, we'll re-use the logic for building all_ajax_to_probe_map from its previous version.
    
    # This part needs to align with how ajax_checker.py stores its input list or discovered items.
    # Let's assume ajax_checker.py's findings["ajax_action_analysis"]["tested_actions_summary"] contains items with "action" (name)
    # and we can try to get original params if they were part of DEFAULT_AJAX_ACTIONS_TO_TEST or config.
    
    # Rebuild a map of actions that ajax_checker might have tested or discovered.
    # This is a bit redundant if ajax_checker already did basic probing.
    # The goal here is to apply *our* fuzzing logic.
    
    temp_actions_from_ajax_checker = []
    if ajax_checker_findings.get("tested_actions_summary"):
        for item_summary in ajax_checker_findings["tested_actions_summary"]:
            action_name = item_summary.get("action")
            # Try to find original params if this was a configured action
            original_params = {}
            # This is tricky: ajax_checker doesn't store the input `action_item` directly in `tested_actions_summary`.
            # We might need to re-fetch from config or defaults if we want to fuzz with known params.
            # For now, we'll mostly rely on guessed params for AJAX if not in a small default list.
            temp_actions_from_ajax_checker.append({"action_name": action_name, "method": "BOTH", "params": {}}) # Defaulting params to empty for now

    ajax_url = urljoin(target_url, "/wp-admin/admin-ajax.php")
    for action_item in temp_actions_from_ajax_checker: # Iterate over actions identified by ajax_checker
        action_name = action_item.get("action_name")
        if not action_name: continue

        probed_action_detail = {"action": action_name, "unauth_probe_results": []}
        methods_to_try = ["GET", "POST"] # Always try both for unauth probe & fuzz

        for http_method in methods_to_try:
            params_for_probe = {"action": action_name} # Basic probe
            probe_resp = make_request(ajax_url, config, method=http_method, data=params_for_probe, timeout=5)
            probe_result = {"method": http_method, "status": probe_resp.status_code if probe_resp else None, "response_snippet": probe_resp.text[:100] if probe_resp and probe_resp.text else ""}
            probed_action_detail["unauth_probe_results"].append(probe_result)
            if probe_resp and probe_resp.status_code == 200 and probe_resp.text and probe_resp.text not in ["0", "-1", ""]:
                findings["fuzzing_results"].append({
                    "type": "AJAX_Unauth_Response", "endpoint_type": "AJAX", "url": ajax_url, "method": http_method, "action":action_name,
                    "observation": "Responded 200 OK with non-standard data to unauthenticated request.", "response_snippet_fuzzed": probe_result["response_snippet"]
                })
                print(f"          [!!!] Unauth AJAX '{action_name}' ({http_method}) -> 200 OK with data.")
            
            # Fuzzing if enabled
            if enable_fuzzing:
                # For AJAX, params are less structured. Use guessed params + any known from action_item.
                ajax_params_to_fuzz = list(action_item.get("params", {}).keys())
                _fuzz_endpoint(ajax_url, http_method, ajax_params_to_fuzz, {"action": action_name, **action_item.get("params", {})}, state, config, findings["fuzzing_results"], "AJAX")
        
        findings["probed_ajax_actions_details"].append(probed_action_detail)


    # Consolidate details
    details_parts = []
    if findings["custom_rest_endpoints_details"]:
        details_parts.append(f"Discovered and probed {len(findings['custom_rest_endpoints_details'])} custom REST API structure(s).")
    if findings["probed_ajax_actions_details"]:
        details_parts.append(f"Probed {len(findings['probed_ajax_actions_details'])} AJAX action(s).")
    if findings["fuzzing_results"]:
        details_parts.append(f"Fuzzing identified {len(findings['fuzzing_results'])} potential issue(s).")
        # Add a general remediation for fuzzing findings
        state.add_remediation_suggestion("custom_endpoint_fuzz_findings", {
            "source": "WP Analyzer (Custom Endpoint Fuzzer)",
            "description": f"Lightweight fuzzing of custom REST/AJAX endpoints revealed {len(findings['fuzzing_results'])} potential vulnerabilities (e.g., XSS reflections, SQL errors, or unexpected behavior).",
            "severity": "High", # Default to High for fuzzing findings, manual review needed
            "remediation": "Thoroughly investigate all fuzzing findings. Review the source code of the implicated custom endpoints for input validation, output encoding, and proper authorization. Use dedicated DAST tools for deeper fuzzing if available."
        })
    
    findings["details"] = " ".join(details_parts) if details_parts else "No custom REST namespaces found. AJAX actions (if any from ajax_checker) probed/fuzzed."
    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Custom Endpoint Fuzzer (Phase 1 & 2) finished. Details: {findings['details']}")
