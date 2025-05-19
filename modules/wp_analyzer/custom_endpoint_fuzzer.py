# Module for Fuzzing Custom WordPress REST/AJAX Endpoints
import requests
import json
import re
from urllib.parse import urljoin
from core.utils import make_request

# Known core WordPress REST API namespaces (non-exhaustive, can be expanded)
CORE_REST_NAMESPACES = [
    "wp/v2", "oembed/1.0", "wc/v1", "wc/v2", "wc/v3", "wc-blocks", "wc-store-api", # WooCommerce
    "contact-form-7/v1", "jetpack/v4", "yoast/v1", # Common plugins
    "buddypress/v1" # BuddyPress
]

def analyze_custom_endpoints(state, config, target_url):
    """
    Identifies potential custom REST API namespaces.
    AJAX action discovery is handled by ajax_checker.py.
    Actual fuzzing of these endpoints is complex and requires dedicated tools.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "custom_endpoint_fuzzing"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Identifying custom REST API namespaces. AJAX fuzzing relies on ajax_checker.py findings.",
        "identified_custom_rest_namespaces": [],
        "identified_custom_ajax_actions": [], # This would be populated by consuming ajax_checker results
        "potential_vulnerabilities": [], # Placeholder for actual fuzzing results
        "recommendation": "Identified custom endpoints should be manually reviewed and tested with dedicated fuzzing/security tools."
    })

    print("    [i] Identifying custom REST API namespaces...")
    
    wp_json_url = urljoin(target_url, 'wp-json/')
    custom_namespaces = []

    try:
        response = make_request(wp_json_url, config, method="GET", timeout=10)
        if response and response.status_code == 200:
            try:
                data = response.json()
                if "namespaces" in data and isinstance(data["namespaces"], list):
                    all_namespaces = data["namespaces"]
                    for ns in all_namespaces:
                        is_core = False
                        for core_ns_pattern in CORE_REST_NAMESPACES:
                            # Check if ns starts with a known core pattern (e.g. "wp/v2" is part of "wp/v2/posts")
                            if ns.startswith(core_ns_pattern):
                                is_core = True
                                break
                        if not is_core:
                            custom_namespaces.append(ns)
                            print(f"      [+] Found potential custom REST API namespace: {ns}")
                
                if custom_namespaces:
                    findings["identified_custom_rest_namespaces"] = custom_namespaces
                    findings["details"] = f"Identified {len(custom_namespaces)} potential custom REST API namespace(s): {', '.join(custom_namespaces)}. These should be manually reviewed and tested."
                    state.add_remediation_suggestion("custom_rest_endpoints_review", {
                        "source": "WP Analyzer (Custom Endpoint Finder)",
                        "description": f"Potential custom REST API namespaces found: {', '.join(custom_namespaces)}. Custom endpoints can introduce unique vulnerabilities if not developed securely.",
                        "severity": "Medium", # Info if just listing, Medium if they exist and need review
                        "remediation": "Thoroughly review the security of any custom REST API endpoints. Ensure proper authentication, authorization (capability checks), and input validation are implemented. Test them with dedicated API security testing tools."
                    })
                else:
                    findings["details"] = "No obvious custom REST API namespaces identified from /wp-json/. AJAX fuzzing relies on ajax_checker.py findings."
                    print("      [i] No obvious non-core REST API namespaces found.")

            except json.JSONDecodeError:
                findings["details"] = "Error decoding JSON response from /wp-json/."
                print(f"      [-] Failed to decode JSON from {wp_json_url}")
            except Exception as e_parse:
                findings["details"] = f"Error parsing /wp-json/ data: {e_parse}"
                print(f"      [-] Error parsing data from {wp_json_url}: {e_parse}")

        elif response:
            findings["details"] = f"/wp-json/ endpoint returned status {response.status_code}. Cannot list namespaces."
            print(f"      [-] /wp-json/ returned status {response.status_code}")
        else:
            findings["details"] = "Request to /wp-json/ failed. Cannot list namespaces."
            print(f"      [-] Request to {wp_json_url} failed.")

    except Exception as e:
        print(f"      [-] Error checking custom REST endpoints: {e}")
        findings["details"] = f"Error during custom REST endpoint check: {e}"

    # Note on AJAX actions:
    # The ajax_checker.py module is responsible for discovering AJAX actions.
    # This module could potentially consume those findings if deeper fuzzing were implemented.
    # For now, we'll just note that.
    ajax_findings = state.get_specific_finding(module_key, "ajax_action_analysis", {})
    if ajax_findings.get("tested_actions"):
        findings["identified_custom_ajax_actions"] = ajax_findings["tested_actions"]
        # No specific message here as ajax_checker handles its own reporting.
        print(f"    [i] AJAX actions discovered by ajax_checker.py: {len(ajax_findings['tested_actions'])} (refer to its findings for details).")


    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Custom endpoint identification finished. Details: {findings['details']}")
