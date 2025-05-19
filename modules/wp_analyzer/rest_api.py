import json
import re
from urllib.parse import urljoin, urlparse
from .utils import make_request # sanitize_filename is not used here, but if it were, it should be from core.utils
from core.utils import sanitize_filename # Example if it were needed

# Known core/common WordPress REST API namespaces to potentially exclude from "custom" or to analyze differently
CORE_COMMON_REST_NAMESPACES = [
    "wp/v2", "oembed/1.0", "wc/v1", "wc/v2", "wc/v3", "wc-blocks", "wc-store-api",
    "contact-form-7/v1", "jetpack/v4", "yoast/v1", "buddypress/v1", "regenerate-thumbnails/v1",
    "akismet/v1", "jetpack/v4", "wordfence/v1" # Added a few more common ones
]

def analyze_rest_api_general(state, config, target_url):
    """
    Performs general analysis of the WordPress REST API.
    - Lists all namespaces and their routes.
    - Checks for information disclosure from the API root.
    - Checks accessibility of core endpoints (e.g., posts, users) unauthenticated.
    - Notes if REST API seems disabled or protected.
    """
    module_key = "wp_analyzer"
    # Use a more general key for these findings, distinct from just user enum
    findings_key = "rest_api_analysis" 
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Performing general REST API analysis.",
        "api_root_url": None,
        "api_root_accessible": None, # True, False, "Error", "Protected"
        "api_root_status_code": None,
        "api_root_info_disclosure": {}, # Site name, description, auth methods etc.
        "namespaces": [], # List of all discovered namespace details [{name, routes_url, routes: [{path, methods, args}]}]
        "core_endpoint_access": { # Checks for unauthenticated access to common core endpoints
            "users": {"status": "Not Checked", "accessible_unauth": None, "data_preview": None},
            "posts": {"status": "Not Checked", "accessible_unauth": None, "count_unauth": None},
            "pages": {"status": "Not Checked", "accessible_unauth": None, "count_unauth": None},
            "media": {"status": "Not Checked", "accessible_unauth": None, "count_unauth": None},
            "settings": {"status": "Not Checked", "accessible_unauth": None, "data_preview": None} # /wp/v2/settings (usually protected)
        },
        "recommendations": []
    })
    print("    [i] Analyzing WordPress REST API General Security...")

    wp_json_url = urljoin(target_url.rstrip('/'), "/wp-json/")
    findings["api_root_url"] = wp_json_url
    
    # 1. Check API Root (/wp-json/)
    print(f"      Checking REST API root: {wp_json_url}")
    try:
        response_root = make_request(wp_json_url, config, method="GET", timeout=10)
        if response_root:
            findings["api_root_status_code"] = response_root.status_code
            if response_root.status_code == 200:
                findings["api_root_accessible"] = True
                print(f"        [+] REST API root accessible (Status: 200).")
                try:
                    data_root = response_root.json()
                    # Information disclosure from root
                    root_info = {
                        "name": data_root.get("name"), "description": data_root.get("description"),
                        "url": data_root.get("url"), "home": data_root.get("home"),
                        "gmt_offset": data_root.get("gmt_offset"), "timezone_string": data_root.get("timezone_string"),
                        "authentication": data_root.get("authentication"), # Can reveal auth methods
                        "namespaces_count": len(data_root.get("namespaces", []))
                    }
                    findings["api_root_info_disclosure"] = {k:v for k,v in root_info.items() if v is not None}
                    if root_info.get("name"): print(f"          Site Name (from API): {root_info['name']}")
                    
                    # Namespace and Route Listing
                    if "namespaces" in data_root and isinstance(data_root["namespaces"], list):
                        print(f"        Discovering all namespaces and their routes...")
                        for ns_name in data_root["namespaces"]:
                            ns_data = {"name": ns_name, "routes_url": None, "routes": [], "is_core_common": False}
                            ns_data["is_core_common"] = any(ns_name.startswith(core_ns) for core_ns in CORE_COMMON_REST_NAMESPACES)
                            
                            namespace_specific_url = data_root["_links"].get(f"https://api.w.org/namespace/{ns_name}", [{}])[0].get("href")
                            if not namespace_specific_url: # Fallback if not in _links (older WP?)
                                namespace_specific_url = urljoin(wp_json_url, ns_name)
                            
                            ns_data["routes_url"] = namespace_specific_url
                            try:
                                resp_ns = make_request(namespace_specific_url, config, method="GET", timeout=7)
                                if resp_ns and resp_ns.status_code == 200:
                                    ns_routes_data = resp_ns.json()
                                    if "routes" in ns_routes_data and isinstance(ns_routes_data["routes"], dict):
                                        for route_path, route_details_obj in ns_routes_data["routes"].items():
                                            # route_details_obj can be a dict or a list of endpoint dicts
                                            endpoints = route_details_obj.get("endpoints", []) if isinstance(route_details_obj, dict) else []
                                            if not endpoints and isinstance(route_details_obj, list): # Handle if route_details_obj is the list of endpoints
                                                endpoints = route_details_obj

                                            methods = []
                                            args_summary = {} # Collect args from first endpoint def
                                            for ep_detail in endpoints:
                                                methods.extend(ep_detail.get("methods", []))
                                                if not args_summary and ep_detail.get("args"): # Get args from first one
                                                    args_summary = {k:{"required":v.get("required", False)} for k,v in ep_detail.get("args", {}).items()}
                                            
                                            ns_data["routes"].append({
                                                "path": route_path, 
                                                "methods": sorted(list(set(methods))),
                                                "args_summary": args_summary
                                            })
                                findings["namespaces"].append(ns_data)
                            except Exception as e_ns: print(f"          Error fetching/parsing namespace {ns_name}: {e_ns}")
                        print(f"        [+] Discovered {len(findings['namespaces'])} namespaces with their routes.")

                except json.JSONDecodeError:
                    findings["api_root_accessible"] = "Partial (Invalid JSON)"
                    print(f"        [-] REST API root returned 200 but with invalid JSON. Snippet: {response_root.text[:200]}")
            elif response_root.status_code in [401, 403]:
                findings["api_root_accessible"] = "Protected"
                findings["details"] = f"REST API root ({wp_json_url}) is protected (Status: {response_root.status_code}). This is a good security measure if public API access is not needed."
                print(f"        [+] REST API root is protected (Status: {response_root.status_code}).")
                state.add_remediation_suggestion("rest_api_protected", {
                    "source": "WP Analyzer (REST API)", "description": "The WordPress REST API root is protected (e.g., via authentication or IP whitelist).",
                    "severity": "Info", "remediation": "This is a good security practice if full public REST API access is not required. Ensure protection methods are robust."})
            elif response_root.status_code == 404:
                findings["api_root_accessible"] = False
                findings["details"] = f"REST API root ({wp_json_url}) not found (404). REST API might be disabled."
                print(f"        [-] REST API root not found (404). Might be disabled via plugin or server rule.")
            else:
                findings["api_root_accessible"] = "Error"
                findings["details"] = f"REST API root ({wp_json_url}) returned unexpected status: {response_root.status_code}."
                print(f"        [?] REST API root returned unexpected status: {response_root.status_code}.")
        else:
            findings["api_root_accessible"] = "Error (No Response)"
            findings["details"] = f"Request to REST API root ({wp_json_url}) failed."
            print(f"        [-] Request to REST API root failed.")
    except Exception as e_root:
        findings["api_root_accessible"] = f"Error ({type(e_root).__name__})"
        findings["details"] = f"Exception during REST API root check: {e_root}"
        print(f"      [-] Exception during REST API root check: {e_root}")

    # 2. Unauthenticated Core Endpoint Checks (only if API root seems somewhat accessible)
    if findings["api_root_accessible"] is True or findings["api_root_accessible"] == "Partial (Invalid JSON)":
        core_endpoints_to_check = {
            "users": "/wp-json/wp/v2/users",
            "posts": "/wp-json/wp/v2/posts?context=view&per_page=1", # Check if any post is listable
            "pages": "/wp-json/wp/v2/pages?context=view&per_page=1",
            "media": "/wp-json/wp/v2/media?context=view&per_page=1",
            "settings": "/wp-json/wp/v2/settings" # Usually requires auth
        }
        print("      Checking unauthenticated access to common core REST API endpoints...")
        for key, path in core_endpoints_to_check.items():
            endpoint_url = urljoin(target_url.rstrip('/'), path)
            findings["core_endpoint_access"][key]["status"] = "Checking"
            try:
                resp_ep = make_request(endpoint_url, config, method="GET", timeout=7)
                if resp_ep:
                    findings["core_endpoint_access"][key]["status_code"] = resp_ep.status_code
                    if resp_ep.status_code == 200:
                        try:
                            data_ep = resp_ep.json()
                            findings["core_endpoint_access"][key]["accessible_unauth"] = True
                            if isinstance(data_ep, list):
                                findings["core_endpoint_access"][key]["count_unauth"] = len(data_ep)
                                if data_ep: findings["core_endpoint_access"][key]["data_preview"] = str(data_ep[0])[:150] + "..."
                                print(f"        [!] Core endpoint {path} accessible unauthenticated, returned {len(data_ep)} item(s).")
                            elif isinstance(data_ep, dict): # e.g. settings
                                findings["core_endpoint_access"][key]["data_preview"] = str(data_ep)[:150] + "..."
                                print(f"        [!] Core endpoint {path} accessible unauthenticated, returned data.")
                            
                            # Add remediation for exposed core endpoints
                            if key in ["users", "settings"] or (key in ["posts", "pages", "media"] and len(data_ep) > 0) :
                                state.add_remediation_suggestion(f"rest_api_core_{key}_exposed", {
                                    "source": "WP Analyzer (REST API)",
                                    "description": f"Core REST API endpoint '{path}' is accessible to unauthenticated users and returns data. This may expose sensitive information ({key}).",
                                    "severity": "Medium" if key in ["users", "settings"] else "Low",
                                    "remediation": f"Restrict public access to the '{path}' REST API endpoint if not necessary. Use security plugins or custom filters (e.g., 'rest_authentication_errors', 'rest_{key}_query') to enforce authentication and limit data exposure."
                                })

                        except json.JSONDecodeError:
                             findings["core_endpoint_access"][key]["accessible_unauth"] = "Partial (Invalid JSON)"
                             print(f"        [?] Core endpoint {path} returned 200 but with invalid JSON.")
                    elif resp_ep.status_code in [401, 403]:
                        findings["core_endpoint_access"][key]["accessible_unauth"] = False
                        print(f"        [+] Core endpoint {path} correctly protected (Status: {resp_ep.status_code}).")
                    else:
                        findings["core_endpoint_access"][key]["accessible_unauth"] = "Unexpected Status"
                        print(f"        [?] Core endpoint {path} returned status {resp_ep.status_code}.")
                else:
                    findings["core_endpoint_access"][key]["status"] = "Error (No Response)"
            except Exception as e_ep:
                findings["core_endpoint_access"][key]["status"] = f"Error ({type(e_ep).__name__})"
            if findings["core_endpoint_access"][key]["status"] == "Checking": findings["core_endpoint_access"][key]["status"] = "Completed"
    else:
        print("      Skipping core endpoint checks as REST API root is not accessible or protected.")
        for key in findings["core_endpoint_access"]: findings["core_endpoint_access"][key]["status"] = "Skipped (API Root Inaccessible)"


    # Finalize overall status and details
    final_details_parts = []
    if findings["api_root_accessible"] is True: final_details_parts.append(f"API root at {wp_json_url} is accessible.")
    elif findings["api_root_accessible"] == "Protected": final_details_parts.append(f"API root at {wp_json_url} is protected.")
    elif findings["api_root_accessible"] is False: final_details_parts.append(f"API root at {wp_json_url} seems disabled/not found.")
    
    if findings["namespaces"]: final_details_parts.append(f"Discovered {len(findings['namespaces'])} namespaces.")
    
    exposed_core_eps = [k for k,v in findings["core_endpoint_access"].items() if v.get("accessible_unauth") is True and (v.get("count_unauth",0) > 0 or v.get("data_preview"))]
    if exposed_core_eps: final_details_parts.append(f"Unauthenticated access to core endpoints: {', '.join(exposed_core_eps)}.")

    findings["details"] = " ".join(final_details_parts) if final_details_parts else "General REST API analysis performed. See specific findings."
    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] General REST API analysis finished. Details: {findings['details']}")
