import json
from urllib.parse import urljoin
from .utils import make_request # Local utils for requests

def analyze_rest_api_user_enum(state, config, target_url):
    """Checks for user enumeration via the REST API users endpoint."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "rest_api_user_enum" not in analyzer_findings:
        analyzer_findings["rest_api_user_enum"] = {"status": "Running", "exposed_users": []}
    rest_user_enum_details = analyzer_findings["rest_api_user_enum"]

    # Check config flag first
    if not config.get("analyzer_check_rest_user_enum", True):
        print("    [i] REST API user enumeration check disabled in configuration.")
        rest_user_enum_details["status"] = "Disabled in Config"
        analyzer_findings["rest_api_user_enum"] = rest_user_enum_details
        state.update_module_findings(module_key, analyzer_findings)
        return # Correctly indented return statement

    # Standard REST API users endpoint
    users_endpoint = urljoin(target_url.rstrip('/'), "/wp-json/wp/v2/users")
    print(f"    Checking REST API users endpoint: {users_endpoint}")
    response = make_request(users_endpoint, config)

    # Ensure exposed_users list exists
    if "exposed_users" not in rest_user_enum_details:
        rest_user_enum_details["exposed_users"] = []
    exposed_users_list = rest_user_enum_details["exposed_users"]

    if response and response.status_code == 200:
        try:
            users_data = response.json()
            # Check if the response is a list (expected format for users)
            if isinstance(users_data, list) and users_data:
                print(f"    [!!!] REST API exposes user data at {users_endpoint}!")
                for user_entry in users_data:
                    # Extract relevant user info, avoid overly verbose data
                    user_info = {
                        "id": user_entry.get("id"),
                        "name": user_entry.get("name"),
                        "slug": user_entry.get("slug"), # Often the username
                        "link": user_entry.get("link"),
                        # Include a snippet of the description if present
                        "description": (user_entry.get("description","")[:100] + "...") if user_entry.get("description") else ""
                    }
                    # Avoid adding duplicates if run multiple times
                    if user_info not in exposed_users_list:
                        exposed_users_list.append(user_info)
                    print(f"      [!] Exposed User: ID={user_info['id']}, Name='{user_info['name']}', Slug='{user_info['slug']}'")

                rest_user_enum_details["status"] = "Exposed"
                state.add_critical_alert(f"REST API exposes user data at {users_endpoint} ({len(exposed_users_list)} users found).")
                state.add_remediation_suggestion("rest_api_user_exposure", {
                    "source": "WP Analyzer",
                    "description": f"The WordPress REST API at {users_endpoint} lists user information (names, slugs), aiding in username enumeration and targeted attacks.",
                    "severity": "Medium",
                    "remediation": "Restrict access to the users endpoint of the REST API. Use security plugins or custom code (e.g., filters like 'rest_user_query', 'rest_authentication_errors') to prevent unauthorized access or limit fields returned for non-authenticated users."
                })
            # Check if the response indicates access is forbidden
            elif isinstance(users_data, dict) and users_data.get("code") == "rest_user_cannot_view":
                 rest_user_enum_details["status"] = "Protected (rest_user_cannot_view)"
                 print(f"    [+] REST API users endpoint seems protected ('rest_user_cannot_view').")
            # Handle cases where the endpoint is accessible but returns empty list or unexpected format
            elif isinstance(users_data, list) and not users_data:
                 rest_user_enum_details["status"] = "Accessible but No Users Listed"
                 print(f"    [i] REST API users endpoint accessible but no users were listed at {users_endpoint}.")
            else:
                rest_user_enum_details["status"] = "Accessible but Unexpected Format"
                print(f"    [i] REST API users endpoint accessible but returned an unexpected format at {users_endpoint}.")
        except json.JSONDecodeError:
            rest_user_enum_details["status"] = "Accessible but Invalid JSON"
            print(f"    [-] REST API users endpoint accessible but returned invalid JSON at {users_endpoint}. Response snippet: {response.text[:200]}")
    elif response:
        # Handle other non-200 status codes
        rest_user_enum_details["status"] = f"Error (Status: {response.status_code})"
        print(f"    [-] REST API users endpoint check failed at {users_endpoint} (Status: {response.status_code}).")
    else:
        # Handle request failure
        rest_user_enum_details["status"] = "Request Failed"
        print(f"    [-] Request to REST API users endpoint failed for {users_endpoint}.")

    rest_user_enum_details["exposed_users"] = exposed_users_list
    analyzer_findings["rest_api_user_enum"] = rest_user_enum_details
    state.update_module_findings(module_key, analyzer_findings)
