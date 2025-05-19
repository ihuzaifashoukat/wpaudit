# Module for Advanced WordPress User Enumeration Techniques
import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup # To potentially parse author pages later
from core.utils import make_request # Assuming a utility for requests exists

def analyze_advanced_user_enum(state, config, target_url):
    """
    Performs advanced user enumeration techniques beyond the REST API.
    Currently implements author archive scanning (/?author=N).
    Login error analysis remains a placeholder due to complexity.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "advanced_user_enum"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Performing author archive user enumeration.",
        "author_archive_users": [], # Users found via /?author=N
        "login_error_users": [] # Placeholder - Not Implemented
    })

    print("    Attempting user enumeration via author archives (/?author=N)...")
    found_users = []
    # Define a reasonable limit to check author IDs
    max_author_id = config.get("wp_analyzer", {}).get("max_author_enum_id", 15)
    print(f"      Checking author IDs from 1 to {max_author_id}")

    base_url_parsed = urlparse(target_url)
    base_site_url = f"{base_url_parsed.scheme}://{base_url_parsed.netloc}" # Used to compare redirect locations

    for i in range(1, max_author_id + 1):
        author_url = urljoin(target_url, f'?author={i}')
        print(f"      Checking {author_url}")
        try:
            # Follow redirects to see where it lands
            response = make_request(author_url, config, method="GET", allow_redirects=True, timeout=10)

            if response:
                # Check if the final URL after redirects is different from the base site URL
                # and potentially contains a username-like slug in the path.
                # A successful author page often redirects to /author/username/
                final_url = response.url
                if final_url != base_site_url and final_url != target_url.rstrip('/') + '/': # Avoid simple redirects back home
                    # Attempt to extract username from common /author/username/ pattern
                    match = re.search(r'/author/([^/]+)/?', final_url)
                    if match:
                        username = match.group(1)
                        if username not in found_users:
                            found_users.append(username)
                            print(f"        [+] Found potential username via author redirect: {username} (ID: {i}) -> {final_url}")
                    # Also consider cases where ?author=N resolves directly without redirect but isn't homepage
                    elif response.status_code == 200 and final_url == author_url:
                         # Less reliable, but might indicate a user ID exists. Need manual verification.
                         # Avoid adding just the ID as a username.
                         print(f"        [?] Author ID {i} resolved directly ({author_url}), might indicate a user exists but couldn't extract username slug.")

            else:
                print(f"        [-] Request failed for author ID {i}.")

        except requests.exceptions.RequestException as e:
            print(f"      [-] Error checking author ID {i}: {e}")
            # Break if too many errors occur?
            if i > 5 and len(found_users) == 0: # Heuristic: if first few fail, stop
                 print("      [-] Stopping author enumeration due to early request errors.")
                 break

    findings["author_archive_users"] = found_users
    findings["status"] = "Completed"
    if found_users:
        findings["details"] = f"Found {len(found_users)} potential username(s) via author archive enumeration. Login error analysis not implemented."
        state.add_remediation_suggestion("user_enum_author_archive", {
            "source": "WP Analyzer",
            "description": f"Usernames ({', '.join(found_users)}) were potentially enumerated via author archives (?author=N redirects).",
            "severity": "Low",
            "remediation": "Consider using plugins or web server rules to prevent user enumeration via author archives if this is a concern. Ensure strong passwords for all users."
        })
    else:
        findings["details"] = "No usernames found via author archive enumeration. Login error analysis not implemented."

    print(f"    [+] Author archive enumeration finished. Found {len(found_users)} potential username(s).")
    state.update_specific_finding(module_key, findings_key, findings)
