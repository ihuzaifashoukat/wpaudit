# Module for Advanced WordPress User Enumeration Techniques
import requests # Retained for context
from urllib.parse import urljoin, urlparse
from .utils import make_request
import re
import json

from bs4 import BeautifulSoup
# Removed duplicate: from core.utils import make_request

def _find_first_post_url(target_url, config):
    """Helper to find a likely first post URL for oEmbed checks."""
    print("      Attempting to find a valid post URL for oEmbed check...")
    try:
        response = make_request(target_url, config, method="GET", timeout=7)
        if response and response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Look for oEmbed link first
            oembed_link = soup.find('link', attrs={'type': 'application/json+oembed', 'href': True})
            if oembed_link and oembed_link['href']:
                # Extract the URL from the oEmbed href attribute's 'url' query parameter
                parsed_oembed_href = urlparse(oembed_link['href'])
                query_params = urlparse.parse_qs(parsed_oembed_href.query)
                if 'url' in query_params and query_params['url']:
                    post_url = query_params['url'][0]
                    print(f"        Found post URL via oEmbed discovery: {post_url}")
                    return post_url

            # Fallback: Look for common article links
            # This is a very basic heuristic, might need refinement
            for tag_name in ['article', 'div', 'main']: # Common containers for posts
                container = soup.find(tag_name, class_=re.compile(r'(post|entry|article|content)'))
                if container:
                    link_tag = container.find('a', href=True)
                    if link_tag and link_tag['href'].startswith(('http://', 'https://', '/')):
                        post_url = urljoin(target_url, link_tag['href'])
                        # Basic validation: ensure it's not just the homepage or an image
                        if urlparse(post_url).path not in ['/', ''] and not post_url.endswith(('.png', '.jpg', '.jpeg', '.gif')):
                            print(f"        Found potential post URL via page parsing: {post_url}")
                            return post_url
            
            # Fallback to a common default if nothing else found
            common_post_slug = "/hello-world/"
            print(f"        Could not find a specific post URL, trying default: {common_post_slug}")
            return urljoin(target_url, common_post_slug)
            
    except Exception as e:
        print(f"        Error finding post URL: {e}")
    return None


def analyze_advanced_user_enum(state, config, target_url):
    """
    Performs advanced user enumeration techniques:
    - Author archive scanning (/?author=N)
    - oEmbed API user disclosure
    - JSON REST API /wp/v2/users endpoint
    Login error analysis remains a placeholder.
    """
    module_key = "wp_analyzer"
    findings_key = "advanced_user_enum"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Performing advanced user enumeration techniques.",
        "author_archive_users": [],
        "oembed_disclosed_authors": [],
        "rest_api_users": [],
        "login_error_users": [] # Placeholder
    })
    
    all_found_usernames = set() # To store unique usernames across all methods

    # 1. Author Archive Enumeration (/?author=N)
    print("    [i] Attempting user enumeration via author archives (/?author=N)...")
    author_archive_found_users_slugs = []
    max_author_id = config.get("wp_analyzer", {}).get("max_author_enum_id", 15)
    print(f"      Checking author IDs from 1 to {max_author_id}")
    base_url_parsed = urlparse(target_url)
    base_site_url = f"{base_url_parsed.scheme}://{base_url_parsed.netloc}"

    for i in range(1, max_author_id + 1):
        author_url = urljoin(target_url, f'?author={i}')
        # print(f"      Checking {author_url}") # Can be verbose
        try:
            response = make_request(author_url, config, method="GET", allow_redirects=True, timeout=7)
            if response:
                final_url = response.url
                if final_url != base_site_url and final_url != target_url.rstrip('/') + '/':
                    match = re.search(r'/author/([^/]+)/?', final_url)
                    if match:
                        username_slug = match.group(1)
                        if username_slug not in author_archive_found_users_slugs:
                            author_archive_found_users_slugs.append(username_slug)
                            all_found_usernames.add(username_slug)
                            print(f"        [+] Author Archive: Found username '{username_slug}' (ID: {i}) via redirect to {final_url}")
                    elif response.status_code == 200 and final_url == author_url:
                         print(f"        [?] Author Archive: ID {i} resolved directly ({author_url}), might indicate user but no slug extracted.")
            # else: print(f"        [-] Author Archive: Request failed for author ID {i}.")
        except requests.exceptions.RequestException: # More generic exception
            # print(f"      [-] Author Archive: Error checking author ID {i}: {e}")
            if i > 5 and not author_archive_found_users_slugs:
                 print("      [-] Author Archive: Stopping enumeration due to early request errors and no users found.")
                 break
    findings["author_archive_users"] = author_archive_found_users_slugs
    if author_archive_found_users_slugs:
        print(f"    [+] Author Archive: Found {len(author_archive_found_users_slugs)} potential username(s).")


    # 2. oEmbed User Enumeration
    print("    [i] Attempting user enumeration via oEmbed API...")
    oembed_users = []
    first_post_url_for_oembed = _find_first_post_url(target_url, config)
    if first_post_url_for_oembed:
        oembed_api_url = urljoin(target_url, f'/wp-json/oembed/1.0/embed?url={quote(first_post_url_for_oembed)}')
        print(f"      Checking oEmbed endpoint: {oembed_api_url}")
        try:
            response = make_request(oembed_api_url, config, method="GET", timeout=7)
            if response and response.status_code == 200 and response.text:
                try:
                    data = json.loads(response.text)
                    author_name = data.get("author_name")
                    author_url_str = data.get("author_url")
                    if author_name:
                        # Try to extract username from author_url if it follows common pattern
                        username_from_url = None
                        if author_url_str:
                            url_match = re.search(r'/author/([^/]+)/?', author_url_str)
                            if url_match:
                                username_from_url = url_match.group(1)
                        
                        user_info = {"display_name": author_name}
                        if username_from_url:
                            user_info["username_slug"] = username_from_url
                            all_found_usernames.add(username_from_url)
                        
                        oembed_users.append(user_info)
                        print(f"        [+] oEmbed: Found author '{author_name}'" + (f" (slug: '{username_from_url}')" if username_from_url else ""))
                except json.JSONDecodeError:
                    print("        [-] oEmbed: Failed to parse JSON response.")
            elif response:
                print(f"        [-] oEmbed: Request failed or non-200 status: {response.status_code}")
            # else: print("        [-] oEmbed: Request failed.")
        except requests.exceptions.RequestException as e:
            print(f"      [-] oEmbed: Error checking endpoint: {e}")
    else:
        print("      [i] oEmbed: Could not determine a post URL to test, skipping oEmbed check.")
    findings["oembed_disclosed_authors"] = oembed_users
    if oembed_users:
         print(f"    [+] oEmbed: Found {len(oembed_users)} author(s)/username(s).")


    # 3. JSON REST API User Enumeration (/wp-json/wp/v2/users)
    print("    [i] Attempting user enumeration via JSON REST API (/wp-json/wp/v2/users)...")
    rest_api_found_users = []
    # First, check if the main /users endpoint is accessible
    users_api_url = urljoin(target_url, '/wp-json/wp/v2/users')
    try:
        response = make_request(users_api_url, config, method="GET", timeout=7)
        if response and response.status_code == 200 and response.text:
            print(f"      [+] REST API: /wp-json/wp/v2/users endpoint is accessible. Parsing users...")
            try:
                users_data = json.loads(response.text)
                if isinstance(users_data, list):
                    for user_entry in users_data:
                        if isinstance(user_entry, dict) and "slug" in user_entry and "name" in user_entry:
                            username_slug = user_entry["slug"]
                            display_name = user_entry["name"]
                            user_id = user_entry.get("id", "N/A")
                            rest_api_found_users.append({"id": user_id, "slug": username_slug, "name": display_name})
                            all_found_usernames.add(username_slug)
                            print(f"        [+] REST API: Found user: ID={user_id}, Slug='{username_slug}', Name='{display_name}'")
            except json.JSONDecodeError:
                print("        [-] REST API: Failed to parse JSON from /wp/v2/users.")
        elif response and response.status_code == 401: # Unauthorized
            print("      [i] REST API: /wp-json/wp/v2/users endpoint requires authentication (401). Trying individual ID enumeration...")
        elif response and response.status_code == 403: # Forbidden
            print("      [i] REST API: /wp-json/wp/v2/users endpoint is forbidden (403). Trying individual ID enumeration...")
        elif response: # Other status codes
            print(f"      [-] REST API: /wp-json/wp/v2/users endpoint returned status {response.status_code}. Trying individual ID enumeration...")
        # else: print(f"      [-] REST API: Request to /wp-json/wp/v2/users failed.")

        # If listing failed or was restricted, try enumerating by ID
        if not rest_api_found_users or (response and response.status_code in [401, 403]):
            max_rest_api_user_id = config.get("wp_analyzer", {}).get("max_rest_api_user_enum_id", 15)
            print(f"      Attempting REST API user enumeration by ID (1 to {max_rest_api_user_id})...")
            for i in range(1, max_rest_api_user_id + 1):
                user_id_url = urljoin(target_url, f'/wp-json/wp/v2/users/{i}')
                try:
                    id_response = make_request(user_id_url, config, method="GET", timeout=5)
                    if id_response and id_response.status_code == 200 and id_response.text:
                        user_data = json.loads(id_response.text)
                        if isinstance(user_data, dict) and "slug" in user_data and "name" in user_data:
                            username_slug = user_data["slug"]
                            display_name = user_data["name"]
                            # Avoid duplicates if already found by full listing
                            if not any(u['id'] == i for u in rest_api_found_users):
                                rest_api_found_users.append({"id": i, "slug": username_slug, "name": display_name})
                                all_found_usernames.add(username_slug)
                                print(f"        [+] REST API (ID): Found user: ID={i}, Slug='{username_slug}', Name='{display_name}'")
                except (requests.exceptions.RequestException, json.JSONDecodeError):
                    continue # Silently continue on errors for individual ID checks
    except requests.exceptions.RequestException as e:
        print(f"      [-] REST API: Error accessing /wp-json/wp/v2/users: {e}")
    findings["rest_api_users"] = rest_api_found_users
    if rest_api_found_users:
        print(f"    [+] REST API: Found {len(rest_api_found_users)} user(s)/username(s).")


    # Finalize details and remediation
    findings["status"] = "Completed"
    details_parts = []
    if findings["author_archive_users"]:
        details_parts.append(f"{len(findings['author_archive_users'])} user(s) via author archives.")
    if findings["oembed_disclosed_authors"]:
        details_parts.append(f"{len(findings['oembed_disclosed_authors'])} author(s) via oEmbed.")
    if findings["rest_api_users"]:
        details_parts.append(f"{len(findings['rest_api_users'])} user(s) via REST API.")
    
    if not details_parts:
        findings["details"] = "No users explicitly enumerated via advanced techniques. Login error analysis not implemented."
    else:
        findings["details"] = " ".join(details_parts) + " Login error analysis not implemented."

    unique_usernames_list = sorted(list(all_found_usernames))
    if unique_usernames_list:
        findings["all_discovered_usernames_combined"] = unique_usernames_list # Add combined list
        state.add_remediation_suggestion("user_enum_advanced_techniques", {
            "source": "WP Analyzer (Advanced User Enum)",
            "description": f"Usernames potentially enumerated via various advanced techniques: {', '.join(unique_usernames_list)}. Methods tried: Author Archives, oEmbed, REST API.",
            "severity": "Medium", # Severity can be context-dependent
            "remediation": "Review WordPress configurations to restrict user information exposure via REST API and oEmbed if not needed for public functionality. Consider disabling author archives or using plugins to prevent enumeration if this is a concern. Ensure strong, unique passwords for all users."
        })
        # Update the global user list in state if such a concept exists
        # current_known_users = state.get_full_state().get("discovered_entities", {}).get("usernames", [])
        # for un in unique_usernames_list:
        #    if un not in current_known_users: current_known_users.append(un)
        # state.update_discovered_entities("usernames", current_known_users)


    print(f"    [+] Advanced user enumeration finished. Combined unique usernames found: {len(unique_usernames_list)}.")
    state.update_specific_finding(module_key, findings_key, findings)
