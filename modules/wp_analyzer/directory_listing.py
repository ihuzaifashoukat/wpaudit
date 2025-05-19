import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import datetime # For year/month upload paths
from core.utils import sanitize_filename
from .utils import make_request

SENSITIVE_FILE_EXTENSIONS = ['.log', '.sql', '.bak', '.zip', '.tar.gz', '.tgz', '.sitemap', '.xml', '.phps', '.env', '.config', '.conf', '.ini', '.sh', '.txt']
SENSITIVE_FILENAME_KEYWORDS = ['debug', 'error', 'backup', 'dump', 'secret', 'password', 'key', 'config']

def _is_directory_listing(html_content, url_path):
    """Checks if HTML content indicates a directory listing."""
    if not html_content:
        return False
    text_lower = html_content.lower()
    # More specific title check
    title_match = re.search(r"<title>index of\s+" + re.escape(url_path.lower()), text_lower)
    # Check for "Parent Directory" link text (common on Apache listings)
    parent_dir_match_apache = "parent directory" in text_lower and "<a href" in text_lower
    # Check for "Name Last modified Size Description" which is common on Nginx/Apache
    common_header_match = all(kw in text_lower for kw in ["name", "last modified", "size"])
    
    # Heuristic: count file-like links (ending with common extensions or / for dirs)
    # This needs to be robust enough not to count navigation links.
    soup = BeautifulSoup(html_content, 'lxml')
    listing_links_count = 0
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # Skip common non-listing links
        if href.startswith(('?', '#', 'javascript:', 'mailto:')) or href == '../' or href == './':
            continue
        # Check if it looks like a file or directory within the current path context
        if href.endswith('/') or any(href.lower().endswith(ext) for ext in ['.php', '.html', '.txt', '.js', '.css', '.jpg', '.png', '.zip', '.log']):
            listing_links_count += 1
            
    return bool(title_match or parent_dir_match_apache or common_header_match or listing_links_count > 3)

def _extract_links_from_listing(html_content, base_url):
    """Extracts file and directory links from a directory listing page."""
    links = {"dirs": [], "files": []}
    if not html_content:
        return links
    soup = BeautifulSoup(html_content, 'lxml')
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        # Skip parent directory, current directory, query string links, and fragment links
        if href == "../" or href == "./" or href.startswith("?") or href.startswith("#") or href.startswith("javascript:"):
            continue
        
        full_url = urljoin(base_url, href) # Resolve relative links
        # Ensure we are still within the same path segment or deeper
        if not full_url.startswith(base_url): 
            continue

        if href.endswith('/'):
            links["dirs"].append(href.strip('/')) # Store dir name
        else:
            links["files"].append(href) # Store file name
    return links

def _check_and_log_listing(test_url, response, state, config, vulnerable_paths_map, dir_path_key_for_remediation):
    """Helper to check response, log findings, and extract links if listing is found."""
    if response and response.status_code == 200:
        parsed_url = urlparse(test_url)
        if _is_directory_listing(response.text, parsed_url.path):
            print(f"    [!!!] Directory Listing ENABLED for: {test_url}")
            
            listed_content = _extract_links_from_listing(response.text, test_url)
            sensitive_files_found = []
            for fname in listed_content["files"]:
                if any(fname.lower().endswith(ext) for ext in SENSITIVE_FILE_EXTENSIONS) or \
                   any(keyword in fname.lower() for keyword in SENSITIVE_FILENAME_KEYWORDS):
                    sensitive_files_found.append(fname)
            
            path_finding = {
                "url": test_url,
                "listed_dirs": listed_content["dirs"],
                "listed_files_count": len(listed_content["files"]),
                "sensitive_files_hint": sensitive_files_found
            }
            
            if test_url not in [vp["url"] for vp in vulnerable_paths_map.get(dir_path_key_for_remediation, [])]:
                 vulnerable_paths_map.setdefault(dir_path_key_for_remediation, []).append(path_finding)

            severity = "Medium"
            description_extra = ""
            if sensitive_files_found:
                severity = "High"
                description_extra = f" Sensitive files potentially exposed: {', '.join(sensitive_files_found[:3])}{'...' if len(sensitive_files_found)>3 else ''}."

            state.add_critical_alert(f"Directory Listing enabled: {test_url}" + (f" (Sensitive files: {len(sensitive_files_found)})" if sensitive_files_found else ""))
            # Use a more generic remediation key if it's for a sub-path, or specific if it's a top-level common dir
            remediation_key = f"dir_listing_{sanitize_filename(dir_path_key_for_remediation.replace('/', '_'))}"
            state.add_remediation_suggestion(remediation_key, {
                "source": "WP Analyzer (Directory Listing)",
                "description": f"Directory listing is enabled for '{test_url}', potentially exposing file names or structures.{description_extra}",
                "severity": severity,
                "remediation": "Disable directory listing via web server configuration (e.g., 'Options -Indexes' in .htaccess for Apache, or 'autoindex off;' in Nginx)."
            })
            return True, listed_content # Listing found, return content
    return False, None # No listing or error

def check_directory_listing(state, config, target_url):
    """Checks for directory listing enabled on common and discovered WordPress directories."""
    module_key = "wp_analyzer"
    findings_key = "directory_listing_enhanced" # New key for enhanced findings
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "vulnerable_paths_map": {}, # Store findings per base path for better organization
        "details": "Checking for directory listings..."
    })
    print("    [i] Enhanced Directory Listing Checks...")

    # Common base directories to check
    # Added more specific paths and common misconfigurations
    base_dirs_to_check = [
        "wp-content/", "wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/",
        "wp-includes/", "wp-admin/", "wp-admin/includes/", "wp-admin/css/", "wp-admin/js/",
        "wp-content/backups/", "wp-content/backup/", "wp-content/cache/", "wp-content/logs/"
        # "wp-content/mu-plugins/" # Must-use plugins
    ]
    
    # Use a dictionary to store vulnerable paths, keyed by the initial path checked for remediation grouping
    vulnerable_paths_map = findings.get("vulnerable_paths_map", {})

    # Initial scan of base directories
    for dir_path in base_dirs_to_check:
        test_url = urljoin(target_url, dir_path)
        print(f"    Checking base directory: {test_url}")
        try:
            response = make_request(test_url, config, timeout=7)
            is_listing, listed_content = _check_and_log_listing(test_url, response, state, config, vulnerable_paths_map, dir_path)

            # Recursive checks for uploads, plugins, themes if listing found on their parent
            if is_listing and listed_content:
                if dir_path == "wp-content/uploads/":
                    # Check current year and previous year for month subdirs
                    current_year = datetime.datetime.now().year
                    for year_offset in range(2): # Check current and previous year
                        year_to_check = str(current_year - year_offset)
                        if year_to_check in listed_content["dirs"]: # Check if year dir was listed
                            year_url = urljoin(test_url, f"{year_to_check}/")
                            print(f"      Recursively checking uploads year: {year_url}")
                            year_resp = make_request(year_url, config, timeout=5)
                            is_year_listing, year_listed_content = _check_and_log_listing(year_url, year_resp, state, config, vulnerable_paths_map, dir_path)
                            if is_year_listing and year_listed_content:
                                for month_num in range(1, 13):
                                    month_str = f"{month_num:02d}" # Format as 01, 02, etc.
                                    if month_str in year_listed_content["dirs"]:
                                        month_url = urljoin(year_url, f"{month_str}/")
                                        print(f"        Recursively checking uploads month: {month_url}")
                                        month_resp = make_request(month_url, config, timeout=5)
                                        _check_and_log_listing(month_url, month_resp, state, config, vulnerable_paths_map, dir_path)
                
                elif dir_path in ["wp-content/plugins/", "wp-content/themes/"]:
                    item_type = "plugin" if "plugins" in dir_path else "theme"
                    for item_name in listed_content["dirs"]:
                        item_url = urljoin(test_url, f"{item_name}/")
                        print(f"      Recursively checking {item_type}: {item_url}")
                        item_resp = make_request(item_url, config, timeout=5)
                        _check_and_log_listing(item_url, item_resp, state, config, vulnerable_paths_map, dir_path)
        except Exception as e:
            print(f"    [-] Error checking directory {dir_path}: {e}")
            # Log error for this specific path if needed in state

    findings["vulnerable_paths_map"] = vulnerable_paths_map
    total_vulnerable_unique_urls = sum(len(paths) for paths in vulnerable_paths_map.values())
    if total_vulnerable_unique_urls > 0:
        findings["status"] = "Vulnerabilities Found"
        findings["details"] = f"Found {total_vulnerable_unique_urls} path(s) with directory listing enabled. Check 'vulnerable_paths_map' for details."
    else:
        findings["status"] = "Completed (No Listings Found)"
        findings["details"] = "No directory listings found on checked paths."
    
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Enhanced Directory Listing checks finished. Status: {findings['status']}")
