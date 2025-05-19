import re
from urllib.parse import urljoin
from core.utils import sanitize_filename # Core utils needed here
from .utils import make_request # Local utils for requests
# from datetime import datetime # Uncomment if adding date-based paths

def check_directory_listing(state, config, target_url):
    """Checks for directory listing enabled on common WordPress directories."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "directory_listing" not in analyzer_findings:
        analyzer_findings["directory_listing"] = {"status": "Running", "vulnerable_paths": []}
    dir_listing_details = analyzer_findings["directory_listing"]

    # Common directories to check
    common_dirs = [
        "wp-content/",
        "wp-content/uploads/",
        "wp-content/plugins/",
        "wp-content/themes/",
        "wp-includes/" # Less common to be listable but worth checking
        # Add dynamic paths like year/month for uploads if desired:
        # f"wp-content/uploads/{datetime.now().year}/",
        # f"wp-content/uploads/{datetime.now().year}/{datetime.now().strftime('%m')}/"
    ]

    # Ensure vulnerable_paths list exists
    if "vulnerable_paths" not in dir_listing_details:
        dir_listing_details["vulnerable_paths"] = []
    vulnerable_paths_found = dir_listing_details["vulnerable_paths"]

    for dir_path in common_dirs:
        test_url = urljoin(target_url, dir_path)
        print(f"    Checking directory listing for: {test_url}")
        response = make_request(test_url, config)

        if response and response.status_code == 200:
            # Common indicators of directory listing enabled:
            # 1. Title often contains "Index of /path/"
            # 2. Body often contains "<title>Index of /", "Parent Directory" link, or multiple file links.
            text_lower = response.text.lower()

            # More specific title check
            title_match = re.search(r"<title>index of\s+" + re.escape(urlparse(test_url).path.lower()), text_lower)
            # Check for "Parent Directory" link text
            parent_dir_match = "parent directory" in text_lower and "<a href" in text_lower
            # Check for multiple links that look like files or directories (heuristic)
            # Avoid matching navigation links, look for common file extensions or trailing slashes
            potential_file_links = re.findall(r'href="([^"]+)"', text_lower)
            listing_links_count = sum(1 for link in potential_file_links if not link.startswith("?") and not link.startswith("#") and ('.' in link.split('/')[-1] or link.endswith('/')))

            # If title matches, or parent directory link exists, or multiple file-like links found
            if title_match or parent_dir_match or listing_links_count > 3: # Threshold of >3 links
                print(f"    [!!!] Directory Listing ENABLED for: {test_url}")
                # Avoid adding duplicates
                if test_url not in vulnerable_paths_found:
                    vulnerable_paths_found.append(test_url)
                state.add_critical_alert(f"Directory Listing enabled: {test_url}")
                state.add_remediation_suggestion(f"dir_listing_{sanitize_filename(dir_path)}", {
                    "source": "WP Analyzer",
                    "description": f"Directory listing is enabled for '{test_url}', potentially exposing sensitive file names or structures.",
                    "severity": "Medium", # Can be Low to Medium depending on content
                    "remediation": "Disable directory listing via web server configuration (e.g., 'Options -Indexes' in .htaccess for Apache, or 'autoindex off;' in Nginx)."
                })
            # else:
            #     print(f"      [+] Directory listing likely disabled for {test_url}") # Optional: Add positive confirmation

    dir_listing_details["vulnerable_paths"] = vulnerable_paths_found
    dir_listing_details["status"] = "Checked"
    analyzer_findings["directory_listing"] = dir_listing_details
    state.update_module_findings(module_key, analyzer_findings)
