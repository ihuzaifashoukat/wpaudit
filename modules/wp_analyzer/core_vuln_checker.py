# Module for WordPress Core Version Detection and Vulnerability Correlation
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from core.utils import make_request # Assuming a utility for requests exists

# Placeholder for vulnerability database interaction
# CORE_VULN_DB = {}

def _extract_version_from_url(url):
    """Attempts to extract a ?ver= query parameter from a URL."""
    try:
        query = urlparse(url).query
        params = parse_qs(query)
        return params.get('ver', [None])[0]
    except Exception:
        return None

def _get_version_from_meta(soup):
    """Extracts version from <meta name="generator" content="WordPress X.Y.Z">"""
    generator_tag = soup.find('meta', attrs={'name': 'generator'})
    if generator_tag and 'content' in generator_tag.attrs:
        content = generator_tag['content']
        match = re.search(r'WordPress\s+([\d\.]+)', content, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def _get_version_from_readme(target_url, config):
    """Extracts version from /readme.html"""
    readme_url = urljoin(target_url, 'readme.html')
    print(f"      Checking {readme_url} for version...")
    response = make_request(readme_url, config, method="GET", timeout=5)
    if response and response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', '').lower():
        match = re.search(r'<br\s*/?>\s*Version\s+([\d\.]+)', response.text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def _get_version_from_license(target_url, config):
    """Extracts version from /license.txt (less common but possible for older versions)"""
    license_url = urljoin(target_url, 'license.txt')
    print(f"      Checking {license_url} for version...")
    response = make_request(license_url, config, method="GET", timeout=5)
    if response and response.status_code == 200 and 'text/plain' in response.headers.get('Content-Type', '').lower():
        # WordPress versions are sometimes mentioned in license.txt, e.g., "WordPress version X.Y.Z"
        match = re.search(r'WordPress\s+version\s+([\d\.]+)', response.text, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def _get_version_from_feed(target_url, config):
    """Extracts version from RSS/Atom feed generator tag"""
    feed_urls = [urljoin(target_url, 'feed/'), urljoin(target_url, 'rdf/'), urljoin(target_url, 'atom/')]
    for feed_url in feed_urls:
        print(f"      Checking {feed_url} for version...")
        response = make_request(feed_url, config, method="GET", timeout=5)
        if response and response.status_code == 200:
            match = re.search(r'<generator>(?:https?://)?wordpress\.org/\?v=([\d\.]+)</generator>', response.text, re.IGNORECASE)
            if match:
                return match.group(1)
    return None

def _get_version_from_core_files(soup, target_url):
    """Extracts version from common core CSS/JS file ?ver= parameters"""
    if not soup: return None
    tags = soup.find_all(['link', 'script'])
    # More specific core file names to reduce false positives from themes/plugins
    core_file_identifiers = [
        '/wp-includes/css/dist/', '/wp-includes/js/dist/', # Gutenberg blocks
        '/wp-includes/js/tinymce/',
        'wp-emoji-release.min.js', 'jquery.js', 'jquery-migrate.min.js',
        'admin-bar.min.css', 'dashicons.min.css'
        # Add more specific core file names or paths as needed
    ]
    versions_found = set()
    for tag in tags:
        url = tag.get('href') or tag.get('src')
        if not url:
            continue

        absolute_url = urljoin(target_url, url)
        # Check if the URL contains known core file identifiers
        if any(identifier in absolute_url for identifier in core_file_identifiers):
            version = _extract_version_from_url(absolute_url)
            if version and re.match(r'^\d+(\.\d+){1,2}$', version): # Plausible version format
                versions_found.add(version)
    
    # If multiple distinct versions found in core files, it's ambiguous. Prefer if only one.
    if len(versions_found) == 1:
        return versions_found.pop()
    elif len(versions_found) > 1:
        print(f"        [?] Ambiguous versions from core files: {versions_found}. Not using this method.")
    return None


def analyze_core_version(state, config, target_url):
    """
    Detects the WordPress core version using multiple methods.
    Updates the state with findings. Vulnerability checking is NOT implemented.
    """
    module_key = "wp_analyzer"
    findings_key = "core_vulnerabilities"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Attempting to detect WordPress core version.",
        "detected_version": None,
        "detection_methods_tried": {}, # Store version by method
        "potential_vulnerabilities": []
    })

    all_detected_versions = {} # method -> version

    # Fetch homepage HTML once for methods that need it
    print("    Fetching homepage HTML for version detection...")
    homepage_response = make_request(target_url, config, method="GET", timeout=10)
    homepage_soup = None
    if homepage_response and homepage_response.status_code == 200:
        try:
            homepage_soup = BeautifulSoup(homepage_response.text, 'lxml')
        except Exception as e:
            print(f"      [-] Error parsing homepage HTML: {e}")
    else:
        print(f"    [-] Could not fetch homepage HTML (Status: {homepage_response.status_code if homepage_response else 'N/A'}). Some checks will be skipped.")

    # Method 1: Meta Generator Tag
    if homepage_soup:
        v = _get_version_from_meta(homepage_soup)
        if v: all_detected_versions["Meta Generator Tag"] = v

    # Method 2: Readme file
    v = _get_version_from_readme(target_url, config)
    if v: all_detected_versions["Readme File (/readme.html)"] = v

    # Method 3: License file
    v = _get_version_from_license(target_url, config)
    if v: all_detected_versions["License File (/license.txt)"] = v
    
    # Method 4: Feed Generator
    v = _get_version_from_feed(target_url, config)
    if v: all_detected_versions["Feed Generator Tag"] = v

    # Method 5: Core File Versions (from homepage HTML)
    if homepage_soup:
        v = _get_version_from_core_files(homepage_soup, target_url)
        if v: all_detected_versions["Core File Version Parameter"] = v
    
    findings["detection_methods_tried"] = all_detected_versions

    # Determine final version
    # Prioritize meta, then readme, then feed, then license, then core files.
    # If multiple unique versions found, report ambiguity.
    unique_versions = set(all_detected_versions.values())
    final_version = None
    final_method = "Undetermined"

    if len(unique_versions) == 1:
        final_version = unique_versions.pop()
        # Find the method that yielded this version (can be multiple)
        final_method = "; ".join([method for method, ver in all_detected_versions.items() if ver == final_version])
        print(f"    [+] Consistent Version Detected: {final_version} (via {final_method})")
    elif len(unique_versions) > 1:
        # Handle conflicting versions - report ambiguity
        findings["details"] = f"Multiple conflicting WordPress versions detected: {all_detected_versions}. Manual verification needed."
        print(f"    [!] Conflicting versions detected: {all_detected_versions}")
        # Optionally, pick one based on a priority or report all
        # For now, let's pick the one from meta if available, else readme, etc.
        priority_methods = ["Meta Generator Tag", "Readme File (/readme.html)", "Feed Generator Tag", "License File (/license.txt)", "Core File Version Parameter"]
        for m in priority_methods:
            if m in all_detected_versions:
                final_version = all_detected_versions[m]
                final_method = f"{m} (among conflicting results)"
                break
        if final_version:
             findings["detected_version"] = final_version # Report one, but note conflict
             print(f"    [?] Reporting version {final_version} from {final_method} despite conflicts.")
        else: # Should not happen if unique_versions > 1
             final_version = None 
    elif not all_detected_versions: # No versions found at all
        final_version = None
        print("    [-] No WordPress version detected by any method.")
    else: # Only one method found a version (already handled by len(unique_versions) == 1)
        # This case is covered, but for clarity:
        if all_detected_versions: # Should be true if unique_versions was 0 but all_detected_versions is not empty (impossible)
            method_name, version_val = list(all_detected_versions.items())[0]
            final_version = version_val
            final_method = method_name


    if final_version:
        findings["detected_version"] = final_version
        findings["status"] = "Completed"
        if len(unique_versions) > 1:
             findings["details"] = f"Potentially detected WordPress core version {final_version} (via {final_method}). However, conflicting versions were found: {all_detected_versions}. Manual verification advised. Vulnerability check NOT implemented."
        else:
             findings["details"] = f"Detected WordPress core version {final_version} (via {final_method}). Vulnerability check NOT implemented."
        
        print("    [!] Vulnerability correlation against database is NOT IMPLEMENTED in this version.")
    else:
        findings["status"] = "Completed"
        findings["details"] = "Could not reliably detect WordPress core version using common methods."

    state.update_specific_finding(module_key, findings_key, findings)
