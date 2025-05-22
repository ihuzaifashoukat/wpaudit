# Module for WordPress Theme and Plugin Enumeration and Vulnerability Scanning
import requests
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup # Ensure this is imported
from .utils import make_request
from core.vulnerability_manager import VulnerabilityManager # Import the new manager

# Regex patterns to find theme/plugin slugs in URLs
THEME_PATTERN = re.compile(r'/wp-content/themes/([^/]+)/')
PLUGIN_PATTERN = re.compile(r'/wp-content/plugins/([^/]+)/')

def _extract_version_from_url(url):
    """Attempts to extract a ?ver= query parameter from a URL."""
    try:
        query = urlparse(url).query
        params = parse_qs(query)
        return params.get('ver', [None])[0]
    except Exception:
        return None

def _extract_version_from_readme_txt(content):
    """Extracts 'Stable tag' or 'Version' from readme.txt content."""
    stable_tag_match = re.search(r"Stable tag:\s*([\w\.\-]+)", content, re.IGNORECASE)
    if stable_tag_match:
        return stable_tag_match.group(1)
    version_match = re.search(r"Version:\s*([\w\.\-]+)", content, re.IGNORECASE)
    if version_match:
        return version_match.group(1)
    return None

def _extract_version_from_style_css(content):
    """Extracts 'Version:' from style.css content."""
    version_match = re.search(r"Version:\s*([\w\.\-]+)", content, re.IGNORECASE)
    if version_match:
        return version_match.group(1)
    return None

def _parse_html_for_extensions(html_content, target_url, found_themes, found_plugins):
    """Parses HTML content to find theme and plugin references."""
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        
        # 1. Search common tags and attributes
        tags_to_check = soup.find_all(['link', 'script', 'img', 'iframe', 'a'])
        for tag in tags_to_check:
            url = None
            if tag.name == 'a' or tag.name == 'link':
                url = tag.get('href')
            if not url and tag.name in ['script', 'img', 'iframe']: # Check src for these tags
                url = tag.get('src')
            
            if not url:
                # For script tags, also check inline content
                if tag.name == 'script' and tag.string:
                    inline_script_content = tag.string
                    for match in PLUGIN_PATTERN.finditer(inline_script_content):
                        plugin_slug = match.group(1)
                        # Version from inline script is hard, so we'll rely on readme.txt later
                        found_plugins.setdefault(plugin_slug, {}).update({"source_urls": set()})
                        found_plugins[plugin_slug]["source_urls"].add(f"inline_script_mention_on_{target_url}")
                    for match in THEME_PATTERN.finditer(inline_script_content):
                        theme_slug = match.group(1)
                        found_themes.setdefault(theme_slug, {}).update({"source_urls": set()})
                        found_themes[theme_slug]["source_urls"].add(f"inline_script_mention_on_{target_url}")
                continue

            absolute_url = urljoin(target_url, url)
            version_from_url = _extract_version_from_url(absolute_url)

            theme_match = THEME_PATTERN.search(absolute_url)
            if theme_match:
                theme_slug = theme_match.group(1)
                # Update if new, or if this finding provides a version and previous didn't
                if theme_slug not in found_themes or (version_from_url and not found_themes[theme_slug].get("version_from_url")):
                    found_themes.setdefault(theme_slug, {}).update({"version_from_url": version_from_url, "source_urls": set()})
                found_themes[theme_slug]["source_urls"].add(absolute_url)


            plugin_match = PLUGIN_PATTERN.search(absolute_url)
            if plugin_match:
                plugin_slug = plugin_match.group(1)
                if plugin_slug not in found_plugins or (version_from_url and not found_plugins[plugin_slug].get("version_from_url")):
                    found_plugins.setdefault(plugin_slug, {}).update({"version_from_url": version_from_url, "source_urls": set()})
                found_plugins[plugin_slug]["source_urls"].add(absolute_url)

        # 2. Raw text search for plugin patterns in the entire HTML (as a fallback)
        # This can be noisy, so it's a supplemental check.
        for match in PLUGIN_PATTERN.finditer(html_content):
            plugin_slug = match.group(1)
            if plugin_slug not in found_plugins: # Only add if not already found by more precise methods
                found_plugins.setdefault(plugin_slug, {}).update({"source_urls": set()})
                print(f"        [i] Plugin '{plugin_slug}' detected via raw HTML search on {target_url}.")
            found_plugins[plugin_slug]["source_urls"].add(f"raw_html_mention_on_{target_url}")
            
        for match in THEME_PATTERN.finditer(html_content):
            theme_slug = match.group(1)
            if theme_slug not in found_themes:
                found_themes.setdefault(theme_slug, {}).update({"source_urls": set()})
                print(f"        [i] Theme '{theme_slug}' detected via raw HTML search on {target_url}.")
            found_themes[theme_slug]["source_urls"].add(f"raw_html_mention_on_{target_url}")

    except Exception as e:
        print(f"      [-] Error parsing HTML for extensions on {target_url}: {e}")

def _fetch_sitemap_urls(target_url, config):
    """Fetches URLs from sitemap.xml or sitemap_index.xml."""
    sitemap_urls_to_check = [
        urljoin(target_url, 'sitemap.xml'),
        urljoin(target_url, 'sitemap_index.xml')
    ]
    discovered_page_urls = set()
    max_sitemap_entries = config.get("wp_analyzer", {}).get("max_sitemap_scan_entries", 10)


    for sitemap_url in sitemap_urls_to_check:
        print(f"    Attempting to fetch sitemap: {sitemap_url}")
        response = make_request(sitemap_url, config, method="GET")
        if response and response.status_code == 200 and 'xml' in response.headers.get('Content-Type', '').lower():
            try:
                soup = BeautifulSoup(response.content, 'xml') # Use 'xml' parser
                # For sitemap index files, find sitemap locs
                sitemap_tags = soup.find_all('sitemap')
                if sitemap_tags:
                    for s_tag in sitemap_tags:
                        loc_tag = s_tag.find('loc')
                        if loc_tag and loc_tag.text:
                            # Recursively fetch and parse sub-sitemaps if needed, or add to a queue
                            # For simplicity here, we'll just add them to a list to check later if they are page sitemaps
                            # This part could be expanded to handle nested sitemaps more deeply
                            nested_sitemap_url = loc_tag.text
                            print(f"      Found nested sitemap: {nested_sitemap_url}")
                            # Add to sitemap_urls_to_check if it's not already processed (simple check)
                            if nested_sitemap_url not in sitemap_urls_to_check and len(sitemap_urls_to_check) < 5: # Limit recursion
                                sitemap_urls_to_check.append(nested_sitemap_url)
                    continue # Move to the next sitemap URL (which might be a sub-sitemap)

                # For regular sitemaps, find URL locs
                url_tags = soup.find_all('url')
                for u_tag in url_tags:
                    loc_tag = u_tag.find('loc')
                    if loc_tag and loc_tag.text:
                        discovered_page_urls.add(loc_tag.text)
                        if len(discovered_page_urls) >= max_sitemap_entries:
                            break
                if len(discovered_page_urls) >= max_sitemap_entries:
                    break
            except Exception as e:
                print(f"      [-] Error parsing sitemap {sitemap_url}: {e}")
        elif response:
            print(f"      Sitemap at {sitemap_url} not found or not XML (Status: {response.status_code}, Type: {response.headers.get('Content-Type', '')}).")

    print(f"    Discovered {len(discovered_page_urls)} URLs from sitemaps.")
    return list(discovered_page_urls)[:max_sitemap_entries]


def analyze_extensions(state, config, target_url):
    """
    Enumerates installed themes and plugins by parsing HTML from multiple site pages
    and attempting to fetch readme.txt/style.css for version info.
    Vulnerability checking is NOT implemented.
    """
    module_key = "wp_analyzer"
    findings_key = "extension_vulnerabilities"

    # Get the full wp_analyzer findings
    all_wp_analyzer_findings = state.get_module_findings(module_key, {})

    # Get the specific findings for this sub-module, or initialize if not present
    findings = all_wp_analyzer_findings.get(findings_key, {})
    if not findings: # Initialize with default structure
        findings = {
            "status": "Not Checked",
            "details": "",
            "enumerated_themes": [],
            "enumerated_plugins": [],
            "vulnerable_themes": [],
            "vulnerable_plugins": []
        }

    findings["status"] = "Running"
    findings["details"] = "Enumerating themes and plugins..."
    # Ensure lists are initialized if findings were pre-existing but incomplete
    for list_key in ["enumerated_themes", "enumerated_plugins", "vulnerable_themes", "vulnerable_plugins"]:
        if list_key not in findings:
            findings[list_key] = []
            
    all_wp_analyzer_findings[findings_key] = findings # Place it back into the main structure
    state.update_module_findings(module_key, all_wp_analyzer_findings) # Save initial state

    found_themes = {}  # slug -> {"version": "x.y.z", "version_from_url": "a.b.c", "source_urls": set()}
    found_plugins = {} # slug -> {"version": "x.y.z", "version_from_url": "a.b.c", "source_urls": set()}

    urls_to_scan = {target_url} # Start with the main target URL
    sitemap_page_urls = _fetch_sitemap_urls(target_url, config)
    urls_to_scan.update(sitemap_page_urls)

    max_pages_to_scan_for_assets = config.get("wp_analyzer", {}).get("max_pages_for_extension_scan", 3)
    scanned_page_count = 0

    for page_url in list(urls_to_scan)[:max_pages_to_scan_for_assets]:
        if scanned_page_count >= max_pages_to_scan_for_assets:
            break
        print(f"    Fetching HTML from {page_url} to analyze extensions...")
        response = make_request(page_url, config, method="GET")
        if response and response.status_code == 200 and 'text/html' in response.headers.get('Content-Type','').lower():
            _parse_html_for_extensions(response.text, target_url, found_themes, found_plugins)
            scanned_page_count += 1
        elif response:
            print(f"    [-] Failed to fetch or not HTML: {page_url} (Status: {response.status_code})")
        else:
            print(f"    [-] Request failed for {page_url}")


    # Attempt to get more accurate versions from readme.txt / style.css
    print("    Attempting to fetch readme.txt/style.css for version confirmation...")
    for slug, data in found_themes.items():
        style_css_url = urljoin(target_url, f'/wp-content/themes/{slug}/style.css')
        print(f"      Checking theme style.css: {style_css_url}")
        response = make_request(style_css_url, config, method="GET")
        if response and response.status_code == 200:
            version_from_style = _extract_version_from_style_css(response.text)
            if version_from_style:
                data["version"] = version_from_style
                print(f"        [+] Found version {version_from_style} for theme {slug} from style.css")

    for slug, data in found_plugins.items():
        readme_url = urljoin(target_url, f'/wp-content/plugins/{slug}/readme.txt')
        print(f"      Checking plugin readme.txt: {readme_url}")
        response = make_request(readme_url, config, method="GET")
        if response and response.status_code == 200:
            version_from_readme = _extract_version_from_readme_txt(response.text)
            if version_from_readme:
                data["version"] = version_from_readme
                print(f"        [+] Found version {version_from_readme} for plugin {slug} from readme.txt")

    # Initial formatting of enumerated themes and plugins (before fetching full metadata)
    enumerated_themes_list = []
    for slug, data in found_themes.items():
        enumerated_themes_list.append({
            "name": slug, 
            "version": data.get("version") or data.get("version_from_url"), 
            "detection_sources": list(data.get('source_urls', [])),
            "metadata": {} # Placeholder for richer metadata
        })
    findings["enumerated_themes"] = enumerated_themes_list

    enumerated_plugins_list = []
    for slug, data in found_plugins.items():
        enumerated_plugins_list.append({
            "name": slug,
            "version": data.get("version") or data.get("version_from_url"),
            "detection_sources": list(data.get('source_urls', [])),
            "metadata": {} # Placeholder for richer metadata
        })
    findings["enumerated_plugins"] = enumerated_plugins_list

    num_themes = len(findings["enumerated_themes"])
    num_plugins = len(findings["enumerated_plugins"])
    
    print(f"    [+] Initial extension enumeration complete: Found {num_themes} theme(s), {num_plugins} plugin(s).")
    print(f"    Attempting to fetch detailed metadata and vulnerabilities from WPScan API...")

    # --- Vulnerability Correlation and Metadata Fetching for Themes and Plugins ---
    vuln_manager = VulnerabilityManager(config, state)
    updated_enumerated_themes = []
    updated_enumerated_plugins = []
    # vulnerable_themes_found and vulnerable_plugins_found will be derived from updated_enumerated lists
    details_log = []

    for theme_info_initial in findings["enumerated_themes"]:
        theme_slug = theme_info_initial["name"]
        theme_version = theme_info_initial.get("version")
        theme_data_from_api = {"metadata": {}, "vulnerabilities": []}
        try:
            theme_data_from_api = vuln_manager.get_theme_vulnerabilities(theme_slug, theme_version)
            
            # Update the theme_info with metadata
            theme_info_initial["metadata"] = theme_data_from_api.get("metadata", {})
            # If API provides a more accurate version (e.g. latest_version if detected is null), consider updating
            if not theme_version and theme_info_initial["metadata"].get("latest_version"):
                 theme_info_initial["version"] = theme_info_initial["metadata"]["latest_version"]
                 theme_version = theme_info_initial["version"] # update for vuln list
                 print(f"        [i] Updated version for theme {theme_slug} to latest known: {theme_version}")

            if theme_data_from_api.get("vulnerabilities"):
                msg = f"Found {len(theme_data_from_api['vulnerabilities'])} potential vulnerabilities for theme {theme_slug} (version: {theme_version or 'Unknown'})."
                print(f"      [+] {msg}")
                details_log.append(msg)
                # Add vulnerabilities directly to the theme_info_initial object
                theme_info_initial["vulnerabilities"] = theme_data_from_api["vulnerabilities"]
            else:
                theme_info_initial["vulnerabilities"] = []
            
            updated_enumerated_themes.append(theme_info_initial)

        except Exception as e:
            err_msg = f"Error during metadata/vulnerability lookup for theme {theme_slug}: {e}"
            print(f"      [-] {err_msg}")
            details_log.append(err_msg)
            theme_info_initial["metadata"]["error"] = err_msg # Log error in metadata
            theme_info_initial["vulnerabilities"] = []
            updated_enumerated_themes.append(theme_info_initial) # Still add it to the list
    
    findings["enumerated_themes"] = updated_enumerated_themes
    # Filter for themes that have vulnerabilities for the separate "vulnerable_themes" list
    findings["vulnerable_themes"] = [t for t in updated_enumerated_themes if t.get("vulnerabilities")]


    for plugin_info_initial in findings["enumerated_plugins"]:
        plugin_slug = plugin_info_initial["name"]
        plugin_version = plugin_info_initial.get("version")
        plugin_data_from_api = {"metadata": {}, "vulnerabilities": []}
        try:
            plugin_data_from_api = vuln_manager.get_plugin_vulnerabilities(plugin_slug, plugin_version)

            plugin_info_initial["metadata"] = plugin_data_from_api.get("metadata", {})
            if not plugin_version and plugin_info_initial["metadata"].get("latest_version"):
                 plugin_info_initial["version"] = plugin_info_initial["metadata"]["latest_version"]
                 plugin_version = plugin_info_initial["version"]
                 print(f"        [i] Updated version for plugin {plugin_slug} to latest known: {plugin_version}")

            if plugin_data_from_api.get("vulnerabilities"):
                msg = f"Found {len(plugin_data_from_api['vulnerabilities'])} potential vulnerabilities for plugin {plugin_slug} (version: {plugin_version or 'Unknown'})."
                print(f"      [+] {msg}")
                details_log.append(msg)
                plugin_info_initial["vulnerabilities"] = plugin_data_from_api["vulnerabilities"]
            else:
                plugin_info_initial["vulnerabilities"] = []

            updated_enumerated_plugins.append(plugin_info_initial)

        except Exception as e:
            err_msg = f"Error during metadata/vulnerability lookup for plugin {plugin_slug}: {e}"
            print(f"      [-] {err_msg}")
            details_log.append(err_msg)
            plugin_info_initial["metadata"]["error"] = err_msg
            plugin_info_initial["vulnerabilities"] = []
            updated_enumerated_plugins.append(plugin_info_initial)

    findings["enumerated_plugins"] = updated_enumerated_plugins
    findings["vulnerable_plugins"] = [p for p in updated_enumerated_plugins if p.get("vulnerabilities")]
    
    findings["status"] = "Completed"
    base_detail = f"Enumerated {num_themes} theme(s) and {num_plugins} plugin(s) from {scanned_page_count} scanned page(s)."
    # Correctly refer to the findings dictionary for vulnerable counts
    if findings.get("vulnerable_themes") or findings.get("vulnerable_plugins"):
        base_detail += f" Found {len(findings.get('vulnerable_themes', []))} theme(s) and {len(findings.get('vulnerable_plugins', []))} plugin(s) with potential vulnerabilities."
    else:
        base_detail += " No vulnerabilities found for enumerated extensions based on available data."
    
    if details_log: # Add any specific error messages from correlation
        base_detail += " Correlation notes: " + " | ".join(details_log[:3]) # Show first few notes
        if len(details_log) > 3: base_detail += " ... (see logs for more)."

    findings["details"] = base_detail
    
    # Update the findings within the larger wp_analyzer structure
    all_wp_analyzer_findings = state.get_module_findings(module_key, {}) # Re-fetch to be safe
    all_wp_analyzer_findings[findings_key] = findings # Update the specific part
    state.update_module_findings(module_key, all_wp_analyzer_findings) # Save the entire wp_analyzer findings
