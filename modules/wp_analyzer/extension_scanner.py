# Module for WordPress Theme and Plugin Enumeration and Vulnerability Scanning
import requests
import re
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup # Ensure this is imported
from .utils import make_request

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
        tags = soup.find_all(['link', 'script'])
        for tag in tags:
            url = tag.get('href') or tag.get('src')
            if not url:
                continue

            absolute_url = urljoin(target_url, url)
            version_from_url = _extract_version_from_url(absolute_url)

            theme_match = THEME_PATTERN.search(absolute_url)
            if theme_match:
                theme_slug = theme_match.group(1)
                if theme_slug not in found_themes or (version_from_url and not found_themes[theme_slug].get("version")):
                    found_themes.setdefault(theme_slug, {}).update({"version_from_url": version_from_url, "source_urls": set()})
                    found_themes[theme_slug]["source_urls"].add(absolute_url)
                elif theme_slug in found_themes:
                     found_themes[theme_slug]["source_urls"].add(absolute_url)


            plugin_match = PLUGIN_PATTERN.search(absolute_url)
            if plugin_match:
                plugin_slug = plugin_match.group(1)
                if plugin_slug not in found_plugins or (version_from_url and not found_plugins[plugin_slug].get("version")):
                    found_plugins.setdefault(plugin_slug, {}).update({"version_from_url": version_from_url, "source_urls": set()})
                    found_plugins[plugin_slug]["source_urls"].add(absolute_url)
                elif plugin_slug in found_plugins:
                    found_plugins[plugin_slug]["source_urls"].add(absolute_url)

    except Exception as e:
        print(f"      [-] Error parsing HTML for extensions: {e}")

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
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Enumerating themes and plugins...",
        "enumerated_themes": [],
        "enumerated_plugins": [],
        "vulnerable_themes": [],
        "vulnerable_plugins": []
    })

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

    # Format findings
    findings["enumerated_themes"] = [{"name": slug, "version": data.get("version") or data.get("version_from_url"), "details": f"Sources: {len(data['source_urls'])} URL(s)"} for slug, data in found_themes.items()]
    findings["enumerated_plugins"] = [{"name": slug, "version": data.get("version") or data.get("version_from_url"), "details": f"Sources: {len(data['source_urls'])} URL(s)"} for slug, data in found_plugins.items()]

    num_themes = len(findings["enumerated_themes"])
    num_plugins = len(findings["enumerated_plugins"])
    findings["status"] = "Completed"
    findings["details"] = f"Enumerated {num_themes} theme(s) and {num_plugins} plugin(s) from {scanned_page_count} scanned page(s). Vulnerability check NOT implemented."
    print(f"    [+] Extension enumeration complete: Found {num_themes} theme(s), {num_plugins} plugin(s).")
    print("    [!] Vulnerability correlation against database is NOT IMPLEMENTED in this version.")

    state.update_specific_finding(module_key, findings_key, findings)
