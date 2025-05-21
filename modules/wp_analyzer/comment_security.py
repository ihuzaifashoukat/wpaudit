# Module for WordPress Comment Security Analysis
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from .utils import make_request # Assuming a utility for requests exists

def find_post_with_comments(state, config, target_url):
    """Attempts to find a URL that likely has comments enabled."""
    # Try homepage first
    print("      Checking homepage for comment form...")
    response = make_request(target_url, config, method="GET")
    if response and response.status_code == 200:
        if '<form action="{}/wp-comments-post.php"'.format(target_url.rstrip('/')) in response.text or 'id="commentform"' in response.text:
            print("      Found comment form on homepage.")
            return target_url, response.text

    # If not on homepage, try finding a post via RSS feed (common pattern)
    print("      Checking feed for a recent post URL...")
    feed_url = urljoin(target_url, 'feed/')
    feed_response = make_request(feed_url, config, method="GET")
    if feed_response and feed_response.status_code == 200:
        # Look for the first <link> tag within an <item>
        soup_feed = BeautifulSoup(feed_response.text, 'xml') # Use xml parser for feed
        first_item = soup_feed.find('item')
        if first_item:
            post_link_tag = first_item.find('link')
            if post_link_tag and post_link_tag.text:
                post_url = post_link_tag.text
                print(f"      Found potential post URL from feed: {post_url}. Checking it for comments...")
                post_response = make_request(post_url, config, method="GET")
                if post_response and post_response.status_code == 200:
                     if '<form action="{}/wp-comments-post.php"'.format(target_url.rstrip('/')) in post_response.text or 'id="commentform"' in post_response.text:
                         print(f"      Found comment form on post: {post_url}")
                         return post_url, post_response.text
                     else:
                         print(f"      No comment form found on post: {post_url}")
                else:
                    print(f"      Failed to fetch post URL {post_url} (Status: {post_response.status_code if post_response else 'N/A'})")
            else:
                 print("      Could not find a <link> tag in the first feed item.")
        else:
            print("      Could not find an <item> in the feed.")
    else:
        print(f"      Failed to fetch feed {feed_url} (Status: {feed_response.status_code if feed_response else 'N/A'})")

    print("      Could not find a page with an obvious comment form.")
    return None, None # Could not find a suitable page/HTML

def analyze_comment_security(state, config, target_url):
    """
    Analyzes comment form settings, potential spam protection, and related security aspects.
    Updates the state with findings.
    """
    module_key = "wp_analyzer"
    findings_key = "comment_security"

    all_wp_analyzer_findings = state.get_module_findings(module_key, {})
    findings = all_wp_analyzer_findings.get(findings_key, {})
    if not findings: # Initialize with default structure
        findings = {
            "status": "Not Run",
            "details": "Analyzing comment security aspects.",
            "comments_enabled_on_checked_page": None,
            "checked_page_url": None,
            "spam_protection_hints": [],
            "comment_author_link_rel_attributes": {"nofollow_found": False, "ugc_found": False, "other_rel_values": []},
            "moderation_hint": None,
            "wp_comments_post_php_status": {"accessible": None, "http_auth": False, "status_code": None},
            "potential_vulnerabilities": []
        }

    findings["status"] = "Running"
    # Ensure sub-dictionaries and lists are initialized
    if "spam_protection_hints" not in findings:
        findings["spam_protection_hints"] = []
    if "comment_author_link_rel_attributes" not in findings:
        findings["comment_author_link_rel_attributes"] = {"nofollow_found": False, "ugc_found": False, "other_rel_values": []}
    if "wp_comments_post_php_status" not in findings:
        findings["wp_comments_post_php_status"] = {"accessible": None, "http_auth": False, "status_code": None}
    if "potential_vulnerabilities" not in findings:
        findings["potential_vulnerabilities"] = []

    all_wp_analyzer_findings[findings_key] = findings
    state.update_module_findings(module_key, all_wp_analyzer_findings) # Save initial state

    print("    [i] Analyzing Comment Security...")

    page_url_with_form, page_html_with_form = find_post_with_comments(state, config, target_url)

    if not page_html_with_form:
        findings["status"] = "Completed"
        findings["details"] = "Could not find a page with a comment form to analyze."
        all_wp_analyzer_findings = state.get_module_findings(module_key, {}) # Re-fetch
        all_wp_analyzer_findings[findings_key] = findings
        state.update_module_findings(module_key, all_wp_analyzer_findings)
        print("    [-] Comment security analysis skipped: No comment form found.")
        return

    findings["checked_page_url"] = page_url_with_form
    findings["comments_enabled_on_checked_page"] = True

    try:
        soup = BeautifulSoup(page_html_with_form, 'lxml')
        comment_form = soup.find('form', id='commentform') or soup.find('form', action=re.compile(r'wp-comments-post\.php$'))

        if not comment_form:
            findings["comments_enabled_on_checked_page"] = False # Should have been caught by find_post_with_comments
            findings["details"] = "Comment form initially indicated, but could not be parsed from fetched HTML."
            print("      [-] Error: Comment form tag not found in fetched HTML despite initial indication.")
        else:
            print("      Analyzing comment form and page HTML...")
            form_html_lower = str(comment_form).lower() # For form specific checks
            page_html_lower = page_html_with_form.lower() # For page-wide checks like moderation messages

            # Spam Protection Hints
            spam_hints = []
            if 'name="ak_js"' in form_html_lower or 'id="akismet_comment_form"' in form_html_lower or 'class="akismet_hidden_field"' in form_html_lower:
                spam_hints.append("Akismet")
            if 'name="captcha_code"' in form_html_lower or 'id="captcha_image"' in form_html_lower or \
               'class="g-recaptcha"' in form_html_lower or 'class="cf-turnstile"' in form_html_lower or \
               'hcaptcha' in form_html_lower:
                spam_hints.append("CAPTCHA/Challenge")
            if re.search(r'input\s+[^>]*type=["\']hidden["\'][^>]*name=["\'][^"\']*(?:honeypot|hp|bot)[^"\']*["\']', form_html_lower):
                spam_hints.append("Honeypot")
            findings["spam_protection_hints"] = list(set(spam_hints))
            if spam_hints: print(f"        [+] Spam protection hints: {', '.join(spam_hints)}")
            else: print("        [i] No obvious spam protection hints in form HTML.")

            # Comment Author Link `rel` attributes (from existing comments on the page)
            # Look for typical comment list structures
            comment_list = soup.find('ol', class_=re.compile(r'commentlist|comment-list')) or \
                           soup.find('ul', class_=re.compile(r'commentlist|comment-list'))
            if comment_list:
                author_links = comment_list.find_all('a', class_=re.compile(r'comment-author-link|url'), rel=True)
                if not author_links: # Fallback if specific classes not found, check any link within comment metadata
                    author_links = comment_list.find_all('a', rel=True) # Broader check

                rels_found = set()
                for link in author_links:
                    rel_values = link.get('rel', [])
                    for r_val in rel_values: rels_found.add(r_val.lower())
                
                if 'nofollow' in rels_found: findings["comment_author_link_rel_attributes"]["nofollow_found"] = True
                if 'ugc' in rels_found: findings["comment_author_link_rel_attributes"]["ugc_found"] = True
                findings["comment_author_link_rel_attributes"]["other_rel_values"] = [r for r in rels_found if r not in ['nofollow', 'ugc']]
                print(f"        [i] Comment author link rel attributes found: nofollow={findings['comment_author_link_rel_attributes']['nofollow_found']}, ugc={findings['comment_author_link_rel_attributes']['ugc_found']}, other={findings['comment_author_link_rel_attributes']['other_rel_values']}")
            else:
                print("        [i] Could not find a typical comment list to check author link rel attributes.")


            # Moderation Hint
            moderation_keywords = ["comment is awaiting moderation", "your comment will be visible after approval"]
            if any(kw in page_html_lower for kw in moderation_keywords):
                findings["moderation_hint"] = "Awaiting moderation message found."
                print("        [+] 'Awaiting moderation' message hint found on page.")
            else:
                findings["moderation_hint"] = "No explicit 'awaiting moderation' message found."
                print("        [i] No explicit 'awaiting moderation' message found on page.")


        # Check wp-comments-post.php accessibility and protection
        wp_comments_post_url = urljoin(target_url, "wp-comments-post.php")
        print(f"      Checking accessibility of {wp_comments_post_url}...")
        try:
            # Try a GET request first; usually expects POST but can reveal protection
            response_wcp = make_request(wp_comments_post_url, config, method="GET", allow_redirects=False, timeout=5)
            if response_wcp:
                findings["wp_comments_post_php_status"]["status_code"] = response_wcp.status_code
                if response_wcp.status_code == 401:
                    findings["wp_comments_post_php_status"]["http_auth"] = True
                    findings["wp_comments_post_php_status"]["accessible"] = True # Path exists but protected
                    print(f"        [+] HTTP Authentication detected on {wp_comments_post_url}.")
                elif response_wcp.status_code == 405: # Method Not Allowed (common for GET to this endpoint)
                    findings["wp_comments_post_php_status"]["accessible"] = True # Endpoint exists
                    print(f"        [i] {wp_comments_post_url} returned 405 Method Not Allowed (expected for GET).")
                elif 200 <= response_wcp.status_code < 400: # Should not be 200 for GET usually
                    findings["wp_comments_post_php_status"]["accessible"] = True
                    print(f"        [?] {wp_comments_post_url} returned {response_wcp.status_code} for GET request.")
                else:
                    findings["wp_comments_post_php_status"]["accessible"] = False
                    print(f"        [-] {wp_comments_post_url} not accessible or blocked (Status: {response_wcp.status_code}).")
            else:
                findings["wp_comments_post_php_status"]["accessible"] = "Error (No Response)"
                print(f"        [-] Request to {wp_comments_post_url} failed.")
        except Exception as e_wcp:
            print(f"        [-] Error checking {wp_comments_post_url}: {e_wcp}")
            findings["wp_comments_post_php_status"]["accessible"] = f"Error ({type(e_wcp).__name__})"


    except Exception as e_main:
        findings["status"] = "Error"
        findings["details"] = f"Error during comment security analysis: {e_main}"
        print(f"      [-] Main error in comment security analysis: {e_main}")

    # Consolidate details for reporting
    summary_parts = []
    if findings["comments_enabled_on_checked_page"]:
        summary_parts.append(f"Comments appear enabled on {findings['checked_page_url']}.")
        if findings["spam_protection_hints"]:
            summary_parts.append(f"Spam protection hints: {', '.join(findings['spam_protection_hints'])}.")
        else:
            summary_parts.append("No obvious spam protection hints found in form.")
            state.add_remediation_suggestion("comment_spam_protection_v2", {
                "source": "WP Analyzer (Comment Security)",
                "description": "No common spam protection mechanisms (like Akismet, CAPTCHA, or honeypots) were detected in the comment form HTML.",
                "severity": "Low",
                "remediation": "Ensure adequate comment spam protection is configured (e.g., using Akismet or a CAPTCHA plugin) to prevent spam and potential abuse."
            })
        if findings["moderation_hint"] == "Awaiting moderation message found.":
            summary_parts.append("Comments likely require moderation.")
        
        rel_attr = findings["comment_author_link_rel_attributes"]
        if not rel_attr["nofollow_found"] or not rel_attr["ugc_found"]:
            summary_parts.append("Comment author links may be missing 'nofollow' or 'ugc' attributes.")
            state.add_remediation_suggestion("comment_author_link_rel", {
                "source": "WP Analyzer (Comment Security)",
                "description": "Comment author links might be missing 'rel=\"nofollow\"' or 'rel=\"ugc\"' attributes, which is a best practice for SEO and indicating user-generated content.",
                "severity": "Info",
                "remediation": "Ensure WordPress or your theme correctly adds 'rel=\"nofollow ugc\"' (or at least 'nofollow') to comment author links."
            })

    if findings["wp_comments_post_php_status"]["http_auth"]:
        summary_parts.append("wp-comments-post.php is protected by HTTP Authentication.")
    elif findings["wp_comments_post_php_status"]["accessible"] is False:
         summary_parts.append(f"wp-comments-post.php was not accessible or blocked (Status: {findings['wp_comments_post_php_status']['status_code']}).")


    findings["details"] = " ".join(summary_parts) if summary_parts else "Comment security checks performed. See specific findings."
    findings["status"] = "Completed"
    all_wp_analyzer_findings = state.get_module_findings(module_key, {}) # Re-fetch
    all_wp_analyzer_findings[findings_key] = findings
    state.update_module_findings(module_key, all_wp_analyzer_findings)
    print(f"    [+] Comment security analysis finished. Details: {findings['details']}")
