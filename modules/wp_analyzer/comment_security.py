# Module for WordPress Comment Security Analysis
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from core.utils import make_request # Assuming a utility for requests exists

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
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Analyzing comment form security.",
        "comments_enabled_on_checked_page": None, # True/False/None
        "checked_page_url": None,
        "spam_protection_hints": [], # e.g., ["Akismet detected", "Captcha detected"]
        "potential_vulnerabilities": [] # e.g., Unfiltered HTML in comments (checked by XSS module ideally)
    })

    page_url, page_html = find_post_with_comments(state, config, target_url)

    if not page_html:
        findings["status"] = "Completed"
        findings["details"] = "Could not find a page with a comment form to analyze."
        state.update_specific_finding(module_key, findings_key, findings)
        print("    [-] Comment security analysis skipped: No comment form found.")
        return

    findings["checked_page_url"] = page_url
    findings["comments_enabled_on_checked_page"] = True # Form was found

    try:
        soup = BeautifulSoup(page_html, 'lxml')
        comment_form = soup.find('form', id='commentform') or soup.find('form', action=re.compile(r'wp-comments-post\.php$'))

        if not comment_form:
             # This case should ideally be caught by find_post_with_comments, but double-check
             findings["comments_enabled_on_checked_page"] = False
             findings["details"] = "Comment form identified initially, but could not be parsed."
             print("      [-] Error parsing comment form.")
        else:
            print("      Analyzing comment form HTML...")
            form_html = str(comment_form).lower()

            # Check for common spam protection hints
            spam_hints = []
            # Akismet (often adds specific hidden fields or classes)
            if 'name="ak_js"' in form_html or 'id="akismet_comment_form"' in form_html or 'class="akismet_hidden_field"' in form_html:
                spam_hints.append("Akismet")
                print("        [+] Akismet hint detected.")
            # Basic CAPTCHA (look for common input names or image tags)
            if 'name="captcha_code"' in form_html or 'id="captcha_image"' in form_html or 'class="g-recaptcha"' in form_html or 'class="cf-turnstile"' in form_html:
                 spam_hints.append("CAPTCHA/Turnstile")
                 print("        [+] CAPTCHA/Turnstile hint detected.")
            # Honeypot fields (look for hidden fields designed to trap bots)
            if re.search(r'input\s+[^>]*type=["\']hidden["\'][^>]*name=["\'][^"\']*(?:honeypot|hp|bot)[^"\']*["\']', form_html):
                 spam_hints.append("Honeypot")
                 print("        [+] Honeypot field hint detected.")

            findings["spam_protection_hints"] = list(set(spam_hints)) # Unique hints

            # Note: Checking for unfiltered HTML submission is complex and better handled by XSS tests.
            # We can add an informational note if no obvious spam protection is found.
            if not spam_hints:
                 findings["details"] = "Comment form found, but no obvious spam protection (Akismet, CAPTCHA, Honeypot) detected in the form HTML. Manual verification recommended."
                 print("      [?] No obvious spam protection hints found in comment form.")
                 state.add_remediation_suggestion("comment_spam_protection", {
                     "source": "WP Analyzer",
                     "description": "No common spam protection mechanisms (like Akismet, CAPTCHA, or honeypots) were detected in the comment form HTML.",
                     "severity": "Low",
                     "remediation": "Ensure adequate comment spam protection is configured (e.g., using Akismet or a CAPTCHA plugin) to prevent spam and potential abuse."
                 })
            else:
                 findings["details"] = f"Comment form found on {page_url}. Detected hints of: {', '.join(findings['spam_protection_hints'])}."

    except Exception as e:
        findings["status"] = "Error"
        findings["details"] = f"Error during comment form HTML parsing: {e}"
        print(f"      [-] Error parsing comment form: {e}")


    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Comment security analysis finished. Details: {findings['details']}")
