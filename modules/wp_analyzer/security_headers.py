import requests
import re
from urllib.parse import urljoin
from .utils import make_request, sanitize_filename

# CSP Parser Helper (Simplified)
def _parse_csp(csp_header_value):
    directives = {}
    if not csp_header_value:
        return directives
    parts = csp_header_value.split(';')
    for part in parts:
        part = part.strip()
        if not part:
            continue
        directive_parts = part.split(None, 1) # Split only on the first space
        directive_name = directive_parts[0].lower()
        values = directive_parts[1].split() if len(directive_parts) > 1 else []
        directives[directive_name] = values
    return directives

def _analyze_headers_for_url(url_to_check, state, config, url_label="Target URL"):
    """Analyzes security headers for a specific URL and returns a dictionary of findings."""
    print(f"      Fetching headers from: {url_to_check} ({url_label})")
    response = make_request(url_to_check, config, method="HEAD", timeout=7)
    
    current_url_findings = {
        "url_checked": url_to_check,
        "status": "Error (Request Failed)", # Default status
        "headers_present": {},
        "missing_recommended": [],
        "misconfigured": [],
        "info_leak_headers": {}
    }

    if not response:
        return current_url_findings

    headers = response.headers # CaseInsensitiveDict
    current_url_findings["status"] = "Checked"
    
    # Define checks for common security headers
    # 'value_in_exact' for exact match in a list of allowed values
    # 'value_contains' for checking if a substring is present (useful for HSTS preload)
    # 'value_not_contains' for flagging bad values
    # 'check_func' for custom check logic
    header_checks = {
        "Content-Security-Policy": {"present": True, "severity": "Medium", "remediation": "Implement a strong Content Security Policy (CSP) to mitigate XSS and data injection attacks. Start with default-src 'self'; script-src 'self' 'nonce-XYZ'; object-src 'none'; base-uri 'self'; and expand as needed.", "check_func": _check_csp_details},
        "Strict-Transport-Security": {"present": True, "severity": "Medium", "remediation": "Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS. A common policy is 'max-age=31536000; includeSubDomains; preload'.", "check_func": _check_hsts_details},
        "X-Content-Type-Options": {"present": True, "value_exact": "nosniff", "severity": "Low", "remediation": "Set X-Content-Type-Options to 'nosniff' to prevent browsers from MIME-sniffing a response away from the declared content-type."},
        "X-Frame-Options": {"present": True, "value_in_exact": ["DENY", "SAMEORIGIN"], "severity": "Medium", "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to protect against clickjacking. Consider using CSP frame-ancestors as a more flexible alternative or addition."},
        "Referrer-Policy": {"present": True, "value_in_exact": ["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin"], "severity": "Low", "remediation": "Set a Referrer-Policy (e.g., 'strict-origin-when-cross-origin' or 'no-referrer') to control how much referrer information is sent with requests."},
        "Permissions-Policy": {"present": True, "severity": "Low", "remediation": "Implement Permissions-Policy (formerly Feature-Policy) to control access to browser features (e.g., microphone, camera, geolocation). Example: 'geolocation=(), microphone=()'."},
        "X-XSS-Protection": {"present": False, "value_exact": "0", "severity": "Info", "remediation": "Modern browsers recommend disabling X-XSS-Protection (set to '0') and relying on a strong Content Security Policy. If set to '1' or '1; mode=block', it's an older protection that might have bypasses or introduce self-XSS issues."},
        "Cross-Origin-Opener-Policy": {"present": True, "value_in_exact": ["same-origin", "same-origin-allow-popups", "unsafe-none"], "severity": "Low", "remediation": "Set Cross-Origin-Opener-Policy (COOP) to 'same-origin' or 'same-origin-allow-popups' to protect against cross-origin attacks."},
        "Cross-Origin-Embedder-Policy": {"present": True, "value_in_exact": ["require-corp", "credentialless", "unsafe-none"], "severity": "Low", "remediation": "Set Cross-Origin-Embedder-Policy (COEP) (e.g., 'require-corp') to prevent a document from loading any cross-origin resources that don't explicitly grant the document permission."},
        "Cross-Origin-Resource-Policy": {"present": True, "value_in_exact": ["same-origin", "same-site", "cross-origin"], "severity": "Low", "remediation": "Set Cross-Origin-Resource-Policy (CORP) (e.g., 'same-origin' or 'same-site') to control which cross-origin sites can embed your resources."}
    }

    for header_name, check_details in header_checks.items():
        header_value = headers.get(header_name)
        current_url_findings["headers_present"][header_name] = header_value if header_value else "Not Present"

        if check_details["present"] and not header_value:
            current_url_findings["missing_recommended"].append(header_name)
            # Remediation added globally later if missing on main target
        elif header_value: # Header is present, perform value checks
            if "value_exact" in check_details and header_value.lower().strip() != check_details["value_exact"].lower():
                if not (header_name == "X-XSS-Protection" and not check_details["present"]): # Special handling for X-XSS-Protection '0'
                    current_url_findings["misconfigured"].append({"header": header_name, "value": header_value, "expected": f"Exactly '{check_details['value_exact']}'", "details": "Value does not match recommended."})
            elif "value_in_exact" in check_details and header_value.lower().strip() not in [v.lower() for v in check_details["value_in_exact"]]:
                current_url_findings["misconfigured"].append({"header": header_name, "value": header_value, "expected": f"One of {check_details['value_in_exact']}", "details": "Value not in recommended set."})
            
            if "check_func" in check_details: # Custom check function
                custom_issues = check_details["check_func"](header_name, header_value, state, url_label)
                current_url_findings["misconfigured"].extend(custom_issues)
        elif not check_details["present"] and header_value and header_name == "X-XSS-Protection" and header_value.strip() != '0':
            # X-XSS-Protection is present but not '0' (and check["present"] is False, meaning we prefer it absent or '0')
             current_url_findings["misconfigured"].append({"header": header_name, "value": header_value, "expected": "'0' or not present", "details": "X-XSS-Protection is enabled; modern best practice is often to disable (set to '0') and rely on strong CSP."})


    # Information Leakage Headers
    for leak_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]:
        val = headers.get(leak_header)
        if val:
            current_url_findings["info_leak_headers"][leak_header] = val
            print(f"        [i] Info Leak: {leak_header}: {val} on {url_label}")
            # Remediation added globally later

    return current_url_findings

def _check_csp_details(header_name, header_value, state, url_label):
    issues = []
    parsed_csp = _parse_csp(header_value)
    if not parsed_csp:
        issues.append({"header": header_name, "value": header_value, "expected": "Parseable CSP", "details": "CSP header found but could not be parsed or is empty."})
        return issues

    unsafe_inline = "'unsafe-inline'" in parsed_csp.get("script-src", []) or "'unsafe-inline'" in parsed_csp.get("style-src", []) or \
                    ("'unsafe-inline'" in parsed_csp.get("default-src", []) and not (parsed_csp.get("script-src") or parsed_csp.get("style-src")))
    unsafe_eval = "'unsafe-eval'" in parsed_csp.get("script-src", []) or \
                  ("'unsafe-eval'" in parsed_csp.get("default-src", []) and not parsed_csp.get("script-src"))
    
    if unsafe_inline: issues.append({"header": header_name, "value": header_value, "expected": "No 'unsafe-inline' for scripts/styles without nonces/hashes", "details": "CSP allows 'unsafe-inline', increasing XSS risk."})
    if unsafe_eval: issues.append({"header": header_name, "value": header_value, "expected": "No 'unsafe-eval' for scripts", "details": "CSP allows 'unsafe-eval', increasing XSS risk."})

    for directive in ["default-src", "script-src", "style-src", "img-src", "connect-src", "font-src", "media-src", "frame-src"]:
        if any(src in parsed_csp.get(directive, []) for src in ["*", "data:", "blob:", "filesystem:"]):
            if not (directive == "img-src" and "data:" in parsed_csp.get(directive, [])): # data: for img-src is common
                 issues.append({"header": header_name, "value": header_value, "expected": f"Specific sources for {directive}", "details": f"CSP directive '{directive}' uses overly broad sources like '*' or 'data:'."})
    
    if not parsed_csp.get("default-src"): issues.append({"header": header_name, "value": header_value, "expected": "default-src directive", "details": "CSP missing 'default-src' directive, which can lead to fallback to overly permissive browser defaults."})
    if "object-src" not in parsed_csp or "'none'" not in parsed_csp["object-src"]: issues.append({"header": header_name, "value": header_value, "expected": "object-src 'none'", "details": "CSP 'object-src' should ideally be 'none' to prevent execution of plugins like Flash."})
    if "base-uri" not in parsed_csp or not any(s in ["'self'", "'none'"] for s in parsed_csp["base-uri"]): issues.append({"header": header_name, "value": header_value, "expected": "base-uri 'self' or 'none'", "details": "CSP 'base-uri' not set or too permissive, risk of base tag hijacking."})
    if "frame-ancestors" not in parsed_csp: issues.append({"header": header_name, "value": header_value, "expected": "frame-ancestors directive for clickjacking protection", "details": "CSP missing 'frame-ancestors' directive. X-Frame-Options should be used if CSP is not comprehensive."})
    
    return issues

def _check_hsts_details(header_name, header_value, state, url_label):
    issues = []
    max_age_match = re.search(r"max-age=(\d+)", header_value, re.IGNORECASE)
    min_recommended_max_age = 15552000 # ~6 months
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < min_recommended_max_age:
            issues.append({"header": header_name, "value": header_value, "expected": f"max-age >= {min_recommended_max_age}", "details": f"HSTS max-age ({max_age}) is less than recommended {min_recommended_max_age} seconds."})
    else:
        issues.append({"header": header_name, "value": header_value, "expected": "max-age directive", "details": "HSTS header missing 'max-age' directive."})
    
    if "includesubdomains" not in header_value.lower(): issues.append({"header": header_name, "value": header_value, "expected": "includeSubDomains directive", "details": "HSTS header missing 'includeSubDomains' directive."})
    if "preload" in header_value.lower(): print(f"        [i] HSTS 'preload' directive found on {url_label} (good practice).") # Informational
    return issues


def analyze_security_headers(state, config, target_url):
    """Analyzes the security headers of the target URL and wp-login.php."""
    module_key = "wp_analyzer"
    findings_key = "security_headers_analysis" # New key for enhanced findings
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details_summary": "Analyzing security headers...",
        "target_url_analysis": {},
        "login_page_analysis": {}
    })
    print("    [i] Enhanced Security Header Analysis...")

    # Analyze main target URL
    findings["target_url_analysis"] = _analyze_headers_for_url(target_url, state, config, "Target URL")

    # Analyze wp-login.php
    login_url = urljoin(target_url, "wp-login.php")
    # Check if login page is accessible before analyzing its headers (use findings from login_page.py if available)
    login_page_info = state.get_module_findings(module_key, {}).get("login_page_analysis", {})
    if login_page_info.get("standard_login_accessible") is True or login_page_info.get("final_login_page_url"):
        effective_login_url = login_page_info.get("final_login_page_url", login_url)
        findings["login_page_analysis"] = _analyze_headers_for_url(effective_login_url, state, config, "Login Page")
    else:
        print(f"      Skipping header analysis for login page as it was not found accessible by login_page.py module.")
        findings["login_page_analysis"] = {"url_checked": login_url, "status": "Skipped (Login Page Not Accessible)", "headers_present": {}}


    # Consolidate and add global remediations based on target_url_analysis
    # (Remediations for login_page specific issues could be added too if different)
    target_analysis = findings["target_url_analysis"]
    if target_analysis.get("status") == "Checked":
        for header_name in target_analysis.get("missing_recommended", []):
            check_def = header_checks.get(header_name, {}) # Re-access check_def for remediation
            state.add_remediation_suggestion(f"sec_header_missing_{sanitize_filename(header_name.lower())}", {
                "source": "WP Analyzer (Security Headers)", 
                "description": f"Recommended security header '{header_name}' is missing from the main site response.", 
                "severity": check_def.get("severity", "Low"), 
                "remediation": check_def.get("remediation", "Implement this security header according to best practices.")
            })
        for misconfig in target_analysis.get("misconfigured", []):
            header_name = misconfig["header"]
            check_def = header_checks.get(header_name, {})
            state.add_remediation_suggestion(f"sec_header_misconfigured_{sanitize_filename(header_name.lower())}", {
                "source": "WP Analyzer (Security Headers)", 
                "description": f"Security header '{header_name}' is present but potentially misconfigured. Value: '{misconfig['value']}'. Expected: '{misconfig['expected']}'. Details: {misconfig.get('details', '')}",
                "severity": check_def.get("severity", "Low"), 
                "remediation": check_def.get("remediation", f"Review and correct the configuration of the '{header_name}' header.")
            })
        for leak_header, val in target_analysis.get("info_leak_headers", {}).items():
            state.add_remediation_suggestion(f"sec_header_info_leak_{sanitize_filename(leak_header.lower())}", {
                "source": "WP Analyzer (Security Headers)", 
                "description": f"Informational header '{leak_header}: {val}' found, potentially revealing server/technology details.",
                "severity": "Low", 
                "remediation": f"Consider removing or obscuring the '{leak_header}' header via server configuration to reduce information leakage."
            })
        
        num_missing = len(target_analysis.get("missing_recommended", []))
        num_misconfigured = len(target_analysis.get("misconfigured", []))
        if num_missing == 0 and num_misconfigured == 0:
            findings["details_summary"] = "Essential security headers on target URL appear to be present and reasonably configured."
        else:
            findings["details_summary"] = f"Target URL: {num_missing} recommended headers missing, {num_misconfigured} potentially misconfigured."
            if num_missing > 0: state.add_summary_point(f"Missing {num_missing} security headers on main target.")

    else: # Error fetching target URL headers
        findings["details_summary"] = f"Could not analyze security headers for target URL: {target_analysis.get('status')}"

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Enhanced Security Header analysis finished. Summary: {findings['details_summary']}")

# Need to define header_checks globally or pass it to _analyze_headers_for_url if it's to be used there for remediation text.
# For now, remediation text is generic if not found in _analyze_headers_for_url's local scope.
# Let's define it globally for access in remediation generation.
header_checks = {
    "Content-Security-Policy": {"present": True, "severity": "Medium", "remediation": "Implement a strong Content Security Policy (CSP) to mitigate XSS and data injection attacks. Start with default-src 'self'; script-src 'self' 'nonce-XYZ'; object-src 'none'; base-uri 'self'; and expand as needed.", "check_func": _check_csp_details},
    "Strict-Transport-Security": {"present": True, "severity": "Medium", "remediation": "Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS. A common policy is 'max-age=31536000; includeSubDomains; preload'.", "check_func": _check_hsts_details},
    "X-Content-Type-Options": {"present": True, "value_exact": "nosniff", "severity": "Low", "remediation": "Set X-Content-Type-Options to 'nosniff' to prevent browsers from MIME-sniffing a response away from the declared content-type."},
    "X-Frame-Options": {"present": True, "value_in_exact": ["DENY", "SAMEORIGIN"], "severity": "Medium", "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to protect against clickjacking. Consider using CSP frame-ancestors as a more flexible alternative or addition."},
    "Referrer-Policy": {"present": True, "value_in_exact": ["no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin"], "severity": "Low", "remediation": "Set a Referrer-Policy (e.g., 'strict-origin-when-cross-origin' or 'no-referrer') to control how much referrer information is sent with requests."},
    "Permissions-Policy": {"present": True, "severity": "Low", "remediation": "Implement Permissions-Policy (formerly Feature-Policy) to control access to browser features (e.g., microphone, camera, geolocation). Example: 'geolocation=(), microphone=()'."},
    "X-XSS-Protection": {"present": False, "value_exact": "0", "severity": "Info", "remediation": "Modern browsers recommend disabling X-XSS-Protection (set to '0') and relying on a strong Content Security Policy. If set to '1' or '1; mode=block', it's an older protection that might have bypasses or introduce self-XSS issues."},
    "Cross-Origin-Opener-Policy": {"present": True, "value_in_exact": ["same-origin", "same-origin-allow-popups", "unsafe-none"], "severity": "Low", "remediation": "Set Cross-Origin-Opener-Policy (COOP) to 'same-origin' or 'same-origin-allow-popups' to protect against cross-origin attacks."},
    "Cross-Origin-Embedder-Policy": {"present": True, "value_in_exact": ["require-corp", "credentialless", "unsafe-none"], "severity": "Low", "remediation": "Set Cross-Origin-Embedder-Policy (COEP) (e.g., 'require-corp') to prevent a document from loading any cross-origin resources that don't explicitly grant the document permission."},
    "Cross-Origin-Resource-Policy": {"present": True, "value_in_exact": ["same-origin", "same-site", "cross-origin"], "severity": "Low", "remediation": "Set Cross-Origin-Resource-Policy (CORP) (e.g., 'same-origin' or 'same-site') to control which cross-origin sites can embed your resources."}
}
