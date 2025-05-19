import requests # Keep requests import if needed for type hints or direct use, though make_request handles it
from .utils import make_request # Import the helper function

def analyze_security_headers(state, config, target_url):
    """Analyzes the security headers of the target URL."""
    module_key = "wp_analyzer"
    # Get the current findings for this specific sub-module, or initialize if not present
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "security_headers" not in analyzer_findings:
        analyzer_findings["security_headers"] = {"status": "Running", "details": {}}
    sec_headers_details = analyzer_findings["security_headers"]

    print(f"    Fetching headers from: {target_url}")
    # Use the imported make_request function
    response = make_request(target_url, config, method="HEAD")

    if not response:
        sec_headers_details["status"] = "Error (Request Failed)"
    else:
        headers = response.headers
        sec_headers_details["status"] = "Checked"
        missing_headers = []
        present_headers = {}
        # Define checks for common security headers
        checks = {
            "Content-Security-Policy": {"present": True, "severity": "Medium", "remediation": "Implement a strong Content Security Policy to mitigate XSS and data injection attacks."},
            "Strict-Transport-Security": {"present": True, "severity": "Medium", "remediation": "Implement HSTS to enforce HTTPS connections."},
            "X-Content-Type-Options": {"present": True, "value": "nosniff", "severity": "Low", "remediation": "Set X-Content-Type-Options to 'nosniff' to prevent MIME-sniffing attacks."},
            "X-Frame-Options": {"present": True, "value_in": ["DENY", "SAMEORIGIN"], "severity": "Medium", "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to protect against clickjacking."},
            "Referrer-Policy": {"present": True, "severity": "Low", "remediation": "Set a Referrer-Policy (e.g., 'strict-origin-when-cross-origin', 'no-referrer') to control referrer information."},
            "Permissions-Policy": {"present": True, "severity": "Low", "remediation": "Implement Permissions-Policy (formerly Feature-Policy) to control browser feature access."},
            # X-XSS-Protection is often recommended to be disabled ('0') with strong CSP. Check if present and not '0'.
            "X-XSS-Protection": {"present": False, "value": "0", "severity": "Info", "remediation": "Modern browsers often recommend disabling X-XSS-Protection (set to '0') in favor of strong CSP. If set to '1; mode=block', it's an older protection mechanism."}
        }

        for header, check in checks.items():
            header_val = headers.get(header)
            present_headers[header] = header_val if header_val else "Not Present"

            # Check if header should be present but isn't
            if check["present"] and not header_val:
                missing_headers.append(header)
                state.add_remediation_suggestion(f"sec_header_missing_{header.lower()}", {"source": "WP Analyzer", "description": f"Security header '{header}' is missing.", "severity": check["severity"], "remediation": check["remediation"]})
            # Check if header has a specific required value
            elif "value" in check and header_val and header_val.lower().strip() != check["value"].lower():
                 # Special case for X-XSS-Protection: if it's present but not '0', flag it unless check["present"] is True (which it isn't here)
                 if header == "X-XSS-Protection":
                     state.add_remediation_suggestion(f"sec_header_xss_protection_enabled", {"source": "WP Analyzer", "description": f"Security header '{header}' is set to '{header_val}'. Modern best practice is often to set it to '0' and rely on CSP.", "severity": check["severity"], "remediation": check["remediation"]})
                 else:
                     state.add_remediation_suggestion(f"sec_header_incorrect_{header.lower()}", {"source": "WP Analyzer", "description": f"Security header '{header}' has value '{header_val}' but expected '{check['value']}'.", "severity": check["severity"], "remediation": check["remediation"]})
            # Check if header value is one of the allowed values
            elif "value_in" in check and header_val and not any(v.lower() in header_val.lower() for v in check["value_in"]):
                state.add_remediation_suggestion(f"sec_header_bad_value_{header.lower()}", {"source": "WP Analyzer", "description": f"Security header '{header}' has value '{header_val}' not in recommended values {check['value_in']}.", "severity": check["severity"], "remediation": check["remediation"]})

        sec_headers_details["details"] = present_headers
        if missing_headers:
            print(f"    [!] Missing recommended security headers: {', '.join(missing_headers)}")
            sec_headers_details["missing"] = missing_headers
            state.add_summary_point(f"Missing {len(missing_headers)} security headers.")
        else:
            print("    [+] Essential security headers checked appear to be present or configured.")

        # Check for information leakage headers
        server_banner = headers.get("Server")
        x_powered_by = headers.get("X-Powered-By")
        if server_banner:
            print(f"    [i] Server Banner: {server_banner}")
            sec_headers_details["details"]["Server_Banner"] = server_banner
            state.add_remediation_suggestion("server_banner_leak", {"source": "WP Analyzer", "description": f"Server banner '{server_banner}' may reveal specific software versions.", "severity": "Low", "remediation": "Minimize server banner information via server configuration."})
        if x_powered_by:
            print(f"    [i] X-Powered-By: {x_powered_by}")
            sec_headers_details["details"]["X_Powered_By"] = x_powered_by
            state.add_remediation_suggestion("x_powered_by_leak", {"source": "WP Analyzer", "description": f"X-Powered-By header '{x_powered_by}' reveals underlying technology.", "severity": "Low", "remediation": "Remove or obscure the X-Powered-By header."})

    # Update the specific sub-key within the module's findings
    analyzer_findings["security_headers"] = sec_headers_details
    state.update_module_findings(module_key, analyzer_findings)
