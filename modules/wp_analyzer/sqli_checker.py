# Module for Contextual WordPress SQLi Checks
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus
from core.utils import make_request
import difflib # For comparing response bodies (optional, can be heavy)

# Common SQL error patterns (non-exhaustive)
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning: mysql_", re.IGNORECASE),
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"SQL command not properly ended", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE),
    re.compile(r"Oracle ODBC Driver", re.IGNORECASE),
    re.compile(r"supplied argument is not a valid MySQL result resource", re.IGNORECASE),
    re.compile(r"PostgreSQL query failed", re.IGNORECASE),
    re.compile(r"Syntax error near", re.IGNORECASE),
    re.compile(r"ORA-\d{5}:", re.IGNORECASE) # Oracle errors
]

# Basic SQLi test characters for error-based
SQLI_ERROR_TEST_CHARS = ["'", "\"", "`", "-- ", "#", ";", "\\"]

# Basic Boolean-based SQLi payloads (very simplified)
# Payloads should be URL-encoded when used in query strings.
# The structure is: (payload_true, payload_false)
SQLI_BOOLEAN_PAYLOADS = {
    "numeric_context": [ # Assuming param value is numeric
        (" OR 1=1", " OR 1=2"),
        (" AND 1=1", " AND 1=2"),
        # (" UNION SELECT NULL-- ", " UNION SELECT 1-- ") # More advanced
    ],
    "string_context_single_quote": [ # Assuming param value is enclosed in single quotes
        ("' OR '1'='1", "' OR '1'='2"),
        ("' AND '1'='1", "' AND '1'='2"),
        # ("' UNION SELECT NULL-- ", "' UNION SELECT 1-- ")
    ],
    "string_context_double_quote": [ # Assuming param value is enclosed in double quotes
        ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
        ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ]
}
# Note: Comments like -- or # might need a space or newline depending on DB.
# For URL encoding, # becomes %23. Space becomes %20 or +.

def _test_sqli_payload(url, config, expected_content_pattern=None, compare_to_response=None):
    """Helper to test a single SQLi payload and check for errors or content differences."""
    try:
        response = make_request(url, config, method="GET", timeout=7)
        if not response or not response.text:
            return None, "No response or empty response"

        # Check for SQL errors
        for pattern in SQL_ERROR_PATTERNS:
            if pattern.search(response.text):
                return response, f"SQL error pattern matched: {pattern.pattern}"
        
        # Check for expected content (for some boolean-based true conditions)
        if expected_content_pattern and expected_content_pattern.search(response.text):
            return response, "Expected content pattern matched (boolean true)"

        # Compare to another response (for boolean-based true vs false)
        if compare_to_response and compare_to_response.text:
            # Simple length comparison (heuristic)
            # A more robust diff would use difflib, but can be slow for large pages.
            len_current = len(response.text)
            len_compare = len(compare_to_response.text)
            # Arbitrary threshold for "significant" difference, adjust as needed
            if abs(len_current - len_compare) > max(100, 0.1 * len_compare): # e.g. >100 bytes or >10% difference
                return response, f"Significant content length difference (current: {len_current}, compared: {len_compare})"
            
            # Optional: More detailed diff (can be slow)
            # diff = difflib.unified_diff(
            #     compare_to_response.text.splitlines(),
            #     response.text.splitlines(),
            #     lineterm=''
            # )
            # diff_lines = list(diff)
            # if len(diff_lines) > 5: # Arbitrary number of differing lines
            #     return response, f"Significant content difference detected ({len(diff_lines)} differing lines)"

        return response, None # No specific SQLi indicator found by this check
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except Exception as e:
        return None, f"Error during request: {e}"


def analyze_sqli(state, config, target_url):
    """
    Performs enhanced heuristic checks for potential SQLi vulnerabilities.
    Includes error-based checks and basic boolean-based differential analysis.
    This is NOT a comprehensive SQLi scanner. Use SQLMap for thorough testing.
    """
    module_key = "wp_analyzer"
    findings_key = "contextual_sqli"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running",
        "details": "Performing enhanced heuristic SQLi checks...",
        "potential_error_based_sqli": [],
        "potential_boolean_based_sqli": [],
        "recommendation": "Use dedicated SQLi tools (like SQLMap) for comprehensive analysis."
    })

    print("    [i] Performing enhanced SQLi heuristic checks (error-based and basic boolean-based)...")
    
    parsed_target_url = urlparse(target_url)
    original_query_params = parse_qs(parsed_target_url.query)
    
    error_based_points = []
    boolean_based_points = []

    if not original_query_params:
        findings["details"] = "No query parameters in target URL to test for SQLi."
        findings["status"] = "Completed"
        state.update_specific_finding(module_key, findings_key, findings)
        print("      [i] No query parameters in target URL for SQLi checks.")
        return

    # Get original response for comparison in boolean tests
    original_response, _ = _test_sqli_payload(target_url, config)
    if not original_response:
        print(f"      [-] Could not fetch original page {target_url}. Boolean-based checks might be less reliable.")

    print(f"      Checking {len(original_query_params)} parameter(s) in URL: {target_url}")
    for param, values in original_query_params.items():
        original_value = values[0]
        param_found_sqli = False

        # 1. Error-based SQLi checks
        print(f"        Testing error-based SQLi for param '{param}'...")
        for test_char in SQLI_ERROR_TEST_CHARS:
            if param_found_sqli: break # Skip if already found for this param by another method

            # Ensure original_value is a string for concatenation
            str_original_value = str(original_value) if original_value is not None else ""
            payload_val = str_original_value + test_char
            
            modified_params = {k: v[0] for k, v in original_query_params.items()}
            modified_params[param] = payload_val
            test_query_string = urlencode(modified_params)
            test_url = parsed_target_url._replace(query=test_query_string).geturl()
            
            _, error_detail = _test_sqli_payload(test_url, config)
            if error_detail and "SQL error pattern matched" in error_detail:
                point_info = {
                    "url": test_url, "parameter": param, "payload_used": payload_val,
                    "type": "Error-based", "observation": error_detail
                }
                error_based_points.append(point_info)
                param_found_sqli = True
                print(f"          [!!!] Potential Error-based SQLi for param '{param}' with char '{test_char}'")
                break # Found error for this param, move to next error char or boolean test

        # 2. Boolean-based SQLi checks (only if no error-based found for this param yet)
        if not param_found_sqli:
            print(f"        Testing boolean-based SQLi for param '{param}'...")
            for context_type, payload_pairs in SQLI_BOOLEAN_PAYLOADS.items():
                if param_found_sqli: break
                for true_payload_suffix, false_payload_suffix in payload_pairs:
                    # Construct true URL
                    str_original_value = str(original_value) if original_value is not None else ""
                    payload_true_val = str_original_value + true_payload_suffix
                    modified_params_true = {k: v[0] for k, v in original_query_params.items()}
                    modified_params_true[param] = payload_true_val
                    query_true = urlencode(modified_params_true)
                    url_true = parsed_target_url._replace(query=query_true).geturl()

                    # Construct false URL
                    payload_false_val = str_original_value + false_payload_suffix
                    modified_params_false = {k: v[0] for k, v in original_query_params.items()}
                    modified_params_false[param] = payload_false_val
                    query_false = urlencode(modified_params_false)
                    url_false = parsed_target_url._replace(query=query_false).geturl()

                    print(f"          Testing boolean pair for {context_type}: TRUE='{true_payload_suffix}', FALSE='{false_payload_suffix}'")
                    
                    resp_true, _ = _test_sqli_payload(url_true, config) # We don't care about errors here, just content
                    resp_false, _ = _test_sqli_payload(url_false, config)

                    if resp_true and resp_false and original_response:
                        # Basic differential check:
                        # True response should be similar to original, False response should be different from True AND original.
                        # Or, True different from False, and one of them is similar to original.
                        len_orig = len(original_response.text)
                        len_true = len(resp_true.text)
                        len_false = len(resp_false.text)

                        # Heuristic: True is different from False, AND (True is like Original OR False is like Original, but not both)
                        # This tries to avoid cases where both true/false payloads break the page similarly.
                        # Threshold for "similar" length (e.g., within 5-10%)
                        similar_threshold = 0.10 
                        
                        is_true_diff_false = abs(len_true - len_false) > similar_threshold * max(len_true, len_false, 1)
                        is_true_like_orig = abs(len_true - len_orig) < similar_threshold * max(len_true, len_orig, 1)
                        is_false_like_orig = abs(len_false - len_orig) < similar_threshold * max(len_false, len_orig, 1)

                        if is_true_diff_false and (is_true_like_orig != is_false_like_orig): # XOR condition
                            point_info = {
                                "url_true": url_true, "url_false": url_false, "parameter": param,
                                "payload_true": payload_true_val, "payload_false": payload_false_val,
                                "type": "Boolean-based (Differential)",
                                "observation": f"Response lengths: Original={len_orig}, True={len_true}, False={len_false}. Significant difference suggests boolean-based SQLi."
                            }
                            boolean_based_points.append(point_info)
                            param_found_sqli = True
                            print(f"            [!!!] Potential Boolean-based SQLi for param '{param}' (Context: {context_type})")
                            break # Found for this payload pair
                    elif resp_true and resp_false: # Less reliable if original_response failed
                         if abs(len(resp_true.text) - len(resp_false.text)) > similar_threshold * max(len(resp_true.text), len(resp_false.text),1):
                            point_info = {
                                "url_true": url_true, "url_false": url_false, "parameter": param,
                                "payload_true": payload_true_val, "payload_false": payload_false_val,
                                "type": "Boolean-based (Differential - No Original Baseline)",
                                "observation": f"Response lengths: True={len(resp_true.text)}, False={len(resp_false.text)}. Significant difference suggests boolean-based SQLi."
                            }
                            boolean_based_points.append(point_info)
                            param_found_sqli = True
                            print(f"            [!!!] Potential Boolean-based SQLi for param '{param}' (Context: {context_type} - No Original Baseline)")
                            break


    if error_based_points:
        findings["potential_error_based_sqli"] = error_based_points
    if boolean_based_points:
        findings["potential_boolean_based_sqli"] = boolean_based_points

    details_parts = []
    if error_based_points:
        details_parts.append(f"{len(error_based_points)} potential error-based SQLi point(s)")
    if boolean_based_points:
        details_parts.append(f"{len(boolean_based_points)} potential boolean-based SQLi point(s)")

    if details_parts:
        findings["details"] = f"Found {', '.join(details_parts)}. This strongly suggests SQLi vulnerabilities. Use SQLMap for confirmation and exploitation."
        state.add_remediation_suggestion("sqli_heuristic_enhanced", {
            "source": "WP Analyzer (SQLi Heuristic - Enhanced)",
            "description": f"Enhanced heuristic checks suggest potential SQL Injection vulnerabilities: {', '.join(details_parts)}.",
            "severity": "High",
            "remediation": "Immediately investigate and fix these potential SQLi vulnerabilities. Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Run a full scan with a dedicated SQLi tool like SQLMap to confirm and assess the impact."
        })
    else:
        findings["details"] = "No obvious SQLi indicators detected from enhanced heuristic checks. This does not rule out SQLi. Use SQLMap for thorough testing."

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Enhanced SQLi heuristic checks finished. Details: {findings['details']}")
