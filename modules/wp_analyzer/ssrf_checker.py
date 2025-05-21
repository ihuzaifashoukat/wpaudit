# Module for Contextual WordPress SSRF Checks
import requests
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from .utils import make_request

# Expanded common parameters that might be vulnerable to SSRF
SSRF_TARGET_PARAMS = [
    "url", "uri", "u", "src", "source", "dest", "destination", "redirect", "feed", "image_url", 
    "file", "path", "data", "host", "site", "page", "show", "load", "view", "content", 
    "document", "target", "return", "return_to", "rurl", "out", "proxy", "remote",
    "fetch", "file_url", "image", "img", "link", "goto", "from_url", "import_url"
]

# Payloads for SSRF checks
SSRF_INTERNAL_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://0.0.0.0", "http://[::1]", "http://0",
    "http://127.0.0.1:80", "http://127.0.0.1:443", "http://127.0.0.1:22", "http://127.0.0.1:3306",
    "http://127.0.0.1:5432", "http://127.0.0.1:6379", "http://127.0.0.1:11211",
    "http://127.0.0.1:27017", "http://127.0.0.1:9200", "http://127.0.0.1:9300",
    "http://127.0.0.1:8080", "http://127.0.0.1:8000",
    "http://127.0.0.1:5000", # Common dev ports
    # Using a clearly non-standard port to observe behavior
    "http://127.0.0.1:23456", 
    "http://[::1]:23456",
    # File protocol (often blocked, but worth a try if context allows)
    # "file:///etc/passwd", "file:///c:/windows/win.ini" 
]

# Cloud metadata endpoints - EXTREME CAUTION - COMMENTED OUT BY DEFAULT
# Uncommenting and using these can have serious security implications and may violate terms of service.
# ONLY USE IF YOU HAVE EXPLICIT PERMISSION AND UNDERSTAND THE RISKS.
SSRF_CLOUD_METADATA_PAYLOADS_COMMENTED = {
    # "AWS_EC2": "http://169.254.169.254/latest/meta-data/",
    # "AWS_ECS_Task": "http://169.254.170.2/v2/metadata", # If ECS Task Metadata Endpoint v2
    # "GCP": "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text", # Requires Header: Metadata-Flavor: Google
    # "Azure_IMDS": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", # Requires Header: Metadata: true
    # "DigitalOcean": "http://169.254.169.254/metadata/v1.json",
    # "OracleCloud": "http://192.0.0.192/latest/",
}
# For a real tool, you'd use a unique URL from a callback server you control (e.g., Interactsh).
OOB_CALLBACK_PAYLOAD_EXAMPLE = "http://YOUR_UNIQUE_INTERACTSH_SUBDOMAIN"

BENIGN_EXTERNAL_PAYLOAD = "http://scanme.nmap.org" # A known, benign external host for baseline

def analyze_ssrf(state, config, target_url):
    module_key = "wp_analyzer"
    findings_key = "contextual_ssrf"

    all_wp_analyzer_findings = state.get_module_findings(module_key, {})
    findings = all_wp_analyzer_findings.get(findings_key, {})
    if not findings: # Initialize with default structure
        findings = {
            "status": "Not Checked",
            "details": "",
            "potential_ssrf_points": [],
            "recommendation": "Use dedicated SSRF scanning tools and out-of-band (OOB) techniques for comprehensive analysis."
        }

    findings["status"] = "Running"
    findings["details"] = "Performing enhanced heuristic SSRF checks. This is not a full SSRF scan."
    if "potential_ssrf_points" not in findings:
        findings["potential_ssrf_points"] = []
        
    all_wp_analyzer_findings[findings_key] = findings
    state.update_module_findings(module_key, all_wp_analyzer_findings) # Save initial state

    print("    [i] Performing enhanced SSRF heuristic checks (not a full scan)...")
    
    parsed_target_url = urlparse(target_url)
    original_query_params = parse_qs(parsed_target_url.query)
    ssrf_points = []

    # TODO: Extend to check forms (POST/GET) and potentially JSON bodies if Content-Type suggests.
    if not original_query_params:
        findings["details"] = "No query parameters in target URL to test for SSRF."
        findings["status"] = "Completed"
        all_wp_analyzer_findings = state.get_module_findings(module_key, {}) # Re-fetch
        all_wp_analyzer_findings[findings_key] = findings
        state.update_module_findings(module_key, all_wp_analyzer_findings)
        print("      [i] No query parameters in target URL for SSRF checks.")
        return

    print(f"      Checking {len(original_query_params)} parameter(s) in URL for SSRF: {target_url}")
    for param, values in original_query_params.items():
        if param.lower() not in SSRF_TARGET_PARAMS:
            continue

        original_value = values[0] if values else ""
        param_ssrf_found = False

        # Baseline with a benign external URL
        modified_params_benign = {k: v[0] for k, v in original_query_params.items()}
        modified_params_benign[param] = BENIGN_EXTERNAL_PAYLOAD
        test_url_benign = parsed_target_url._replace(query=urlencode(modified_params_benign)).geturl()
        
        baseline_response = None
        baseline_time = None
        try:
            start_time = time.time()
            response_benign = make_request(test_url_benign, config, method="GET", timeout=10) # Longer timeout for external
            baseline_time = time.time() - start_time
            if response_benign:
                baseline_response = response_benign
        except requests.exceptions.Timeout:
            baseline_time = 10.0 # Max timeout
            print(f"        Baseline request to {BENIGN_EXTERNAL_PAYLOAD} timed out.")
        except Exception as e_base:
            print(f"        Error on baseline request to {BENIGN_EXTERNAL_PAYLOAD}: {e_base}")


        for internal_payload in SSRF_INTERNAL_PAYLOADS:
            if param_ssrf_found: break 

            modified_params_ssrf = {k: v[0] for k, v in original_query_params.items()}
            modified_params_ssrf[param] = internal_payload
            test_url_ssrf = parsed_target_url._replace(query=urlencode(modified_params_ssrf)).geturl()

            print(f"        Testing param '{param}' with SSRF payload '{internal_payload}'...")
            observation_details = []
            is_suspicious = False
            
            try:
                ssrf_start_time = time.time()
                response_ssrf = make_request(test_url_ssrf, config, method="GET", timeout=3) # Shorter timeout for internal
                ssrf_time = time.time() - ssrf_start_time

                if response_ssrf:
                    # 1. Status code changes
                    if baseline_response and response_ssrf.status_code != baseline_response.status_code:
                        is_suspicious = True
                        observation_details.append(f"Status changed: benign={baseline_response.status_code}, ssrf_payload={response_ssrf.status_code}.")
                    elif not baseline_response and 200 <= response_ssrf.status_code < 400 : # Baseline failed, but this succeeded
                        is_suspicious = True
                        observation_details.append(f"Baseline request failed, but SSRF payload request succeeded (Status: {response_ssrf.status_code}).")


                    # 2. Content length changes significantly
                    if baseline_response and response_ssrf.text and baseline_response.text:
                        len_ssrf = len(response_ssrf.text)
                        len_base = len(baseline_response.text)
                        if abs(len_ssrf - len_base) > max(100, 0.2 * len_base) and len_ssrf != len_base : # 20% difference or >100 bytes
                            is_suspicious = True
                            observation_details.append(f"Content length changed: benign_len={len_base}, ssrf_payload_len={len_ssrf}.")
                    
                    # 3. Specific error messages for internal connections
                    if response_ssrf.text:
                        error_match = re.search(r"(connection refused|could not connect|failed to connect|host not found|network is unreachable|no route to host|timeout was reached|operation timed out)", response_ssrf.text, re.IGNORECASE)
                        if error_match:
                            is_suspicious = True
                            observation_details.append(f"Response contains error: '{error_match.group(0)}'.")
                    
                    # 4. Response time differences (very heuristic)
                    if baseline_time is not None:
                        if ssrf_time < 0.5 and baseline_time > 2.0: # Very fast internal vs slower external
                            is_suspicious = True
                            observation_details.append(f"Response time difference: ssrf_payload_time={ssrf_time:.2f}s, benign_time={baseline_time:.2f}s (fast internal).")

                if is_suspicious:
                    point_info = {"url": test_url_ssrf, "parameter": param, "payload": internal_payload,
                                  "observation_details": " | ".join(observation_details) if observation_details else "Behavior changed with internal payload.",
                                  "detail": "Potential SSRF. Manual verification and OOB testing required."}
                    ssrf_points.append(point_info)
                    param_ssrf_found = True
                    print(f"          [!!!] Potential SSRF for param '{param}' with '{internal_payload}'. Observations: {' | '.join(observation_details)}")

            except requests.exceptions.Timeout:
                observation_details.append("Request timed out (3s).")
                # Timeout to internal host can be an indicator if benign external one didn't timeout or was much slower.
                if baseline_time is None or baseline_time > 3.5: # If baseline also timed out quickly, less indicative
                    is_suspicious = True
                
                if is_suspicious:
                    point_info = {"url": test_url_ssrf, "parameter": param, "payload": internal_payload,
                                  "observation_details": "Request timed out. This can indicate SSRF if the server attempts to connect to an internal non-responsive service.",
                                  "detail": "Potential SSRF (Timeout). Manual verification and OOB testing required."}
                    ssrf_points.append(point_info)
                    param_ssrf_found = True
                    print(f"          [!!!] Potential SSRF (Timeout) for param '{param}' with '{internal_payload}'.")
            except Exception as e:
                print(f"          [-] Error testing SSRF for param {param}: {e}")
            
    if ssrf_points:
        findings["potential_ssrf_points"] = ssrf_points
        findings["details"] = f"Found {len(ssrf_points)} parameter(s) where SSRF heuristics suggest potential vulnerabilities. Thorough manual testing with out-of-band (OOB) techniques (e.g., Interactsh, Burp Collaborator) is CRUCIAL for confirmation."
        state.add_remediation_suggestion("ssrf_heuristic_enhanced", {
            "source": "WP Analyzer (SSRF Heuristic - Enhanced)",
            "description": f"Enhanced heuristic checks found {len(ssrf_points)} URL parameter(s) that might be vulnerable to Server-Side Request Forgery (SSRF). This was based on differing server responses, error messages, or timeouts when internal host payloads were supplied.",
            "severity": "High",
            "remediation": "Validate and sanitize all user-supplied URLs or input used to construct request targets. Use a whitelist approach for allowed domains/IPs and protocols. Implement network segmentation. For definitive SSRF testing, use tools that support out-of-band (OOB) detection."
        })
    else:
        findings["details"] = "No obvious SSRF indicators found from enhanced heuristic checks on URL parameters. This does not rule out SSRF. Use specialized tools and OOB techniques for thorough testing."

    findings["status"] = "Completed"
    all_wp_analyzer_findings = state.get_module_findings(module_key, {}) # Re-fetch
    all_wp_analyzer_findings[findings_key] = findings
    state.update_module_findings(module_key, all_wp_analyzer_findings)
    print(f"    [+] Enhanced SSRF heuristic checks finished. Details: {findings['details']}")
    print("    [IMPORTANT] For reliable SSRF detection, especially blind SSRF, use tools that leverage out-of-band (OOB) callback mechanisms.")
