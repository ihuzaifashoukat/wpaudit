import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
import time
from core.utils import sanitize_filename, user_confirm # Core utils needed here
from .utils import make_request # Local utils for requests

def analyze_xml_rpc(state, config, target_url):
    """Analyzes the XML-RPC interface, including methods and potential SSRF via pingback."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "xml_rpc" not in analyzer_findings:
        analyzer_findings["xml_rpc"] = {"status": "Running", "details": {}, "ssrf_via_pingback_test": {}}
    xmlrpc_details = analyzer_findings["xml_rpc"]

    xmlrpc_url = urljoin(target_url.rstrip('/'), "/xmlrpc.php")
    xmlrpc_details["url_checked"] = xmlrpc_url
    print(f"    Checking XML-RPC: {xmlrpc_url}")

    # Initial check using HEAD
    head_response = make_request(xmlrpc_url, config, method="HEAD")
    if not head_response or head_response.status_code != 200:
        status_code = head_response.status_code if head_response else 'Request Failed'
        xmlrpc_details["status"] = f"Disabled/Blocked (Status: {status_code})"
        print(f"    [-] XML-RPC seems disabled or blocked at {xmlrpc_url} (Status: {status_code}).")
        # Update findings and return early if XML-RPC is not accessible
        analyzer_findings["xml_rpc"] = xmlrpc_details
        state.update_module_findings(module_key, analyzer_findings)
        # Also initialize the SSRF test status if it wasn't already
        if "ssrf_via_pingback_test" not in xmlrpc_details:
             xmlrpc_details["ssrf_via_pingback_test"] = {"status": "Skipped (XML-RPC Not Accessible)"}
        elif "status" not in xmlrpc_details["ssrf_via_pingback_test"]:
             xmlrpc_details["ssrf_via_pingback_test"]["status"] = "Skipped (XML-RPC Not Accessible)"
        return # Stop further XML-RPC checks

    # If HEAD is successful, proceed with method listing
    xmlrpc_details["status"] = "Enabled (Responded 200 to HEAD)"
    print(f"    [i] XML-RPC interface found at {xmlrpc_url}. Probing methods...")
    list_methods_payload = "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"
    response = make_request(xmlrpc_url, config, method="POST", data=list_methods_payload)

    pingback_enabled = False # Flag to track if pingback.ping is found

    if response and response.status_code == 200 and "system.listMethods" in response.text:
        xmlrpc_details["system.listMethods"] = "Accessible"
        print(f"    [+] XML-RPC system.listMethods successful.")
        try:
            root = ET.fromstring(response.content)
            methods = [m.text for m in root.findall('.//methodResponse/params/param/value/array/data/value/string')]
            if methods:
                xmlrpc_details["available_methods_count"] = len(methods)
                xmlrpc_details["available_methods_sample"] = methods[:5] # Keep sample small
                print(f"      [i] Found {len(methods)} XML-RPC methods (e.g., {', '.join(methods[:3])}...).")
                if "pingback.ping" in methods:
                    xmlrpc_details["pingback.ping_enabled"] = True
                    pingback_enabled = True # Set flag for SSRF test
                    state.add_remediation_suggestion("xmlrpc_pingback", {
                        "source": "WP Analyzer",
                        "description": "XML-RPC 'pingback.ping' method is enabled. Can be used for DDoS amplification or internal port scanning (SSRF).",
                        "severity": "Medium",
                        "remediation": "Disable XML-RPC if not needed, or selectively disable pingbacks using filters or security plugins."
                    })
                # Add checks for other potentially risky methods if needed
                # if "wp.getUsersBlogs" in methods: ...
            else:
                 print("      [i] system.listMethods response parsed, but no methods listed.")
                 xmlrpc_details["available_methods_count"] = 0
        except ET.ParseError:
            xmlrpc_details["system.listMethods_parsing_error"] = True
            print("      [-] Could not parse XML-RPC system.listMethods response.")
    elif response:
        xmlrpc_details["system.listMethods"] = f"Failed (Status: {response.status_code})"
        print(f"    [-] system.listMethods failed (Status: {response.status_code}).")
    else:
        xmlrpc_details["system.listMethods"] = "Request Failed"
        print(f"    [-] system.listMethods request failed.")


    # Active XML-RPC Pingback SSRF Test (Conditional)
    # Ensure ssrf_via_pingback_test exists before accessing it
    if "ssrf_via_pingback_test" not in xmlrpc_details:
        xmlrpc_details["ssrf_via_pingback_test"] = {}
    ssrf_test_details = xmlrpc_details["ssrf_via_pingback_test"]

    # Check config flag and if pingback method was found
    run_ssrf_test = config.get("analyzer_xmlrpc_ssrf_test_enabled", False) and pingback_enabled

    if run_ssrf_test:
        if user_confirm("Perform XML-RPC Pingback SSRF test? (Sends outbound requests from target)", config):
            print("    [i] Performing XML-RPC Pingback SSRF test...")
            ssrf_test_details["status"] = "Running"
            ssrf_test_details["targets_tested"] = []
            ssrf_test_details["responses"] = {}

            oast_domain = config.get("oast_domain_placeholder", "YOUR_OAST_DOMAIN_HERE")
            # Get targets from config, ensure it's a list
            pingback_targets = list(config.get("analyzer_xmlrpc_ssrf_pingback_targets", []))

            # Add dynamic OAST target if domain is configured
            if "YOUR_OAST_DOMAIN_HERE" not in oast_domain and oast_domain:
                # Generate a unique subdomain for this scan
                unique_id = f"{sanitize_filename(urlparse(target_url).netloc)}_{int(time.time())}"
                oast_target = f"http://{unique_id}.{oast_domain}"
                pingback_targets.insert(0, oast_target) # Add to the beginning

            if not pingback_targets:
                ssrf_test_details["status"] = "Skipped (No Targets)"
                print("      [!] No valid targets configured for XML-RPC SSRF pingback test.")
            else:
                for pb_target in pingback_targets:
                    ssrf_test_details["targets_tested"].append(pb_target)
                    print(f"      Pinging: {pb_target} via XML-RPC pingback...")
                    # Source URL for the pingback (can be anything, use target URL for context)
                    source_ping_url = urljoin(target_url, f'/pingback-ssrf-test-source-{int(time.time())}')
                    ssrf_payload = f"<methodCall><methodName>pingback.ping</methodName><params><param><value><string>{pb_target}</string></value></param><param><value><string>{source_ping_url}</string></value></param></params></methodCall>"

                    ssrf_response = make_request(xmlrpc_url, config, method="POST", data=ssrf_payload)

                    response_summary = "No response"
                    response_status = "Request Failed"
                    response_snippet = ""

                    if ssrf_response:
                        response_summary = f"Status: {ssrf_response.status_code}, Len: {len(ssrf_response.text)}"
                        response_snippet = ssrf_response.text[:200] # Get snippet
                        text_lower = ssrf_response.text.lower()
                        # Check if the response indicates success (no faultCode)
                        if "faultcode" not in text_lower:
                            response_status = "Potential SSRF (No Fault)"
                            print(f"        [!!!] XML-RPC pingback to {pb_target} did NOT return faultCode. Check OAST/target logs. {response_summary}")
                            state.add_critical_alert(f"XML-RPC Pingback to {pb_target} succeeded (no faultCode). Potential SSRF. Check OAST/target logs.")
                        else:
                            response_status = "Fault Code Returned"
                            print(f"        [i] XML-RPC pingback to {pb_target} returned faultCode (likely blocked/failed). {response_summary}")
                    else:
                         print(f"        [-] XML-RPC pingback request to {pb_target} failed.")


                    ssrf_test_details["responses"][pb_target] = {
                        "status": response_status,
                        "details": response_summary,
                        "snippet": response_snippet
                    }
                ssrf_test_details["status"] = "Completed"
        else:
            ssrf_test_details["status"] = "Skipped (User Declined)"
    else:
        # Set status if test wasn't run due to config or missing pingback method
        if not pingback_enabled and xmlrpc_details["status"].startswith("Enabled"):
             ssrf_test_details["status"] = "Skipped (Pingback Method Not Found)"
        elif not config.get("analyzer_xmlrpc_ssrf_test_enabled", False):
             ssrf_test_details["status"] = "Skipped (Disabled in Config)"
        # If status was already set (e.g., XML-RPC not accessible), don't overwrite
        elif "status" not in ssrf_test_details:
             ssrf_test_details["status"] = "Skipped (Condition Not Met)"


    xmlrpc_details["ssrf_via_pingback_test"] = ssrf_test_details
    analyzer_findings["xml_rpc"] = xmlrpc_details
    state.update_module_findings(module_key, analyzer_findings)
