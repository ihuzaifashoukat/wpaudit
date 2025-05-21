import os
import xml.etree.ElementTree as ET # Uncommented for XML parsing
from core.tool_runner import run_command
from core.utils import get_scan_filename_prefix

def parse_nmap_xml(xml_file, state):
    """Parses Nmap XML output to extract open ports, services, and script outputs."""
    print(f"    Parsing Nmap XML: {xml_file}")
    findings = {
        "open_ports": [],
        "host_scripts": [],
        "os_detection": {}
    }
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host_node in root.findall('host'):
            # OS Detection
            os_node = host_node.find('os')
            if os_node is not None:
                for osmatch in os_node.findall('osmatch'):
                    findings["os_detection"] = {
                        "name": osmatch.get('name'),
                        "accuracy": osmatch.get('accuracy'),
                        "line": osmatch.get('line')
                    }
                    # Could also iterate over osclass elements for more detail
                    break # Usually take the first best osmatch

            # Ports
            ports_node = host_node.find('ports')
            if ports_node:
                for port_node in ports_node.findall('port'):
                    state_elem = port_node.find('state')
                    if state_elem is None or state_elem.get('state') != 'open':
                        continue
                    
                    service_elem = port_node.find('service')
                    port_info = {
                        "portid": port_node.get('portid'),
                        "protocol": port_node.get('protocol'),
                        "state": state_elem.get('state'),
                        "reason": state_elem.get('reason'),
                        "service_name": service_elem.get('name') if service_elem is not None else 'unknown',
                        "product": service_elem.get('product') if service_elem is not None else '',
                        "version": service_elem.get('version') if service_elem is not None else '',
                        "extrainfo": service_elem.get('extrainfo') if service_elem is not None else '',
                        "method": service_elem.get('method') if service_elem is not None else '',
                        "conf": service_elem.get('conf') if service_elem is not None else '',
                        "cpe": [cpe.text for cpe in service_elem.findall('cpe')] if service_elem is not None else [],
                        "scripts": []
                    }
                    
                    # Port Scripts
                    for script_elem in port_node.findall('script'):
                        script_output = script_elem.get('output', '').strip()
                        # Some scripts have structured data in <elem> or <table_elem>
                        # For simplicity, we'll grab raw output. Can be expanded.
                        port_info["scripts"].append({
                            "id": script_elem.get('id'),
                            "output": script_output
                        })
                        if "http-title" == script_elem.get('id') and script_output:
                            port_info["http_title"] = script_output.split('Site title:')[1].strip() if 'Site title:' in script_output else script_output

                    findings["open_ports"].append(port_info)

            # Host Scripts (scripts run against the host, not a specific port)
            hostscript_node = host_node.find('hostscript')
            if hostscript_node:
                for script_elem in hostscript_node.findall('script'):
                    findings["host_scripts"].append({
                        "id": script_elem.get('id'),
                        "output": script_elem.get('output', '').strip()
                    })

        current_nmap_findings = state.get_module_findings("nmap_results", {})
        current_nmap_findings.update(findings) # Merge new parsed findings
        state.update_module_findings("nmap_results", current_nmap_findings)

        if findings["open_ports"]:
            print(f"    [i] Parsed {len(findings['open_ports'])} open port(s) from Nmap results.")
        if findings["host_scripts"]:
            print(f"    [i] Parsed {len(findings['host_scripts'])} host script output(s).")
        if findings["os_detection"].get("name"):
             print(f"    [i] OS Detection: {findings['os_detection']['name']} (Accuracy: {findings['os_detection']['accuracy']})")
        if not findings["open_ports"] and not findings["host_scripts"] and not findings["os_detection"].get("name"):
            print("    [i] No open ports, host scripts, or OS detection info found in Nmap XML or parsing failed to extract.")

    except ET.ParseError as e:
        print(f"    [-] Error parsing Nmap XML file '{xml_file}': {e}")
        state.add_tool_error(f"Nmap XML Parse Error: {e}")
    except Exception as e:
        print(f"    [-] Unexpected error during Nmap XML parsing: {e}")
        state.add_tool_error(f"Nmap XML Parse Unexpected Error: {e}")


def run_scan(state, config):
    """
    Runs Nmap scan based on the selected profile, including NSE scripts.
    Parses XML output for open ports, services, and script results.
    """
    full_state_data = state.get_full_state()
    target_info = full_state_data["scan_metadata"]["target_info"]
    target_ip = target_info.get("ip")
    hostname = target_info.get("hostname")
    # Corrected path to scan_config_used
    profile_name = full_state_data["scan_metadata"]["config_used"].get("profile_name", "default")
    
    # Ensure profile exists, fallback to a minimal default if necessary
    scan_profiles_config = config.get("scan_profiles", {})
    profile = scan_profiles_config.get(profile_name, scan_profiles_config.get("default", {}))
    if not profile: # If even default is missing, use hardcoded minimal
        print(f"    [!] Nmap profile '{profile_name}' or 'default' not found in config. Using minimal Nmap scan.")
        profile = {"nmap_options": "-sV -T4", "nmap_ports": "T:21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"}


    if not target_ip:
        print("[!] Nmap phase skipped: Target IP could not be resolved.")
        state.update_module_findings("nmap_results", {"status": "Skipped (No IP)"})
        state.mark_phase_executed("nmap")
        state.save_state()
        return

    print(f"\n[*] Phase 1: Nmap Network Scan on {target_ip} ({hostname}) [Profile: {profile_name}]")
    state.update_module_findings("nmap_results", {"target_ip": target_ip, "hostname": hostname, "profile": profile_name, "status": "Running", "open_ports": [], "host_scripts": [], "os_detection": {}})

    base_filename = get_scan_filename_prefix(state, config)
    nmap_output_xml = os.path.join(config.get("output_dir", "omegascythe_overlord_reports"), f"{base_filename}_nmap.xml")
    # Ensure output directory exists
    os.makedirs(os.path.dirname(nmap_output_xml), exist_ok=True)


    command = ["nmap"]
    # Base options from profile
    nmap_base_options = profile.get("nmap_options", "-sV -T4").split() # Default to basic version scan if not specified
    command.extend(nmap_base_options)

    # Ports from profile
    nmap_profile_ports = profile.get("nmap_ports")
    if nmap_profile_ports:
        command.extend(["-p", nmap_profile_ports])
    
    # NSE Scripts from profile
    nmap_scripts = profile.get("nmap_scripts")
    if nmap_scripts:
        command.extend(["--script", nmap_scripts])
        print(f"    [i] Using Nmap NSE scripts: {nmap_scripts}")

    command.extend(["-oX", nmap_output_xml, target_ip])

    nmap_timeout = config.get("nmap_timeout", 7200) # Default 2 hours (increased from 1200s)
    process_obj = run_command(command, "Nmap", config, timeout=nmap_timeout, return_proc=True)

    state.update_module_findings("nmap_results", {"raw_xml_path": nmap_output_xml})

    if process_obj and process_obj.returncode == 0 and os.path.exists(nmap_output_xml) and os.path.getsize(nmap_output_xml) > 0:
        print(f"    [+] Nmap scan completed. XML output: {nmap_output_xml}")
        parse_nmap_xml(nmap_output_xml, state) # Call the parser
        # Update status based on parsing results or keep as completed
        parsed_findings = state.get_module_findings("nmap_results")
        if parsed_findings.get("open_ports") or parsed_findings.get("host_scripts") or parsed_findings.get("os_detection"):
            state.update_module_findings("nmap_results", {"status": "Completed (Parsed)"})
        else:
            state.update_module_findings("nmap_results", {"status": "Completed (XML Generated, No Data Parsed)"})
        state.add_summary_point(f"Nmap scan completed for {target_ip} using '{profile_name}' profile. Results parsed.")

    elif process_obj: # Nmap ran but had an error or XML is empty/missing
        error_detail = f"RC: {process_obj.returncode}"
        if process_obj.stderr:
            error_detail += f", Stderr: {process_obj.stderr[:200]}" # Truncate long errors
        if not os.path.exists(nmap_output_xml) or os.path.getsize(nmap_output_xml) == 0:
            error_detail += ", Output XML empty or not found."
            
        error_msg = f"Nmap scan failed or produced no output. {error_detail}. Check Nmap logs/errors."
        state.update_module_findings("nmap_results", {"status": "Failed", "error": error_msg})
        state.add_critical_alert(f"Nmap scan failed for {target_ip}. Details: {error_detail}")
        state.add_tool_error(f"Nmap Scan Failed: {error_detail}")
    else: # run_command itself returned None (e.g., tool not found by run_command)
        state.update_module_findings("nmap_results", {"status": "Execution Error", "error": "run_command failed to execute Nmap."})
        state.add_critical_alert(f"Nmap scan execution error for {target_ip}. Tool might be missing or misconfigured.")
        # Tool error (e.g. "Tool not found") would have been logged by run_command

    state.mark_phase_executed("nmap")
    state.save_state()
