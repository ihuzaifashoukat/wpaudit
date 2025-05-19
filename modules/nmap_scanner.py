import os
from core.tool_runner import run_command
from core.utils import get_scan_filename_prefix
# Import xml parser if you want to parse results here
# import xml.etree.ElementTree as ET

def run_scan(state, config):
    """
    Runs Nmap scan based on the selected profile.
    """
    target_info = state.get_full_state()["scan_metadata"]["target_info"]
    target_ip = target_info.get("ip")
    hostname = target_info.get("hostname")
    profile_name = state.get_full_state()["scan_config_used"].get("profile_name", "default")
    profile = config.get("scan_profiles", {}).get(profile_name, config.get("scan_profiles", {}).get("default"))

    if not target_ip:
        print("[!] Nmap phase skipped: Target IP could not be resolved.")
        state.update_module_findings("nmap_results", {"status": "Skipped (No IP)"})
        state.mark_phase_executed("nmap")
        state.save_state()
        return

    print(f"\n[*] Phase 1: Nmap Network Scan on {target_ip} ({hostname}) [Profile: {profile_name}]")
    state.update_module_findings("nmap_results", {"target_ip": target_ip, "hostname": hostname, "profile": profile_name, "status": "Running"})

    # Use get_scan_filename_prefix from utils, passing state and config
    base_filename = get_scan_filename_prefix(state, config)
    nmap_output_xml = f"{base_filename}_nmap.xml"

    command = ["nmap"] # Tool key from config
    command.extend(profile["nmap_options"].split())
    if profile.get("nmap_ports"):
        command.extend(["-p", profile["nmap_ports"]])
    command.extend(["-oX", nmap_output_xml, target_ip]) # Output to XML

    nmap_timeout = config.get("nmap_timeout", 1200)
    process_obj = run_command(command, "Nmap", config, timeout=nmap_timeout, return_proc=True)

    state.update_module_findings("nmap_results", {"raw_xml_path": nmap_output_xml})

    if process_obj and process_obj.returncode == 0 and os.path.exists(nmap_output_xml):
        print(f"[+] Nmap scan completed. XML: {nmap_output_xml}")
        state.update_module_findings("nmap_results", {"status": "Completed"})
        state.add_summary_point(f"Nmap scan completed for {target_ip} using '{profile_name}' profile.")
        # Optional: Add basic parsing here or leave for manual review/other tools
        # parse_nmap_xml(nmap_output_xml, state) # Example call
    elif process_obj:
        error_msg = f"Nmap scan failed. RC: {process_obj.returncode}. Check Nmap logs/errors."
        state.update_module_findings("nmap_results", {"status": "Failed", "error": error_msg})
        state.add_critical_alert(f"Nmap scan failed for {target_ip}.")
        state.add_tool_error(f"Nmap Scan Failed: RC={process_obj.returncode}, stderr={process_obj.stderr}")
    else: # run_command returned None
        state.update_module_findings("nmap_results", {"status": "Execution Error"})
        state.add_critical_alert(f"Nmap scan execution error for {target_ip}.")
        # Tool error already logged by run_command

    state.mark_phase_executed("nmap")
    state.save_state()

# --- Optional XML Parsing ---
# def parse_nmap_xml(xml_file, state):
#     """Basic Nmap XML parsing example."""
#     print(f"    Parsing Nmap XML: {xml_file}")
#     open_ports = []
#     try:
#         tree = ET.parse(xml_file)
#         root = tree.getroot()
#         for host in root.findall('host'):
#             ports = host.find('ports')
#             if ports is None: continue
#             for port in ports.findall('port'):
#                 state_elem = port.find('state')
#                 if state_elem is None or state_elem.get('state') != 'open': continue
#                 service_elem = port.find('service')
#                 port_info = {
#                     "port": port.get('portid'),
#                     "protocol": port.get('protocol'),
#                     "state": state_elem.get('state'),
#                     "service": service_elem.get('name') if service_elem is not None else 'unknown',
#                     "product": service_elem.get('product') if service_elem is not None else '',
#                     "version": service_elem.get('version') if service_elem is not None else '',
#                     "extrainfo": service_elem.get('extrainfo') if service_elem is not None else ''
#                 }
#                 open_ports.append(port_info)
#         state.update_module_findings("nmap_results", {"open_ports": open_ports})
#         if open_ports:
#             print(f"    [i] Parsed {len(open_ports)} open ports from Nmap results.")
#         else:
#             print("    [i] No open ports found in Nmap XML or parsing failed.")
#     except ET.ParseError as e:
#         print(f"    [-] Error parsing Nmap XML file '{xml_file}': {e}")
#         state.add_tool_error(f"Nmap XML Parse Error: {e}")
#     except Exception as e:
#         print(f"    [-] Unexpected error during Nmap XML parsing: {e}")
#         state.add_tool_error(f"Nmap XML Parse Unexpected Error: {e}")