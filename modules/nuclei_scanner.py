import json
import os
import re # For potential output cleaning
import json
import os
import re # For potential output cleaning
import tempfile # To create temporary file for target list
from core.tool_runner import run_command
from core.utils import get_scan_filename_prefix

def run_scan(state, config, target_urls=None, discovered_paths=None, urls_with_params=None): # Added more target inputs
    """
    Runs Nuclei scan based on the selected profile against a comprehensive list of targets.
    """
    primary_target_url = state.get_full_state()["scan_metadata"]["target_info"]["url"] # For fallback
    profile_name = state.get_full_state()["scan_config_used"].get("profile_name", "default")
    profile = config.get("scan_profiles", {}).get(profile_name, config.get("scan_profiles", {}).get("default", {}))

    # Consolidate all potential targets for Nuclei
    comprehensive_target_list = set()
    if target_urls and isinstance(target_urls, list):
        comprehensive_target_list.update(target_urls)
    if discovered_paths and isinstance(discovered_paths, list):
        # These are often full URLs from ffuf, add them directly
        comprehensive_target_list.update(discovered_paths)
    if urls_with_params and isinstance(urls_with_params, list):
        comprehensive_target_list.update(urls_with_params)

    if not comprehensive_target_list: # Fallback if all lists are empty for some reason
        comprehensive_target_list.add(primary_target_url)
        print(f"    [i] No expanded targets for Nuclei, using primary URL: {primary_target_url}")

    targets_to_scan_final = sorted(list(comprehensive_target_list))
    target_log_str = f"{len(targets_to_scan_final)} unique URLs/paths"

    print(f"\n[*] Phase Nuclei: Active Vulnerability Scanning for {target_log_str} [Profile: {profile_name}]")
    state.update_module_findings("nuclei_results", {"targets_scanned_count": len(targets_to_scan_final), "profile": profile_name, "findings": [], "status": "Running"})

    base_filename = get_scan_filename_prefix(state, config)
    nuclei_output_jsonl = f"{base_filename}_nuclei.jsonl"
    temp_target_file = None

    command_base = [
        "nuclei",
        "-jsonl", "-o", nuclei_output_jsonl,
        "-t", profile.get("nuclei_templates", "technologies/wordpress"), # Use .get with fallback
        "-rl", str(profile.get("nuclei_rate_limit", 150)), # Use .get with fallback
        "-H", f"User-Agent: {config.get('default_user_agent', 'OmegaScytheDominator')}" # Use .get with fallback
    ]

    # Add target(s) using -u or -l
    if not targets_to_scan_final:
        print("    [!] No targets for Nuclei. Skipping.")
        state.update_module_findings("nuclei_results", {"status": "Skipped (No Targets)"})
        state.mark_phase_executed("nuclei")
        state.save_state()
        return

    if len(targets_to_scan_final) == 1:
        command = command_base + ["-u", targets_to_scan_final[0]]
    else:
        # Create a temporary file with the list of URLs
        try:
            # Ensure targets_to_scan_final contains only strings
            string_targets = [str(t) for t in targets_to_scan_final if t]
            if not string_targets:
                raise ValueError("No valid string targets to write to Nuclei target file.")

            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt", prefix="nuclei_targets_") as tf:
                tf.write("\n".join(string_targets))
                temp_target_file = tf.name
            print(f"    [i] Using temporary file for {len(string_targets)} Nuclei targets: {temp_target_file}")
            command = command_base + ["-l", temp_target_file]
        except Exception as e:
            print(f"    [!] Error creating temporary target file for Nuclei: {e}. Skipping Nuclei.")
            state.update_module_findings("nuclei_results", {"error": f"Failed to create temp target file: {e}", "status": "Skipped (Temp File Error)"})
            state.mark_phase_executed("nuclei")
            state.save_state()
            return

    # Add other useful Nuclei flags from config? e.g., severity, proxy, headers
    # if config.get("nuclei_severity"): command.extend(["-severity", config["nuclei_severity"]])
    # if config.get("proxy"): command.extend(["-proxy", config["proxy"]])

    nuclei_timeout = config.get("nuclei_timeout", 7200)
    process_obj = run_command(command, "Nuclei", config, timeout=nuclei_timeout, return_proc=True)

    # Clean up temporary file if it was created
    if temp_target_file and os.path.exists(temp_target_file):
        try:
            os.remove(temp_target_file)
            print(f"    [i] Cleaned up temporary target file: {temp_target_file}")
        except OSError as e:
            print(f"    [!] Warning: Could not remove temporary file {temp_target_file}: {e}")


    state.update_module_findings("nuclei_results", {"raw_jsonl_path": nuclei_output_jsonl})

    if process_obj and process_obj.returncode == 0 and os.path.exists(nuclei_output_jsonl):
        print(f"[+] Nuclei scan completed. Results: {nuclei_output_jsonl}")
        findings = []
        processed_finding_ids = set() # To help basic deduplication by template-id/host/matched
        try:
            with open(nuclei_output_jsonl, 'r', errors='ignore') as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)

                        # Add Remediation Suggestion
                        info = finding.get("info", {})
                        severity = info.get("severity", "info").lower()
                        # Create a more unique ID incorporating matched value if possible
                        finding_key = finding.get("template-id", "nuclei")
                        if finding.get("matcher-name"): finding_key += f"_{finding.get('matcher-name')}"
                        # Add part of the matched URL/value to distinguish findings from same template
                        matched_part = re.sub(r'[^a-zA-Z0-9_-]', '_', finding.get("matched-at", finding.get("host",""))[:50])
                        unique_finding_id = f"{finding_key}_{matched_part}"

                        # Basic deduplication check
                        if unique_finding_id in processed_finding_ids: continue
                        processed_finding_ids.add(unique_finding_id)

                        remediation_details = {
                            "source": "Nuclei",
                            "template_id": finding.get("template-id"),
                            "finding_name": info.get("name"),
                            "description": info.get("description", "N/A"),
                            "severity": severity,
                            "tags": info.get("tags", []),
                            "reference": info.get("reference", []),
                            "matched_at": finding.get("matched-at"),
                            "remediation": info.get("remediation", "Review finding details and apply recommended security configurations or patches.")
                        }
                        state.add_remediation_suggestion(unique_finding_id, remediation_details)

                    except json.JSONDecodeError:
                        print(f"   [!] Warning: Could not decode Nuclei JSON line: {line.strip()}")
            state.update_module_findings("nuclei_results", {"findings": findings, "status": "Completed"})
            state.add_summary_point(f"Nuclei scan completed ({profile_name}), found {len(findings)} potential issues across {len(targets_to_scan_final)} target(s).")
            if findings: state.add_critical_alert(f"Nuclei found {len(findings)} issues ({profile_name}) across {len(targets_to_scan_final)} target(s)!")

        except Exception as e: # Catch errors during file reading/processing
            err_msg = f"Error parsing Nuclei output file '{nuclei_output_jsonl}': {e}"
            print(f"[-] {err_msg}")
            state.update_module_findings("nuclei_results", {"error": err_msg, "status": "Completed with Parse Error"})
            state.add_tool_error(err_msg)

    elif process_obj: # Process ran but might have failed
        err_msg = f"Nuclei scan failed. RC: {process_obj.returncode}. Check logs/errors."
        state.update_module_findings("nuclei_results", {"error": err_msg, "status": "Failed"})
        state.add_critical_alert(f"Nuclei scan failed for target(s): {target_log_str}.")
        state.add_tool_error(f"Nuclei Scan Failed: RC={process_obj.returncode}, stderr={process_obj.stderr}")
    else: # run_command returned None
        state.update_module_findings("nuclei_results", {"error": "Execution Error", "status": "Execution Error"})
        state.add_critical_alert(f"Nuclei scan execution error for target(s): {target_log_str}.")
        # Tool error already logged by run_command

    state.mark_phase_executed("nuclei")
    state.save_state()
