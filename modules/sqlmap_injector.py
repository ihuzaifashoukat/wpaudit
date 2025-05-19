import subprocess
import json
import os
import re
from urllib.parse import unquote
import sys # For stdout writing
from urllib.parse import unquote, urlparse # Added urlparse
from core.tool_runner import run_command # Though not directly used for sqlmap's Popen
from core.utils import get_scan_filename_prefix, user_confirm, sanitize_filename

def run_scan(state, config, user_targets=None, target_urls=None): # Added target_urls from main.py
    """
    Runs SQLMap scan based on the selected profile and identified/provided targets.
    """
    full_state_data = state.get_full_state()
    primary_target_url = full_state_data["scan_metadata"]["target_info"]["url"] # Keep for reference
    # Corrected path to scan_config_used
    profile_name = full_state_data["scan_metadata"]["config_used"].get("profile_name", "default")
    # profile = config.get("scan_profiles", {}).get(profile_name, config.get("scan_profiles", {}).get("default")) # Not directly used for sqlmap_options anymore

    print(f"\n[*] Phase SQLMap: SQL Injection Deep Dive [Profile: {profile_name}]")
    state.update_module_findings("sqlmap_results", {"status": "Initializing", "profile": profile_name, "targets_tested": [], "logs": {}, "vulnerable_targets": []})

    potential_sqli_targets = set()

    # 1. Add explicitly provided user targets (CLI)
    if user_targets:
        for t in user_targets:
            potential_sqli_targets.add(t)
            print(f"    [i] Added SQLMap target from CLI: {t}")

    # 2. Add targets inferred from Nuclei SQLi findings
    nuclei_findings = state.get_module_findings("nuclei_results", {}).get("findings", [])
    for finding in nuclei_findings:
        info = finding.get("info", {})
        tags = info.get("tags", [])
        tags_str = "".join(tags) if isinstance(tags, list) else str(tags)

        if "sql-injection" in finding.get("template-id", "") or "sqli" in tags_str:
            matched_url = finding.get("matched-at", finding.get("host"))
            if matched_url and matched_url not in potential_sqli_targets:
                potential_sqli_targets.add(matched_url)
                print(f"    [i] Added potential SQLi target from Nuclei: {matched_url}")

    # 3. Add validated URLs from subdomain scan (passed as target_urls)
    # These are broader targets; SQLMap will try to find injectable parameters.
    if target_urls:
        for t_url in target_urls:
            if t_url not in potential_sqli_targets:
                potential_sqli_targets.add(t_url)
                print(f"    [i] Added general target for SQLMap (from subdomain/main scan): {t_url}")

    # 4. Add URLs with parameters found by parameter_finder
    param_finder_results = state.get_module_findings("parameter_finder", {}).get("found_parameters", {})
    for url_with_params, params in param_finder_results.items():
        if params and url_with_params not in potential_sqli_targets: # Only add if it has params and not already added
            potential_sqli_targets.add(url_with_params) # SQLMap can often auto-detect parameters
        print(f"    [i] Added potential SQLi target from Parameter Finder: {url_with_params}")


    final_target_list = sorted(list(potential_sqli_targets)) # Sort for consistent order
    if not final_target_list:
        print("    [i] No specific SQLi targets identified or provided. Skipping SQLMap.")
        state.update_module_findings("sqlmap_results", {"status": "Skipped (No Targets)"})
        state.mark_phase_executed("sqlmap")
        state.save_state()
        return

    prompt = f"SQLMap on {len(final_target_list)} target(s) with '{profile_name}' profile. This can be INTRUSIVE/DESTRUCTIVE. Proceed?"
    if not user_confirm(prompt, config):
        print("    [!] SQLMap execution cancelled by user.")
        state.update_module_findings("sqlmap_results", {"status": "Cancelled by user"})
        state.mark_phase_executed("sqlmap") # Mark as executed even if cancelled
        state.save_state()
        return

    state.update_module_findings("sqlmap_results", {"status": "Running"})
    sqlmap_log_dir = os.path.join(config["output_dir"], "sqlmap_logs")
    os.makedirs(sqlmap_log_dir, exist_ok=True)
    sqlmap_timeout = config.get("sqlmap_timeout_per_target", 7200)

    vulnerable_found_list = []

    for i, sqli_target_url in enumerate(final_target_list):
        print(f"\n    Testing SQLMap target {i+1}/{len(final_target_list)}: {sqli_target_url}")
        current_targets_tested = state.get_module_findings("sqlmap_results").get("targets_tested", [])
        if sqli_target_url not in current_targets_tested: # Ensure no duplicates if re-run
            current_targets_tested.append(sqli_target_url)
        # Corrected variable name below
        state.update_module_findings("sqlmap_results", {"targets_tested": current_targets_tested}) 


        # Use get_scan_filename_prefix to get the base for the overall scan run
        base_filename_for_run = get_scan_filename_prefix(state, config) # Overall scan prefix
        # Sanitize target URL for filename (use hostname primarily)
        parsed_sqli_url = urlparse(sqli_target_url)
        sanitized_target_host_part = sanitize_filename(parsed_sqli_url.netloc + parsed_sqli_url.path.replace("/", "_"))
        sqlmap_run_log_file = os.path.join(sqlmap_log_dir, f"{os.path.basename(base_filename_for_run)}_sqlmap_{sanitized_target_host_part[:50]}.log")

        command = ["sqlmap", "-u", sqli_target_url]
        # Get profile-specific or default options
        sqlmap_options_key = f"sqlmap_options_{profile_name}" # e.g., sqlmap_options_aggressive
        sqlmap_options_str = config.get(sqlmap_options_key, config.get("sqlmap_options_default", "--batch --random-agent"))
        sqlmap_cli_options = sqlmap_options_str.format(DEFAULT_USER_AGENT=config.get('default_user_agent', '')).split()
        command.extend(sqlmap_cli_options)

        # Add tamper scripts if configured
        tamper_config_key = f"sqlmap_tamper_scripts_{profile_name}"
        default_tamper_key = "sqlmap_tamper_scripts_default"
        tamper_scripts_str = config.get(tamper_config_key, config.get(default_tamper_key, ""))
        if tamper_scripts_str:
            command.extend(["--tamper", tamper_scripts_str])
            print(f"      Using tamper scripts: {tamper_scripts_str}")

        # Control output directory to keep sessions separate per target if desired (can conflict with --batch sometimes)
        # Consider making session/output dir configurable per target or globally
        # sqlmap_session_output_dir = os.path.join(config["output_dir"], "sqlmap_sessions", f"{os.path.basename(base_filename_for_run)}_{sanitized_target_host_part}_sessiondata")
        # command.extend(["--output-dir", sqlmap_session_output_dir])

        print(f"      Executing: {' '.join(command)}")
        log_content_header = f"SQLMap run for: {sqli_target_url}\nProfile: {profile_name}\nCommand: {' '.join(command)}\n\n"
        log_path = None
        is_vulnerable = False
        error_msg = None

        try:
            with open(sqlmap_run_log_file, 'w', errors='ignore') as log_f:
                log_f.write(log_content_header)
                # Use Popen for streaming output
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, errors='ignore')
                for line in process.stdout:
                    sys.stdout.write(line)
                    log_f.write(line)
                process.wait(timeout=sqlmap_timeout)
            log_path = sqlmap_run_log_file # Log file was created and written to

            # Check log content for vulnerability indicators
            with open(sqlmap_run_log_file, 'r', errors='ignore') as f_check:
                 log_text_for_check = f_check.read() # Keep case for regex accuracy if needed, or use re.IGNORECASE

            # Refined vulnerability detection patterns
            # Pattern 1: "parameter 'X' is vulnerable"
            vuln_param_direct_match = re.search(r"parameter\s+'([^']+)'\s+is\s+vulnerable", log_text_for_check, re.IGNORECASE)
            # Pattern 2: "[CRITICAL] ... parameter 'X' appears to be '...' injectable"
            vuln_param_critical_match = re.search(r"\[critical\].*parameter\s+'([^']+)'\s+appears\s+to\s+be.*?injectable", log_text_for_check, re.IGNORECASE)
            # Pattern 3: "identified the following injection point(s) with a total of X payload(s):" followed by details
            injection_points_summary = re.search(r"identified the following injection point\(s\)", log_text_for_check, re.IGNORECASE)
            # Pattern 4: SQLMap's data table summary for a vulnerable parameter
            # Example: --- \nparameter: id (GET)\n    type: boolean-based blind\n ... ---
            injection_table_match = re.search(r"---\s*\nparameter:\s*.+\((GET|POST)\)\s*\n\s+type:\s*.+\n", log_text_for_check, re.IGNORECASE)
            # Pattern 5: "all tested parameters do not appear to be injectable" - indicates NOT vulnerable
            not_vulnerable_explicit = "all tested parameters do not appear to be injectable" in log_text_for_check.lower()
            # Pattern 6: "it looks like the back-end DBMS is" - often precedes detailed vuln info
            dbms_identified_positive = "it looks like the back-end dbms is" in log_text_for_check.lower() and not not_vulnerable_explicit


            if vuln_param_direct_match or vuln_param_critical_match or injection_points_summary or injection_table_match or dbms_identified_positive:
                if not_vulnerable_explicit:
                    print(f"      [-] SQLMap explicitly stated no injection found for {sqli_target_url}, despite other keywords.")
                    is_vulnerable = False
                else:
                    is_vulnerable = True
                    details = []
                    if vuln_param_direct_match: details.append(f"Directly stated vulnerable parameter: {vuln_param_direct_match.group(1)}")
                    if vuln_param_critical_match: details.append(f"Critically identified injectable parameter: {vuln_param_critical_match.group(1)}")
                    if injection_points_summary: details.append("Summary of injection points found.")
                    if injection_table_match: details.append("Detailed injection table present.")
                    if dbms_identified_positive and not details: details.append("DBMS identified and no explicit non-vulnerable message.") # Only if other checks didn't catch it
                    print(f"      [+] VULNERABLE: SQLMap indicates potential vulnerability for {sqli_target_url}. Details: {'; '.join(details)}. Review log: {sqlmap_run_log_file}")

            if is_vulnerable:
                vulnerable_found_list.append(sqli_target_url)
                state.add_critical_alert(f"SQLMap: VULNERABLE - {sqli_target_url}. REVIEW LOGS.")
                vuln_id = f"sqli_{sanitize_filename(sqli_target_url)}_{profile_name}" # Make ID more unique
                state.add_remediation_suggestion(vuln_id, {
                    "source": "SQLMap",
                    "description": f"SQLMap reported potential SQL injection vulnerability at URL (or parameters within): {sqli_target_url}. See log: {sqlmap_run_log_file}",
                    "severity": "critical", "tags": ["sqli", "database"],
                    "remediation": "Immediately investigate and fix the injection point(s). Implement parameterized queries/prepared statements server-side. Perform strict input validation and sanitization. Apply principle of least privilege to database user."
                 })

                # --- Attempt Dumping if Enabled and Vulnerable ---
                if config.get("sqlmap_enable_dumping", False):
                    print(f"      [*] Vulnerability found and dumping enabled. Attempting dump for {sqli_target_url}...")
                    # Use the same base options for the dump command for session reuse
                    dump_command = ["sqlmap", "-u", sqli_target_url] + sqlmap_cli_options
                    dump_options_str = config.get("sqlmap_dump_options", "--dump --exclude-sysdbs")
                    dump_command.extend(dump_options_str.split())

                    sqlmap_dump_log_file = os.path.join(sqlmap_log_dir, f"{os.path.basename(base_filename_for_run)}_sqlmap_dump_{sanitized_target_host_part[:50]}.log")
                    dump_log_content_header = f"SQLMap DUMP run for: {sqli_target_url}\nProfile: {profile_name}\nCommand: {' '.join(dump_command)}\n\n"
                    dump_error_msg = None
                    dump_log_path = None

                    try:
                        with open(sqlmap_dump_log_file, 'w', errors='ignore') as dump_log_f:
                            dump_log_f.write(dump_log_content_header)
                            dump_process = subprocess.Popen(dump_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, errors='ignore')
                            for line in dump_process.stdout:
                                sys.stdout.write(line) # Show dump progress
                                dump_log_f.write(line)
                            dump_process.wait(timeout=sqlmap_timeout) # Use same timeout for dump attempt
                        dump_log_path = sqlmap_dump_log_file
                        print(f"      [+] SQLMap dump attempt finished. Review log: {sqlmap_dump_log_file}")
                    except subprocess.TimeoutExpired:
                        dump_error_msg = f"{sqlmap_dump_log_file} (DUMP TIMED OUT after {sqlmap_timeout}s)"
                        print(f"      [-] SQLMap dump attempt timed out for {sqli_target_url}.")
                        state.add_tool_error(f"SQLMap Dump Timeout: {sqli_target_url}")
                    except Exception as e:
                        dump_error_msg = f"{sqlmap_dump_log_file} (DUMP ERROR: {e})"
                        print(f"      [-] SQLMap dump execution error for {sqli_target_url}: {e}")
                        state.add_tool_error(f"SQLMap Dump Error: {sqli_target_url} - {e}")
                    finally:
                        # Log dump attempt result
                        current_logs = state.get_module_findings("sqlmap_results").get("logs", {})
                        dump_log_key = f"{sqli_target_url}_dump"
                        current_logs[dump_log_key] = dump_error_msg if dump_error_msg else dump_log_path if dump_log_path else "Dump log creation failed"
                        state.update_module_findings("sqlmap_results", {"logs": current_logs})

            else:
                print(f"      [-] SQLMap did not definitively report an injection for {sqli_target_url}. Manual log review recommended.")

        except subprocess.TimeoutExpired:
            error_msg = f"{sqlmap_run_log_file} (CHECK TIMED OUT after {sqlmap_timeout}s)"
            print(f"      [-] SQLMap check timed out for {sqli_target_url}.")
            state.add_tool_error(f"SQLMap Check Timeout: {sqli_target_url}")
        except Exception as e:
            error_msg = f"{sqlmap_run_log_file} (CHECK ERROR: {e})"
            print(f"      [-] SQLMap check execution error for {sqli_target_url}: {e}")
            state.add_tool_error(f"SQLMap Check Error: {sqli_target_url} - {e}")
        finally:
            # Update log path in findings, even if error occurred
             current_logs = state.get_module_findings("sqlmap_results").get("logs", {})
             current_logs[sqli_target_url] = error_msg if error_msg else log_path if log_path else "Check log creation failed"
             state.update_module_findings("sqlmap_results", {"logs": current_logs})


    # Final update after loop
    final_status = state.get_module_findings("sqlmap_results").get("status", "Unknown")
    if final_status == "Running": final_status = "Completed" # Update status if it was still running
    state.update_module_findings("sqlmap_results", {"status": final_status, "vulnerable_targets": vulnerable_found_list})
    state.mark_phase_executed("sqlmap")
    state.save_state()
