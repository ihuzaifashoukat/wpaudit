import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
from core.utils import get_scan_filename_prefix # To get consistent report names

# Basic severity mapping (can be expanded)
SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}

def save_full_report(state, config):
    """Saves the complete scan state to a JSON file."""
    # Use the state's save method which already knows the path
    state.save_state()
    print(f"[+] Full detailed report saved/updated in '{config['output_dir']}'.")


def generate_summary_report(state, config):
    """Generates and prints a text summary report to the console."""
    full_state = state.get_full_state() # Get a copy of the state
    scan_metadata = full_state.get("scan_metadata", {})
    target_info = scan_metadata.get("target_info", {})
    findings = full_state.get("findings", {})
    critical_alerts = full_state.get("critical_alerts", [])
    remediation_suggestions = full_state.get("remediation_suggestions", {})
    config_used = full_state.get("scan_config_used", {})

    print("\n" + "="*40 + " WPAUDIT - EXECUTIVE SUMMARY " + "="*40)
    print(f"Audit Target: {target_info.get('url')} (IP: {target_info.get('ip', 'N/A')})")
    print(f"Scan Profile Used: {config_used.get('profile_name', 'N/A')}")
    print(f"Scan Started: {scan_metadata.get('start_time')}")
    print(f"Scan Ended: {scan_metadata.get('end_time')}")

    # --- Pre-flight Info ---
    print("\n--- Pre-flight Scan Info ---")
    robots_info = findings.get("robots_txt_info", {})
    if robots_info.get("status") == "Found":
        print(f"  [Robots.txt]: Found. Disallowed paths: {len(robots_info.get('disallowed_paths',[]))}. Respect flag: {config.get('respect_robots_txt')}")
    elif robots_info: print(f"  [Robots.txt]: Status - {robots_info.get('status','N/A')}")

    waf_info = findings.get("waf_info", {})
    waf_status = waf_info.get("status", "Not Checked")
    if "Detected" in waf_status: print(f"  [WAF]: {waf_status}. This can influence scan results/exploitability.")
    elif waf_status not in ["Not Checked", "Disabled in Config", "Skipped (Tool Missing/Failed Check)", "Skipped (requests library missing for fallback)"]: print(f"  [WAF]: Status - {waf_status}")

    # --- Subdomain Info ---
    subdomain_results = findings.get("subdomain_scanner", {})
    subdomain_status = subdomain_results.get("status", "Not Run")
    if subdomain_status not in ["Not Run", "Disabled in Config", "Skipped (Subfinder Missing)"]:
        sub_count = len(subdomain_results.get("subdomains_found", []))
        takeover_checks = subdomain_results.get("takeover_checks", {})
        takeover_status = takeover_checks.get("status", "Not Run")
        potential_takeovers = len(takeover_checks.get("potential_takeovers", []))
        print(f"  [Subdomains]: Status - {subdomain_status}. Found: {sub_count}. Takeover Check: {takeover_status} (Potential: {potential_takeovers})")
    elif subdomain_status != "Not Run": print(f"  [Subdomains]: Status - {subdomain_status}")


    # --- Critical Alerts ---
    print("\n--- [!!!] CRITICAL & HIGH SEVERITY ALERTS (AUTOMATIC FLAGS) [!!!] ---")
    critical_alerts_summary = {}
    for alert_msg in critical_alerts:
        key = alert_msg.split(':')[0].strip()[:50] # Shorten key
        critical_alerts_summary[key] = critical_alerts_summary.get(key, 0) + 1
    if critical_alerts_summary:
        for key, count in critical_alerts_summary.items(): print(f"  -> {key}: {count} instance(s).")
    else: print("  No critical alerts automatically flagged (manual review essential).")


    # --- Vulnerability Counts & Types ---
    print("\n--- Key Vulnerability Areas Summary (Counts & Types) ---")
    # WPScan Summary
    wps_vulns = {"core": 0, "themes": 0, "plugins": 0}
    wps_results = findings.get("wpscan_results", {})
    wps_data = wps_results.get("data")
    if wps_results.get("status") == "Completed" and wps_data:
        if wps_data.get("version") and wps_data["version"].get("vulnerabilities"): wps_vulns["core"] = len(wps_data["version"]["vulnerabilities"])
        main_theme_data = wps_data.get("main_theme")
        if main_theme_data and main_theme_data.get("vulnerabilities"): wps_vulns["themes"] = len(main_theme_data["vulnerabilities"])
        plugins_data = wps_data.get("plugins")
        if plugins_data:
            for p_info in plugins_data.values():
                if p_info.get("vulnerabilities"): wps_vulns["plugins"] += len(p_info["vulnerabilities"])
        print(f"  [WPScan]: Core Vulns: {wps_vulns['core']}, Theme Vulns (main): {wps_vulns['themes']}, Plugin Vulns (total): {wps_vulns['plugins']}")
    elif wps_results: print(f"  [WPScan]: Status - {wps_results.get('status', 'N/A')}. {wps_results.get('error','')}")

    # Nuclei Severity Summary
    nuclei_severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown":0}
    nuclei_results = findings.get("nuclei_results", {})
    nuclei_findings_list = nuclei_results.get("findings", [])
    if nuclei_results.get("status") == "Completed" or nuclei_results.get("status") == "Completed with Parse Error":
        if nuclei_findings_list:
            for finding in nuclei_findings_list: nuclei_severity_counts[finding.get("info", {}).get("severity", "unknown").lower()] += 1
            print(f"  [Nuclei]: Critical: {nuclei_severity_counts['critical']}, High: {nuclei_severity_counts['high']}, Medium: {nuclei_severity_counts['medium']}")
        else: print("  [Nuclei]: Scan completed but no findings reported.")
    elif nuclei_results: print(f"  [Nuclei]: Status - {nuclei_results.get('status', 'N/A')}. {nuclei_results.get('error','')}")

    # SQLMap Summary
    sqlmap_results = findings.get("sqlmap_results", {})
    sqlmap_status = sqlmap_results.get("status", "Not Run")
    if sqlmap_status not in ["Not Run", "Skipped (No Targets)", "Cancelled by user"]:
        sqlmap_vuln_count = len(sqlmap_results.get("vulnerable_targets", []))
        print(f"  [SQLMap]: Status - {sqlmap_status}. Potential SQL Injections found: {sqlmap_vuln_count}.")
    elif sqlmap_status != "Not Run": print(f"  [SQLMap]: Status - {sqlmap_status}.")
    # Add mention of dumping if attempted
    sqlmap_logs = sqlmap_results.get("logs", {})
    dump_logs = [k for k in sqlmap_logs if k.endswith("_dump")]
    if dump_logs: print(f"    -> Dump attempts made for {len(dump_logs)} target(s). Review logs.")


    # Directory Bruteforce Summary
    dirb_results = findings.get("directory_bruteforcer", {})
    dirb_status = dirb_results.get("status", "Not Run")
    if dirb_status not in ["Not Run", "Disabled in Config", "Skipped (ffuf Missing)", "Skipped (Wordlist Missing)", "Skipped (User Declined)"]:
        interesting_paths = len(dirb_results.get("findings_summary", []))
        print(f"  [Directory Brute]: Status - {dirb_status}. Found {interesting_paths} potentially interesting paths (non-404).")
    elif dirb_status != "Not Run": print(f"  [Directory Brute]: Status - {dirb_status}.")

    # Parameter Finder Summary
    param_results = findings.get("parameter_finder", {})
    param_status = param_results.get("status", "Not Run")
    if param_status not in ["Not Run", "Disabled in Config", "Skipped (Arjun Missing)", "Skipped (User Declined)"]:
        urls_with_params = len(param_results.get("found_parameters", {}))
        print(f"  [Parameter Finder]: Status - {param_status}. Found parameters for {urls_with_params} URL(s).")
    elif param_status != "Not Run": print(f"  [Parameter Finder]: Status - {param_status}.")


    # REST API Issues (Assuming this is from wp_analyzer)
    # Note: The key might be 'wp_analyzer' now, need to check state structure if this breaks
    rest_api_data = findings.get("wp_analyzer", {}).get("rest_api_analysis", {}) # Adjust key if needed
    if rest_api_data.get("status") == "Found":
        issues_count = len(rest_api_data.get("potential_issues", []))
        if issues_count > 0: print(f"  [WordPress REST API]: Found {issues_count} potential issues (e.g., user enumeration).")


    # --- Exploit Availability & Guidance ---
    print("\n--- Exploit Availability & Guidance ---")
    exploit_intel_results = findings.get("exploit_intelligence", {})
    exploit_data = exploit_intel_results.get("found_exploits", {})
    exploit_guidance = exploit_intel_results.get("exploit_guidance", {})
    manual_ss_cmds = exploit_guidance.get("manual_searchsploit_cmds", [])
    generated_msf_rcs = exploit_guidance.get("generated_msf_rc_files", [])
    autorun_attempts = exploit_intel_results.get("autorun_attempts", [])
    
    exploitable_queries_count = sum(1 for data in exploit_data.values() if data.get("searchsploit") or data.get("metasploit"))

    if exploit_intel_results.get("status") == "Completed":
        if exploitable_queries_count > 0:
            print(f"  Public exploits (SearchSploit/Metasploit) potentially available for {exploitable_queries_count} distinct findings.")
            
            if manual_ss_cmds:
                print("\n  [SearchSploit - Manual Commands Suggested]:")
                for cmd_info in manual_ss_cmds[:5]: # Show top 5
                    print(f"    - For '{cmd_info.get('query', 'N/A')}' (EDB-ID: {cmd_info.get('EDB-ID', 'N/A')}): {cmd_info.get('command')}")
                if len(manual_ss_cmds) > 5:
                    print("      ... (more commands in full report/logs)")
            
            if generated_msf_rcs:
                print("\n  [Metasploit - Generated Resource (.rc) Files]:")
                for rc_info in generated_msf_rcs[:5]: # Show top 5
                    print(f"    - For module '{rc_info.get('module', 'N/A')}' (Query: '{rc_info.get('query', 'N/A')}'):")
                    print(f"      Run with: msfconsole -r \"{rc_info.get('rc_file')}\"")
                if len(generated_msf_rcs) > 5:
                    print("      ... (more .rc files listed in full report/logs)")
        else:
            print("  No direct public exploits found for identified items based on current queries.")

        # Summary of autorun attempts
        if autorun_attempts:
            print("\n  [Metasploit - Autorun Attempts Summary]:")
            success_count = sum(1 for attempt in autorun_attempts if "Success" in attempt.get("status", ""))
            skipped_count = sum(1 for attempt in autorun_attempts if "Skipped" in attempt.get("status", ""))
            failed_count = len(autorun_attempts) - success_count - skipped_count
            print(f"    Attempts: {len(autorun_attempts)}, Success Indications: {success_count}, Failed/Timeout: {failed_count}, Skipped: {skipped_count}.")
            print(f"    (Note: Autorun is EXPERIMENTAL and DANGEROUS. Review logs carefully.)")

    elif exploit_intel_results and exploit_intel_results.get("status") not in ["Not Run", "Skipped (No Queries)"]:
        print(f"  Exploit Intel Status: {exploit_intel_results.get('status', 'N/A')}")
    else:
        print("  Exploit intelligence gathering was not run or skipped.")


    # --- Prioritized Remediation ---
    print("\n--- Prioritized Remediation Guidance (Top 5) ---")
    # Sort remediation suggestions by severity
    sorted_remediations = sorted(
        remediation_suggestions.items(),
        key=lambda item: SEVERITY_ORDER.get(item[1].get('severity', 'unknown'), 0),
        reverse=True
    )

    if sorted_remediations:
        count = 0
        for finding_id, details in sorted_remediations:
            if count >= 5: break
            severity = details.get('severity', 'unknown').upper()
            desc = details.get('description', 'N/A').split('.')[0] # First sentence
            source = details.get('source', 'Unknown')
            print(f"  {count+1}. [{severity} - {source}] {desc}.")
            count += 1
        if len(sorted_remediations) > 5: print("      ... (See full report for all suggestions)")
    else:
        print("  No specific high-priority remediation actions automatically generated (manual review essential).")

    print("\n  General Recommendations:")
    print("  - Patch Management, Input Validation, Secure Configuration, WAF, Log Review, Least Privilege, Regular Audits.")

    print("\n" + "="*45 + " END OF SUMMARY " + "="*45)
    # Use get_scan_filename_prefix for consistent naming with other reports
    base_report_name = state.get_report_file_prefix() # This method should exist in ScanState or be passed
    if not base_report_name: # Fallback if state method not available yet
        base_report_name = get_scan_filename_prefix(state, config)

    print(f"\n[INFO] Full detailed findings in JSON: {base_report_name}_FULL_REPORT.json")
    print(f"[INFO] HTML report generated: {base_report_name}_REPORT.html")
    print("[INFO] Individual tool logs are also in the output directory: " + config["output_dir"])

def generate_html_report(state, config):
    """Generates an HTML report from the scan state."""
    full_state = state.get_full_state()
    scan_metadata = full_state.get("scan_metadata", {})
    target_info = scan_metadata.get("target_info", {})
    findings = full_state.get("findings", {})
    critical_alerts = full_state.get("critical_alerts", [])
    remediation_suggestions = full_state.get("remediation_suggestions", {})
    config_used = full_state.get("scan_config_used", {})

    # Prepare context for Jinja2 template
    # Critical alerts summary (as used in text summary)
    critical_alerts_summary_dict = {}
    for alert_msg in critical_alerts:
        key = alert_msg.split(':')[0].strip()[:50]
        critical_alerts_summary_dict[key] = critical_alerts_summary_dict.get(key, 0) + 1
    
    # Sorted remediations (as used in text summary)
    sorted_remediations_list = sorted(
        remediation_suggestions.items(),
        key=lambda item: SEVERITY_ORDER.get(item[1].get('severity', 'unknown'), 0),
        reverse=True
    )
    tool_errors_list = full_state.get("tool_errors", []) # Get tool errors

    context = {
        "target_info": target_info,
        "scan_metadata": scan_metadata,
        "scan_config_used": config_used,
        "findings": findings, # Pass all findings, template can iterate
        "critical_alerts": critical_alerts, # Raw list
        "critical_alerts_summary": critical_alerts_summary_dict, # Summarized dict
        "remediation_suggestions": remediation_suggestions, # Raw dict
        "sorted_remediations": sorted_remediations_list, # Sorted list of tuples
        "SEVERITY_ORDER": SEVERITY_ORDER, # For potential use in template if needed
        "tool_errors": tool_errors_list # Pass tool errors to the template
    }

    try:
        # Setup Jinja2 environment
        # Assuming report_template.html is in the same directory as generator.py
        # For robustness, use absolute path or path relative to a known base dir
        template_dir = os.path.dirname(os.path.abspath(__file__))
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template("report_template.html")
        html_output = template.render(context)

        # Determine output filename
        base_report_name = state.get_report_file_prefix()
        if not base_report_name:
             base_report_name = get_scan_filename_prefix(state, config) # Fallback
        
        html_report_path = f"{base_report_name}_REPORT.html"
        
        with open(html_report_path, 'w', encoding='utf-8') as f_html:
            f_html.write(html_output)
        print(f"[+] HTML report successfully generated: {html_report_path}")
        return html_report_path
    except Exception as e:
        print(f"[!!!] Error generating HTML report: {e}")
        import traceback
        traceback.print_exc()
        return None
