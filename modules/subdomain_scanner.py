import os
import re
import dns.resolver # Requires dnspython
from core.tool_runner import run_command
from core.utils import get_scan_filename_prefix, sanitize_filename

def run_scan(state, config):
    """
    Performs subdomain enumeration using Subfinder and optional takeover checks.
    """
    target_info = state.get_full_state()["scan_metadata"]["target_info"]
    base_domain = target_info.get("hostname") # Use the main hostname as the base domain

    if not config.get("enable_subdomain_scan", False):
        print("[i] Subdomain scanning disabled in configuration. Skipping.")
        state.update_module_findings("subdomain_scanner", {"status": "Disabled in Config"})
        state.mark_phase_executed("subdomain_scan") # Mark as "executed" (skipped)
        state.save_state()
        return

    if state.get_full_state()["tool_checks"].get("subfinder", {}).get("status") != "Found":
        print("[!] Subfinder tool not found or check failed. Skipping subdomain scan.")
        state.update_module_findings("subdomain_scanner", {"status": "Skipped (Subfinder Missing)"})
        state.mark_phase_executed("subdomain_scan")
        state.save_state()
        return

    print(f"\n[*] Phase Subdomain: Enumerating subdomains for {base_domain}")
    state.update_module_findings("subdomain_scanner", {
        "base_domain": base_domain,
        "status": "Running Subfinder",
        "subdomains_found": [],
        "takeover_checks": {"status": "Not Run", "potential_takeovers": []}
    })

    base_filename = get_scan_filename_prefix(state, config)
    subfinder_output_file = f"{base_filename}_subfinder.txt"

    subfinder_options = config.get("subfinder_options", "-silent").split()
    command = ["subfinder", "-d", base_domain, "-o", subfinder_output_file] + subfinder_options
    subfinder_timeout = config.get("subfinder_timeout", 600)

    process_obj = run_command(command, "Subfinder", config, timeout=subfinder_timeout, return_proc=True)

    subdomains = []
    if process_obj and process_obj.returncode == 0 and os.path.exists(subfinder_output_file):
        print(f"[+] Subfinder completed. Results: {subfinder_output_file}")
        with open(subfinder_output_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        state.update_module_findings("subdomain_scanner", {"status": "Subdomains Enumerated", "subdomains_found": subdomains})
        state.add_summary_point(f"Subfinder found {len(subdomains)} subdomains for {base_domain}.")
        if subdomains:
             print(f"    [i] Found {len(subdomains)} subdomains. Example: {', '.join(subdomains[:3])}{'...' if len(subdomains)>3 else ''}")
    elif process_obj:
        error_msg = f"Subfinder failed. RC: {process_obj.returncode}. Check errors."
        state.update_module_findings("subdomain_scanner", {"status": "Subfinder Failed", "error": error_msg})
        state.add_tool_error(f"Subfinder Failed: RC={process_obj.returncode}, stderr={process_obj.stderr}")
    else:
        state.update_module_findings("subdomain_scanner", {"status": "Subfinder Execution Error"})
        # Tool error already logged by run_command

    # --- Subdomain Takeover Check ---
    if subdomains and config.get("enable_subdomain_takeover_check", False):
        _check_subdomain_takeovers(state, config, subdomains)
    elif config.get("enable_subdomain_takeover_check", False):
         state.update_module_findings("subdomain_scanner", {"takeover_checks": {"status": "Skipped (No Subdomains Found)"}})


    state.mark_phase_executed("subdomain_scan")
    state.save_state()


def _check_subdomain_takeovers(state, config, subdomains):
    print("\n    --- Checking for Potential Subdomain Takeovers ---")
    takeover_module_findings = state.get_module_findings("subdomain_scanner", {}).get("takeover_checks", {"status": "Running", "potential_takeovers": []})
    takeover_module_findings["status"] = "Running"

    cname_patterns = config.get("takeover_check_cname_patterns", [])
    potential_takeovers = takeover_module_findings.get("potential_takeovers", [])

    if not cname_patterns:
        print("      [i] No CNAME patterns for takeover checks configured. Skipping detailed CNAME checks.")
        takeover_module_findings["status"] = "Skipped (No Patterns)"
        state.update_module_findings("subdomain_scanner", {"takeover_checks": takeover_module_findings})
        return

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for sub in subdomains:
        print(f"      Checking CNAME for: {sub}")
        try:
            answers = resolver.resolve(sub, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target).rstrip('.')
                # print(f"        CNAME -> {cname_target}")
                for pattern in cname_patterns:
                    if pattern.lower() in cname_target.lower():
                        # Further check if the service is actually vulnerable (e.g., NXDOMAIN for the CNAME target, or specific error messages)
                        # This basic check just flags based on pattern match.
                        # A true takeover check would try to resolve the CNAME target itself.
                        is_vulnerable_flag = False
                        try:
                            # Check if the CNAME target itself has an A record or gives NXDOMAIN
                            # This is a very simplified check. Real takeover tools do more.
                            cname_target_answers = resolver.resolve(cname_target, 'A')
                            if not cname_target_answers: # No A record might be one indicator
                                 # is_vulnerable_flag = True # This is not always true
                                 pass
                        except dns.resolver.NXDOMAIN:
                            is_vulnerable_flag = True # CNAME points to something that doesn't exist = strong indicator
                            print(f"        [!!!] POTENTIAL TAKEOVER: {sub} CNAMEs to {cname_target} (Pattern: {pattern}) which resulted in NXDOMAIN.")
                        except dns.resolver.NoAnswer:
                            # No answer for CNAME target's A record might also be an indicator
                            # print(f"        [!] INFO: {sub} CNAMEs to {cname_target} (Pattern: {pattern}) but CNAME target has no A record.")
                            pass # Not a strong indicator by itself

                        if is_vulnerable_flag:
                            details = {"subdomain": sub, "cname_target": cname_target, "matched_pattern": pattern, "status": "Potential NXDOMAIN Takeover"}
                            potential_takeovers.append(details)
                            state.add_critical_alert(f"Potential Subdomain Takeover: {sub} CNAMEs to non-existent {cname_target} (Pattern: {pattern})")
                            state.add_remediation_suggestion(f"sub_takeover_{sanitize_filename(sub)}", {
                                "source": "Subdomain Scanner",
                                "description": f"Subdomain '{sub}' CNAMEs to '{cname_target}' which appears to be claimable (NXDOMAIN). Matched pattern: '{pattern}'.",
                                "severity": "High",
                                "remediation": f"Remove the DNS CNAME record for '{sub}' or claim the resource at '{cname_target}' on the respective service."
                            })
                        elif pattern.lower() in cname_target.lower(): # Log even if not NXDOMAIN, for manual check
                            print(f"        [i] INFO: {sub} CNAMEs to {cname_target} (Pattern: {pattern}). Manual verification for takeover needed.")
                            details = {"subdomain": sub, "cname_target": cname_target, "matched_pattern": pattern, "status": "Pattern Matched - Manual Verification Required"}
                            potential_takeovers.append(details)


        except dns.resolver.NXDOMAIN:
            # print(f"        No CNAME record (or A/AAAA) found for {sub} (NXDOMAIN).")
            pass # Subdomain itself doesn't exist, not a CNAME takeover issue
        except dns.resolver.NoAnswer:
            # print(f"        No CNAME record found for {sub} (NoAnswer).")
            pass
        except dns.exception.Timeout:
            print(f"        DNS query timed out for {sub}.")
        except Exception as e:
            print(f"        Error resolving CNAME for {sub}: {e}")
        time.sleep(0.1) # Small delay

    takeover_module_findings["potential_takeovers"] = potential_takeovers
    takeover_module_findings["status"] = "Completed"
    state.update_module_findings("subdomain_scanner", {"takeover_checks": takeover_module_findings})