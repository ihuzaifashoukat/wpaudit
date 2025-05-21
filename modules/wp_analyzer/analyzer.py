# Main orchestrator for the WP Analyzer module

# Ensure sanitize_filename is imported from core.utils, not from .utils
from core.utils import sanitize_filename 
# Remove any incorrect local import if it exists, e.g.:
# from .utils import sanitize_filename # THIS WOULD BE WRONG

# Import analysis functions from sibling modules
from .security_headers import analyze_security_headers
from .user_registration import analyze_user_registration
from .xml_rpc import analyze_xml_rpc
from .file_exposure import check_sensitive_file_exposure
from .login_page import analyze_login_page
from .directory_listing import check_directory_listing
from .debug_exposure import check_wp_debug_exposure
from .rest_api import analyze_rest_api_general
from .ajax_checker import analyze_ajax_actions # Import the new AJAX checker
from .extension_scanner import analyze_extensions # Import the new extension scanner
from .core_vuln_checker import analyze_core_version # Import the new core vuln checker
from .xss_checker import analyze_xss # Import the new XSS checker
from .sqli_checker import analyze_sqli # Import the new SQLi checker
from .ssrf_checker import analyze_ssrf # Import the new SSRF checker
from .file_inclusion_checker import analyze_file_inclusion # Import the new File Inclusion checker
from .config_audit import analyze_configuration # Import the new Config Audit checker
from .auth_hardening_checker import analyze_auth_hardening # Import the new Auth Hardening checker
from .advanced_user_enum import analyze_advanced_user_enum # Import the new Advanced User Enum checker
from .admin_area_security import analyze_admin_area_security # Import the new Admin Area Security checker
from .comment_security import analyze_comment_security # Import the new Comment Security checker
from .custom_endpoint_fuzzer import analyze_custom_endpoints # Import the new Custom Endpoint Fuzzer
from .cron_checker import analyze_cron # Import the new Cron checker
from .multisite_checker import analyze_multisite # Import the new Multisite checker

# We might still need urlparse here if target_url needs processing before passing
from urllib.parse import urlparse

def run_analysis(state, config):
    """
    Runs advanced WordPress specific analysis by calling sub-modules.
    Covers REST API, Security Headers, XML-RPC, Debug/Config exposure, etc.
    """
    target_url = state.get_full_state()["scan_metadata"]["target_info"]["url"]
    print(f"\n[*] Phase WP Analyzer: Advanced WordPress Analysis for {target_url}")
    module_key = "wp_analyzer" # Define module key for state updates

    # Centralize findings initialization for this module
    # Define the expected structure for findings. Sub-modules will populate these keys.
    default_analyzer_findings = {
        "security_headers": {"status": "Not Checked", "details": {}},
        "user_registration": {"status": "Not Checked", "details": {}},
        "xml_rpc": {"status": "Not Checked", "details": {}, "ssrf_via_pingback_test": {}},
        "rest_api_user_enum": {"status": "Not Checked", "exposed_users": []},
        "sensitive_file_exposure": {"status": "Not Checked", "found_files": [], "parsed_config_files": []},
        "wp_debug_exposure": {"status": "Not Checked", "exposed_on_pages": []},
        "ajax_action_analysis": {"status": "Not Checked", "tested_actions": [], "potential_issues": []},
        "extension_vulnerabilities": {"status": "Not Checked", "details": "", "enumerated_themes": [], "enumerated_plugins": [], "vulnerable_themes": [], "vulnerable_plugins": []}, # Added for extension scanner
        "core_vulnerabilities": {"status": "Not Checked", "details": "", "detected_version": None, "potential_vulnerabilities": []}, # Added for core vuln checker
        "contextual_xss": {"status": "Not Checked", "details": "", "potential_vulnerabilities": []}, # Added for XSS checker
        "contextual_sqli": {"status": "Not Checked", "details": "", "potential_vulnerabilities": []}, # Added for SQLi checker
        "contextual_ssrf": {"status": "Not Checked", "details": "", "potential_vulnerabilities": []}, # Added for SSRF checker
        "file_inclusion": {"status": "Not Checked", "details": "", "potential_lfi_vulnerabilities": [], "potential_rfi_vulnerabilities": []}, # Added for File Inclusion checker
        "configuration_audit": {"status": "Not Checked", "details": "", "db_prefix_check": {}, "security_keys_check": {}, "file_permissions_check": {}, "htaccess_check": {}}, # Added for Config Audit checker
        "auth_hardening": {"status": "Not Checked", "details": "", "password_policy_check": {}, "lockout_mechanism_check": {}, "captcha_check": {}, "two_factor_auth_check": {}}, # Added for Auth Hardening checker
        "advanced_user_enum": {"status": "Not Checked", "details": "", "author_archive_users": [], "login_error_users": []}, # Added for Advanced User Enum checker
        "admin_area_security": {"status": "Not Checked", "details": "", "standard_login_accessible": None, "standard_admin_accessible": None, "http_auth_detected": False}, # Added for Admin Area Security checker
        "comment_security": {"status": "Not Checked", "details": "", "comments_enabled": None, "spam_protection_hint": None, "potential_vulnerabilities": []}, # Added for Comment Security checker
        "custom_endpoint_fuzzing": {"status": "Not Checked", "details": "", "identified_custom_rest_routes": [], "identified_custom_ajax_actions": [], "potential_vulnerabilities": []}, # Added for Custom Endpoint Fuzzer
        "cron_analysis": {"status": "Not Checked", "details": "", "wp_cron_accessible": None, "potential_dos_risk": None}, # Added for Cron checker
        "multisite_analysis": {"status": "Not Checked", "details": "", "is_multisite_detected": False, "user_signup_check": {}, "network_settings_check": {}}, # Added for Multisite checker
        # "robots_sitemap_deep_scan": {"status": "Not Checked", "interesting_paths": []}, # Placeholder if added later
        "login_page_analysis": {"status": "Not Checked", "details": {}}, # Note: login_page_analysis might overlap/be refined by auth_hardening
        "directory_listing": {"status": "Not Checked", "vulnerable_paths": []}
    }

    # Initialize in state: Get existing findings or use defaults, ensuring all keys are present.
    existing_analyzer_findings = state.get_module_findings(module_key, {})
    for key, default_value in default_analyzer_findings.items():
        if key not in existing_analyzer_findings:
            existing_analyzer_findings[key] = default_value
        # Ensure sub-dictionaries also have default keys if the top key exists but is incomplete
        elif isinstance(default_value, dict):
             for sub_key, sub_default_value in default_value.items():
                 if sub_key not in existing_analyzer_findings[key]:
                     existing_analyzer_findings[key][sub_key] = sub_default_value

    state.update_module_findings(module_key, existing_analyzer_findings) # Save the initialized structure

    # --- Run Sub-Analyses ---
    # Each function is responsible for updating its part of the state findings.
    # Structure: (Name, function, phase_marker, condition_lambda (optional))
    # condition_lambda: A function that takes (state, config) and returns True if the step should run.

    # Helper to check conditions, can be expanded
    def should_run_multisite(current_state, current_config):
        # Placeholder: In a real scenario, this would check WPScan results or other indicators
        # For now, assume it's enabled by a config flag or always runs if module is present
        is_multisite_detected = current_state.get_module_findings("wpscan_results", {}).get("is_multisite", False) # Example dependency
        if is_multisite_detected:
            print("    [i] Condition met: Multisite detected, proceeding with multisite checks.")
            return True
        print("    [i] Condition not met: Multisite not detected by WPScan (example). Skipping multisite-specific checks.")
        # Update multisite findings to "Skipped (Not Multisite)"
        ms_findings = current_state.get_module_findings(module_key, {}).get("multisite_analysis", {})
        ms_findings["status"] = "Skipped (Not Detected as Multisite)"
        ms_findings["details"] = "Skipped as WordPress instance was not identified as a multisite setup by preceding scans."
        current_state.update_specific_finding(module_key, "multisite_analysis", ms_findings)
        return False

    def is_rest_api_generally_accessible(current_state, current_config):
        # Placeholder: Check if REST API user enum found anything or if /wp-json/ is not 403/404
        rest_api_findings = current_state.get_module_findings(module_key, {}).get("rest_api_user_enum", {})
        # A simple check: if the status isn't "Not Checked" and not explicitly an error that implies total inaccessibility.
        # This is a basic heuristic. A better check would be to see if /wp-json/ itself returns a valid JSON response.
        if rest_api_findings.get("status") not in ["Not Checked", "Skipped (Not Found)", "Error (Access Denied)"]: # Example statuses
            print("    [i] Condition met: REST API seems generally accessible, proceeding with related checks.")
            return True
        print("    [i] Condition not met: REST API does not seem generally accessible. Skipping some REST-dependent checks.")
        return False


    analysis_steps = [
        ("Security Headers", analyze_security_headers, "analyzer_sec_headers", None),
        ("User Registration & Roles", analyze_user_registration, "analyzer_user_reg", None),
        ("XML-RPC Interface", analyze_xml_rpc, "analyzer_xml_rpc", None),
        ("Sensitive File Exposures", check_sensitive_file_exposure, "analyzer_file_exposure", None),
        ("Login Page", analyze_login_page, "analyzer_login_page", None),
        ("Directory Listing", check_directory_listing, "analyzer_dir_listing", None),
        ("WP_DEBUG Exposure", check_wp_debug_exposure, "analyzer_wp_debug", None),
        ("REST API General Analysis", analyze_rest_api_general, "analyzer_rest_api_general", None), # Changed from user_enum
        ("AJAX Action Analysis", analyze_ajax_actions, "analyzer_ajax_actions", None),
        ("Theme/Plugin Vulnerabilities", analyze_extensions, "analyzer_extensions", None),
        ("Core Version & Vulnerabilities", analyze_core_version, "analyzer_core_vuln", None),
        ("Contextual XSS Checks", analyze_xss, "analyzer_xss", None),
        ("Contextual SQLi Checks", analyze_sqli, "analyzer_sqli", None),
        ("Contextual SSRF Checks", analyze_ssrf, "analyzer_ssrf", None),
        ("File Inclusion Checks (LFI/RFI)", analyze_file_inclusion, "analyzer_file_inclusion", None),
        ("Configuration Audit", analyze_configuration, "analyzer_config_audit", None),
        ("Authentication Hardening", analyze_auth_hardening, "analyzer_auth_hardening", None),
        ("Advanced User Enumeration", analyze_advanced_user_enum, "analyzer_adv_user_enum", None),
        ("Admin Area Security", analyze_admin_area_security, "analyzer_admin_sec", None),
        ("Comment Security", analyze_comment_security, "analyzer_comment_sec", None),
        ("Custom Endpoint Fuzzing", analyze_custom_endpoints, "analyzer_custom_fuzz", is_rest_api_generally_accessible), # Example conditional
        ("Cron Job Analysis", analyze_cron, "analyzer_cron", None),
        ("Multisite Specific Checks", analyze_multisite, "analyzer_multisite", should_run_multisite), # Example conditional
    ]

    for name, func, phase_marker, condition_func in analysis_steps:
        run_step = True
        if condition_func:
            try:
                run_step = condition_func(state, config)
            except Exception as ce:
                print(f"    [-] Error evaluating condition for '{name}': {ce}. Skipping step.")
                run_step = False
        
        if run_step:
            try:
                print(f"\n  --- Analyzing {name} ---")
                func(state, config, target_url) # Call the specific analysis function
                state.mark_phase_executed(phase_marker) # Mark individual sub-phase
            except Exception as e:
                print(f"    [-] Error during {name} analysis: {e}")
                error_message = f"Module: {module_key}, Sub-module: {name}, Error: {type(e).__name__} - {e}"
                state.add_tool_error(error_message)
                # Update the specific finding for this sub-module to reflect the error
                # This requires a mapping from 'name' or 'func' to the actual key in `default_analyzer_findings`
                # For now, this is a general error. Individual modules should set their own status to "Error" on failure.
        else:
            print(f"    Skipping '{name}' due to unmet conditions or conditional check error.")
            # Mark as skipped in state? The condition_func might do this already.
            # state.mark_phase_executed(phase_marker, status="Skipped") # If state supports status for phases

    print("\n[i] Advanced WordPress analysis phase finished.")
    state.mark_phase_executed("wp_analyzer_full")
