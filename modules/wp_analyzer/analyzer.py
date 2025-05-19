# Main orchestrator for the WP Analyzer module

# Import analysis functions from sibling modules
from .security_headers import analyze_security_headers
from .user_registration import analyze_user_registration
from .xml_rpc import analyze_xml_rpc
from .file_exposure import check_sensitive_file_exposure
from .login_page import analyze_login_page
from .directory_listing import check_directory_listing
from .debug_exposure import check_wp_debug_exposure
from .rest_api import analyze_rest_api_user_enum
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

    analysis_steps = [
        ("Security Headers", analyze_security_headers, "analyzer_sec_headers"),
        ("User Registration & Roles", analyze_user_registration, "analyzer_user_reg"),
        ("XML-RPC Interface", analyze_xml_rpc, "analyzer_xml_rpc"),
        ("Sensitive File Exposures", check_sensitive_file_exposure, "analyzer_file_exposure"),
        ("Login Page", analyze_login_page, "analyzer_login_page"),
        ("Directory Listing", check_directory_listing, "analyzer_dir_listing"),
        ("WP_DEBUG Exposure", check_wp_debug_exposure, "analyzer_wp_debug"),
        ("REST API User Enumeration", analyze_rest_api_user_enum, "analyzer_rest_user_enum"),
        ("AJAX Action Analysis", analyze_ajax_actions, "analyzer_ajax_actions"),
        ("Theme/Plugin Vulnerabilities", analyze_extensions, "analyzer_extensions"), # Added extension scanner step
        ("Core Version & Vulnerabilities", analyze_core_version, "analyzer_core_vuln"), # Added core vuln checker step
        ("Contextual XSS Checks", analyze_xss, "analyzer_xss"), # Added XSS checker step
        ("Contextual SQLi Checks", analyze_sqli, "analyzer_sqli"), # Added SQLi checker step
        ("Contextual SSRF Checks", analyze_ssrf, "analyzer_ssrf"), # Added SSRF checker step
        ("File Inclusion Checks (LFI/RFI)", analyze_file_inclusion, "analyzer_file_inclusion"), # Added File Inclusion checker step
        ("Configuration Audit", analyze_configuration, "analyzer_config_audit"), # Added Config Audit checker step
        ("Authentication Hardening", analyze_auth_hardening, "analyzer_auth_hardening"), # Added Auth Hardening step
        ("Advanced User Enumeration", analyze_advanced_user_enum, "analyzer_adv_user_enum"), # Added Advanced User Enum step
        ("Admin Area Security", analyze_admin_area_security, "analyzer_admin_sec"), # Added Admin Area Security step
        ("Comment Security", analyze_comment_security, "analyzer_comment_sec"), # Added Comment Security step
        ("Custom Endpoint Fuzzing", analyze_custom_endpoints, "analyzer_custom_fuzz"), # Added Custom Endpoint Fuzzer step
        ("Cron Job Analysis", analyze_cron, "analyzer_cron"), # Added Cron checker step
        ("Multisite Specific Checks", analyze_multisite, "analyzer_multisite"), # Added Multisite checker step
        # Add other analyses here if implemented
    ]

    for name, func, phase_marker in analysis_steps:
        try:
            print(f"\n  --- Analyzing {name} ---")
            func(state, config, target_url) # Call the specific analysis function
            state.mark_phase_executed(phase_marker) # Mark individual sub-phase
        except Exception as e:
            print(f"    [-] Error during {name} analysis: {e}")
            # Log the error in the specific sub-module's findings if possible,
            # otherwise log a general error for the wp_analyzer module.
            # Example: Update the status of the specific finding key if known.
            # This requires mapping the function/name back to the findings key.
            # For simplicity, we can log a general error note here.
            state.add_error_log(module_key, f"Error in {name}: {e}")
            # Optionally update the status for the specific finding key if easily mappable
            # e.g., if name == "Security Headers": state.update_module_findings(...)

    print("\n[i] Advanced WordPress analysis phase finished.")
    # Final save of state is typically handled by the main loop after the module finishes.
    state.mark_phase_executed("wp_analyzer_full") # Mark the entire module as completed
