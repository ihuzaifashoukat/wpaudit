import re
from urllib.parse import urljoin, urlparse
from core.utils import sanitize_filename # Core utils needed here
from .utils import make_request # Local utils for requests

def _parse_wp_config_content(content, source_url, state, module_key):
    """Helper function to parse potential wp-config content for sensitive info."""
    print(f"      Attempting to parse content from presumed wp-config backup: {source_url}")
    # Initialize structure for parsed details within the main findings dictionary
    analyzer_findings = state.get_module_findings(module_key, {})
    exposure_details = analyzer_findings.get("sensitive_file_exposure", {})
    if "parsed_config_files" not in exposure_details:
        exposure_details["parsed_config_files"] = []
    parsed_configs = exposure_details["parsed_config_files"]

    found_config_details = {"source_url": source_url, "parsed_items": {}}
    db_creds_found = False

    # Regex for define('KEY', 'VALUE'); - handles single and double quotes
    define_pattern = re.compile(r"define\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)\s*;")
    matches = define_pattern.findall(content)
    
    # Store actual credentials temporarily for command generation, but obfuscate for general reporting
    extracted_creds = {}

    for key, value in matches:
        # List of sensitive keys to look for
        db_keys = ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"]
        other_sensitive_keys = [
            "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
            "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"
        ]
        
        if key in db_keys:
            extracted_creds[key] = value # Store actual value for potential command generation
            found_config_details["parsed_items"][key] = "********" if key == "DB_PASSWORD" else value
            db_creds_found = True
        elif key in other_sensitive_keys:
            found_config_details["parsed_items"][key] = "********" # Obfuscate salts and keys
            
        # Check for WP_DEBUG specifically
        if key == "WP_DEBUG" and value.lower() == "true":
            found_config_details["parsed_items"]["WP_DEBUG"] = "true"
            state.add_remediation_suggestion("wp_debug_enabled_config", {
                "source": "WP Analyzer",
                "description": f"WP_DEBUG is enabled in an exposed configuration file ({source_url}).",
                "severity": "Medium",
                "remediation": "Disable WP_DEBUG on production sites."
            })

    if db_creds_found:
        print("      [!!!] Database credentials potentially found in exposed config!")
        state.add_critical_alert(f"DB Credentials potentially found in exposed config: {source_url}")
        found_config_details["parsed_items"]["DB_CREDENTIALS_HINT"] = "Present (Details partially obfuscated in report)"
        
        # Add extracted (but not fully reported) creds to the specific config detail for this file
        # This is sensitive; ensure it's handled carefully and not broadly logged.
        found_config_details["_extracted_db_credentials"] = extracted_creds 

    # Append the parsed details to the list
    parsed_configs.append(found_config_details)
    exposure_details["parsed_config_files"] = parsed_configs
    analyzer_findings["sensitive_file_exposure"] = exposure_details
    state.update_module_findings(module_key, analyzer_findings)
    
    return extracted_creds if db_creds_found else None


def check_sensitive_file_exposure(state, config, target_url):
    """Checks for publicly accessible sensitive files."""
    module_key = "wp_analyzer"
    analyzer_findings = state.get_module_findings(module_key, {})
    # Ensure the specific key exists before trying to access sub-keys
    if "sensitive_file_exposure" not in analyzer_findings:
        analyzer_findings["sensitive_file_exposure"] = {"status": "Running", "found_files": []}
    exposure_details = analyzer_findings["sensitive_file_exposure"]

    # Expanded list of sensitive files and backup patterns
    sensitive_files = [
        # Config files and backups
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old", "wp-config.php.save",
        "wp-config.php.swp", "wp-config.php.txt", "wp-config.php~", "wp-config.bak",
        "wp-config.old", "wp-config.save", ".wp-config.php.swp", "config.php.bak",
        # Logs
        "debug.log", "wp-content/debug.log", "logs/debug.log", "error.log", "php_error.log",
        "error_log", "php_errors.log", "access.log", "access_log",
        # Environment files
        ".env", ".env.example", ".env.local", ".env.dev", ".env.prod", ".env.bak",
        # Database dumps
        "dump.sql", "backup.sql", "db.sql", "database.sql", "site.sql", "wordpress.sql",
        "data.sql", "export.sql", "wp_backup.sql",
        # PHP config/info
        "php.ini", "php.ini.bak", ".user.ini", ".user.ini.bak",
        "phpinfo.php", "info.php", "test.php", "phpversion.php",
        # Common archive formats
        "backup.zip", "site.zip", "wordpress.zip", "wp.zip", "files.zip",
        "backup.tar.gz", "site.tar.gz", "wordpress.tar.gz", "wp.tar.gz", "files.tar.gz",
        "backup.rar", "site.rar", "wordpress.rar", "wp.rar", "files.rar",
        # Version control system files
        ".git/config", ".svn/wc.db",
        # Dependency management files
        "composer.json", "composer.lock", "package.json", "yarn.lock"
    ]
    # Note: Dynamic pattern generation (e.g., timestamps) could be added but increases complexity.

    base_parsed_url = urlparse(target_url)
    # Ensure found_files list exists
    if "found_files" not in exposure_details:
        exposure_details["found_files"] = []
    found_files_list = exposure_details["found_files"]

    for file_path in sensitive_files:
        # Define potential locations for the file
        test_urls = []
        # 1. At the web root
        test_urls.append(urljoin(target_url, file_path))
        # 2. Inside common WP directories (unless path already includes it)
        if not any(wp_dir in file_path for wp_dir in ["wp-content/", "wp-includes/", "wp-admin/"]):
            test_urls.append(urljoin(f"{base_parsed_url.scheme}://{base_parsed_url.netloc}/wp-includes/", file_path))
            test_urls.append(urljoin(f"{base_parsed_url.scheme}://{base_parsed_url.netloc}/wp-admin/", file_path))
            # wp-content is often handled by paths like wp-content/debug.log already in the list

        # Check unique URLs
        for test_url in set(test_urls):
            print(f"    Checking for sensitive file: {test_url}")
            # Use GET to retrieve content for basic checks
            response = make_request(test_url, config, method="GET")

            if response and response.status_code == 200:
                # Basic content check to avoid false positives on generic 200 OK error pages
                content_type = response.headers.get("Content-Type", "").lower()
                # Check if it looks like an HTML error/redirect page rather than the actual file
                is_likely_html_error = "text/html" in content_type and any(
                    kw in response.text.lower() for kw in ["error", "not found", "forbidden", "page not found", "<!doctype html>", "redirecting"]
                )

                # Check if content length is plausible (e.g., > 0, maybe > 10 bytes to avoid tiny files)
                plausible_size = len(response.content) > 10

                if not is_likely_html_error and plausible_size:
                    print(f"    [!!!] POTENTIALLY SENSITIVE FILE EXPOSED: {test_url}")
                    details = {
                        "url": test_url,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "size": len(response.content)
                    }
                    # Avoid adding duplicates if run multiple times
                    if details not in found_files_list:
                        found_files_list.append(details)

                    # Determine severity based on file type
                    severity = "Medium" # Default
                    if "wp-config" in file_path or ".sql" in file_path or ".env" in file_path or ".git" in file_path or ".svn" in file_path:
                        severity = "High"
                    elif "log" in file_path or ".ini" in file_path or "phpinfo" in file_path:
                        severity = "Medium"
                    elif any(ext in file_path for ext in [".zip", ".tar.gz", ".rar"]):
                         severity = "Medium" # Could be high depending on content
                    else:
                         severity = "Low" # e.g., composer.json

                    state.add_critical_alert(f"Sensitive File Exposed ({severity}): {test_url}")
                    state.add_remediation_suggestion(f"file_expose_{sanitize_filename(file_path)}", {
                        "source": "WP Analyzer",
                        "description": f"Potentially sensitive file '{file_path}' found at {test_url}. Content should be reviewed manually.",
                        "severity": severity,
                        "remediation": "Remove publicly accessible sensitive files. Ensure proper server permissions and web server rules (e.g., .htaccess, Nginx config) to deny access to backup files, logs, environment files, VCS directories, and database dumps."
                    })

                    # If it's a potential wp-config backup, try parsing it
                    if "wp-config" in file_path and response.text:
                        extracted_db_creds = _parse_wp_config_content(response.text, test_url, state, module_key)
                        if extracted_db_creds:
                            # Check if mysql client is available (example, tool check should handle this)
                            mysql_available = state.get_full_state().get("tool_checks", {}).get("mysql", {}).get("status") == "Found"
                            
                            db_name = extracted_db_creds.get("DB_NAME")
                            db_user = extracted_db_creds.get("DB_USER")
                            db_pass = extracted_db_creds.get("DB_PASSWORD")
                            db_host = extracted_db_creds.get("DB_HOST", "localhost") # Default to localhost if not found

                            if db_name and db_user and db_pass:
                                # Add to the specific file's details in found_files_list
                                for item in found_files_list:
                                    if item["url"] == test_url:
                                        item["actionable_info"] = item.get("actionable_info", {})
                                        item["actionable_info"]["db_credentials_extracted"] = {
                                            "db_name": db_name,
                                            "db_user": db_user,
                                            "db_host": db_host,
                                            # Password is not stored here directly for safety, command uses it
                                        }
                                        if mysql_available:
                                            # Advise user on how to connect, rather than trying to perfectly escape the password in a command string.
                                            mysql_command_suggestion = f"mysql -h \"{db_host}\" -u \"{db_user}\" -p YOUR_PASSWORD_HERE \"{db_name}\" -e \"SHOW TABLES;\""
                                            suggestion_text = (
                                                f"Extracted DB credentials. Try connecting (USE WITH CAUTION):\n"
                                                f"    Host: {db_host}, User: {db_user}, DB: {db_name} (Password found but not shown here for safety).\n"
                                                f"    Example command (replace YOUR_PASSWORD_HERE or use interactive prompt):\n"
                                                f"    {mysql_command_suggestion}\n"
                                                f"    (Ensure 'mysql' client is installed. Consider using MYSQL_PWD environment variable for the password to avoid shell history issues.)"
                                            )
                                            item["actionable_info"]["suggested_db_connect_command"] = suggestion_text
                                            item["actionable_info"]["extracted_db_password_NOTE"] = "Password was extracted but is not directly included in this suggested command for security. Use the extracted password when prompted or via MYSQL_PWD."
                                            print(f"        [ACTIONABLE] {suggestion_text}")
                                            # Add a specific remediation for this actionable item
                                            state.add_remediation_suggestion(f"db_creds_exposed_connect_{sanitize_filename(file_path)}", {
                                                "source": "WP Analyzer (File Exposure)",
                                                "description": f"Database credentials found in {test_url}. Suggested manual connection command provided. IMMEDIATE ATTENTION REQUIRED.",
                                                "severity": "Critical",
                                                "remediation": f"Immediately secure or remove the exposed file ({test_url}). Change database credentials. Investigate potential unauthorized access. Review web server configurations to prevent access to sensitive files."
                                            })
                                        else:
                                            item["actionable_info"]["db_connection_note"] = "MySQL client not detected by tool checker; manual connection attempt may still be possible."
                                        break


    exposure_details["found_files"] = found_files_list
    exposure_details["status"] = "Checked"
    analyzer_findings["sensitive_file_exposure"] = exposure_details
    state.update_module_findings(module_key, analyzer_findings)
