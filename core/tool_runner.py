import subprocess
import os
import sys

# Note: Consider passing 'state' to this function if you want to log tool errors directly from here.
# For now, error logging is handled by the calling modules based on the return value.

def run_command(command_list, tool_name, config, timeout=None, capture_output=True, text=True, check=False, cwd=None, shell=False, return_proc=False, log_file_path=None):
    """
    Executes an external tool command using subprocess.run or Popen for live logging.

    Args:
        command_list (list): The command and its arguments. The first element should be the tool key
                             name found in config['tool_paths'] or the direct command.
        tool_name (str): The user-friendly name of the tool (for logging).
        config (dict): The loaded configuration dictionary.
        timeout (int, optional): Timeout in seconds. Defaults to None.
        capture_output (bool, optional): Capture stdout/stderr (if not live logging). Defaults to True.
        text (bool, optional): Decode stdout/stderr as text. Defaults to True.
        check (bool, optional): Raise CalledProcessError if return code is non-zero. Defaults to False.
        cwd (str, optional): Working directory for the command. Defaults to None.
        shell (bool, optional): Execute command through the shell (use with caution). Defaults to False.
        return_proc(bool, optional): If True, return the CompletedProcess or Popen object. Defaults to False.
        log_file_path (str, optional): If provided, stream stdout/stderr to this file and console.

    Returns:
        subprocess.CompletedProcess or subprocess.Popen or str or None:
            - If log_file_path is provided: Returns the Popen object.
            - Else if return_proc is True: Returns the subprocess.CompletedProcess object or None on execution error.
            - Else if capture_output is True: Returns stdout string or None on error.
            - Else: Returns empty string or None on error.
    """
    if not command_list:
        print(f"[-] {tool_name}: Empty command list provided.")
        return None

    tool_path_key = command_list[0]
    tool_paths = config.get('tool_paths', {})
    actual_command_path = tool_paths.get(tool_path_key, tool_path_key) # Fallback to key if not in config

    final_command_list = [actual_command_path] + command_list[1:]

    default_ua = config.get('default_user_agent', 'OmegaScytheDominator')
    final_command_list = [
        str(arg).replace('{DEFAULT_USER_AGENT}', default_ua) if isinstance(arg, str) else str(arg)
        for arg in final_command_list
    ]

    print(f"    Executing ({tool_name}): {' '.join(final_command_list)}")
    process_obj = None
    try:
        if log_file_path:
            # Live streaming to file and console
            # Ensure log_file_path directory exists (caller should handle or we add it here)
            # os.makedirs(os.path.dirname(log_file_path), exist_ok=True) # Optional: ensure dir
            with open(log_file_path, 'w', errors='ignore') as log_f:
                process_obj = subprocess.Popen(
                    final_command_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, # Redirect stderr to stdout
                    text=text,
                    bufsize=1, # Line buffered
                    universal_newlines=True, # Ensures text mode works across platforms
                    cwd=cwd,
                    shell=shell,
                    errors='ignore'
                )
                log_f.write(f"Executing: {' '.join(final_command_list)}\n\n")
                for line in process_obj.stdout:
                    sys.stdout.write(line) # Print to console
                    log_f.write(line)     # Write to log file
                process_obj.wait(timeout=timeout) # Wait for completion with timeout
            # After Popen, returncode is available on the object.
            # If return_proc is True, the Popen object itself is returned.
            # The caller will need to check process_obj.returncode.
            return process_obj if return_proc else process_obj.returncode # Or just the object
        else:
            # Standard subprocess.run
            process_obj = subprocess.run(
                final_command_list,
                capture_output=capture_output,
                text=text,
                timeout=timeout,
                check=check,
                cwd=cwd,
                shell=shell,
                errors='ignore'
            )
            return process_obj if return_proc else (process_obj.stdout if capture_output else "")

    except FileNotFoundError:
        msg = f"{tool_name}: Command '{actual_command_path}' not found. Check PATH and config['tool_paths']."
        print(f"[-] {msg}")
    except subprocess.TimeoutExpired:
        msg = f"{tool_name}: Command timed out after {timeout} seconds."
        print(f"[-] {msg}")
        if process_obj and hasattr(process_obj, 'kill'): # For Popen
            process_obj.kill()
            process_obj.wait()
    except subprocess.CalledProcessError as e: # Only if check=True and not live logging
        msg = f"{tool_name}: Command failed with RC {e.returncode}. STDERR: {e.stderr if e.stderr else 'N/A'}"
        print(f"[-] {msg}")
        if return_proc: return e
    except Exception as e:
        msg = f"{tool_name}: Unexpected error running command - {str(e)[:200]}"
        print(f"[-] {msg}")
        if process_obj and hasattr(process_obj, 'kill'): # For Popen
            process_obj.kill()
            process_obj.wait()

    # Fallback return for errors if not returning a process object
    if return_proc and process_obj: return process_obj # Could be Popen obj or CalledProcessError
    if return_proc: return None # If process_obj itself is None due to early error
    return None # For stdout string return type on error
