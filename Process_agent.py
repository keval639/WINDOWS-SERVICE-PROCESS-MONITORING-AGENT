import psutil
import datetime
import time
import os

# --- CONFIGURATION ---
LOG_FILE = "process_alerts.txt"

# SUSPICIOUS PATTERNS: [Parent Process, Child Process]
# Example: If 'winword.exe' spawns 'cmd.exe', it's likely a macro virus.
SUSPICIOUS_CHAINS = [
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe"), # Sometimes suspicious
    ("chrome.exe", "cmd.exe")
]

def log_alert(message):
    """Saves alerts to file and prints them"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] {message}"
    print(full_msg)
    with open(LOG_FILE, "a") as f:
        f.write(full_msg + "\n")

def get_process_tree():
    """Scans all active processes and their parents"""
    processes = []
    try:
        # Iterate over all running processes
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        print(f"Error scanning processes: {e}")
    return processes

def analyze_behavior():
    """Checks for bad parent-child chains"""
    print("[*] Scanning Process Tree for Anomalies...")
    
    # Get all current processes
    all_procs = get_process_tree()
    
    # Create a dictionary for quick lookups {pid: name}
    proc_map = {p['pid']: p['name'].lower() for p in all_procs}

    found_threat = False
    for p in all_procs:
        child_name = p['name'].lower()
        parent_pid = p['ppid']
        
        # If we know the parent's name
        if parent_pid in proc_map:
            parent_name = proc_map[parent_pid]
            
            # Check against our suspicious list
            for bad_parent, bad_child in SUSPICIOUS_CHAINS:
                if parent_name == bad_parent and child_name == bad_child:
                    log_alert(f"THREAT DETECTED: Suspicious Chain! Parent: {parent_name} ({parent_pid}) -> Child: {child_name} ({p['pid']})")
                    found_threat = True

    if not found_threat:
        print("[+] System Clean. No suspicious chains found.")

# --- MAIN LOOP ---
if __name__ == "__main__":
    print("="*50)
    print(" Windows Service & Process Monitoring Agent")
    print("="*50)
    
    try:
        while True:
            analyze_behavior()
            time.sleep(5) # Scan every 5 seconds
    except KeyboardInterrupt:
        print("\n[!] Monitor Stopped.")
