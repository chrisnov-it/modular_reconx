
import argparse
import json
import sched
import time
import sys
import os
import logging
from datetime import datetime
from termcolor import colored

# Add app directory to path so we can import modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

from app.scan import scan

def load_previous_scan(domain):
    """Loads the last scan result for the domain from the monitor file."""
    filename = f"output/monitor_{domain.replace('.', '_')}.json"
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading previous scan: {e}")
            return None
    return None

def save_monitor_state(domain, data):
    """Saves the current scan result as the new baseline."""
    filename = f"output/monitor_{domain.replace('.', '_')}.json"
    os.makedirs("output", exist_ok=True)
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[*] Monitor state saved to {filename}")
    except Exception as e:
        print(f"[!] Error saving monitor state: {e}")

def compare_scans(old_data, new_data):
    """Compares two scan results and returns a list of differences."""
    diffs = []
    
    # 1. Compare Open Ports
    old_ports = set(old_data.get("open_ports", {}).get("open_ports", {}).keys())
    new_ports = set(new_data.get("open_ports", {}).get("open_ports", {}).keys())
    
    new_open = new_ports - old_ports
    closed_ports = old_ports - new_ports
    
    if new_open:
        diffs.append(f"🚨 NEW OPEN PORTS detected: {', '.join(map(str, new_open))}")
    if closed_ports:
        diffs.append(f"ℹ️ Ports closed: {', '.join(map(str, closed_ports))}")

    # 2. Compare Subdomains
    old_subs = set(item['subdomain'] for item in old_data.get("subdomains", {}).get("found", []) if 'subdomain' in item)
    new_subs = set(item['subdomain'] for item in new_data.get("subdomains", {}).get("found", []) if 'subdomain' in item)
    
    new_subdomains = new_subs - old_subs
    if new_subdomains:
        diffs.append(f"🚨 NEW SUBDOMAINS found ({len(new_subdomains)}): {', '.join(list(new_subdomains)[:5])}...")

    # 3. Compare Vulnerabilities (Example: simple count or new CVEs)
    # This is complex because vulns structure varies. Let's just alert on ANY change in vuln count for a tech.
    old_vulns = old_data.get("vulnerabilities", {})
    new_vulns = new_data.get("vulnerabilities", {})
    
    for tech, vulns in new_vulns.items():
        if tech not in old_vulns:
             diffs.append(f"🚨 NEW VULNERABILITIES found for technology: {tech}")
        else:
            if len(vulns) > len(old_vulns[tech]):
                 diffs.append(f"🚨 INCREASED VULNERABILITY COUNT for {tech}: {len(vulns)} (was {len(old_vulns[tech])})")

    return diffs

def monitor_target(target, interval=3600, email=None):
    """Runs the monitor loop."""
    print(colored(f"[*] Starting Monitor for {target} every {interval} seconds", "cyan"))
    
    scheduler = sched.scheduler(time.time, time.sleep)
    
    def run_job():
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Running scheduled scan...")
        
        # Run the scan (store result in memory, don't just rely on file output, but we set output to json)
        # We assume scan module returns the result dict now
        try:
            # We skip 'slow' modules for monitoring to be lightweight, unless specified otherwise?
            # Let's keep it comprehensive but maybe skip bruteforce?
            # User didn't specify, so let's run a "standard" quick scan (skip bruteforce)
            scan_result, _ = scan(
                target=target,
                output_format="json",
                skip_bruteforce=True  # Monitoring usually checks infrastructure changes, bruteforce is aggressive
            )
            
            if not scan_result:
                print("[!] Scan failed.")
                scheduler.enter(interval, 1, run_job)
                return

            old_result = load_previous_scan(target)
            
            if old_result:
                print("[*] Comparing with previous baseline...")
                diffs = compare_scans(old_result, scan_result)
                
                if diffs:
                    print(colored("\n!!! CHANGES DETECTED !!!", "red", attrs=['bold']))
                    for diff in diffs:
                        print(colored(diff, "yellow"))
                    
                    if email:
                        # Placeholder for email alert
                        print(f"[TODO] Sending email alert to {email}...")
                else:
                    print(colored("[*] No significant changes detected.", "green"))
            else:
                print("[*] First run. Saving baseline.")
            
            # Update baseline
            save_monitor_state(target, scan_result)
            
        except Exception as e:
            print(f"[!] Exception during monitoring: {e}")
        
        # Schedule next run
        scheduler.enter(interval, 1, run_job)

    # Start the first job
    scheduler.enter(0, 1, run_job)
    try:
        scheduler.run()
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Modular ReconX - Monitoring Mode")
    parser.add_argument("target", help="Target domain to monitor")
    parser.add_argument("--interval", type=int, default=3600, help="Interval in seconds (default: 1 hour)")
    parser.add_argument("--email", help="Email to send alerts to (simulated)")
    
    args = parser.parse_args()
    
    monitor_target(args.target, args.interval, args.email)
