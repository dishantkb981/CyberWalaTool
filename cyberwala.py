#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   ____      _               __        __     _
#  / ___|   _| |__   ___ _ __  \\ \\      / /__ _| | __ _
# | |  | | | | '_ \\ / _ \\ '__|  \\ \\ /\\ / / _` | |/ _` |
# | |__| |_| | |_) |  __/ |     \\ V  V / (_| | | (_| |
#  \\____\\__, |_.__/ \\___|_|      \\_/\\_/ \\__,_|_|\\__,_|
#       |___/
#
# Tool       : CyberWala Advance Vuln Scanner v1.2
# Usage      : python3 cyberwala.py example.com
# Description: This scanner automates the process of security scanning by using a
#              multitude of available linux security tools and some custom scripts.
# Author     : Your Name
# Website    : https://github.com/yourusername/cyberwala

import sys
import os
import argparse
import subprocess
import time
import random
import threading
import re
from urllib.parse import urlsplit
from tools import tools, run_tool, analyze_results, tool_resp, tools_fix

# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'

# Constants
CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
)

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

def vul_info(val):
    """Classifies the Vulnerability's Severity"""
    result = ''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT + " critical " + bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT + " high " + bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT + " medium " + bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT + " low " + bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT + " info " + bcolors.ENDC
    return result

def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])

def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return int(20)

def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    try:
        subprocess.check_output(['ping', '-c1', 'github.com'], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

# Check if running as root
if os.geteuid() != 0:
    print("This script must be run as root. Please use sudo.")
    sys.exit(1)

# Check for required tools
required_tools = [
    'nmap', 'dnsrecon', 'wafw00f', 'uniscan', 'sslyze', 
    'fierce', 'lbd', 'theharvester', 'amass', 'nikto'
]

def check_required_tools():
    missing_tools = []
    for tool in required_tools:
        if not os.path.exists(f'/usr/bin/{tool}'):
            missing_tools.append(tool)
    return missing_tools

def logo():
    print(bcolors.WARNING)
    logo_ascii = """
   ____      _               __        __     _
  / ___|   _| |__   ___ _ __  \\ \\      / /__ _| | __ _
 | |  | | | | '_ \\ / _ \\ '__|  \\ \\ /\\ / / _` | |/ _` |
 | |__| |_| | |_) |  __/ |     \\ V  V / (_| | | (_| |
  \\____\\__, |_.__/ \\___|_|      \\_/\\_/ \\__,_|_|\\__,_|
       |___/
                     """+bcolors.ENDC+"""(CyberWala Advance Vuln Scanner - The Multi-Tool Web Vulnerability Scanner)

                     """+bcolors.BG_LOW_TXT+"""Advanced Security Scanning Suite"""+bcolors.ENDC+""" - Professional Grade Vulnerability Assessment
    """
    print(logo_ascii)
    print(bcolors.ENDC)

def helper():
    print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
    print("------------")
    print("\t./cyberwala.py example.com: Scans the domain example.com.")
    print("\t./cyberwala.py example.com --skip dmitry --skip theHarvester: Skip the 'dmitry' and 'theHarvester' tests.")
    print("\t./cyberwala.py example.com --nospinner: Disable the idle loader/spinner.")
    print("\t./cyberwala.py --update   : Updates the scanner to the latest version.")
    print("\t./cyberwala.py --help     : Displays this help context.")
    print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
    print("------------")
    print("\tCtrl+C: Skips current test.")
    print("\tCtrl+Z: Quits CyberWala.")
    print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
    print("--------")
    print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
    print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
    print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
    print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
    print("--------------------------")
    print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
    print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
    print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
    print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
    print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")

def main():
    # Check for required tools
    missing_tools = check_required_tools()
    if missing_tools:
        print(f"{bcolors.BADFAIL}Error: The following required tools are missing:{bcolors.ENDC}")
        for tool in missing_tools:
            print(f"  - {tool}")
        print(f"\nPlease install them using: sudo apt install {' '.join(missing_tools)}")
        sys.exit(1)

    # Display logo
    logo()

    # Parse arguments
    parser = argparse.ArgumentParser(description='CyberWala Advance Vuln Scanner')
    parser.add_argument('target', nargs='?', help='Target domain to scan')
    parser.add_argument('--skip', nargs='+', help='Skip specific tests')
    parser.add_argument('--nospinner', action='store_true', help='Disable spinner')
    parser.add_argument('--update', action='store_true', help='Update the scanner')
    args = parser.parse_args()

    if args.update:
        print("Updating CyberWala...")
        # Add update logic here
        sys.exit(0)

    if not args.target:
        helper()
        sys.exit(1)

    # Create results directory
    results_dir = f"scan_results_{args.target.replace('://', '_').replace('/', '_')}"
    os.makedirs(results_dir, exist_ok=True)
    os.chdir(results_dir)

    # Start scanning
    print(f"\n{bcolors.OKGREEN}[+] Starting scan on {args.target}{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}[+] Results will be saved in: {results_dir}{bcolors.ENDC}\n")
    
    # Run each tool
    total_tools = len(tools)
    current_tool = 0
    
    for tool_name, tool_info in tools.items():
        current_tool += 1
        if args.skip and tool_name in args.skip:
            print(f"{bcolors.WARNING}[!] Skipping {tool_name} ({current_tool}/{total_tools}){bcolors.ENDC}")
            continue
            
        print(f"{bcolors.OKBLUE}[*] Running {tool_name} ({current_tool}/{total_tools})...{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}[*] Timeout set to {tool_info['timeout']} seconds{bcolors.ENDC}")
        
        start_time = time.time()
        results = run_tool(tool_name, args.target)
        end_time = time.time()
        
        if results:
            if "timed out" in results.lower():
                print(f"{bcolors.WARNING}[!] {tool_name} timed out after {tool_info['timeout']} seconds{bcolors.ENDC}")
            else:
                analysis = analyze_results(tool_name, results)
                if analysis:
                    print(f"{bcolors.OKGREEN}[+] Found {analysis['type']} issue:{bcolors.ENDC}")
                    print(f"    Severity: {vul_info(analysis['severity'])}")
                    print(f"    Message: {analysis['message']}")
                    print(f"    Fix: {analysis['fix']}")
                    print(f"\n{bcolors.OKBLUE}[*] Raw output (first 500 chars):{bcolors.ENDC}")
                    print(f"{bcolors.OKGREEN}{analysis['raw_output']}{bcolors.ENDC}")
                else:
                    print(f"{bcolors.OKGREEN}[+] {tool_name} completed successfully{bcolors.ENDC}")
                    print(f"\n{bcolors.OKBLUE}[*] Raw output (first 500 chars):{bcolors.ENDC}")
                    print(f"{bcolors.OKGREEN}{results[:500] + '...' if len(results) > 500 else results}{bcolors.ENDC}")
        else:
            print(f"{bcolors.BADFAIL}[!] {tool_name} failed to run{bcolors.ENDC}")
        
        print(f"{bcolors.OKBLUE}[*] {tool_name} took {display_time(int(end_time - start_time))}{bcolors.ENDC}\n")
    
    print(f"\n{bcolors.OKGREEN}[+] Scan completed! Results saved in: {results_dir}{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}[+] To view full results, check the individual scan files in the results directory{bcolors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{bcolors.WARNING}[!] Scan interrupted by user{bcolors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{bcolors.BADFAIL}[!] An error occurred: {str(e)}{bcolors.ENDC}")
        sys.exit(1) 