import subprocess
import re
import json
from typing import Dict, List, Optional, Tuple
import signal
from contextlib import contextmanager
import os

# Timeout handler
@contextmanager
def timeout(seconds):
    def signal_handler(signum, frame):
        raise TimeoutError("Timed out!")
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# Tool responses and fixes
tool_resp = {
    'waf': ['Web Application Firewall detected. This is a security measure that helps protect web applications from various attacks.', 'h'],
    'ssl': ['SSL/TLS configuration issues detected. This could lead to security vulnerabilities.', 'h'],
    'dns': ['DNS misconfiguration detected. This could lead to information disclosure.', 'm'],
    'cms': ['Content Management System detected. Make sure it\'s up to date.', 'm'],
    'dir': ['Directory listing enabled. This could lead to information disclosure.', 'm'],
    'xss': ['Potential XSS vulnerability detected.', 'h'],
    'sqli': ['Potential SQL injection vulnerability detected.', 'c'],
    'rce': ['Potential Remote Code Execution vulnerability detected.', 'c'],
    'lfi': ['Potential Local File Inclusion vulnerability detected.', 'h'],
    'rfi': ['Potential Remote File Inclusion vulnerability detected.', 'h'],
    'dos': ['Potential Denial of Service vulnerability detected.', 'h'],
}

tools_fix = [
    ['waf', 'Web Application Firewall (WAF) is a security measure that helps protect web applications from various attacks.', 'Configure and maintain your WAF properly.'],
    ['ssl', 'SSL/TLS configuration issues can lead to security vulnerabilities.', 'Update SSL/TLS configuration and use strong ciphers.'],
    ['dns', 'DNS misconfiguration can lead to information disclosure.', 'Configure DNS properly and disable zone transfers.'],
    ['cms', 'Outdated CMS can lead to security vulnerabilities.', 'Keep your CMS and plugins up to date.'],
    ['dir', 'Directory listing can lead to information disclosure.', 'Disable directory listing in your web server configuration.'],
    ['xss', 'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.', 'Implement proper input validation and output encoding.'],
    ['sqli', 'SQL Injection allows attackers to manipulate your database.', 'Use prepared statements and input validation.'],
    ['rce', 'Remote Code Execution allows attackers to execute code on your server.', 'Implement proper input validation and use secure coding practices.'],
    ['lfi', 'Local File Inclusion allows attackers to include local files.', 'Implement proper input validation and use secure file handling.'],
    ['rfi', 'Remote File Inclusion allows attackers to include remote files.', 'Implement proper input validation and use secure file handling.'],
    ['dos', 'Denial of Service can make your service unavailable.', 'Implement rate limiting and other DoS protection measures.'],
]

# Tool definitions with timeouts and output files
tools = {
    'nmap': {
        'command': 'nmap -sV -sC -p- --max-retries 2 --min-rate 1000 -oN nmap_scan.txt {target}',
        'type': 'port',
        'severity': 'm',
        'timeout': 300,  # 5 minutes
        'output_file': 'nmap_scan.txt'
    },
    'dnsrecon': {
        'command': 'dnsrecon -d {target} -t std,srv,bing -o dns_scan.txt',
        'type': 'dns',
        'severity': 'm',
        'timeout': 120,  # 2 minutes
        'output_file': 'dns_scan.txt'
    },
    'wafw00f': {
        'command': 'wafw00f {target} -o waf_scan.txt',
        'type': 'waf',
        'severity': 'i',
        'timeout': 30,  # 30 seconds
        'output_file': 'waf_scan.txt'
    },
    'uniscan': {
        'command': 'uniscan -u {target} -qweds -o uniscan_scan.txt',
        'type': 'vuln',
        'severity': 'h',
        'timeout': 180,  # 3 minutes
        'output_file': 'uniscan_scan.txt'
    },
    'sslyze': {
        'command': 'sslyze --regular {target} --json_out=ssl_scan.txt',
        'type': 'ssl',
        'severity': 'h',
        'timeout': 60,  # 1 minute
        'output_file': 'ssl_scan.txt'
    },
    'fierce': {
        'command': 'fierce -dns {target} -o fierce_scan.txt',
        'type': 'dns',
        'severity': 'm',
        'timeout': 120,  # 2 minutes
        'output_file': 'fierce_scan.txt'
    },
    'lbd': {
        'command': 'lbd {target} > lbd_scan.txt',
        'type': 'lb',
        'severity': 'i',
        'timeout': 30,  # 30 seconds
        'output_file': 'lbd_scan.txt'
    },
    'theharvester': {
        'command': 'theHarvester -d {target} -b all -l 100 -o theharvester_scan.txt',
        'type': 'info',
        'severity': 'i',
        'timeout': 180,  # 3 minutes
        'output_file': 'theharvester_scan.txt'
    },
    'amass': {
        'command': 'amass enum -d {target} -passive -o amass_scan.txt',
        'type': 'dns',
        'severity': 'm',
        'timeout': 180,  # 3 minutes
        'output_file': 'amass_scan.txt'
    },
    'nikto': {
        'command': 'nikto -h {target} -maxtime 1h -o nikto_scan.txt',
        'type': 'vuln',
        'severity': 'h',
        'timeout': 300,  # 5 minutes
        'output_file': 'nikto_scan.txt'
    }
}

def run_tool(tool, target):
    if tool not in tools:
        return None
    
    command = tools[tool]['command'].format(target=target)
    timeout_seconds = tools[tool]['timeout']
    output_file = tools[tool]['output_file']
    
    try:
        with timeout(timeout_seconds):
            # Run the command
            subprocess.run(command, shell=True, check=True)
            
            # Read and return the output file
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    return f.read()
            return "No output file generated"
            
    except TimeoutError:
        return f"Tool execution timed out after {timeout_seconds} seconds"
    except subprocess.CalledProcessError as e:
        return f"Command failed with error: {str(e)}"
    except Exception as e:
        return f"An error occurred: {str(e)}"

def analyze_results(tool, results):
    if not results:
        return None
    
    tool_type = tools[tool]['type']
    severity = tools[tool]['severity']
    
    # Basic analysis based on tool type
    if tool_type in tool_resp:
        return {
            'type': tool_type,
            'severity': severity,
            'message': tool_resp[tool_type][0],
            'fix': tools_fix[list(tool_resp.keys()).index(tool_type)][2],
            'raw_output': results[:500] + "..." if len(results) > 500 else results  # Include first 500 chars of raw output
        }
    return None 