import requests
import socket
import re
from bs4 import BeautifulSoup
import concurrent.futures

# Function to check for open ports on a server
def check_open_ports(host, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to check for SQL Injection vulnerability
def sql_injection_test(url):
    injection_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 'a'='a"]
    vulnerable = False
    for payload in injection_payloads:
        response = requests.get(url + payload)
        if "SQL" in response.text or "syntax" in response.text:
            vulnerable = True
            break
    return vulnerable

# Function to check for outdated software versions by analyzing HTML metadata
def check_outdated_versions(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    outdated = False
    for meta in soup.find_all("meta"):
        if 'version' in str(meta):
            version = re.search(r'(\d+\.\d+)', str(meta))
            if version and float(version.group()) < 2.0:  # Example threshold
                outdated = True
                break
    return outdated

# Function to check for Cross-Site Scripting (XSS) vulnerability
def xss_test(url):
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    vulnerable = False
    try:
        for payload in xss_payloads:
            response = requests.get(url + payload, timeout=5)
            if payload in response.text:
                vulnerable = True
                break
    except requests.RequestException as e:
        print(f"Error during XSS test: {e}")
    return vulnerable

# Function to check for Command Injection vulnerability
def command_injection_test(url):
    command_payloads = ["; ls", "& dir", "| whoami"]
    vulnerable = False
    try:
        for payload in command_payloads:
            response = requests.get(url + payload, timeout=5)
            if "root" in response.text or "user" in response.text:
                vulnerable = True
                break
    except requests.RequestException as e:
        print(f"Error during Command Injection test: {e}")
    return vulnerable

# Function to check for Directory Traversal vulnerability
def directory_traversal_test(url):
    traversal_payloads = ["../../etc/passwd", "../windows/system.ini"]
    vulnerable = False
    try:
        for payload in traversal_payloads:
            response = requests.get(url + payload, timeout=5)
            if "root:x" in response.text or "[extensions]" in response.text:
                vulnerable = True
                break
    except requests.RequestException as e:
        print(f"Error during Directory Traversal test: {e}")
    return vulnerable

# Main function to run checks on a target
def bug_bounty_scanner(target_url):
    host = target_url.split("//")[-1].split("/")[0]  # Extract hostname
    
    # Run tests concurrently for efficiency
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_open_ports = executor.submit(check_open_ports, host, [80, 443, 8080])
        future_sql = executor.submit(sql_injection_test, target_url)
        future_outdated = executor.submit(check_outdated_versions, target_url)
        future_xss = executor.submit(xss_test, target_url)
        future_command_injection = executor.submit(command_injection_test, target_url)
        future_directory_traversal = executor.submit(directory_traversal_test, target_url)
        
        open_ports = future_open_ports.result()
        sql_vulnerable = future_sql.result()
        outdated_versions = future_outdated.result()
        xss_vulnerable = future_xss.result()
        command_injection_vulnerable = future_command_injection.result()
        traversal_vulnerable = future_directory_traversal.result()

    # Results summary
    report = f"\n--- Bug Bounty Scan Report for {target_url} ---\n"
    report += f"Open Ports Detected: {open_ports if open_ports else 'None'}\n"
    report += f"SQL Injection Vulnerability: {'Detected' if sql_vulnerable else 'Not Detected'}\n"
    report += f"Outdated Software Version: {'Detected' if outdated_versions else 'Not Detected'}\n"
    report += f"Cross-Site Scripting (XSS) Vulnerability: {'Detected' if xss_vulnerable else 'Not Detected'}\n"
    report += f"Command Injection Vulnerability: {'Detected' if command_injection_vulnerable else 'Not Detected'}\n"
    report += f"Directory Traversal Vulnerability: {'Detected' if traversal_vulnerable else 'Not Detected'}\n"

    print(report)

# Run the scanner
target_url = "https://www.python.org/"
bug_bounty_scanner(target_url)
