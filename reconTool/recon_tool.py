import os
import subprocess
import requests
import re
import concurrent.futures
import yaml
from selenium import webdriver
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options

temp_path = "/tmp/TBD/"
sub_paths = ["screens", "dnsenum", "sublist3r", "domain_tester", "hunter_io", "whois", "nmap"]
GECKODRIVER_PATH = "/usr/bin/geckodriver"
NORMAL_USER = "kali"
domain = "manipal.edu"

def load_config(config_path='config.yaml'):
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

def ensure_base_directory_exists():
    if not os.path.exists(temp_path):
        print(f"[-] Creating temporary directory at {temp_path}...", end="\r", flush=True)
        try:
            subprocess.run(["sudo", "-u", NORMAL_USER, "mkdir", "-p", temp_path], check=True)
            print(f"[+] Temporary directory created successfully at {temp_path}."+" "*20)
        except subprocess.CalledProcessError as e:
            print(f"[!] An error occurred while creating the directory {temp_path}: {e}"+" "*20)
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}"+" "*20)
    else:
        print(f"[+] Temporary directory already exists. Overwriting."+" "*20)

def ensure_sub_directories_exist(path):
    if not os.path.exists(path):
        print(f"[-] Setting up temporary environment...", end="\r", flush=True)
        try:
            subprocess.run(["sudo", "-u", NORMAL_USER , "mkdir", "-p", path], check=True)
            print(f"[+] Environment setup complete"+" "*20, end="\r", flush=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] An error occurred while creating the directory {path}: {e}"+" "*20, end="\r", flush=True)
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}"+" "*20, end="\r", flush=True)
    else:
        print(f"[+] {path} already exists. Overwriting."+" "*20, end="\r", flush=True)

def dnsenum(domain, threads=1, output=temp_path+"dnsenum/dnsenum.txt"):
    print("[-] Extracting DNS information using dnsenum..."+" "*20, end="\r", flush=True)
    command = [
            "dnsenum",
            domain,
            "--threads",
            str(threads),
            "--nocolor"
            ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        with open(output, 'w') as f:
            f.write(result.stdout)
        print("[+] DNS information extracted."+" "*20)
    else:
        print("[!] Error running dnsenum."+" "*20)

def extract_section(content, section_header):
    pattern = re.compile(rf'{section_header}\n(.*?)\n\n', re.DOTALL)
    match = pattern.search(content)
    return match.group(1).strip() if match else ''

def organise_dnsinfo(path=temp_path+"dnsenum/dnsenum.txt", ns_path=temp_path+"dnsenum/nameservers.txt", mx_path=temp_path+"dnsenum/mailservers.txt", ip_map_path=temp_path+"ip_map.txt", domains_path=temp_path+"domains.txt"):
    print("[-] Organising DNS information...", end="\r", flush=True)
    with open(path, 'r') as file:
        content = file.read()
    mx_servers = extract_section(content, 'Mail \(MX\) Servers:\n___________________')
    ns_servers = extract_section(content, 'Name Servers:\n______________')
    all_domains_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    all_domains = all_domains_pattern.findall(content)
    all_domains.remove("dns.txt")
    all_domains = list(set(all_domains))
    ip_map_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\.\s+\d+\s+IN\s+A\s+\d+\.\d+\.\d+\.\d+')
    ip_map = ip_map_pattern.findall(content)
    with open(mx_path, 'w') as file:
        file.write(mx_servers + '\n')
    with open(ns_path, 'w') as file:
        file.write(ns_servers + '\n')
    with open(domains_path, 'w') as file:
        for domain_entry in all_domains:
            file.write(domain_entry + '\n')
    with open(ip_map_path, 'w') as file:
        for entry in ip_map:
            domain_ip = re.findall(r'(\S+)\.\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)', entry)
            for domain, ip in domain_ip:
                file.write(f"{domain}\t{ip}\n")
    print("[+] DNS information organisation complete."+" "*20)

def sublist3r(domain, threads=1, output=temp_path+"/sublist3r/subout.txt"):
    print("[-] Enumerating subdomains with Sublist3r...", end="\r", flush=True)
    cmd = ["sublist3r", "-d", domain, "-t", str(threads), "-o", output]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Subdomain enumeration completed."+" "*20)
        # print(result.stdout)
    else:
        print("[!] Error running Sublist3r"+" "*20)
        print(result.stderr)
    return

def consolidate_dnsenum_sublist3r(dnsout_path=temp_path+"domains.txt", subout_path=temp_path+"/sublist3r/subout.txt"):
    print("[-] Consolidating dnsenum and sublist3r results...", end="\r", flush=True)
    try:
        with open(dnsout_path, 'r') as dnsout_file:
            dnsout_elements = set(line.strip() for line in dnsout_file)
        with open(subout_path, 'r') as subout_file:
            subout_elements = [line.strip() for line in subout_file]
        unique_elements = [element for element in subout_elements if element not in dnsout_elements]
        with open(dnsout_path, 'a') as dnsout_file:
            for element in unique_elements:
                dnsout_file.write(element + '\n')
        print("[+] Consolidation complete."+" "*30)
    except FileNotFoundError:
        print("[!] Outputs of dnsenum or sublist#r not found."+" "*20)
    except Exception as e:
        print(f"[!] An unknown error occured: {e}"+" "*20)

def check_domain(domain, timeout=20):
    http_url = "http://" + domain
    https_url = "https://" + domain
    try:
        response = requests.get(https_url, timeout=timeout, allow_redirects=True)
        if 200 <= response.status_code < 400:
            return (domain, response.status_code, 'active')
        else:
            return (domain, response.status_code, 'inactive')
    except requests.RequestException:
        try:
            response = requests.get(http_url, timeout=timeout, allow_redirects=True)
            if 200 <= response.status_code < 400:
                return (domain, response.status_code, 'active')
            else:
                return (domain, response.status_code, 'inactive')
        except requests.RequestException:
            return (domain, "Exception", 'inactive')

def activeDomainIdentifier(path=temp_path + "domains.txt", timeout=20, max_workers=os.cpu_count()):
    print("[-] Identifying active domains...", end="\r", flush=True)
    all_domains = []
    active_domains = []
    active_codes = []
    inactive_domains = []
    inactive_codes = []
    try:
        with open(path, 'r') as file:
            all_domains = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"[!] Could not find sublist3r output at {path}."+" "*20)
        return
    except Exception as e:
        print(f"[!] An error occurred: {e}"+" "*20)
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(check_domain, domain, timeout): domain for domain in all_domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                domain, code, status = future.result()
                if status == 'active':
                    active_domains.append(domain)
                    active_codes.append(code)
                else:
                    inactive_domains.append(domain)
                    inactive_codes.append(code)
            except Exception as e:
                inactive_domains.append(domain)
                inactive_codes.append(f"Exception")
    with open(temp_path + 'domain_tester/active_domains_with_codes.txt', 'w') as file:
        for domain, code in zip(active_domains, active_codes):
            file.write(f"{domain}\t{code}\n")
    with open(temp_path + 'domain_tester/inactive_domains_with_codes.txt', 'w') as file:
        for domain, code in zip(inactive_domains, inactive_codes):
            file.write(f"{domain}\t{code}\n")
    with open(temp_path + 'domain_tester/active_domains.txt', 'w') as file:
        for domain in active_domains:
            file.write(f"{domain}\n") 
    print("[+] Active domain identification complete."+" "*20)
    # print(active_domains)
    return

def take_screenshot_as_user(url, output_dir, file_name):
    command = [
        "sudo", "-u", NORMAL_USER, "python3", "scraper.py",
        url, output_dir, file_name, GECKODRIVER_PATH
    ]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to take screenshot for {url}: {e}")

def try_screenshot(domain, output_dir):
    file_name = f"{domain.replace('.', '_').replace(':', '_')}.png"
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    # Try HTTPS first
    try:
        take_screenshot_as_user(https_url, output_dir, "https_" + file_name)
        print(f"[+] Screenshot taken for {https_url}"+" "*20, end="\r", flush=True)
    except Exception as e:
        print(f"[-] HTTPS failed for {domain}, trying HTTP. Error: {e}"+" "*20, end="\r", flush=True)
        # If HTTPS fails, try HTTP
        try:
            take_screenshot_as_user(http_url, output_dir, "http_" + file_name)
            print(f"[+] Screenshot taken for {http_url}"+" "*20, end="\r", flush=True)
        except Exception as e:
            print(f"[!] Failed to take screenshot for {http_url}: {e}"+" "*20, end="\r", flush=True)

def screenshotter(path=temp_path+"domain_tester/active_domains.txt", output=temp_path+"screens/"):
    active_domains = []
    print("[-] Attempting to screenshot live domains with Selenium...", end="\r", flush=True)
    try:
        with open(path, 'r') as file:
            active_domains = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"[!] Could not find active domain list at {path}."+" "*20)
    except Exception as e:
        print(f"[!] An error occurred: {e}"+" "*20)
    for domain in active_domains:
        try_screenshot(domain, output)
    print(f"[+] Active domain screenshots saved at {output}")
    return

def hunter_io(domain, output=temp_path+"hunter_io/email_list.txt", config_path="config.yaml", mx_path=temp_path+"dnsenum/mailservers.txt"):
    print("[-] Attempting to find email addresses with hunter.io...", end="\r", flush=True)
    if not os.path.exists(mx_path):
        raise FileNotFoundError(f"[!] Could not find mail servers enumerated by dnsenum."+" "*20)
    if os.path.getsize(mx_path) == 0:
        print("[!] No MX records associated with this domain. Skipping hunter.io recon."+" "*20)
        return
    try:
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"[!] Config file {config_path} not found."+" "*20)
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        if 'hunter_api_key' not in config or not config['hunter_api_key']:
            raise ValueError("[!] API key not found in the config file or it is empty."+" "*20)
        api_key = config['hunter_api_key']
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            emails = data.get('data', {}).get('emails', [])
            with open(output, 'w') as file:
                for email in emails:
                    file.write(email.get('value') + '\n')
            print(f"[+] Found {len(emails)} email addresses stored in {output}."+" "*20)
        else:
            print(f"[!] Error: Unable to fetch data (status code: {response.status_code})"+" "*20)
    except FileNotFoundError as e:
        print(f"[!] Error: {e}"+" "*20)
    except ValueError as e:
        print(f"[!] Error: {e}"+" "*20)
    except requests.RequestException as e:
        print(f"[!] Error: An error occurred while making the request to Hunter.io: {e}"+" "*20)
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}"+" "*20)

def host(path=temp_path+"domains.txt", output=temp_path+"ip_map.txt", timeout=25):
    print("[-] Looking up IP addresses with host...", end="\r", flush=True)
    with open(path, 'r') as file:
        domains = {line.strip() for line in file if line.strip()}
    entries_to_append = []
    for domain in domains:
        try:
            result = subprocess.run(['host', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            if result.returncode == 0:
                ip_addresses = []
                for line in result.stdout.splitlines():
                    if 'has address' in line:
                        ip_addresses.append(line.split()[-1])
                    elif 'has IPv6 address' in line:
                        ip_addresses.append(line.split()[-1])
                for ip in ip_addresses:
                    entry = f"{domain}\t{ip}"
                    if not os.path.exists(output) or not any(entry in line for line in open(output, 'r')):
                        entries_to_append.append(entry)
        except Exception as e:
            print(f"[!] Error resolving domain {domain}: {e}"+" "*20)
    if entries_to_append:
        with open(output, 'a') as file:
            for entry in entries_to_append:
                file.write(entry + '\n')
        print(f"[+] Appended {len(entries_to_append)} new entries to {output}."+" "*20)
    else:
        print("[+] No new entries to append."+" "*20)

def whois(path=temp_path+"ip_map.txt", output=temp_path+"whois", timeout=25, max_workers=os.cpu_count()):
    print("[-] Extracting whois information...", end="\r", flush=True)
    def process_line(line):
        try:
            domain, ip = line.split()
            filename = f"{domain.replace('.', '_')}__{ip.replace(':', '_')}.txt"
            output_file = os.path.join(output, filename)
            result = subprocess.run(['whois', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            if result.returncode == 0:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                return f"[+] WHOIS result saved for {ip}"
            else:
                return f"[!] Error: WHOIS command failed for {ip}"
        except subprocess.TimeoutExpired:
            return f"[!] Error: Timeout expired for WHOIS query on IP {ip}"
        except Exception as e:
            return f"[!] Error processing line '{line}': {e}"
    with open(path, 'r') as file:
        lines = [line.strip() for line in file if line.strip()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_line, line) for line in lines]
        for future in concurrent.futures.as_completed(futures):
            print(future.result() + " "*30, end="\r", flush=True)
    print(f"[+] Whois information saved at {output}." + " "*30)

def nmap(path=temp_path+"ip_map.txt", output=temp_path+"nmap", timeout=500, max_workers=os.cpu_count()):
    print("[-] Performing  Nmap scans...", end="\r", flush=True)
    def process_line(line):
        try:
            domain, ip = line.split()
            filename = f"{domain.replace('.', '_')}__{ip.replace(':', '_')}.txt"
            output_file = os.path.join(output, filename)
            result = subprocess.run(['nmap', '-Pn', '-sV', '-O', '--osscan-guess', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            if result.returncode == 0:
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                return f"[+] Nmap scan result saved for {ip}"
            else:
                return f"[!] Error: Nmap command failed for {ip}"
        except subprocess.TimeoutExpired:
            return f"[!] Error: Timeout expired for Nmap scan on IP {ip}"
        except Exception as e:
            return f"[!] Error processing line '{line}': {e}"
    with open(path, 'r') as file:
        lines = [line.strip() for line in file if line.strip()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_line, line) for line in lines]
        for future in concurrent.futures.as_completed(futures):
            print(future.result() + " "*30, end="\r", flush=True)
    print(f"[+] Nmap scan information saved at {output}." + " "*30)


ensure_base_directory_exists()
for path in sub_paths:
    ensure_sub_directories_exist(temp_path+path)
dnsenum(domain, threads=100)
organise_dnsinfo()
sublist3r(domain, threads=100)
consolidate_dnsenum_sublist3r()
activeDomainIdentifier(max_workers=100)
# screenshotter()
hunter_io(domain)
host()
whois(max_workers=100)
nmap(max_workers=100)
