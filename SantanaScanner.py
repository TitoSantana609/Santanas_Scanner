import os
import subprocess
import requests
import re

import pyfiglet

banner = pyfiglet.figlet_format("Santana Scanner\ncreated by\ntitosantana00")
print(banner)


def run_amass(domain):
    print("[*] Running amass...")
    amass_output = subprocess.check_output(['amass', 'enum', '-d', domain], text=True)
    return amass_output.splitlines()

def query_crtsh(domain):
    print("[*] Querying crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = set()
        for entry in response.json():
            subdomains.update(re.findall(r'\w+\.\w+\.\w+', entry['name_value']))
        return list(subdomains)
    else:
        return []

def run_subfinder(domain):
    print("[*] Running subfinder...")
    subfinder_output = subprocess.check_output(['subfinder', '-d', domain], text=True)
    return subfinder_output.splitlines()

def run_httpx_toolkit(subdomains):
    print("[*] Running httpx-toolkit...")
    # Write subdomains to a temporary file for httpx-toolkit input
    with open('subdomains.txt', 'w') as f:
        for subdomain in subdomains:
            f.write(subdomain + '\n')
    httpx_output = subprocess.check_output(['httpx-toolkit', '-l', 'subdomains.txt', '-silent'], text=True)
    os.remove('subdomains.txt')  # Clean up the temporary file
    return httpx_output.splitlines()

def remove_duplicates(subdomains):
    return list(set(subdomains))

def main():
    domain = input("Enter the domain to search subdomains for: ")
    
    amass_subdomains = run_amass(domain)
    crtsh_subdomains = query_crtsh(domain)
    subfinder_subdomains = run_subfinder(domain)

    all_subdomains = amass_subdomains + crtsh_subdomains + subfinder_subdomains
    unique_subdomains = remove_duplicates(all_subdomains)

    print(f"[*] Found {len(unique_subdomains)} unique subdomains")

    alive_subdomains = run_httpx_toolkit(unique_subdomains)

    output_path = input("Enter the output file path to save the alive subdomains: ")
    
    # Check if the provided path is a directory
    if os.path.isdir(output_path):
        output_file = os.path.join(output_path, 'alive_subdomains.txt')
    else:
        output_file = output_path
    
    with open(output_file, 'w') as f:
        for subdomain in alive_subdomains:
            f.write(subdomain + '\n')

    print(f"Alive subdomains saved to {output_file}")

if __name__ == "__main__":
    main()
