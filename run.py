import time
import sublist3r
import requests
import shutil
import socket
import ssl
import os
import subprocess
from rich.console import Console
from rich import print
from termcolor import colored
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import re
import sys
import aiohttp
import asyncio
import cfscrape

loop = asyncio.get_event_loop()

console = Console()
def extract_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

def find_hidden_subdomains(domain):
    url = "https://crt.sh/?q=%.{0}&output=json".format(domain)
    try:
        response = requests.get(url)
        data = response.json()
        subdomains = set()
        for item in data:
            subdomains.add(item['name_value'])
        return subdomains
    except requests.exceptions.RequestException as e:
        return []

def gather_dns_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        return None

def gather_ssl_info(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except (socket.error, ssl.SSLError) as e:
        return None

def save_subdomains_to_file(subdomains, hidden_subdomains):
    all_subdomains = subdomains + hidden_subdomains
    unique_subdomains = []
    with open('domains.txt', 'w') as file:
        for subdomain in all_subdomains:
            if subdomain not in unique_subdomains:
                file.write(subdomain + '\n')
                unique_subdomains.append(subdomain)

def remove_duplicates(lst):
    return list(set(lst))

file_name = 'domains.txt'
def remove_text_from_file(file_name, text_to_remove):
    with open(file_name, 'r') as file:
        lines = file.readlines()
    with open(file_name, 'w') as file:
        for line in lines:
            if text_to_remove not in line:
                file.write(line)

text_to_remove = '*.google.com'
remove_text_from_file(file_name, text_to_remove)

def main():
    console = Console()
    console.print('[bold green]After the process of extracting the domains, they will be saved in the domains.txt file[/bold green] . \n')
    target_domain = console.input("[☠][magenta]Enter the target domain: [/magenta]")
    console.print("[bold cyan]Please wait.....\n[/bold cyan]")
    subdomains = extract_subdomains(target_domain)
    hidden_subdomains = find_hidden_subdomains(target_domain)
    ip_ranges = []
    console.print(f"\n[bold cyan]Target Domain:[/bold cyan] [green]{target_domain}[/green]")
    console.print("[bold cyan]Subdomains:[/bold cyan]")
    for subdomain in subdomains:
        console.print(subdomain)
        ip = gather_dns_info(subdomain)
        if ip:
            ip_ranges.append(ip)

    console.print("[bold cyan]Hidden Subdomains:[/bold cyan]")
    for hidden_subdomain in hidden_subdomains:
        console.print(hidden_subdomain)
        ip = gather_dns_info(hidden_subdomain)
        if ip:
            ip_ranges.append(ip)

    hidden_subdomains = remove_duplicates(hidden_subdomains)
    subdomains = remove_duplicates(subdomains)
    save_subdomains_to_file(subdomains, hidden_subdomains)
    console.print("Subdomains and Hidden Subdomains have been saved to [bold]domains.txt[/bold]")
    console.print("[bold cyan]IP Ranges:[/bold cyan]")
    for ip in ip_ranges:
        console.print(ip)
    choice = console.input("[bold cyan]Do you want to check for free tool?[/bold cyan] (y/n): ")
    if choice.lower() == 'y':
        use_checkfree_tool()
    choice = console.input("[bold cyan]Do you want to go back to the main menu?[/bold cyan] (y/n): ")
    if choice.lower() == 'y':
        second_menu()


def use_checkfree_tool():
    with open('domains.txt', 'r') as file:
        hosts = file.readlines()
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_address, re.sub(r'^(https?://)?', r'https://', host.strip())) for host in hosts]

        for future in futures:
            future.result()

def second_menu():
    console = Console()
    console.print("[bold blue]Telegram: @@VictorIsGeek [/bold blue]\n")
    console.print("[bold yellow][1] Dig Subdomains[/bold yellow]")
    console.print("[bold red][2] Subdomain Finder with Bugscanner[/bold red]")
    console.print("[bold yellow][3] SNI finder[/bold yellow]")
    console.print("[bold green][4] CDN SSL Scanner[/bold green]")
    console.print("[bold cyan][5] Scan  Cloudflare IP[/bold cyan]\n")

    choice = console.input("[magenta][-][/magenta] Select method (1-5):> ")
    os.system('clear')
    time.sleep(0.2)

    if choice == '1':
        main()
    elif choice == '2':
        b()
        bugscanner_subdomain_scan()
    elif choice == '3':
        b()
        bugscanner_cdn_ssl_scan()
    elif choice == '4':
        b()
        bugscanner_sni_scan()
    elif choice == '5':
        cloudip_scan()

def b():
    if shutil.which('bugscanner-go') is None:
        console.print("[yellow]Bugscanner-go is not installed. Installing now...[/yellow]")
        subprocess.run(['pkg', 'update', '&&', 'pkg', 'upgrade', '-y'])
        subprocess.run(['pkg', 'install', 'golang',])
        subprocess.run(['go', 'install', '-v', 'github.com/aztecrabbit/bugscanner-go@latest'])
        console.print("[green]Bugscanner-go installed successfully![/green]")

def bugscanner_subdomain_scan():
    target_file = 'domains.txt'
    target_proxy = console.input("[yellow]Enter proxy IP[/yellow]: ")
    target_port = console.input("[yellow]Enter target port[/yellow] (default is 443): ") or '443'
    bugscanner_command = f"bugscanner --mode direct --proxy {target_proxy} --port {target_port} {target_file}"
    os.system(bugscanner_command)

    console.print("[red]Scan complete[/red].")
    choice = console.input("[yellow]Do you want to go back to the main menu?[/yellow][red](y/n)[/red]: ")
    if choice.lower() == 'y':
        second_menu()

def bugscanner_cdn_ssl_scan():
    target_file = 'domains.txt'
    new_target = console.input("Enter a new target (leave blank to keep [blue]sa.zain.com[/blue]): ")
    target = new_target if new_target else "sa.zain.com"
    target_proxy = console.input("[yellow]Enter proxy IP[/yellow]: ")
    bugscanner_command = f"bugscanner-go scan cdn-ssl --proxy-filename {target_file} --target {target}"
    os.system(bugscanner_command)
    print("Scan complete..")
    choice = console.input("[bold cyan]Do you want to go back to the main menu?[/bold cyan][yellow](y/n)[/yellow]: ")
    if choice.lower() == 'y':
        second_menu()

def bugscanner_sni_scan():
    target_file = 'domains.txt'
    bugscanner_command = f"bugscanner-go scan sni -f {target_file}"
    os.system(bugscanner_command)

    print("Scan complete.")
    choice = console.input("[bold cyan]Do you want to go back to the main menu?[/bold cyan] [yellow](y/n)[/yellow]: ")
    if choice.lower() == 'y':
        second_menu()

def cloudip_scan():
    try:
        target_range = console.input("[yellow]Enter IP range [/yellow](e.g., 192.0.0.0/24): ")
        net4 = ipaddress.ip_network(target_range)
        addresses = [str(host) for host in net4.hosts()]
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'TE': 'Trailers',
        }

        with ThreadPoolExecutor(max_workers=20) as executor:
            https_futures = [executor.submit(check_address, re.sub(r'^(https?://)?', r'https://', address.strip()), headers=headers) for address in addresses]

            for future in https_futures:
                future.result()

        print("HTTPS Scan complete.")
        print("[bold cyan]Starting HTTP Scan...[/bold cyan]")
        time.sleep(2)
        headers = {}
        with ThreadPoolExecutor(max_workers=20) as executor:
            http_futures = [executor.submit(check_address, f'http://{address.strip()}', headers=headers) for address in addresses]
            for future in http_futures:
                future.result()

        print("Scan complete.")
        choice = console.input("[bold cyan]Do you want to go back to the main menu?[/bold cyan] [yellow](y/n)[/yellow]: ")
        if choice.lower() == 'y':
            second_menu()

    except ValueError as e:
        print(f'\nError: {str(e)}')
        print("Please enter a valid IP range.")
        cloudip_scan()

def check_address(address, headers=None):
    try:
        scraper = cfscrape.create_scraper()
        headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        response = scraper.get(address, headers=headers, timeout=60, allow_redirects=True, verify=False)
        status_code = response.status_code
        server = response.headers.get('Server')
        if status_code == 200:
            print_status(address, status_code, server)
        else:
            result = f"[-] {address} - {status_code} {response.reason}"
            console.print(f"[-] {address} - [red]{status_code} {response.reason}[/]")
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.SSLError):
            result = f"[-] {address} - SSL Error: {str(e)}"
            console.print(f"[-] {address} - [red]SSL Error: {str(e)}[/]")
        else:
            result = f"[-] {address} - Connection Error: {str(e)}"
            console.print(f"[-] {address} - [red]Connection Error: {str(e)}[/]")
    except Exception as ex:
        result = f"[-] {address} - An unexpected error occurred: {str(ex)}"
        console.print(f"[-] {address} - [red]An unexpected error occurred: {str(ex)}[/]")

def print_status(address, status_code, server):
    if server:
        server = server.lower()
        if any(name in server for name in ['cloudflare', 'cloudfront', 'akamai', 'AkamaiGHost']):
            result = f"[+] {address} - [green]{status_code} OK ([green]{server}[/])"
        elif any(name in server for name in ['varnish', 'litespeed', 'fastly', 'nginx']):
            result = f"[+] {address} - [on_green]{status_code} OK ([on_green]{server}[/])"
        else:
            result = f"[+] {address} - [purple]{status_code} OK ([purple]{server}[/])"
    else:
        result = f"[+] {address} - [on_red]{status_code} OK (Server type unknown)"

    print(result)
    with open('fpi.txt', 'a') as file:
        file.write(address + '\n')

if __name__ == "__main__":
    os.system('clear')

fpi = f'''



`___
| __\_  _  ___  ___  ___ __ _ _ __  
| _ / | | |  _ \/ __|/ __/ _` | '_ \ 
| __\ |_| | |_) \__ \ (_| (_| | | | |
|___/\__,_|___  |___/\___\__,_|_| |_| 
           / _| |
           | ___|

               __    _____           __         
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /    
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/
`         


'''
console = Console()

B ="=========by: Victor Geek \n                         Telegram :@VictorIsGeek \n"

for char in B:
    if char.isalpha():
        console.print(char, end='', style="bold cyan")
    else:
        console.print(char, end='')
    time.sleep(0.1)
os.system('clear')
for char in fpi:
    print(char, end='')
    time.sleep(0.001)
second_menu()
