from termcolor import colored
import re 
import src.modules.core as core
import src.modules.config as config


def scan(dc_ip): 
    open_ports =[]
    flags = "-Pn -oA basic_nmap"
    print(colored(f"\n[*] Running nmap command: 'nmap {dc_ip} {flags}'", 'blue'))
    out, err = core.execute_command(f"nmap {dc_ip} {flags}") 
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    lines = out.split("\n")
    write = 0
    for line in lines:
        if "PORT" in line:
            write = 1
        if "MAC" in line:
            write = 2
        if write==1:
            print(line)
            match = re.search(r"(\d+)/", line)
            if match:
                open_ports.append(match.group(1))
    if not write:
        print(colored(f"[-] Could not perform vulnerability scan on {dc_ip}.", 'yellow'))
        exit(1)
    return open_ports

def scan_for_domain(dc_ip):
    flags = "-p 389,636 -sV -Pn"
    print(colored(f"\n[*] Running nmap command to retrieve domain name: 'nmap {dc_ip} {flags}'", 'blue'))
    out, err = core.execute_command(f"nmap {dc_ip} {flags}") 
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
    match_dc = re.search(r"Host:\s+(\S+);", out)
    dc = None
    if match_dc:
        dc = match_dc.group(1)
        print(f"[+] Domain Controller's name: {dc}")

    match = re.search(r"Domain: ([A-Za-z.]+)\d\.", out)
    if match:
        domain = match.group(1)
        print(colored(f"[+] Success! Domain name is: {domain}", 'green'))
        return domain, dc
    else:
        print(colored(f"[-] No domain name found. Supply domain name or try to run nmap SMB discovery module.", 'yellow'))
        return 
