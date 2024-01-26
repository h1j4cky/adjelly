from termcolor import colored
import re 
import src.modules.core as core
import src.modules.meta_smb as meta_smb
import src.modules.config as config

def smb_config_scan(dc_ip):
    print(colored("\n[*] Running nmap scripts to retreive information about SMB configuration.", 'blue'))
    out, err = core.execute_command(f"nmap --script smb-protocols,smb-os-discovery,smb-security-mode,smb2-security-mode -Pn -sT -p445 {dc_ip}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    out = out.replace("|", " ")
    out = out.replace("_", " ")
    lines = out.split("\n")
    write = False
    for line in lines:
        if "Host script results" in line:
            write = True
            print(colored("[+] " + line, 'green'))
        elif write:
            if "smb-" in line or 'smb2-' in line:
                lines_color = line.split(':',1)[0]
                lines_nocolor = line.split(':',1)[1]
                print(colored(lines_color.strip(), 'grey', 'on_white') + ":" + lines_nocolor)
            elif "message signing: " in line:
                if not "required" in line:
                    print("  " + colored(line, 'red'))
                else:
                    print("  " + line)
            elif "Nmap done" in line:
                break   
            else:
                print("  " + line)
    if not write:
        print(colored(f"[-] Could not perform vulnerability scan on {dc_ip}. Check if IP is correct.", 'yellow'))
        exit(1)

# check for basic smb vulns
def smb_vulns_scan(dc_ip):
    print(colored("\n[*] Running nmap scripts to identify SMB vulnerabilites.", 'blue'))
    out, err = core.execute_command(f"nmap --script smb-vuln* -Pn -sT -p445 {dc_ip}") 
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    out = out.replace("|", " ")
    out = out.replace("_", " ")
    lines = out.split("\n")
    write = False
    for line in lines: #coloring
        if "Host script results" in line:
            write = True
            print(colored("[+] " + line, 'green'))
        elif write:
            if "smb-" in line:
                lines_color = line.split(':',1)[0]
                lines_nocolor = line.split(':',1)[1]
                print(colored(lines_color.strip(), 'grey', 'on_white') + ":" + lines_nocolor)
            elif "State: LIKELY VULNERABLE" in line:
                print(colored(line, 'yellow'))
            elif "State: VULNERABLE" in line: 
                print(colored(line, 'red'))
            elif "Nmap done" in line:
                break   
            else:
                print("  " + line)
    if not write:
        print(colored("[-] Could not perform vulnerability scan on {}. Check if IP is correct.".format(dc_ip), 'yellow'))
        exit(1)

def smb_list_shares(dc_ip, user, password):
    print(colored("\n[*] Trying to list SMB shares permissions.", 'blue'))
    if user == "" or user is None: 
        user = "notausername" # any nonexistent name will work
        out, err = core.execute_command((f"smbmap -H {dc_ip} -u {user}"))
    else:
        out, err = core.execute_command((f"smbmap -H {dc_ip} -u {user} -p {password}"))
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
    if "0 hosts" in out:
        print(colored(f"[-] No hosts with SMB found. Check if IP is correct.", 'yellow'))
        exit(1)
    if "Established 0" in out:
        print(colored(f"[-] Anonymous logon is not enabled.", 'yellow'))
        return
    disk_list = []
    lines = out.split("\n")
    write = False
    for line in lines:
        if "..." in line:
            continue
        if "[+] IP" in line:
            write = True
        if write:
            print(line.strip())
            elems = re.split("[\s]\\s+", line)
            if elems[0].startswith('\t') and not elems[0].startswith('\tDisk') and not elems[0].startswith('\t----'):
                    disk = elems[0].split('\t')[1]
                    tmp_perms = elems[1].split('\t')[0]
                    ansi_escape =re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
                    perms = ansi_escape.sub('', tmp_perms)
                    disk_list.append((disk, perms))
    return disk_list


# returns file listing of a given share
def smb_list_contents(dc_ip, domain_name, user, password, sharename, cnt):
    print(colored(f"\n[*] Trying to get contents of \"{sharename}\" SMB share.", 'blue'))
    out, err = core.execute_command(f"smbclient //{dc_ip}/{sharename} -c recurse;ls -U {domain_name}/{user}%{password}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    if "NT_STATUS" in out:
        print(colored(f"[-] Error: {out.strip()}",'red'))
        return 
    lines = out.split("\n")
    # create folder before first 'save to file' operation
    with open(f"smb_{sharename}_listing.txt", "w") as f:
        f.write(out)
    print(colored(f"[+] Success! File listing result saved to {config.out_folder}/smb_{sharename}_listing.txt.", 'green'))
    if len(lines) <= 100 and cnt < 3: 
        for line in lines: # coloring
            if "blocks available" in line:
                break
            if line.startswith("\\"):
                print(colored(line.strip(), 'grey', 'on_green'), end='')
                print(":")
            else:
                print(line.strip())



def smb_main(dc_ip, domain, username, password, meta):
    smb_config_scan(dc_ip)
    smb_vulns_scan(dc_ip)
    if not config.out_folder:
        core.makeworkdir()
    # gets all shares and reads permissions - if share is accessible - lists its contents
    disk_list = smb_list_shares(dc_ip, username, password)
    if not disk_list:
        return 
    cnt = 0
    special = ["IPC$", "NETLOGON", "SYSVOL", "CertEnroll"]
    for disk in disk_list:
        if not disk[1] == "NO ACCESS" and disk[0] not in special:
            smb_list_contents(dc_ip, domain, username, password, disk[0], cnt)
            cnt +=1
    if not meta:
        return
    if username is None:
        username = "notausername"
        password = ""
    meta_smb.main(username, password, "servername", dc_ip, domain)