from termcolor import colored
import re 
import src.modules.core as core
import src.modules.config as config


def ldap_try_to_bind(dc_ip,user=None,pwd=None):
    print(colored("\n[*] Trying to dump ldap info.",'blue'))
    print(colored("[*] Trying unauthenticated bind...",'grey'))
    out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -x -s base namingcontexts")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    nc = 0
    domain_full = None
    lines = out.split('\n')
    for line in lines:
        if line.startswith("namingcontexts:"):
            nc += 1
            fqdn = line.strip("namingcontexts:")
            if nc == 1:
                print(colored("[+] Success! Listing naming contexts:", 'green'))
                domain_full = fqdn.strip()
            print(fqdn.strip())
    if not nc:
        print(colored("[-] Bind to LDAP failed! Exiting...", 'red'))
        exit(1) 
    return domain_full


def ldap_dump_full(dc_ip, domain_full,user=None,pwd=None):
    print(colored("\n[*] Full LDAP domain dump into file.",'blue'))
    file = "ldap_domain_full.raw"
    if user:
        domain = domain_strip(domain_full)
        print(colored("[*] Trying authenticated bind...",'grey'))
        out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -D {user}@{domain} -w {pwd} -b {domain_full}")
    else:
        print(colored("[*] Trying unauthenticated bind...",'grey'))
        out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -x -b {domain_full}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    if "Operations error" in out:
        print(colored("[-] Operation failed.", 'yellow'))
        exit(1) 
    # create folder before first 'save to file' operation
    if not config.out_folder:
        core.makeworkdir()
    try:
        with open(file, "w") as f:
            f.writelines(out.strip())
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    print(colored(f"[+] Success! Results saved in {config.out_folder}/{file}.", 'green'))


def ldap_list_users_computers(dc_ip, domain_full,user=None,pwd=None):
    print(colored("\n[*] Listing non-admin AD users and computers.",'blue'))
    if user:
        domain = domain_strip(domain_full)
        print(colored("[*] Trying authenticated bind...",'grey'))
        out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -D {user}@{domain} -w {pwd} -b {domain_full} (objectClass=Person) sAMAccountName")
    else:
        print(colored("[*] Trying unauthenticated bind...",'grey'))
        out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -x -b {domain_full} (objectClass=Person) sAMAccountName")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    try:
        write1= False
        write2 = False
        f1 = open("ldap_users.txt", "w")
        f2 = open("ldap_computers.txt", "w")
        lines = out.split('\n')
        cnt = 0
        for line in lines:
            if not "sAMAccountName:" in line:
                continue
            cnt+=1
            aduc = line.split("sAMAccountName:")[1]
            if cnt < 100:
                print(f"[+] {aduc.strip()}")
            if "$" in aduc:
                f2.write(aduc.strip()+'\n')
                write2 =True
            else:
                f1.write(aduc.strip()+'\n')
                write1 =True
        f1.close()
        f2.close()
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    if write1 or write2:
        print(colored(f"[+] Success! Results saved in {config.out_folder}/ldap_users.txt and {config.out_folder}/ldap_computers.txt.", 'green'))
    else:
        print(colored("[-] Listing was not possible.", 'yellow'))

def ldap_find_desc(dc_ip, domain_full,user=None,pwd=None):
    print(colored("\n[*] Looking for interesting descriptions in User and Computer Objects.",'blue'))
    if user:
        domain = domain_strip(domain_full)
        print(colored("[*] Trying authenticated bind...",'grey'))
        out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -D {user}@{domain} -w {pwd} -b {domain_full} (objectClass=Person) description")
    else:
        print(colored("[*] Trying unauthenticated bind...",'grey'))
        out, err = core.execute_command(f"ldapsearch -H ldap://{dc_ip} -x -b {domain_full} (objectClass=Person) description")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    try:
        lines = out.split("\n")
        r = re.compile(r'description:')
        found = False
        for i,line in enumerate(lines):
            if r.search(line):
                if not "Built" in line:
                    found = True
                    print(lines[max(0, i-1)].strip("dn: ").strip()+ " ", end='')
                    print(colored(line, 'red'))
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    if not found:
        print(colored("[-] Nothing interesting found", 'grey'))

def domain_strip(domain_full):
    pattern = re.compile("DC=", re.IGNORECASE)
    temp = pattern.sub("", domain_full)
    domain_full_stripped = temp.replace(',','.')
    return domain_full_stripped

def bloodhound_dump(dc_ip, domain_full, user, pwd):
    print(colored("\n[*] Running python based ingestor for Bloodhound - full dump.",'blue'))
    domain = domain_strip(domain_full)
    proc = f"bloodhound-python -c ALL -u {user} -p {pwd} -d {domain} -ns {dc_ip} --dns-timeout 120 --zip"
    out, err = core.execute_command(proc)
    if "LifetimeTimeout" in err:
        print(colored("[-] Error occured. Make sure specified IP address is correct. \n[-] Exiting...",'red'))
        exit(1)
    if err and not "INFO" in err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    if "ERROR" in err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    print(colored(f"[+] Success! Results saved to zip in {config.out_folder} directory.", 'green'))

def ldap_main(dc_ip, domain, user, pwd):
    domain_full = ldap_try_to_bind(dc_ip,user,pwd)
    if not domain_full:
        print(colored(f"[-] Failed to bind to LDAP server.",'red'))
    ldap_dump_full(dc_ip, domain_full,user,pwd)
    ldap_list_users_computers(dc_ip, domain_full,user,pwd)
    ldap_find_desc(dc_ip, domain_full,user,pwd)
    if user:
        bloodhound_dump(dc_ip, domain_full, user, pwd)