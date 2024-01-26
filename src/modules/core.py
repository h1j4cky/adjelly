import os
from colorama import init
from termcolor import colored
from subprocess import Popen, PIPE, TimeoutExpired
from datetime import datetime

import src.modules.ldap_main as ldap_main
import src.modules.krb_init as krb_init
import src.modules.krb_lateral as krb_lateral
import src.modules.dns_main as dns_main
import src.modules.smb_main as smb_main
import src.modules.nmap_main as nmap_main
import src.modules.certificates as certificates
import src.modules.config as config
import src.addins.lolcat as lolcat

def initialize():
    if not run_as_sudo():
        print(colored("[-] You must run the script as root.", 'yellow'))
        exit(1)
    init() # init colors

def run_as_sudo():
    return os.geteuid() == 0

def makeworkdir():
    now = datetime.now()
    current_time = now.strftime("%Y%m%d_%H%M%S")
    folder_name = "out_" + current_time
    os.system(f"mkdir {folder_name} 2>/dev/null")
    os.chdir(folder_name)
    if 'KRB5CCNAME' in os.environ:
        del os.environ['KRB5CCNAME']
    print(colored(f"[*] Output folder created: '{folder_name}'.",'blue'))
    config.out_folder = folder_name

def execute_command(proc):
    try:
        process = Popen(proc.split(" "), stdout=PIPE, stderr=PIPE, universal_newlines=True)
        outs, errs = process.communicate()
    except KeyboardInterrupt as ki:
        print(colored(f"[-] Program stopped by user.", 'yellow'))
        exit(1)
    except Exception as e:
        print(colored(f"[-] Execute command - error occured: {e}",'red'))
        exit(1)
    return outs, errs

def execute_command_with_timeout(proc):
    try:
        process = Popen(proc.split(" "), stdout=PIPE, stderr=PIPE, universal_newlines=True)
        outs, errs = process.communicate(timeout=15)
    except TimeoutExpired:
        process.kill()
        outs, errs = process.communicate()
        print(colored("[-] Timeout. Make sure that provided input is correct.",'red'))
        exit(1)
    except KeyboardInterrupt as ki:
        print(colored(f"[-] Program stopped by user.", 'yellow'))
        exit(1)
    except Exception as e:
        print(colored(f"[-] Execute command - error occured: {e}",'red'))
        exit(1)
    return outs, errs

def execute_command_in(proc, input):
    try:
        process = Popen(proc.split(" "), stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        outs, errs = process.communicate(input)
    except TimeoutExpired:
        process.kill()
        outs, errs = process.communicate()
        print(colored("[-] Timeout. Make sure that specified input is correct.",'red'))
        exit(1)
    except KeyboardInterrupt as ki:
        print(colored(f"[-] Program stopped by user.", 'yellow'))
        exit(1)
    except Exception as e:
        print(colored(f"[-] Execute command - error occured: {e}",'red'))
        exit(1)
    return outs, errs

def fullscan(dc_ip, username, password, domain, dcname, meta, spraypass, enumlist, cracklist, nocrack, altname):
    if not username:
        username = ''
        password = ''
    if not config.out_folder:
        makeworkdir() # create folder before first 'save to file' operation
    open_ports = nmap_main.scan(dc_ip)
    if domain is None or dcname is None:
        domain, dcname = nmap_main.scan_for_domain(dc_ip)
    if "53" in open_ports:
        dns_main.main(dc_ip, domain)
    if "445" in open_ports:
        smb_main.smb_main(dc_ip, domain, username, password, meta)
    if "389" or "636" in open_ports:
        print(password)
        ldap_main.ldap_main(dc_ip, domain, username, password)
    if "88" in open_ports:
        krb_init.krbinit_full(dc_ip, domain, spraypass, enumlist, cracklist, nocrack)

    # fullscan: authenticated user
    if username != '':
        krb_lateral.krblateral_main(dc_ip, domain, username, password, altname, nocrack)
        certificates.cert_main(domain, dc_ip, username, password, dcname, altname)
    
    krb_init.restoretime()