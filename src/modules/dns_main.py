from termcolor import colored
import re 
import src.modules.core as core
import src.modules.config as config

def dns_enum(dc_ip, domain_name):
    print(colored("\n[*] Performing DNS enumeration.", 'blue'))
    out, err = core.execute_command(f"dig any @{dc_ip} {domain_name}")
    lines = out.split("\n")
    if "failed" in out:
        print(colored("[-] DNS enumeration failed.", 'yellow'))
    elif "timed out" in out:
        print(colored("[-] Connection timed out. Make sure that specified IP address is correct.", 'yellow')) # firewall?
    else:
        print(colored("[+] Success! DNS enumeration results:", 'green'))
        save_to_file = True
        first_line = False
        try:
            f = open("/etc/hosts", "a")
        except:
            print(colored("[-] Error occured while opening /etc/hosts file.", 'yellow'))
            save_to_file = False
        for line in lines:
            if not line.startswith(";") and line.strip():
                print(line.strip())
            if re.search("[\t]A[\t]",line) and (save_to_file is True):
                arr = re.split("[\t]+", line.strip())
                ip_addr = arr[-1]
                hostname = arr[0].split(" ")[0].rstrip('.')
                try:
                    if first_line is False:
                        f.write("# --- The following lines were appended by ADJ tool ---\n")
                        first_line = True
                    f.write(ip_addr +'\t' + hostname + '\n')
                except:
                    print(colored("[-] Error occured while saving to /etc/hosts file.", 'yellow'))
        if save_to_file is True:
            try:
                f.write("# ----------------- ADJ tool end ----------------------\n")
                f.close()
            except:
                print(colored("[-] Error occured while closing /etc/hosts file.", 'yellow'))
                return
            print(colored("[+] DNS entries added to /etc/hosts file.", 'green'))

def clear_etc_hosts():
    print(colored("\n[+] Reverting /etc/hosts file to previous contents...", 'blue'))
    beg = "# --- The following lines were appended by ADJ tool ---"
    end = "# ----------------- ADJ tool end ----------------------"
    try:
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()
        with open("/etc/hosts", "w") as f:
            write = True
            for i in range(len(lines)):
                if i < (len(lines)-1) and (lines[i].strip() == beg or (lines[i+1].strip() == beg and lines[i].strip == "")):
                    write = False
                elif lines[i].strip() == end:
                    write = True
                elif write is True:
                    f.write(lines[i])
    except Exception as e:
        print(colored(f"[-] Error occured while reverting /etc/hosts file. {e}", 'yellow'))
        return
    print(colored("[+] Success!", 'green'))

def zone_transfer(dc_ip, domain_name):
    print(colored("\n[*] Trying DNS zone transfer using DIG.", 'blue'))
    out, err = core.execute_command(f"dig axfr @{dc_ip} {domain_name}")
    if err:
        print(colored(f"[-] Error: {err.strip()} \n[-] Exiting...",'red'))
        exit(1)

    lines = out.split("\n")
    if "failed" in out:
        print(colored("[-] DNS zone transfer failed.", 'yellow'))
        return
    elif "timed out" in out:
        print(colored("[-] Connection timed out. Make sure that specified IP address is correct.", 'yellow'))
        return
    try:
        if not config.out_folder:
            core.makeworkdir()
        with open("dns_zone_transfer.txt", "w") as f: 
            if len(lines) >= 50: # if more than ~50 records save results to file and do not print them
                print(colored(f"[+] Success! DNS zone file saved to {config.out_folder}/dns_zone_transfer.txt.", 'green'), end = "")
                for i in range(len(lines)):
                    f.write(lines[i].strip()+'\n')
            else:
                print(colored("[+] Success! DNS zone file contents:", 'grey'))
                for line in lines:
                    if not line.startswith(";"):
                        if line.startswith("_"): print(line.strip())
                        else: print(colored(line.strip(), "cyan"))
                        f.write(line.strip()+'\n')
    except Exception as e:
        print(colored(f"[-] Error occured: {e}",'red'))
        exit(1)

def main(dc_ip, domain):
    dns_enum(dc_ip, domain)
    # create folder before first 'save to file' operation
    zone_transfer(dc_ip, domain)
    #clear_etc_hosts()