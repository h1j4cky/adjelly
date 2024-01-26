#!/bin/bash

# run 'chmod +x install.sh' first

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root." 
   exit 1
fi

dir="/opt/ADJ_toolkit"
tools_dir="/opt/ADJ_toolkit/ADJ_tools"
lists_dir="/opt/ADJ_toolkit/ADJ_lists"

apt-get update && apt-get install -y ntpdate systemd-timesyncd dnsutils nmap ldap-utils smbclient smbmap certipy-ad python3-impacket impacket-scripts crackmapexec hashcat bloodhound.py

mkdir $dir $tools_dir $lists_dir 

# ---------------- tools ---------------------
wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64/ -O "$tools_dir/kerbrute"
chmod +x "$tools_dir/kerbrute"

# ---------------- lists ---------------------
wget https://github.com/insidetrust/statistically-likely-usernames/blob/master/jjsmith.txt -O "$lists_dir/usernames.txt"
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O "$lists_dir/rockyou.txt"
