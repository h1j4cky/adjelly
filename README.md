# ADJelly
Active Directory enumeration and exploitation tool

## Installation
Go to adjelly directory
```
cd adjelly
```
There is pyproject.toml file located in it. Install ADJELLY with _flit_ package manager: 
```
flit build
```
Run _install.sh_ script as root to install necessary tools (nmap, crackmapexec, etc.)
```
sudo ./install.sh
```
The script also creates directories with default enumeration lists and scripts in /opt directory. 

## Usage
Run `sudo adjelly` to get the list of available modules:
```
Usage: adjelly [OPTIONS] COMMAND [ARGS]...

  ADJelly is an Active Directory enumeration and exploitation tool.

Options:
  --help  Show this message and exit.

Commands:
  cert         Checks for AD CS vulnerabilities and tries to exploit them.
  clean        Restores previous time settings and /etc/hosts file contents.
  dns          Performs DNS enumeration.
  fullscan     Tries to exploit all available AD attack paths.
  krb_init     Performs Kerberos attacks that do not require creds.
  krb_lateral  Performs Kerberos attacks focused on lateral movement.
  krb_spray    Performs AS-REP roast and password spray attack.
  ldap         Performs LDAP enumeration.
  smb          Performs SMB enumeration and exploitation.
  synchronize  Synchronizes time with NTP server.
```
