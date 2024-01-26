# ADJelly
ADJelly is an Active Directory enumeration and exploitation tool.

Choose module that suits you best.

## Installation
Go to adjelly directory
```
cd adjelly
```
There is pyproject.toml file located in it. Install ADJELLY with _flit_ package manager: 
```
flit build
flit install
```
// byc moze totalnie nie trzeba build
//If not done - add this directory to path to run it with name only
//Successfully uninstalled adversary-1.0.0
  WARNING: The script adversary is installed in '/home/hijacky/.local/bin' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.

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
### Fullscan
Fullscan command enumerates and exploits all attack paths that ADJelly has to offer.
```
Usage: adjelly fullscan [OPTIONS]

  Tries to exploit all available AD attack paths.

Options:
  -i, --dc-ip TEXT     Domain Controller IP address  [required]
  -u, --username TEXT  Username to authenticate as
  -p, --password TEXT  User password
  -d, --domain TEXT    Domain name
  -dc, --dcname TEXT   DC name in <dc_name>.<domain> format
  --meta               If set, the program tries to retrieve users from files'
                       metadata
  --spray-pass TEXT    Password to spray with.
  --enum-list TEXT     Full path to the list of users used for user
                       enumeration.
  --crack-list TEXT    Full path to the list of passwords used for cracking.
                       Default: rockyou.txt
  --no-crack           If specified, the tool will not try to crack hashes.
  -a, --altname TEXT   Specifies the username for certificate request. If not
                       provided, default to 'admin'.
  --help               Show this message and exit.
```
### SMB
Performs SMB enumeration and exploitation.  
If no creds provided, ADJelly tries anonymous SMB session.  

```
Usage: adjelly smb [OPTIONS]

  Performs SMB enumeration and exploitation.

Options:
  -i, --dc-ip TEXT     Domain Controller IP address  [required]
  -u, --username TEXT  Username to authenticate as
  -p, --password TEXT  User password
  -d, --domain TEXT    Domain name  [required]
  --meta               If set, the program tries to retrieve users from files'
                       metadata
  --help               Show this message and exit.
```

### LDAP
Performs LDAP enumeration.  
If no creds provided, ADJelly tries unauthenticated LDAP bind.
```
Usage: adjelly ldap [OPTIONS]

  Performs LDAP enumeration.

Options:
  -i, --dc-ip TEXT     Domain Controller IP address  [required]
  -d, --domain TEXT    Domain name
  -u, --username TEXT  Username to authenticate as
  -p, --password TEXT  User password
  --help               Show this message and exit.
```

### DNS
Performs DNS enumeration.
```
Usage: adjelly dns [OPTIONS]

  Performs DNS enumeration.

Options:
  -i, --dc-ip TEXT   Domain Controller IP address  [required]
  -d, --domain TEXT  Domain name  [required]
  --help             Show this message and exit.
```

### KRB_INIT
Performs Kerberos attacks that do not require creds.
```
Usage: adjelly krb_init [OPTIONS]

  Performs Kerberos attacks that do not require creds.

Options:
  -i, --dc-ip TEXT       Domain Controller IP address  [required]
  -d, --domain TEXT      Domain name  [required]
  -p, --spray-pass TEXT  Password to spray with.
  --enum-list TEXT       Full path to the list of users used for user
                         enumeration.
  --crack-list TEXT      Full path to the list of passwords used for cracking.
                         Default: rockyou.txt
  --no-crack             If specified, the tool will not try to crack hashes.
  --help                 Show this message and exit.
```

### KRB_SPRAY
Performs AS-REP roast and password spraying attack.
```
Usage: adjelly krb_spray [OPTIONS]

  Performs AS-REP roast and password spray attack.

Options:
  -i, --dc-ip TEXT       Domain Controller IP address  [required]
  -d, --domain TEXT      Domain name  [required]
  -p, --spray-pass TEXT  Password to spray with.
  --userlist TEXT        Full path to the list of users used for as-rep roast
                         and password spray.  [required]
  --crack-list TEXT      Full path to the list of passwords used for cracking.
                         Default: rockyou.txt
  --no-crack             If specified, the tool will not try to crack hashes.
  --help                 Show this message and exit.
```

### KRB_LATERAL
Performs Kerberos attacks focused on lateral movement.
```
Usage: adjelly krb_lateral [OPTIONS]

  Performs Kerberos attacks focused on lateral movement.

Options:
  -i, --dc-ip TEXT     Domain Controller IP address  [required]
  -u, --username TEXT  Username to authenticate as  [required]
  -p, --password TEXT  User password  [required]
  -d, --domain TEXT    Domain name  [required]
  -a, --altname TEXT   Username for ticket creation. If not provided, default
                       to 'admin'
  --no-crack           If specified, the tool will not try to crack hashes.
  --help               Show this message and exit.                                                 
```

### CERT
Checks for AD CS vulnerabilities and tries to exploit them (right now only ESC1 vulnerability is exploited when found).
```
Usage: adjelly cert [OPTIONS]

  Checks for AD CS vulnerabilities and tries to exploit them.

Options:
  -i, --dc-ip TEXT     Domain Controller IP address  [required]
  -u, --username TEXT  Username to authenticate as  [required]
  -p, --password TEXT  User password  [required]
  -d, --domain TEXT    Domain name  [required]
  -dc, --dcname TEXT   DC name in <dc_name>.<domain> format
  -a, --altname TEXT   Specifies the username for certificate request. If not
                       provided, default to 'admin'.
  --help               Show this message and exit.                                                     
```

### TODO
// here put chains with module names on it - at the beginning  
// in description of each module explain what exactly is going to happen  
