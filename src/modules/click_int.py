import click
import src.modules.ldap_main as ldap_main
import src.modules.krb_init as krb_init
import src.modules.krb_lateral as krb_lateral
import src.modules.dns_main as dns_main
import src.modules.smb_main as smb_main
import src.modules.certificates as certificates
import src.modules.config as config
import src.modules.core as core
import src.addins.lolcat as lolcat

CONTEXT_SETTINGS = lolcat.logo()

@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    """ADversary is an Active Directory enumeration and exploitation tool."""
    core.initialize()

@cli.command()
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--username','-u', help='Username to authenticate as')
@click.option('--password','-p', help='User password')
@click.option('--domain','-d', default=None, required=False, help='Domain name')
@click.option('--dcname','-dc', required=False, help='DC name in <dc_name>.<domain> format')
@click.option('--meta', required=False, is_flag=True, show_default=True, default=False, help='If set, the program tries to retrieve users from files\' metadata')
@click.option('--spray-pass', required=False, help='Password to spray with.', default="Password123")
@click.option('--enum-list', required=False, help='Full path to the list of users used for user enumeration.')
@click.option('--crack-list', required=False, help='Full path to the list of passwords used for cracking. Default: rockyou.txt')
@click.option('--no-crack', required=False, is_flag=True, show_default=True, default=False, help='If specified, the tool will not try to crack hashes.')
@click.option('--altname','-a', required=False, help='Specifies the username for certificate request. If not provided, default to \'admin\'.')
def fullscan(dc_ip, username, password, domain, dcname, meta, spray_pass, enum_list, crack_list, no_crack, altname): 
    """ Tries to exploit all available AD attack paths. """
    core.fullscan(dc_ip, username, password, domain, dcname, meta, spray_pass, enum_list, crack_list, no_crack, altname)


@cli.command('cert')
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--username','-u', required=True, help='Username to authenticate as')
@click.option('--password','-p', required=True, help='User password')
@click.option('--domain','-d', required=True, help='Domain name')
@click.option('--dcname','-dc', required=False, help='DC name in <dc_name>.<domain> format')
@click.option('--altname','-a', required=False, help='Specifies the username for certificate request. If not provided, default to \'admin\'.')
def certs(dc_ip, username, password, domain, dcname, altname):
    """ Checks for AD CS vulnerabilities and tries to exploit them. """
    certificates.cert_main(domain, dc_ip, username, password, dcname, altname)


@cli.command()
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--domain','-d', required=True, help='Domain name')
def dns(dc_ip, domain):
    """Performs DNS enumeration."""
    dns_main.main(dc_ip, domain)


@cli.command('ldap')
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--domain','-d', required=False, help='Domain name')
@click.option('--username','-u', required=False, help='Username to authenticate as')
@click.option('--password','-p', required=False, help='User password')
def ldap_enum(dc_ip, domain, username, password):
    """Performs LDAP enumeration."""
    ldap_main.ldap_main(dc_ip, domain, username, password)


@cli.command()
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--username','-u', required=False, help='Username to authenticate as')
@click.option('--password','-p', required=False, help='User password')
@click.option('--domain','-d', required=True, help='Domain name')
@click.option('--meta', required=False, is_flag=True, show_default=True, default=False, help='If set, the program tries to retrieve users from files\' metadata')
def smb(dc_ip, domain, username, password, meta):
    """Performs SMB enumeration and exploitation."""
    smb_main.smb_main(dc_ip, domain, username, password, meta)

@cli.command('krb_init')
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--domain','-d', required=True, help='Domain name')
@click.option('--spray-pass','-p', required=False, help='Password to spray with.', default="Password123")
@click.option('--enum-list', required=False, help='Full path to the list of users used for user enumeration.')
@click.option('--crack-list', required=False, help='Full path to the list of passwords used for cracking. Default: rockyou.txt')
@click.option('--no-crack', required=False, is_flag=True, show_default=True, default=False, help='If specified, the tool will not try to crack hashes.')
def kerberos_init(dc_ip, domain, spray_pass, enum_list, crack_list, no_crack):
    """Performs Kerberos attacks that do not require creds."""
    krb_init.krbinit_full(dc_ip, domain, spray_pass, enum_list, crack_list, no_crack)
    krb_init.restoretime()



@cli.command('krb_spray')
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--domain','-d', required=True, help='Domain name')
@click.option('--spray-pass','-p', required=False, help='Password to spray with.', default="Password123")
@click.option('--userlist', required=True, help='Full path to the list of users used for as-rep roast and password spray.')
@click.option('--crack-list', required=False, help='Full path to the list of passwords used for cracking. Default: rockyou.txt')
@click.option('--no-crack', required=False, is_flag=True, show_default=True, default=False, help='If specified, the tool will not try to crack hashes.')
def kerberos_spray(dc_ip, domain, spray_pass, userlist, crack_list, no_crack):
    """Performs AS-REP roast and password spray attack."""
    krb_init.krb_spray(dc_ip, domain, spray_pass, userlist, crack_list, no_crack)
    krb_init.restoretime()



@cli.command('krb_lateral')
@click.option('--dc-ip', '-i', required=True, help='Domain Controller IP address')
@click.option('--username','-u', required=True, help='Username to authenticate as')
@click.option('--password','-p', required=True, help='User password')
@click.option('--domain','-d', required=True, help='Domain name')
@click.option('--altname','-a', required=False, help='Username for ticket creation. If not provided, default to \'admin\'')
@click.option('--no-crack', required=False, is_flag=True, show_default=True, default=False, help='If specified, the tool will not try to crack hashes.')
def kerberos_lateral(dc_ip, username, password, domain, altname, no_crack):
    """Performs Kerberos attacks focused on lateral movement."""
    krb_init.synchrotime(dc_ip)
    krb_lateral.krblateral_main(dc_ip, domain, username, password, altname, no_crack)
    krb_init.restoretime()

@cli.command()
@click.option('--dc-ip', '-i', required=True, help='NTP server\'s IP address')
def synchronize(dc_ip):
    """Synchronizes time with NTP server."""
    krb_init.synchrotime(dc_ip)

@cli.command()
def clean():
    """Restores previous time settings and /etc/hosts file contents."""
    krb_init.restoretime()
    dns_main.clear_etc_hosts()