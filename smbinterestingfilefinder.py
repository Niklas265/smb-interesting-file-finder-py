import argparse
import concurrent.futures
import logging
import ntpath
import os
import signal
import threading
import time
import socket
from nslookup import Nslookup
from impacket.ldap.ldap import LDAPConnection
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.ldap.ldapasn1 import SimplePagedResultsControl
from impacket import smb
from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SMB2_DIALECT_002

# These are all variables that the threads need.
# Easy solution to just make them global, as the threads only read these variables.
dc_ip = None
dc_fqdn = None
username = None
password = None
hashes = None
lmhash = None
nthash = None
domain = None
basedn = None
delay = None
keywords = None
exclude_hosts = None
finished_hosts_output_file = None
output_dir = None
lock = None
auth_type = None
excluded_shares = ['admin$','ipc$','sysvol']

# This is intentional a HARD FORCED QUIT
# As a soft quit somehow takes ages and doesn't really work
# and I don't know python enough currently to fix the soft quit version
def signal_handler(signal, frame):
    print("\n[+] Received SIGINT, exiting...")
    os._exit(1)

def parse_dn(domainname:str):
    dn = ""
    first = True
    for i in domainname.split("."):
        if first is False:
            dn = dn + ","
        dn = dn + f"DC={i.upper()}"
        first = False
    return dn

def parse_search_list(path:str):
    try:
        search_terms = []
        if os.path.exists(path) and os.path.isfile(path):
            file = open(path,"r")
            if file.readable():
                lines = file.readlines()
                for line in lines:
                    #search_terms.append(line[:-1].encode('utf-8'))
                    search_terms.append(line.rstrip().lstrip().replace(" ", "").replace("-", "").replace("_", "").lower().encode('utf-8'))
                return search_terms
        return []
    except:
        return []

def open_output_file(path:str, output_type:str):
    return open(os.path.join(output_dir, path + ".txt"),"a")

def connect_ldap(ldapServer: str, user: str,password: str, domain: str, base_dn:str):
    try:
        ldap_con = LDAPConnection(ldapServer,baseDN=base_dn)
        if auth_type == 'pass':
            ldap_con.login(user,password,domain,'','')
        elif auth_type == 'pth':
            ldap_con.login(user,'',domain,lmhash,nthash)
        elif auth_type == 'kerberos-pass':
            ldap_con.kerberosLogin(user,password,domain,'','',None,dc_ip)
        elif auth_type == 'kerberos-pth':
            ldap_con.kerberosLogin(user,password,domain,lmhash,nthash,None,dc_ip)
        else:
            logging.info('[-] Corrupt Auth Type')
            os.exit(-1)
        logging.info(f'[+] Successfull LDAP bind!')
        return ldap_con
    except OSError:
        logging.info('[-] No route to host!')
        return None
    except LDAPSessionError:
        logging.info("[-] Invalid credentials!")
        return None

def ldap_query(ldap_connection, base_dn:str, search_filter:str):
    paged_search_control = SimplePagedResultsControl(critical=True, size=1000)
    result = ldap_connection.search(searchFilter=search_filter,attributes=['name'], searchControls=[paged_search_control])
    return result

def parse_computers(ldap_result):
    ret = []
    for computer in ldap_result:
        if isinstance(computer,SearchResultEntry) is not True:
            continue
        for attribute in computer['attributes']:
            if str(attribute['type']) == 'name':
                name = str(attribute['vals'][0])
                ret.append(name)
    return ret

def resolve_hostname(dns_server: str,host: str, domain: str):
    fqdn = f"{host}.{domain}"
    dns_query = Nslookup(dns_servers=[dns_server],verbose=False)
    a_record = dns_query.dns_lookup(fqdn).answer
    if len(a_record) > 0:
        return a_record[0]
    else:
        return None

def connect_smb(connection_dest:str,username:str,password:str,domain:str):
    try:
        smbClient = SMBConnection(connection_dest,connection_dest,sess_port=445,preferredDialect=None, timeout=10)
        if auth_type == 'pass':
            smbClient.login(username,password,domain,'','')
        elif auth_type == 'pth':
            smbClient.login(username,'',domain,lmhash,nthash)
        elif auth_type == 'kerberos-pass':
            smbClient.kerberosLogin(username,password,domain,'','','', dc_ip)
        elif auth_type == 'kerberos-pth':
            smbClient.kerberosLogin(username,'',domain,lmhash,nthash,'',dc_ip)
        else:
            logging.info("[-] Corrupt Auth Type")
        return smbClient
    except:
        logging.info("[-] %s: Connection Error: %s", host, str(connection_dest))
        return None

def get_smb_share_list(con):
    ret = []
    try:
        shares = con.listShares()
        for i in shares:
            ret.append(i["shi1_netname"].rstrip('\x00'))
    except:
        pass
    return ret

def eval_filename(filename,keywords):
    fn = filename.rstrip().lstrip().replace("+", "").replace("=", "").replace(".", "").replace("\\", "").replace(" ", "").replace("-", "").replace("_", "").lower().encode('utf-8')
    for i in keywords:
        if i in fn:
            logging.debug(i)
            return True
    return False

def recurse_share(con,sharename,directory,keywords,host,output):
    try:
        output = open_output_file(host, "output")
        files = con.listPath(sharename,directory)
        for i in files:
            try:
                if i.is_directory() and i.get_longname() != "." and i.get_longname() != "..":
                    new_dir = directory[:-1]
                    recurse_share(con,sharename,directory[:-1]+i.get_longname()+"/*",keywords,host,output)
                elif not i.is_directory():
                    if eval_filename(i.get_longname(),keywords):
                        full_path = f"//{con.getRemoteHost()}/{sharename}/{directory[:-1]}{i.get_longname()}"
                        full_path = full_path.replace("/", "\\")
                        logging.info("%s\t%s", host, full_path)
                        if output != None:
                            output.write(f"{full_path}\n")
                            output.flush()
            except:
                pass
    except smb.SessionError as e:
        logging.info(e)

def write_finished_host(host, ip):
    if finished_hosts_output_file != None:
        with lock:
            with open(finished_hosts_output_file, "a") as file:
                file.write(f"{host} {ip}\n")

def traverse_shares(share_list,con,keywords,host):
    # Iterate over all shares but skip uninteresting shares like admin$, ipc$ and sysvol
    try:
        with open_output_file(host, "output") as output:
            for share in share_list:
                if not share.lower() in excluded_shares:
                    try:
                        logging.info(f"[+] {host}: Searching Share {share}...")
                        share_con = con.connectTree(share)
                        recurse_share(con,str(share),"*",keywords,host,output)
                    except:
                        logging.info("[-] %s: Error while accessing share (e.g. insufficient permissions)", host)
    except:
        logging.info("[-] Error: Unable to access output directory")

def get_hosts_from_file(filename):
    ret = []
    with open(filename, 'r') as file:
        for line in file:
            ret.append(line.strip())
        return ret

# TODO: Doing the delay twice in the else-case and at the end is quite ugly
# But I wanted to keep the delay for both cases (IP could be found and no IP)
# As this function is called from the multithreading ".map()" library function
# we can't do the delay outside of the function
def search_host(host):
    if str(host) in exclude_hosts:
        logging.info("[+] host is excluded")
        return

    ip = resolve_hostname(dc_ip,host,domain)
    if ip != None:
        logging.info(f"[+] {host}: START")
        smb_connection_destination = ip
        if 'kerberos' in auth_type:
            smb_connection_destination = host
        connection = connect_smb(smb_connection_destination,username,password,domain)
        if connection != None:
            share_list = get_smb_share_list(connection)
            traverse_shares(share_list,connection,keywords,host)
    else:
        return

    try:
        write_finished_host(host, ip)
    except Exception as e:
        logging.info("WRITING HOST DIDN'T WORK: %s", e)

    if delay > 0:
        logging.info(f"[+] {delay} seconds delay between servers...")
        time.sleep(delay)

    logging.info("[+] %s: END", host)

def main():
    parser = argparse.ArgumentParser(description="Tool to find interesting files, that are accessible on shares inside a domain")
    authgroup = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument('-n','--dc-ip', action='store', type=str, help='IP of Domain Controller', required=True)
    parser.add_argument('-u',"--username", action='store', type=str, help='Username', required=True)
    authgroup.add_argument('-p',"--password", action='store', type=str, help='Password')
    authgroup.add_argument('-H',"--hashes", action='store',type=str, help='NTLM hashes, format is LMHASH:NTHASH')
    parser.add_argument('-d',"--domain", action='store', type=str, help='FQDN of the domain', required=True)
    parser.add_argument('-k','--kerberos', action='store_true', default=False, help='Use Kerberos authentication instead of NTLM', required=False)
    parser.add_argument('-s',"--search", action='store', type=str, help='Path to file with searchterms', required=True)
    parser.add_argument('-f','--filter', action='store', type=str, help="Regex LDAP-Filter for specific computer objects, such as *dc*", required=False)
    parser.add_argument('-S',"--ldaps", action='store_true', default=False, help="Use LDAPS")
    parser.add_argument('-o','--output-dir', action='store', type=str, help="Output directory: One file per host will be written", required=False)
    parser.add_argument('-l','--output-hosts', action='store', type=str, help="Write the queried hosts from LDAP to file", required=False)
    parser.add_argument('-w','--delay', action='store', type=int, help="Delay between SMB-Servers", required=False)
    parser.add_argument('-r','--hosts', action='store', type=str, help="Use hosts file instead of querying LDAP", required=False)
    parser.add_argument('-x','--exclude-hosts', action='store', type=str, help="File with hosts that should be excluded", required=False)
    parser.add_argument('-z','--finished-hosts', action='store', type=str, help="Write finished hosts and their IP address to file; this can be the same as -x (--exclude-hosts)", required=False)
    parser.add_argument('-t','--number-threads', action='store', type=int, help="Number of threads: Default is 5", required=False)
    parser.add_argument('-X','--exclude-shares',action='store',type=str, help='Comma-separated list of case-insensitives sharenames, e.g. c$, always skips admin$, ipc$ and sysvol')

    arguments = parser.parse_args()
    
    global dc_ip
    global dc_fqdn
    global username
    global password
    global hashes
    global lmhash
    global nthash
    global auth_type
    global domain
    global basedn
    global delay
    global keywords
    global exclude_hosts
    global finished_hosts_output_file
    global output_dir
    global lock
    global excluded_shares

    signal.signal(signal.SIGINT, signal_handler)

    # Setup the logging facility
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO, datefmt="%FT%H:%M:%S")
    
    dc_ip = arguments.dc_ip
    username = arguments.username
    password = arguments.password
    hashes = arguments.hashes
    if arguments.hashes is not None:
        lmhash,nthash = hashes.split(':')
    domain = arguments.domain
    basedn = parse_dn(domain)
    delay = -1
    keywords = parse_search_list(arguments.search)
    exclude_hosts = ""
    finished_hosts_output_file = None
    auth_type = None
    kerberos = arguments.kerberos

    dc_connection = dc_ip
    
    if password != None:
        auth_type = 'pass'
    elif hashes != None:
        auth_type = 'pth'

    if kerberos:
        auth_type = 'kerberos-' + auth_type
        dc_fqdn = socket.getnameinfo((dc_ip,0),0)[0]
        dc_connection = dc_fqdn

    if len(keywords) == 0:
        logging.info("[-] Empty list of searchterms or unable to read searchterm file")
        return

    if arguments.exclude_shares != None:
        for share in arguments.exclude_shares.split(','):
            excluded_shares.append(share.lower())

    # TODO: should probably move the logic to a function
    host_list = []
    if arguments.hosts:
        host_list = get_hosts_from_file(arguments.hosts)
    else:
        
        ldap_connect_string = f"ldap://{dc_connection}"
        if arguments.ldaps == True:
            ldap_connect_string = f"ldaps://{dc_connection}"
        connection = connect_ldap(ldap_connect_string,username,password,domain,basedn)
        if not connection:
            return

        ldap_filter = "(objectCategory=computer)"
        if arguments.filter:
            ldap_filter = f"(&{ldap_filter}(name={arguments.filter}))"

        results = ldap_query(connection, basedn,ldap_filter)
        host_list = parse_computers(results)
    
    # TODO: should probably move the logic to a function
    logging.info(f"[+] Found {len(host_list)} computers!")
    if arguments.output_hosts:
        logging.info(f"[+] Writing computers to file")
        computers_file = open_output_file(arguments.output_hosts, "computers output")
        if computers_file is None:
            return
        computers_file.writelines(item + '\n' for item in host_list)
        computers_file.close()

    if arguments.exclude_hosts:
        try:
            with open(arguments.exclude_hosts, "r") as file:
                exclude_hosts = file.read()
        except Exception as e:
            logging.info("Reading Exclude hosts didn't work: %s", e)
            exit()
    
    if arguments.finished_hosts:
        finished_hosts_output_file = arguments.finished_hosts
    
    # The base directory to which a results file for each host is written to
    if arguments.output_dir and os.path.exists(arguments.output_dir):
        output_dir = arguments.output_dir
        if output_dir is None:
            return
    
    if arguments.delay:
        delay = int(arguments.delay)

    lock = threading.Lock()

    # Start the scan using a thread pool
    logging.debug("Starting scan")
    num_threads = 5
    if arguments.number_threads:
        num_threads = arguments.number_threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        executor.map(search_host, host_list)

if __name__ == "__main__":
    main()
