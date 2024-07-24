import os
import time
from nslookup import Nslookup
from impacket.ldap.ldap import LDAPConnection
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap
from impacket import smb
from impacket.smbconnection import SMB2_DIALECT_002
from impacket.examples.smbclient import MiniImpacketShell
import ntpath
import argparse

def parseDN(domainname:str):
    dn = ""
    first = True
    for i in domainname.split("."):
        if first is False:
            dn = dn + ","
        dn = dn + f"DC={i.upper()}"
        first = False
    return dn

def parseSearchList(path:str):
    try:
        search_terms = []
        if os.path.exists(path) and os.path.isfile(path):
            file = open(path,"r")
            if file.readable():
                lines = file.readlines()
                for line in lines:
                    search_terms.append(line[:-1])
                return search_terms
        return []
    except:
        return []

def open_output_file(path:str):
    if os.path.exists(path):
        print("[-] File for output already exists")
        return None
    else:
        return open(path,"w+")

def connect_ldap(ldapServer: str, user: str,password: str, domain: str, base_dn:str):
    try:
        ldap_con = LDAPConnection(ldapServer,baseDN=base_dn)
        ldap_con.login(user,password,domain,'','')
        print(f'[+] Successfull LDAP bind!')
        return ldap_con
    except OSError:
        print('[-] No route to host!')
        return None
    except LDAPSessionError:
        print("[-] Invalid credentials!")
        return None

def ldap_query(ldap_connection, base_dn:str, search_filter:str):
    sc = ldap.SimplePagedResultsControl(size=100)
    result = ldap_connection.search(searchFilter=search_filter,attributes=['name'],searchControls=[sc])
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

def connect_smb(ip:str,username:str,password:str,domain:str):
    try:
        smbClient = SMBConnection(ip,ip,sess_port=445,preferredDialect=None, timeout=10)
        smbClient.login(username,password,domain,'','')
        return smbClient
    except:
        print("[-] Connection Error")
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
    for i in keywords:
        if i in filename:
            return True
    return False

def recurse_share(con,sharename,directory,keywords,output):
    try:
        files = con.listPath(sharename,directory)
        for i in files:
            try:
                if i.is_directory() and i.get_longname() != "." and i.get_longname() != "..":
                    new_dir = directory[:-1]
                    recurse_share(con,sharename,directory[:-1]+i.get_longname()+"/*",keywords,output)
                elif not i.is_directory():
                    if eval_filename(i.get_longname(),keywords):
                        full_path = f"//{con.getRemoteHost()}/{sharename}/{directory[:-1]}{i.get_longname()}"
                        print(full_path)
                        if output != None:
                            output.write(f"{full_path}\n")
                            output.flush()
            except:
                pass
    except smb.SessionError as e:
        print(e)

def traverse_shares(share_list,con,keywords,output):
    # Iterate over all shares but skip uninteresting shares like admin$, ipc$ and sysvol
    for share in share_list:
        if share.lower() != 'admin$' and share.lower() != 'sysvol' and share.lower() != 'ipc$':
            try:
                print(f"[+] Searching Share {share}...")
                #shell = MiniImpacketShell(con)
                #shell.onecmd(f"use {share}")
                #shell.onecmd("ls")
                #continue
                share_con = con.connectTree(share)
                recurse_share(con,str(share),"*",keywords,output)
            except:
                print("[-] Error while accessing share (e.g. insufficient permissions)")


def main():
    parser = argparse.ArgumentParser(description="Tool to find interesting files, that are accessible on shares inside a domain")
    parser.add_argument('-n','--dc-ip', action='store', type=str, help='IP of Domain Controller', required=True)
    parser.add_argument('-u',"--username", action='store', type=str, help='Username', required=True)
    parser.add_argument('-p',"--password", action='store', type=str, help='Password', required=True)
    parser.add_argument('-d',"--domain", action='store', type=str, help='FQDN of the domain', required=True)
    parser.add_argument('-s',"--search", action='store', type=str, help='Path to file with searchterms', required=True)

    parser.add_argument('-f','--filter', action='store', type=str, help="Regex LDAP-Filter for specific computer objects, such as *dc*", required=False)
    parser.add_argument('-o','--output', action='store', type=str, help="Output file", required=False)
    parser.add_argument('-t','--delay', action='store', type=int, help="Delay between SMB-Servers, required=false")
    arguments = parser.parse_args()
    
    dc_ip = arguments.dc_ip
    username = arguments.username
    password = arguments.password
    domain = arguments.domain
    basedn = parseDN(domain)
    keywords = parseSearchList(arguments.search)
    
    if len(keywords) == 0:
        print("[-] Empty list of searchterms or unable to read searchterm file")
        return

    connection = connect_ldap(f"ldap://{dc_ip}",username,password,domain,basedn)
    if not connection:
        return

    ldap_filter = "(objectCategory=computer)"
    if arguments.filter:
        ldap_filter = f"(&{ldap_filter}(name={arguments.filter}))"
    
    outputFile = None
    if arguments.output:
        outputFile = open_output_file(arguments.output)
        if outputFile is None:
            return

    delay = -1
    if arguments.delay:
        delay = int(arguments.delay)
    
        
    results = ldap_query(connection, basedn,ldap_filter)
    host_list = parse_computers(results)
    print(f"[+] Found {len(host_list)} computers!")
    for host in host_list:
        ip = resolve_hostname(dc_ip,host,domain)
        if ip != None:
            print(f"[+] Searching host {host}")
            connection = connect_smb(ip,username,password,domain)
            if connection != None:
                share_list = get_smb_share_list(connection)
                traverse_shares(share_list,connection,keywords,outputFile)
        if delay > 0:
            print(f"[+] {delay} seconds delay between servers...")
            time.sleep(delay)

if __name__ == "__main__":
    main()
