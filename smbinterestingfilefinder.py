import os
import ldap
from nslookup import Nslookup
from impacket.smbconnection import SMBConnection
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

def connect_ldap(ldapServer: str, user: str,password: str):
    ldap_con = ldap.initialize(ldapServer)
    ldap_con.set_option(ldap.OPT_REFERRALS,0)
    try:
        ldap_con.protocol_version = ldap.VERSION3
        ldap_con.simple_bind_s(user,password)
        print(f'[+] Successfull bind! as {ldap_con.whoami_s()}')
        return ldap_con
    except ldap.INVALID_CREDENTIALS:
        print("[-] Invalid credentials!")
        return None

def ldap_query(ldap_connection, base_dn:str, search_filter:str):
    gid = ldap_connection.search(base_dn,ldap.SCOPE_SUBTREE,search_filter)
    result_type,result = ldap_connection.result(gid)
    return result

def parse_computers(ldap_result):
    ret = []
    for computer in ldap_result:
        dn,attributes = computer
        if dn != None:
            ret.append(attributes["name"][0].decode())
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
        smbClient = SMBConnection(ip,ip,sess_port=445,preferredDialect=None)
        print(smbClient.getDialect())
        smbClient.login(username,password,domain,'','')
        return smbClient
    except:
        print("Connection Error")
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

def recurse_share(con,sharename,directory,keywords):
    try:
        files = con.listPath(sharename,directory)
        for i in files:
            try:
                if i.is_directory() and i.get_shortname() != "." and i.get_shortname() != "..":
                    #print(i.get_shortname())
                    new_dir = directory[:-1]
                    recurse_share(con,sharename,directory[:-1]+i.get_shortname()+"/*",keywords)
                elif not i.is_directory():
                    if eval_filename(i.get_shortname(),keywords):
                        print(f"//{con.getRemoteHost()}/{sharename}/{directory[:-1]}{i.get_shortname()}")
            except:
                pass
    except smb.SessionError as e:
        print(e)

def traverse_shares(share_list,con,keywords):
    print(share_list)
    # Iterate over all shares but skip uninteresting shares like admin$, ipc$ and sysvol
    for share in share_list:
        if share.lower() != 'admin$' and share.lower() != 'sysvol' and share.lower() != 'ipc$':
            try:
                print(share)
                #shell = MiniImpacketShell(con)
                #shell.onecmd(f"use {share}")
                #shell.onecmd("ls")
                #continue
                share_con = con.connectTree(share)
                print(share_con)
                recurse_share(con,str(share),"*",keywords)
            except:
                print("Error")


def main():
    parser = argparse.ArgumentParser(description="Tool to find interesting files, that are accessible on shares inside a domain")
    parser.add_argument('--dc-ip', action='store', type=str, help='IP of Domain Controller', required=True)
    parser.add_argument('-u',"--username", action='store', type=str, help='Username', required=True)
    parser.add_argument('-p',"--password", action='store', type=str, help='Password', required=True)
    parser.add_argument('-d',"--domain", action='store', type=str, help='FQDN of the domain', required=True)
    parser.add_argument('-s',"--search", action='store', type=str, help='Path to file with searchterms', required=True)

    parser.add_argument('-f','--filter', action='store', type=str, help="Regex LDAP-Filter for specific computer objects, such as *dc*", required=False)
    
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

    connection = connect_ldap(f"ldap://{dc_ip}",f"{username}@{domain}",password)
    if not connection:
        return

    ldap_filter = "(objectCategory=computer)"
    if arguments.filter:
        ldap_filter = f"(&{ldap_filter}(name={arguments.filter}))"
    
    results = ldap_query(connection, basedn,ldap_filter)
    host_list = parse_computers(results)
    print(f"[+] Found {len(host_list)} computers!")
    for host in host_list:
        print(host)
        ip = resolve_hostname(dc_ip,host,domain)
        if ip != None:
            print(ip)
            connection = connect_smb(ip,username,password,domain)
            if connection != None:
                share_list = get_smb_share_list(connection)
                traverse_shares(share_list,connection,keywords)

if __name__ == "__main__":
    main()
