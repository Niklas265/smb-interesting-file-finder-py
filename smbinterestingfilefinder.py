import ldap
from nslookup import Nslookup
import smbclient

basedn="xxxxx"
dc_ip = "xxxx"
username = "xxxxx"
domain = "xxxxxx"
password = "xxxxxx"

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


def main():
    connection = connect_ldap(f"ldap://{dc_ip}",f"{username}@{domain}",password)
    if not connection:
        return
    results = ldap_query(connection, basedn,"(objectCategory=computer)")
    host_list = parse_computers(results)
    print(f"[+] Found {len(host_list)} computers!")
    for host in host_list:
        print(host)
        ip = resolve_hostname(dc_ip,host,domain)
        if ip != None:
            print(ip)

if __name__ == "__main__":
    main()
