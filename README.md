# smb-interesting-file-finder-py

```
$ python smbinterestingfilefinder.py -h                                                                                                                                                                                                  
usage: smbinterestingfilefinder.py [-h] -n DC_IP -u USERNAME -p PASSWORD -d DOMAIN -s SEARCH [-f FILTER] [-o OUTPUT] [-t DELAY]

Tool to find interesting files, that are accessible on shares inside a domain

options:
  -h, --help            show this help message and exit
  -n DC_IP, --dc-ip DC_IP
                        IP of Domain Controller
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
  -d DOMAIN, --domain DOMAIN
                        FQDN of the domain
  -s SEARCH, --search SEARCH
                        Path to file with searchterms
  -f FILTER, --filter FILTER
                        Regex LDAP-Filter for specific computer objects, such as *dc*
  -o OUTPUT, --output OUTPUT
                        Output file
  -t DELAY, --delay DELAY
                        Delay between SMB-Servers, required=false

```
