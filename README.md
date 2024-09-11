# smb-interesting-file-finder-py
Python AD enumeration tool to find accessible files with interesting keywords in their name on all readable SMB shares of the domain.

Inspired by Find-InterestingDomainShareFiles from PowerView
```
$ python smbinterestingfilefinder.py -h                                                                                                                                                                                                  
usage: smbinterestingfilefinder.py [-h] -n DC_IP -u USERNAME -p PASSWORD -d DOMAIN -s SEARCH [-f FILTER] [-o OUTPUT_DIR] [-l OUTPUT_HOSTS] [-w DELAY] [-r HOSTS] [-x EXCLUDE_HOSTS] [-z FINISHED_HOSTS] [-t NUMBER_THREADS]

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
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output directory: One file per host will be written
  -l OUTPUT_HOSTS, --output-hosts OUTPUT_HOSTS
                        Write the queried hosts from LDAP to file
  -w DELAY, --delay DELAY
                        Delay between SMB-Servers
  -r HOSTS, --hosts HOSTS
                        Use hosts file instead of querying LDAP
  -x EXCLUDE_HOSTS, --exclude-hosts EXCLUDE_HOSTS
                        File with hosts that should be excluded
  -z FINISHED_HOSTS, --finished-hosts FINISHED_HOSTS
                        Write finished hosts and their IP address to file; this can be the same as -x (--exclude-hosts)
  -t NUMBER_THREADS, --number-threads NUMBER_THREADS
                        Number of threads: Default is 5

```
