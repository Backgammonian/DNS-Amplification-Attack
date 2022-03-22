# DNS-Amplification-Attack
A set of Python scripts for performing stress-test using DNS amplification attack\
These scripts were created during Networks and Communications course as coursework
## Usage
* `dns_server_scan.py` - makes request to DNS-server and calculates resulting amplification ratio
* `dns_server_check.py` - checks if DNS-server is tolerant for query flood
* `dns_amplification.py` - performs DNS amplification attack using target's IP-address and information about viable DNS-servers and queries with confirmed amplification ratio
