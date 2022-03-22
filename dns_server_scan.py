from scapy.all import *
import argparse

def dns_scan(ip, q, qt, timeout, output):
    source_port = random.randint(1025, 65534)
    p = IP(dst = ip) / UDP(sport = source_port, dport = 53) / DNS(rd = 1, qd = DNSQR(qname = q, qtype = qt))
    resp = sr(p, timeout = timeout, verbose = 0)
    f = open(output, 'a')
    for a in resp[0]:
        if a[1].haslayer(DNS):
            ampl_ratio = len(a[1]) / len(p)
            f.write(a[1].src + ' ' + q + ' ' + qt + ' ' + str(ampl_ratio)+ '\n')
            print(a[1].src, q, qt, ampl_ratio)
    f.close()  

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', help = 'IP-address of DNS-server or range of IP-addresses (Example: 192.168.1.100 or 192.168.0.0/24)')
    parser.add_argument('-query', default = '.', help = 'DNS-query, i.e. domain name (Default: . (root))')
    parser.add_argument('-querytype', default = 'TXT', help = 'Type of DNS-query (Default: TXT')
    parser.add_argument('-timeout', type = int, default = 2, help = 'Timeout for response. 0 - infinite timeout (Default: 2s)')
    parser.add_argument('-output', help = 'Name of output file (Format: IP DNS_query Query_type Amplification_ratio)')
    args = parser.parse_args()
    ip = args.ip
    query = args.query
    query_type = args.querytype
    timeout = args.timeout
    output_name = args.output
    if (output_name == None) or (ip == None):
        print('Some arguments are missing')
        parser.print_help()
        sys.exit(0)
    dns_scan(ip, query, query_type, timeout, output_name)
    print('Scanning is complete')