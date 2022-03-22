from scapy.all import *
import argparse

def read_servers(data_file):
    with open(data_file) as servers_file:
        server_list = [row.strip() for row in servers_file]
    return server_list
    
def main(servers_list, output, timeout):
    f = open(output, 'w')
    i = 0
    for element in servers_list:
        source_port = random.randint(1025, 65534)
        param = servers_list[i].split()
        p = IP(dst = param[0]) / UDP(sport = source_port, dport = 53) / DNS(rd = 1, qd = DNSQR(qname = param[1], qtype = param[2]))
        send(p, inter = 0, verbose = 0, count = 100)
        resp = sr(p, timeout = timeout, verbose = 0)
        for a in resp[0]:
            if a[1].haslayer(DNS):
                ampl_ratio = len(a[1]) / len(p)
                if ampl_ratio >= float(param[3]):
                    print(a[1].src, 'is good')
                    f.write(param[0] + ' ' + param[1] + ' ' + param[2] + ' ' + param[3] + '\n')
        i += 1
    f.close()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-input', help = 'File with list of servers to be checked (Format: IP DNS_query Query_type Amplification_ratio)')
    parser.add_argument('-timeout', type = int, default = 2, help = 'Timeout. 0 - infinite timeout (Default: 2s)')
    parser.add_argument('-output', help = 'Output file (Format: IP DNS_query Query_type Amplification_ratio)')
    args = parser.parse_args()
    input_file = args.input
    timeout = args.timeout
    output_file = args.output
    if (input_file == None) or (output_file == None):
        print('Some arguments are missing')
        parser.print_help()
        sys.exit(0)
    print('Beginning of scan')
    servers = read_servers(input_file)
    main(servers, output_file, timeout)
    print('Scan complete')