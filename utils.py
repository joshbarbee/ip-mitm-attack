import os
import socket
import json
import sys

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

def prompt_pcap_path():
    print("> Input path to PCAP output file")
    print("> Leave path empty to not save PCAP")

    while True:
        path = input("> path: ")

        if len(path) == 0:
            return None

        if path[0] not in {'.', '/'}:
            path = './' + path

        if validate_path(path):
            return path
        
        print("> Invalid path. Unable to create PCAP at provided path")

def prompt_ip_type():
    print("> Use IPv4 and ARP packets or IPv6 and NDP")
    print("> Enter '4' for IPv4 and ARP, '6' for IPv6 and NDP")

    while True:
        ip_type = input("> ip type: ")

        if ip_type in {'4', '6'}:
            return ip_type
        print("> Invalid IP type. Try again")

def validate_path(path):
    if len(path) == 0:
        return False

    # https://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta
    if os.path.exists(path):
        return True
    elif os.access(os.path.dirname(path), os.W_OK):
        return True
    return False