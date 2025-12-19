import sys
import os
import socket
import struct

def get_mac_addr(byte_addr):
    # format: transfer byte into 02x
    # map every address 
    # use symbol ':' to connect it
    byte_str = map('{:02x}'.format,byte_addr)
    return ':'.join(byte_str).upper()
# Sniffer
def get_ethernet_frame(data):
    #first 14 Bytes
    header=data[:14]
    #using struct.unpack
    destination_mac,source_mac,protocol_num = struct.unpack('! 6s 6s H', header)
    return get_mac_addr(destination_mac),get_mac_addr(source_mac),socket.htons(protocol_num), data[14:]

def get_IPv4_data(data):
    # first byte combined protocol version with header length
    version_header_length = data[0]
    version = version_header_length >> 4

    #use 'and' operation for extract info
    header_length = (version_header_length & 15) *4

    # unpack again
    # 8x: jump over first 8 bytes(which means service type, total length, ID, shift ...)
    # B: 1 byte for ttl
    # B: 1 byte for protocol
    # 2x: jump over 2 bytes( checksum)
    # 4s: 4 bytes (source IP)
    # 4s: 4 bytes (destination IP)
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return version,header_length,ttl,protocol,read_IPv4(target),read_IPv4(source),data[header_length:]

def read_IPv4(addr):
    return '.'.join(map(str,addr))

def main():
    if os.getuid() != 0:
        print("Please run as root") # must run as root user
        sys.exit(1)
    print("Starting packet sniffer...")

# establish a socket 
# socket.AF_PACKET: linux only. it is told with core that we are gonna talk with driver
# socket.SOCK_RAW: which means we need the raw data of packets
# socket.nthohs(3): 3 means ETH_P_ALL,'I need to capture all data based on varies protocols.
try:
    conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    #Parameters of 'socket' method: address family,type of data, protocols

    print("start monitoring...")
    while True:
        raw_data, address=conn.recvfrom(65536)
        des_mac,src_mac,eth_protocol,data = get_ethernet_frame(raw_data)
        #what raw_data looks like? b'r\x97\x18ay\x1dh\xaa\xc43po\x08\x00E\x00\x003\x00\x00@\x00:\x11\x9dg\x8e\xfaQ\xe3\xc0\xa8\x01\xcd\x01\xbb\xa7\x91\x00\x1f \x80B6\xfayV\x17\x02\xdb\x06\x89#\xe8\x00\xc3\xc8\x1aS\xd5\x08q,X\x81'
        # we need to transfer it into human-reading version.
        if(eth_protocol == 8):
            (ipversion,header_length,ttl,proto,source_IP,target_IP,data) = get_IPv4_data(data)

        print('\n'+ '=' * 30)
        print(f'destination MAC: {des_mac}')
        print(f'source MAC: {src_mac}')
        print(f'protocol: {eth_protocol}')
        print(f"length: {len(raw_data)} from {address[0]}")
        print('*'*10+'Data Info(Only IPv4)'+'*'*10)
        print(f'IPv4:{ipversion}')
        print(f'Source IP: {source_IP}')
        print(f'Target IP: {target_IP}')
        print(f'Protocol for transpot layer:{proto} (TCP=6, UDP=17)')
        print(f'ttl: {ttl}')
        
        print('=' * 30)
except KeyboardInterrupt:
    print("user stops the monitor...")    

if __name__ == 'main':
    main()
