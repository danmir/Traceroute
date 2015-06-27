import socket
import struct
import random
import operator
import time
import select

from packets_header import iphdr, icmphdr
from get_ip import Getip
from check_whois import CheckWhois

ICMP = socket.getprotobyname('icmp')
ETH_P_IP = 0x0800
ERROR_DESCR = {
    1: ' - Note that ICMP messages can only be '
       'sent from processes running as root.',
    10013: ' - Note that ICMP messages can only be sent by'
           ' users or processes with administrator rights.'
}


class Trace():

    def __init__(self, dest_addr, timeout=1, ttl=1):
        try:
            self.dest_addr = socket.gethostbyname(dest_addr)
        except socket.gaierror:
            raise Exception("Check dest addr")
        self.timeout = timeout
        self.ttl = ttl

    def send_packet(self, ttl):
        try:
            my_socket = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            if e.errno in ERROR_DESCR:
                # Operation not permitted
                raise socket.error(''.join((e.args[1], ERROR_DESCR[e.errno])))
            raise  # raise the original error
        host = self.dest_addr

        # Maximum for an unsigned short int c object counts to 65535 so
        # we have to sure that our packet id is not greater than that.
        packet_id = int((id(self.timeout) * random.random()) % 65535)
        icmp_packet_header = icmphdr()
        icmp_packet_header.id = packet_id
        # icmp_packet_header.data = b"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
        icmp_packet = icmp_packet_header.assemble()

        g = Getip()
        ip_packet_header = iphdr(socket.IPPROTO_ICMP, g.get_lan_ip(), host)
        ip_packet_header.ttl = ttl
        ip_packet_header.data = icmp_packet
        ip_packet = ip_packet_header.assemble()

        full_packet = ip_packet

        my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        while full_packet:
            # The icmp protocol does not use a port, but the function
            # below expects it, so we just give it a dummy port.
            sent = my_socket.sendto(full_packet, (host, 1))
            full_packet = full_packet[sent:]

        delay, recv_addr = self.receive_packet(
            my_socket, packet_id, time.time())
        my_socket.close()
        return delay, recv_addr

    def receive_packet(self, my_socket, packet_id, time_sent):
        # Receive the ping from the socket.
        time_left = self.timeout
        while True:
            started_select = time.time()
            ready = select.select([my_socket], [], [], time_left)
            how_long_in_select = time.time() - started_select
            if ready[0] == []:  # Timeout
                return "Timeout", None
            time_received = time.time()

            rec_packet, addr = my_socket.recvfrom(1024)
            # disassemble layer by layer
            ip_hdr = iphdr.disassemble(rec_packet)
            icmp_hdr = icmphdr.disassemble(rec_packet[20:28])
            # Check icmp id in enclosed packet
            # It must be the same as we sended
            # But if the server replyed no need to check it
            if icmp_hdr.type == 11:  # ttl exc code
                enclosed_icmp_hdr = icmphdr.disassemble(rec_packet[48:56])
                p_id = enclosed_icmp_hdr.id
            else:
                return "Finish", addr

            if p_id == packet_id:
                return time_received - time_sent, addr
            # Wait for our packet
            time_left -= time_received - time_sent
            if time_left <= 0:
                return "Timeout", addr

    def run_trace(self):
        ttl = 1
        while 1:
            delay, recv_host = self.send_packet(ttl)
            if recv_host is not None:
                whois = CheckWhois(recv_host[0], self.timeout)
                _, country_code, originAS = whois.get_whois_info()
                try:
                    curr_host = "%s (%s)" % (
                        socket.gethostbyaddr(recv_host[0])[0], recv_host[0])
                except socket.herror:
                    curr_host = recv_host[0]
            else:
                curr_host = "*"
                country_code, originAS = "Not found", "Not found"
            ret_info = {"delay": delay, "ttl": ttl, "host_info":
                        curr_host, "country_code": country_code, "as": originAS}
            yield ret_info
            ttl += 1

            # print(delay, dest_host, recv_host)
            if delay == "Finish" or ttl >= 255:
                break
        if ttl == 255:
            print("No result for such a large ttl = 255")
