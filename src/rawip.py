import socket
from ctypes import create_string_buffer
from struct import pack_into, unpack, calcsize

from utils import checksum

IP_HDR_FMT = '!BBHHHBBH4s4s'


class IPDatagram:
    '''
    Simple Python model for an IP datagram
    '''
    def __init__(self, ip_src_addr, ip_dest_addr, ip_ver=4,
                 ip_ihl=5, ip_tos=0, ip_id=54321, ip_frag_off=0,
                 ip_ttl=255, ip_proto=socket.IPPROTO_TCP,
                 ip_opts=None, data=''):
        # vars for IP header
        # all IP addresses has been encoded
        self.ip_ver = ip_ver
        self.ip_ihl = ip_ihl
        self.ip_tos = ip_tos
        self.ip_tlen = 0
        self.ip_id = ip_id
        self.ip_frag_off = ip_frag_off
        self.ip_ttl = ip_ttl
        self.ip_proto = ip_proto
        self.ip_hdr_cksum = 0
        self.ip_src_addr = ip_src_addr
        self.ip_dest_addr = ip_dest_addr
        self.ip_opts = ip_opts
        # all TCP stuff goes here
        self.data = data
        # re-calc the IP datagram total length
        self.ip_tlen = 4 * self.ip_ihl + len(self.data)

    def __repr__(self):
        repr = ('IPDatagram: ' +
                '[ver: %d, ihl: %d, tos: %d, tlen: %d, id: %d, ' +
                ' frag_off: %d, ttl: %d, proto: %d, hdr_checksum: 0x%04x,' +
                ' src_addr: %s, dest_addr: %s, options: %s]') \
            % (self.ip_ver, self.ip_ihl, self.ip_tos, self.ip_tlen,
               self.ip_id, self.ip_frag_off, self.ip_ttl, self.ip_proto,
               self.ip_hdr_cksum, socket.inet_ntoa(self.ip_src_addr),
               socket.inet_ntoa(self.ip_dest_addr),
               'Yes' if self.ip_opts else None)
        return repr

    def pack(self):
        '''
        Pack the IPDatagram object to an IP datagram string.
        We compute the IP headers checksum with leaving the
        checksum field empty, and then pack the checksum
        into the IP headers. So that the verification of the
        header checksum could use the same checksum algorithm,
        and then simply check if the result is 0.
        '''
        ip_hdr_buf = create_string_buffer(calcsize(IP_HDR_FMT))
        ip_ver_ihl = (self.ip_ver << 4) + self.ip_ihl
        pack_into(IP_HDR_FMT, ip_hdr_buf, 0,
                  ip_ver_ihl, self.ip_tos, self.ip_tlen,
                  self.ip_id, self.ip_frag_off,
                  self.ip_ttl, self.ip_proto,
                  self.ip_hdr_cksum,
                  self.ip_src_addr, self.ip_dest_addr)
        self.ip_hdr_cksum = checksum(ip_hdr_buf.raw)
        pack_into('!H', ip_hdr_buf, calcsize(IP_HDR_FMT[:8]),
                  self.ip_hdr_cksum)
        ip_datagram = ''.join([ip_hdr_buf.raw, self.data])
        return ip_datagram

    def unpack(self, ip_datagram):
        '''
        Unpack the given IP datagram string, the unpacked
        data would be stored in the current object.
        '''
        # get the basic IP headers without opts field
        ip_header_size = calcsize(IP_HDR_FMT)
        ip_headers = ip_datagram[:ip_header_size]
        # use the ip_hdr_cksum field to hold the
        # checksum verification result, because
        # we no longer use it
        hdr_fields = unpack(IP_HDR_FMT, ip_headers)
        self.ip_tos = hdr_fields[1]
        self.ip_tlen = hdr_fields[2]
        self.ip_id = hdr_fields[3]
        self.ip_frag_off = hdr_fields[4]
        self.ip_ttl = hdr_fields[5]
        self.ip_proto = hdr_fields[6]
        self.ip_src_addr = hdr_fields[8]
        self.ip_dest_addr = hdr_fields[9]
        # process the IP opts fields if there are
        # currently just skip it
        ip_ver_ihl = hdr_fields[0]
        self.ip_ihl = ip_ver_ihl - (self.ip_ver << 4)
        if self.ip_ihl > 5:
            opts_size = (self.ip_ihl - 5) * 4
            ip_header_size += opts_size
            ip_headers = ip_datagram[:ip_header_size]
        self.data = ip_datagram[ip_header_size:self.ip_tlen]
        self.ip_hdr_cksum = checksum(ip_headers)

    def verify_checksum(self):
        '''
        Return True if verified the received IP header:
            checksum(recv_ip_headers) == 0x0000
        WARN:
        This method could only be invoked after unpack, otherwise
        the return value is unpredictable.
        '''
        return self.ip_hdr_cksum == 0x0000
