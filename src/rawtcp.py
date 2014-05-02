import socket
from ctypes import create_string_buffer
from struct import pack, pack_into, unpack, calcsize

from utils import checksum

TCP_HDR_FMT = '!HHLLBBHHH'
TCP_PSH_FMT = '!4s4sBBH'


class TCPSegment:
    '''
    Simple Python model for a TCP segment
    '''
    def __init__(self, ip_src_addr, ip_dest_addr, tcp_src_port=12138,
                 tcp_dest_port=80, tcp_seq=1, tcp_ack_seq=0, tcp_doff=5,
                 tcp_furg=0, tcp_fack=1, tcp_fpsh=0, tcp_frst=0, tcp_fsyn=0,
                 tcp_ffin=0, tcp_adwind=1, tcp_urg_ptr=0, tcp_opts=None,
                 data=''):
        # vars for TCP pseudo-header
        # all IP addresses has been encoded
        self.ip_src_addr = ip_src_addr
        self.ip_dest_addr = ip_dest_addr
        self.zeros = 0      # padding placeholder for protocol
        self.protocol = socket.IPPROTO_TCP
        self.tcp_len = 0    # the length of TCP headers and data, computed
        # vars for TCP header
        self.tcp_src_port = tcp_src_port
        self.tcp_dest_port = tcp_dest_port
        self.tcp_seq = tcp_seq
        self.tcp_ack_seq = tcp_ack_seq
        self.tcp_doff = tcp_doff
        self.tcp_resvd = 0  # for future use and should be set to 0
        self.tcp_ffin = tcp_ffin
        self.tcp_fsyn = tcp_fsyn
        self.tcp_frst = tcp_frst
        self.tcp_fpsh = tcp_fpsh
        self.tcp_fack = tcp_fack
        self.tcp_furg = tcp_furg
        self.tcp_adwind = tcp_adwind
        self.tcp_cksum = 0  # to be computed
        self.tcp_urg_ptr = tcp_urg_ptr
        self.tcp_opts = tcp_opts
        # all HTTP stuff goes here
        self.data = data

    def __repr__(self):
        repr = ('TCPSegment: ' +
                '[src_port: %d, dest_port: %d, seq: %d, ack_seq: %d,' +
                ' doff: %d, resvd: %d, urg: %d, ack: %d, psh: %d, rst: %d,' +
                ' syn: %d, fin: %d, adwind: %d, checksum: 0x%04x, ' +
                ' urg_ptr: %d, options: %s, len(HTTP): %d]') \
            % (self.tcp_src_port, self.tcp_dest_port, self.tcp_seq,
               self.tcp_ack_seq, self.tcp_doff, self.tcp_resvd, self.tcp_furg,
               self.tcp_fack, self.tcp_fpsh, self.tcp_frst, self.tcp_fsyn,
               self.tcp_ffin, self.tcp_adwind, self.tcp_cksum,
               self.tcp_urg_ptr, 'Yes' if self.tcp_opts else None,
               len(self.data))
        return repr

    def _shift_flags(self, fin, syn, rst, psh, ack, urg):
        '''
        Shift the TCP flags to their bitwise locations
        '''
        return fin + (syn << 1) + (rst << 2) + (psh << 3) \
            + (ack << 4) + (urg << 5)

    def _deshift_flags(self, tcp_flags):
        '''
        De-shift the TCP flags to a string repr
        '''
        return (tcp_flags & 0x01,
                (tcp_flags >> 1) & 0x01,
                (tcp_flags >> 2) & 0x01,
                (tcp_flags >> 3) & 0x01,
                (tcp_flags >> 4) & 0x01,
                (tcp_flags >> 5) & 0x01,)

    def _tcp_headers_buf(self):
        '''
        Pack the real TCP header.
        '''
        # arrange TCP flags
        tcp_flags = self._shift_flags(self.tcp_ffin, self.tcp_fsyn,
                                      self.tcp_frst, self.tcp_fpsh,
                                      self.tcp_fack, self.tcp_furg)
        # concatenate TCP data offset and reserved field
        tcp_doff_resvd = (self.tcp_doff << 4) + self.tcp_resvd
        # pack real TCP header with checksum set to 0
        tcp_hdr_buf = create_string_buffer(calcsize(TCP_HDR_FMT))
        pack_into(TCP_HDR_FMT, tcp_hdr_buf, 0,
                  self.tcp_src_port, self.tcp_dest_port,
                  self.tcp_seq, self.tcp_ack_seq,
                  tcp_doff_resvd, tcp_flags,
                  self.tcp_adwind, self.tcp_cksum,
                  self.tcp_urg_ptr)
        return tcp_hdr_buf

    def _tcp_pseudo_headers(self, tcp_headers):
        '''
        Pack the TCP pseudo-header.
        '''
        self.tcp_len = len(tcp_headers) + len(self.data)
        tcp_psh = pack(TCP_PSH_FMT,
                       self.ip_src_addr, self.ip_dest_addr,
                       self.zeros, self.protocol,
                       self.tcp_len)
        return tcp_psh

    def pack(self):
        '''
        Pack the TCPSegment object to a TCP segment string.
        '''
        tcp_hdr_buf = self._tcp_headers_buf()
        tcp_psh = self._tcp_pseudo_headers(tcp_hdr_buf.raw)
        self.tcp_cksum = checksum(''.join(
            [tcp_psh, tcp_hdr_buf.raw, self.data]))
        pack_into('!H', tcp_hdr_buf,
                  calcsize(TCP_HDR_FMT[:8]),
                  self.tcp_cksum)
        tcp_segment = ''.join([tcp_hdr_buf.raw, self.data])
        return tcp_segment

    def unpack(self, tcp_segment):
        '''
        Unpack the given TCP segment string, the unpacked
        data would be stored in the current object.
        '''
        tcp_header_size = calcsize(TCP_HDR_FMT)
        tcp_headers = tcp_segment[:tcp_header_size]
        hdr_fields = unpack(TCP_HDR_FMT, tcp_headers)
        self.tcp_src_port = hdr_fields[0]
        self.tcp_dest_port = hdr_fields[1]
        self.tcp_seq = hdr_fields[2]
        self.tcp_ack_seq = hdr_fields[3]
        tcp_doff_resvd = hdr_fields[4]
        self.tcp_doff = tcp_doff_resvd >> 4  # get the data offset
        self.tcp_adwind = hdr_fields[6]
        self.tcp_urg_ptr = hdr_fields[7]
        # parse TCP flags
        tcp_flags = hdr_fields[5]
        self.tcp_ffin, self.tcp_fsyn, self.tcp_frst, \
            self.tcp_fpsh, self.tcp_fack, \
            self.tcp_furg = self._deshift_flags(tcp_flags)
        # process the TCP options if there are
        # currently just skip it
        if self.tcp_doff > 5:
            opts_size = (self.tcp_doff - 5) * 4
            tcp_header_size += opts_size
            tcp_headers = tcp_segment[:tcp_header_size]
        # get the TCP data
        self.data = tcp_segment[tcp_header_size:]
        # compute the checksum of the recv packet with psh
        tcp_psh = self._tcp_pseudo_headers(tcp_headers)
        self.tcp_cksum = checksum(''.join(
            [tcp_psh, tcp_headers, self.data]))

    def verify_checksum(self):
        '''
        Return True if the verified the received TCP packet.
        '''
        return self.tcp_cksum == 0x0000
