from socket import inet_ntoa
from struct import pack, unpack, calcsize

ARP_PKT_FMT = '!HHBBH6s4s6s4s'


class ARPPacket():
    '''
    Simple Python model for an ARP Packet
    '''
    def __init__(self, htype=0x0001, ptype=0x0800, hlen=0x0006,
                 plen=0x0004, optr=1, sha='', spa='', tha='', tpa=''):
        self.arp_htype = htype
        self.arp_ptype = ptype
        self.arp_hlen = hlen
        self.arp_plen = plen
        self.arp_optr = optr
        self.arp_sha = sha
        self.arp_spa = spa
        self.arp_tha = tha
        self.arp_tpa = tpa

    def __repr__(self):
        repr = ('ARPPacket: ' +
                '[htype: 0x%04x, ptype: 0x%04x, hlen: 0x%04x, plen: 0x%04x,' +
                ' optration: %s, sha: %s, spa: %s, tha: %s, tpa: %s]') \
            % (self.arp_htype, self.arp_ptype, self.arp_hlen, self.arp_plen,
               'REQUEST' if self.arp_optr == 1 else 'REPLY',
               self._eth_addr(self.arp_sha), inet_ntoa(self.arp_spa),
               self._eth_addr(self.arp_tha), inet_ntoa(self.arp_tpa))
        return repr

    def pack(self):
        arp_packet = pack(ARP_PKT_FMT,
                          self.arp_htype, self.arp_ptype, self.arp_hlen,
                          self.arp_plen, self.arp_optr, self.arp_sha,
                          self.arp_spa, self.arp_tha, self.arp_tpa)
        return arp_packet

    def unpack(self, arp_packet):
        arp_fields = unpack(ARP_PKT_FMT, arp_packet[:calcsize(ARP_PKT_FMT)])
        self.arp_htype = arp_fields[0]
        self.arp_ptype = arp_fields[1]
        self.arp_hlen = arp_fields[2]
        self.arp_plen = arp_fields[3]
        self.arp_optr = arp_fields[4]
        self.arp_sha = arp_fields[5]
        self.arp_spa = arp_fields[6]
        self.arp_tha = arp_fields[7]
        self.arp_tpa = arp_fields[8]

    def _eth_addr(self, raw):
        hex = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' \
            % (ord(raw[0]), ord(raw[1]), ord(raw[2]),
               ord(raw[3]), ord(raw[4]), ord(raw[5]))
        return hex
