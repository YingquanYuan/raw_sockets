from struct import pack, unpack, calcsize

ETH_HDR_FMT = '!6s6sH'


class EthFrame():
    '''
    Simple Python model for an Ethernet Frame
    '''
    def __init__(self, dest_mac='', src_mac='', tcode=0x0800, data=''):
        self.eth_dest_addr = dest_mac
        self.eth_src_addr = src_mac
        self.eth_tcode = tcode
        self.data = data

    def __repr__(self):
        repr = ('EthFrame: ' +
                '[dest_mac: %s, src_mac: %s, tcode: 0x%04x,' +
                ' len(data): %d]') \
            % (self._eth_addr(self.eth_dest_addr),
               self._eth_addr(self.eth_src_addr),
               self.eth_tcode, len(self.data))
        return repr

    def pack(self):
        eth_header = pack(ETH_HDR_FMT,
                          self.eth_dest_addr, self.eth_src_addr,
                          self.eth_tcode)
        eth_frame = ''.join([eth_header, self.data])
        return eth_frame

    def unpack(self, eth_frame):
        hdr_len = calcsize(ETH_HDR_FMT)
        eth_headers = eth_frame[:hdr_len]
        eth_fields = unpack(ETH_HDR_FMT, eth_headers)
        self.eth_dest_addr = eth_fields[0]
        self.eth_src_addr = eth_fields[1]
        self.eth_tcode = eth_fields[2]
        self.data = eth_frame[hdr_len:]

    def _eth_addr(self, raw):
        hex = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' \
            % (ord(raw[0]), ord(raw[1]), ord(raw[2]),
               ord(raw[3]), ord(raw[4]), ord(raw[5]))
        return hex
