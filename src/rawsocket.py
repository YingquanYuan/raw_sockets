import socket as s
import os
import random
import fcntl
import struct
from select import select
from collections import Counter

from logger import get_logger
from rawarp import ARPPacket
from rawethernet import EthFrame
from rawip import IPDatagram
from rawtcp import TCPSegment


class RawSocket:
    def __init__(self, iface, timeout=180, tick=2):
        self.logger = get_logger(os.path.basename(__file__))
        # socket setup: 0x0800 EthType only IP
        self.socket = s.socket(s.AF_PACKET, s.SOCK_RAW)
        self.socket.bind((iface, s.SOCK_RAW))
        # IPs
        self.ip_gateway = self._get_gateway_ip(iface)
        self.ip_src = self._get_local_ip(iface)
        self.ip_dest = ''
        # ports
        self.port_src = random.randint(0x7530, 0xffff)
        self.port_dest = 80
        # MACs
        self.mac_src = self._get_local_mac(iface)
        self.mac_gateway = self._get_gateway_mac(iface)
        # TCP setup
        self.tcp_seq = random.randint(0x0001, 0xffff)
        self.tcp_ack_seq = 0
        self.tcp_cwind = 64
        # size of the receive buffer
        self.tcp_adwind = 65535
        self.recv_buf = []
        self.tmp_buf = {}
        self.prev_data = ''
        self.tick = tick
        self.maxretry = timeout / tick
        self.metrics = Counter(send=0, recv=0, erecv=0,
                               retry=0, cksumfail=0)

    def connect(self, (hostname, port)):
        '''
        Connect to the given hostname and port
        '''
        self.ip_dest = s.inet_aton(s.gethostbyname(hostname))
        self.port_dest = port
        # 3-way handshake
        self._tcp_handshake()

    def send(self, data=''):
        '''
        Send all the given data, the TCP congestion control
        goes here, so that data might be sliced
        '''
        slen = 0
        tlen = len(data)
        while slen < tlen:
            self._send(data[slen:(slen + self.tcp_cwind)], ack=1)
            # update TCP seq
            if (slen + self.tcp_cwind) > tlen:
                self.tcp_seq += (tlen - slen)
            else:
                self.tcp_seq += self.tcp_cwind
            slen += self.tcp_cwind
        return tlen

    def recv(self, bufsize=8192):
        '''
        Receive the data with the given buffer size,
        the receiving buffer gets maintained here
        '''
        rlen = 0
        tcp_data = ''
        times = 1 + bufsize / self.tcp_adwind
        fin = False
        while times:
            while rlen < self.tcp_adwind:
                tcp_segment = self._recv(self.maxretry)
                if tcp_segment is None:
                    raise RuntimeError('Connection timeout')
                elif tcp_segment.tcp_fack:
                    if (tcp_segment.tcp_seq == self.tcp_ack_seq):
                        self.logger.debug('Recv in-order TCP segment')
                        rlen += self._enbuf(tcp_segment)
                        self._send(ack=1)
                        if tcp_segment.tcp_ffin:
                            fin = True
                            break
                        while self.tcp_ack_seq in self.tmp_buf:
                            tcp_segment = self.tmp_buf[self.tcp_ack_seq]
                            rlen += self._enbuf(tcp_segment)
                            if tcp_segment.tcp_ffin:
                                fin = True
                                break
                        self._send(ack=1)
                        if fin:
                            break
                    elif (tcp_segment.tcp_seq > self.tcp_ack_seq) and \
                            (tcp_segment.tcp_seq not in self.tmp_buf):
                        self.logger.debug('Recv out-of-order TCP segment')
                        self.tmp_buf[tcp_segment.tcp_seq] = tcp_segment
                else:
                    continue
            tcp_data = ''.join([tcp_data, self._debuf()])
            if fin:
                return tcp_data
            times -= 1
        return tcp_data

    def close(self):
        '''
        Tear down the raw socket connection
        '''
        self._tcp_teardown()
        self.socket.close()

    def _get_local_ip(self, iface):
        '''
        Get the IP address of the local interface
        NOTE: IP address already encoded
        '''
        try:
            ip = fcntl.ioctl(self.socket.fileno(), 0x8915,
                             struct.pack('256s', iface[:15]))[20:24]
            return ip
        except IOError:
            raise RuntimeError('Cannot get IP address of local interface %s'
                               % iface)

    def _get_local_mac(self, iface):
        '''
        Get tge mac address of the local interface
        NOTE: MAC address already encoded
        '''
        try:
            mac = fcntl.ioctl(self.socket.fileno(), 0x8927,
                              struct.pack('256s', iface[:15]))[18:24]
            return mac
        except IOError:
            raise RuntimeError('Cannot get mac address of local interface %s'
                               % iface)

    def _get_gateway_ip(self, iface):
        '''
        Look up the gateway IP address from /proc/net/route
        '''
        with open('/proc/net/route') as route_info:
            for line in route_info:
                fields = line.strip().split()
                if fields[0] == iface and fields[1] == '00000000':
                    return struct.pack('<L', int(fields[2], 16))
            else:
                raise RuntimeError('Cannot find the default gateway Ip ' +
                                   'address in /proc/net/route, please ' +
                                   'pass the correct network interface name')

    def _get_gateway_mac(self, iface):
        '''
        Query the gateway MAC address through ARP request
        '''
        spa = self.ip_src
        sha = self.mac_src
        tpa = self.ip_gateway
        # pack the ARP broadcast mac address
        tha = struct.pack('!6B',
                          int('FF', 16), int('FF', 16), int('FF', 16),
                          int('FF', 16), int('FF', 16), int('FF', 16))
        # pack ARP request
        arp_packet = ARPPacket(sha=sha, spa=spa, tha=tha, tpa=tpa)
        eth_data = arp_packet.pack()
        # pack Ethernet Frame: 0x0806 wrapping ARP packet
        eth_frame = EthFrame(dest_mac=tha, src_mac=sha, tcode=0x0806,
                             data=eth_data)
        self.logger.debug('Sending ARP REQUEST for the gateway MAC:' +
                          '\n\t%s\n\t%s' % (arp_packet, eth_frame))
        self.logger.info('Querying gateway MAC address, %s' % arp_packet)
        phy_data = eth_frame.pack()
        self.socket.send(phy_data)
        while True:
            data = self.socket.recv(4096)
            eth_frame.unpack(data)
            if eth_frame.eth_tcode == 0x0806:
                break
        arp_packet.unpack(eth_frame.data)
        self.logger.debug('Receiving ARP REPLY of the gateway MAC:' +
                          '\n\t%s\n\t%s' % (arp_packet, eth_frame))
        self.logger.info('Get gateway MAC address, %s' % arp_packet)
        return arp_packet.arp_sha

    def _tcp_handshake(self):
        '''
        Wrap the TCP 3-way handshake procedure
        '''
        self._send(syn=1)
        tcp_segment = self._recv(self.maxretry)
        # check timeout
        if tcp_segment is None:
            raise RuntimeError('TCP handshake failed, connection timeout')
        # check server ACK | SYN
        if not (tcp_segment.tcp_fack and tcp_segment.tcp_fsyn):
            raise RuntimeError('TCP handshake failed, bad server response')
        # save next ACK seq
        self.tcp_seq = tcp_segment.tcp_ack_seq
        self.tcp_ack_seq = tcp_segment.tcp_seq + 1
        self._send(ack=1)

    def _tcp_teardown(self):
        '''
        Tear down the stateful TCP connection before explicitly
        closing the raw socket
        '''
        self._send(fin=1, ack=1)
        tcp_segment = self._recv(self.maxretry)
        # check timeout
        if tcp_segment is None:
            raise RuntimeError('TCP teardown failed, connection timeout')
        # check server ACK
        if not tcp_segment.tcp_fack:
            raise RuntimeError('TCP teardown failed, server not ACK to FIN')
        tcp_segment = self._recv(self.maxretry)
        # check server FIN
        if not tcp_segment.tcp_ffin:
            raise RuntimeError('TCP teardown failed, server not FIN')
        self.tcp_seq = tcp_segment.tcp_ack_seq
        self.tcp_ack_seq = tcp_segment.tcp_seq + 1
        self._send(ack=1)

    def _send(self, data='', retry=False, urg=0, ack=0, psh=0,
              rst=0, syn=0, fin=0):
        '''
        Send the given data within a packet the set TCP flags,
        return the number of bytes sent.
        '''
        if retry:
            return self.socket.send(self.prev_data)
        else:
            # build TCP segment
            tcp_segment = TCPSegment(ip_src_addr=self.ip_src,
                                     ip_dest_addr=self.ip_dest,
                                     tcp_src_port=self.port_src,
                                     tcp_dest_port=self.port_dest,
                                     tcp_seq=self.tcp_seq,
                                     tcp_ack_seq=self.tcp_ack_seq,
                                     tcp_furg=urg, tcp_fack=ack, tcp_fpsh=psh,
                                     tcp_frst=rst, tcp_fsyn=syn, tcp_ffin=fin,
                                     tcp_adwind=self.tcp_adwind, data=data)
            ip_data = tcp_segment.pack()
            # build IP datagram
            ip_datagram = IPDatagram(ip_src_addr=self.ip_src,
                                     ip_dest_addr=self.ip_dest,
                                     data=ip_data)
            eth_data = ip_datagram.pack()
            # build Ethernet Frame
            eth_frame = EthFrame(dest_mac=self.mac_gateway,
                                 src_mac=self.mac_src,
                                 data=eth_data)
            phy_data = eth_frame.pack()
            # send raw data
            self.logger.debug('Send: %s' % tcp_segment)
            self.metrics['send'] += 1
            self.prev_data = phy_data
            return self.socket.send(phy_data)

    def _recv(self, maxretry, bufsize=1500):
        '''
        Receive a packet with the given buffer size, will not retry
        for per-packet failure until using up maxretry
        '''
        while maxretry:
            self.metrics['recv'] += 1
            # wait with timeout for the readable socket
            rsock, wsock, exsock = select([self.socket], [], [], self.tick)
            # socket is ready to read, no timeout
            if self.socket in rsock:
                # process Ethernet frame
                phy_data = self.socket.recv(bufsize)
                eth_frame = EthFrame()
                eth_frame.unpack(phy_data)
                # process IP datagram
                eth_data = eth_frame.data
                ip_datagram = IPDatagram(self.ip_src, self.ip_dest)
                ip_datagram.unpack(eth_data)
                # IP filtering
                if not self._ip_expected(ip_datagram):
                    continue
                # IP checksum
                if not ip_datagram.verify_checksum():
                    return self._retry(bufsize, maxretry)
                # process TCP segment
                ip_data = ip_datagram.data
                tcp_segment = TCPSegment(self.ip_src, self.ip_dest)
                tcp_segment.unpack(ip_data)
                # TCP filtering
                if not self._tcp_expected(tcp_segment):
                    continue
                # TCP checksum
                if not tcp_segment.verify_checksum():
                    self.metrics['cksumfail'] += 1
                    return self._retry(bufsize, maxretry)
                self.logger.debug('Recv: %s' % tcp_segment)
                self.metrics['erecv'] += 1
                return tcp_segment
            # timeout, re-_send and re-_recv
            else:
                return self._retry(bufsize, maxretry)
        return None

    def _retry(self, bufsize, maxretry):
        '''
        Re-_send and re-_recv with the maxretry -1
        Mutual recursion with self._recv(bufsize)
        '''
        self.metrics['retry'] += 1
        maxretry -= 1
        self._send(retry=True, ack=1)
        return self._recv(bufsize, maxretry)

    def _enbuf(self, tcp_segment):
        '''
        Put the in-order TCP payload into recv buffer
        '''
        self.recv_buf.append(tcp_segment.data)
        elen = len(tcp_segment.data)
        self.tcp_seq = tcp_segment.tcp_ack_seq
        self.tcp_ack_seq += elen
        # self._send(ack=1)
        return elen

    def _debuf(self):
        '''
        Dump all cached TCP payload out from the recv buffer
        '''
        tcp_data = ''
        for slice in self.recv_buf:
            tcp_data = ''.join([tcp_data, slice])
        del self.recv_buf[:]
        self.tmp_buf.clear()
        return tcp_data

    def _ip_expected(self, ip_datagram):
        '''
        Return True if the received ip_datagram is the
        expected one.
        1. ip_ver should be 4
        2. ip_src_addr should be the expected dest machine
        3. ip_proto identifier should be TCP(6)
        '''
        if ip_datagram.ip_ver != 4:
            return False
        elif ip_datagram.ip_src_addr != self.ip_dest:
            return False
        elif ip_datagram.ip_proto != s.IPPROTO_TCP:
            return False
        else:
            return True

    def _tcp_expected(self, tcp_segment):
        '''
        Return True if the received tcp_segment is the
        expected one.
        1. tcp_src_port should be the local dest port
        2. tcp_dest_port shoule be the local src port
        3. raise error if server resets the connection
        4. checksum must be valid
        '''
        if tcp_segment.tcp_src_port != self.port_dest:
            return False
        elif tcp_segment.tcp_dest_port != self.port_src:
            return False
        elif tcp_segment.tcp_frst:
            raise RuntimeError('Connection reset by server')
        else:
            return True

    def dump_metrics(self):
        '''
        Dump the metrics counters for debug usage
        '''
        dump = '\n'.join('\t%s: %d' % (k, v) for (k, v)
                         in self.metrics.items())
        return dump, self.metrics
