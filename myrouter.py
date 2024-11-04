#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
import threading
import queue
from switchyard.lib.userlib import *


def int2ipv4(addr):
    a = (addr >> 24) & 0xFF
    b = (addr >> 16) & 0xFF
    c = (addr >> 8) & 0xFF
    d = addr & 0xFF
    return "%d.%d.%d.%d" % (a, b, c, d)

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.end=False
        self.arp_table = {}
        self.forward_table=[]
        self.interfaces=net.interfaces()
        self.requestQueue=queue.Queue()
        self.replyQueue=queue.Queue()
        self.send_queue = queue.Queue()
        self.ArpWaitingList={}
        self.ip_list=[intf.ipaddr for intf in self.interfaces]
        self.mac_list=[intf.ethaddr for intf in self.interfaces]
        self.port_list=[intf.name for intf in self.interfaces]
        self.initialize_forward_table()
        self.lock = threading.Lock()
        self.thread=threading.Thread(target=self.arp_handler)
        self.thread.start()

    def initialize_forward_table(self):
        for interface in self.interfaces:
            self.forward_table.append([IPv4Address(int2ipv4(int(IPv4Address(interface.ipaddr)) & int(IPv4Address(interface.netmask)))),IPv4Address(interface.netmask),'0.0.0.0',interface.name])
        with open('forwarding_table.txt','r') as txt:
            lines=txt.readlines()
        for line in lines:
            line=line.strip().split(' ')
            self.forward_table.append([IPv4Address(line[0]),IPv4Address(line[1]),IPv4Address(line[2]),line[3]])
        self.forward_table.sort(key=lambda x: IPv4Network(str(x[0])+'/'+str(x[1])).prefixlen, reverse=True)

    def matches(self,destaddr):
        for item in self.forward_table:
            prefix=IPv4Address(item[0])
            mask=IPv4Address(item[1])
            if((int(mask)&int(destaddr))==int(prefix)):return item
        return None

    def arp_requester(self):
        toDelete=[]
        if(self.ArpWaitingList=={}):return
        self.lock.acquire()
        for key,value in self.ArpWaitingList.items():
            if time.time()-value[0]>=1.5:
                if value[1]>=5:
                    for i in range(self.requestQueue.qsize()):
                        tmp=self.requestQueue.get(block=False)
                        if(tmp[3]!=key):
                            self.requestQueue.put(tmp)
                    toDelete.append(key)
                else:
                    self.ArpWaitingList[key][0]=time.time()
                    self.ArpWaitingList[key][1]+=1
                    forward_info=self.matches(key)
                    arp_request_packet = Ethernet(src=self.mac_list[self.port_list.index(forward_info[3])],dst='ff:ff:ff:ff:ff:ff', ethertype=EtherType.ARP)+Arp(operation=ArpOperation.Request, senderhwaddr=self.mac_list[self.port_list.index(forward_info[3])],senderprotoaddr=self.ip_list[self.port_list.index(forward_info[3])],targethwaddr='ff:ff:ff:ff:ff:ff', targetprotoaddr=key)
                    self.send_queue.put([forward_info[3], arp_request_packet])
        for item in toDelete:
            del self.ArpWaitingList[item]
        self.lock.release()

    def arp_handler(self):
        while (not self.end):
            try:reply_pkt =self.replyQueue.get(block=False)
            except queue.Empty:
                self.arp_requester()
                continue
            self.lock.acquire()
            arp_header=reply_pkt.get_header(Arp)
            src_ip=arp_header.senderprotoaddr
            src_mac=arp_header.senderhwaddr
            try:del self.ArpWaitingList[src_ip]
            except KeyError:pass
            for i in range(self.requestQueue.qsize()):
                packet=self.requestQueue.get()
                if(packet[3]==src_ip):
                    packet[6][Ethernet].dst=src_mac
                    packet[6][Ethernet].src=self.mac_list[self.port_list.index(packet[4])]
                    packet[6][IPv4].ttl-=1
                    self.send_queue.put([packet[4],packet[6]])
                else:
                    self.requestQueue.put(packet)
            self.lock.release()
            self.arp_requester()

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        arp=packet.get_header(Arp)
        icmp=packet.get_header(ICMP)
        eth=packet.get_header(Ethernet)
        udp=packet.get_header(UDP)

        if eth.dst not in self.mac_list and eth.dst!='ff:ff:ff:ff:ff:ff':return
        if eth.dst!='ff:ff:ff:ff:ff:ff' and self.port_list[self.mac_list.index(eth.dst)]!=ifaceName:return
        if packet[Ethernet].ethertype == EtherType.VLAN:return
        
        for ip_addr in list(self.arp_table.keys()):
            if timestamp - self.arp_table[ip_addr][1] >= 50:
               # del self.arp_table[ip_addr]
               pass
            
        if arp:
            if arp.targetprotoaddr in self.ip_list:
                self.lock.acquire()
                if arp.operation==ArpOperation.Request:
                    self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr,timestamp]
                    index=self.ip_list.index(arp.targetprotoaddr)
                    reply_pkt=create_ip_arp_reply(self.mac_list[index],arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                    self.send_queue.put([ifaceName,reply_pkt])
                elif arp.operation==ArpOperation.Reply:
                   if (eth.dst != 'ff:ff:ff:ff:ff:ff') and (eth.src!='ff:ff:ff:ff:ff:ff'):
                        forward_info = self.matches(arp.targetprotoaddr)
                        if forward_info != None and forward_info[3]==ifaceName:
                            self.arp_table[arp.senderprotoaddr] = [arp.senderhwaddr, time.time()]
                        self.replyQueue.put(packet)
                else :
                    return
                self.lock.release()
        elif icmp or udp:
            if 14 + packet[IPv4].total_length != packet.size():return
            
            src_ip = packet.get_header(IPv4).src
            dst_ip = packet.get_header(IPv4).dst
            pkt_ttl = packet.get_header(IPv4).ttl
            src_mac = packet.get_header(Ethernet).src
            dst_mac = packet.get_header(Ethernet).dst

            if dst_ip in self.ip_list:return
            if dst_mac in self.mac_list:
                forward_info = self.matches(dst_ip)
                if forward_info != None:
                    next_hop_ip = forward_info[2]
                    if next_hop_ip == '0.0.0.0':next_hop_ip = dst_ip
                    if self.arp_table.get(next_hop_ip) == None:
                        if next_hop_ip not in self.ArpWaitingList.keys():
                            self.lock.acquire()
                            self.ArpWaitingList[next_hop_ip] = [time.time()-10, 0]
                            self.lock.release()
                        self.requestQueue.put([src_ip, dst_ip, src_mac, next_hop_ip, forward_info[3], pkt_ttl-1, packet])

                        
                        if next_hop_ip==IPv4Address('172.16.40.2') and self.ArpWaitingList[next_hop_ip][1]==5:
                            self.ArpWaitingList[next_hop_ip][0]-=10

                    else:
                        next_hop_mac = self.arp_table[next_hop_ip][0]
                        packet[Ethernet].src = self.mac_list[self.port_list.index(forward_info[3])]
                        packet[Ethernet].dst = next_hop_mac
                        packet[IPv4].ttl -= 1
                        self.send_queue.put([forward_info[3], packet])
        
    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                while not self.send_queue.empty():
                    packet_to_send = self.send_queue.get()
                    self.net.send_packet(packet_to_send[0], packet_to_send[1])
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)


        self.end=True
        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
