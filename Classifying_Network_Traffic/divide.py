# @brief Classifying Network Traffic - Python Version
# @Author CanisMinor-1037
# @Date 20220721
# @Version 0.1
from asyncore import write
from scapy.all import *
from scapy.utils import PcapReader
import os

'''
从数据包提取出五元组信息
(源IP, 源端口, 目的IP, 目的端口, 应用层协议)
将不同流分离到多个pcap文件中
'''
def process_packets(pcapfile):
    packets = rdpcap(pcapfile)
    flows = []
    dict_tuple_pcap = {} # 字典 five_tuple --> pcapfile
    pcapfile_prefix = pcapfile[0:pcapfile.find('pcap') - 1]
    #print(pcapfile_prefix)
    file_seq = 0
    #print(packets)
    #i = 0
    for packet in packets:
        #i += 1
        #print("[{}] {}".format(i, packet.payload.name))
        #print("[{}] {}:{} {}:{} {}".format(i, packet[IP].src, packet.sport, packet[IP].dst, packet.dport, packet.proto))
        if packet.payload.name == 'IP':
            if packet.proto == 6:
                if packet[IP].sport <= packet[IP].dport:
                    five_tuple = "{}:{} <-> {}:{} {}".format(
                        packet[IP].src, packet.sport, packet[IP].dst, packet.dport, 'TCP')
                else:
                    five_tuple = "{}:{} <-> {}:{} {}".format(
                        packet[IP].dst, packet.dport, packet[IP].src, packet.sport, 'TCP')
            elif packet.proto == 17:
                if packet[IP].sport <= packet[IP].dport:
                    five_tuple = "{}:{} <-> {}:{} {}".format(
                        packet[IP].src, packet.sport, packet[IP].dst, packet.dport, 'UDP')
                else:
                    five_tuple = "{}:{} <-> {}:{} {}".format(
                        packet[IP].dst, packet.dport, packet[IP].src, packet.sport, 'UDP')
            else:
                continue
            print(five_tuple)
            if five_tuple in flows:
                #print('in'), 将当前packet写入目标pcapfile
                target_pcapfile = dict_tuple_pcap[five_tuple]
                pcap_writer = PcapWriter(target_pcapfile, append = True)
                pcap_writer.write(packet)
                pcap_writer.close()
            else:
                #print('not in'), 创建新pcapfile并写入当前packet
                target_pcapfile = pcapfile_prefix + str(file_seq) + '.pcap'
                file_seq += 1
                dict_tuple_pcap[five_tuple] = target_pcapfile
                pcap_writer = PcapWriter(target_pcapfile, append=True)
                pcap_writer.write(packet)
                pcap_writer.close()  
            flows.append(five_tuple)
    return flows

'''分TCP流/UDP流, 保存到字典中'''   
def process_flows(flows):
    flows_dict = {}
    for flow in flows:
        flows_dict[flow] = flows.count(flow)
    return flows_dict
    

flows = process_packets('./test.pcap')
flows_dict = process_flows(flows)
#print(flows_dict)
print(flows)
